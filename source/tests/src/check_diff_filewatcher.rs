#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;
    use std::net::TcpListener;
    use std::thread;

    use motya::proxy::motya_proxy_service;
    use motya::proxy::upstream_factory::UpstreamFactory;
    use motya::proxy::watcher::file_watcher::ConfigWatcher;
    use motya_config::common_types::definitions::DefinitionsTable;
    use tokio::sync::Mutex;
    use tokio::time::timeout;
    use tempfile::tempdir;
    use motya_config::builder::{ConfigLoader, ConfigLoaderProvider};
    use motya::proxy::filters::{chain_resolver::ChainResolver, registry::FilterRegistry};
    use pingora::server::Server;
    use reqwest::Client;

    fn get_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn get_response_body(port: u16, path: &str) -> Option<String> {
        let client = Client::new();
        let url = format!("http://127.0.0.1:{}{}", port, path);
        
        match client.get(&url).send().await {
            Ok(resp) => {
                // We accept 200 and 500 (used in Stage 2) as valid responses for verification
                if resp.status().is_success() || resp.status().as_u16() == 500 {
                    resp.text().await.ok()
                } else {
                    None
                }
            },
            Err(_) => None,
        }
    }

    async fn wait_for_route_update(
        port: u16, 
        path: &str, 
        expected_body: Option<&str>
    ) {
        let check_future = async {
            loop {
                let current_body = get_response_body(port, path).await;
                let expected_owned = expected_body.map(|s| s.to_string());
                
                if current_body == expected_owned {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };

        if timeout(Duration::from_secs(5), check_future).await.is_err() {
            panic!(
                "Timeout waiting for path '{}' to become {:?}. Current: {:?}", 
                path, expected_body, get_response_body(port, path).await
            );
        }
    }

    #[tokio::test]
    async fn test_config_watcher_fs_integration() {
        let dir = tempdir().expect("Failed to create temp dir");
        let config_path = dir.path().join("motya.conf");
        let port = get_free_port();
        
        // We use __PORT__ placeholder to ensure we can run on a random free port
        let config_stage_1 = r#"
            services {
                TestService {
                    listeners { "127.0.0.1:__PORT__" }
                    connectors {
                        section "/1" { return code="200" response="OK1" }
                        section "/2" { return code="200" response="OK2" }
                        section "/3" { return code="200" response="OK3" }
                    }
                }
            }
        "#;

        let config_stage_2 = r#"
            services {
                TestService {
                    listeners { "127.0.0.1:__PORT__" }
                    connectors {
                        section "/2" { return code="500" response="BAD" }
                        section "/4" { return code="200" response="OK4" }
                        section "/5" { return code="200" response="OK5" }
                    }
                }
            }
        "#;

        let config_stage_3 = r#"
            services {
                TestService {
                    listeners { "127.0.0.1:__PORT__" }
                    connectors {
                        section "/1" { return code="200" response="OK1" }
                        section "/2" { return code="200" response="OK NOW" }
                        section "/3" { return code="200" response="OK3" }
                        section "/4" { return code="200" response="OK4" }
                        section "/5" { return code="200" response="OK5" }
                    }
                }
            }
        "#;

        {
            let mut file = File::create(&config_path).unwrap();
            let content = config_stage_1.replace("__PORT__", &port.to_string());
            file.write_all(content.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }

        let mut definitions = DefinitionsTable::default();
        let loader = ConfigLoader::default();
        
        let config = loader.clone()
            .load_entry_point(Some(config_path.clone()), &mut definitions)
            .await
            .expect("Failed to load initial config")
            .expect("Config should be present");

        let registry = Arc::new(Mutex::new(FilterRegistry::default()));
        let resolver = ChainResolver::new(definitions.clone(), registry).await.unwrap();
        let factory = UpstreamFactory::new(resolver.clone());

        // Start the real Pingora server in background
        let mut app_server = Server::new_with_opt_and_conf(config.pingora_opt(), config.pingora_server_conf());
        app_server.bootstrap();

        let proxy_config = config.basic_proxies[0].clone();
        let (service, shared_state) = motya_proxy_service(proxy_config, resolver, &app_server).await.unwrap();
        
        app_server.add_services(vec![service]);
        thread::spawn(move || {
            app_server.run_forever();
        });

        // Initialize Watcher
        let mut watcher = ConfigWatcher::new(
            config.clone(),
            definitions,
            config_path.clone(),
            factory.clone(),
            loader
        );

        watcher.insert_proxy_state("TestService".to_string(), shared_state.clone());
        
        tokio::spawn(async move {
            let Err(e) = watcher.watch().await;
            panic!("Watcher failed: {}", e);
        });

        println!("Checking Stage 1...");
        // Ensure server is up and routes are ready
        wait_for_route_update(port, "/1", Some("OK1")).await;
        
        assert_eq!(get_response_body(port, "/1").await, Some("OK1".to_string()));
        assert_eq!(get_response_body(port, "/2").await, Some("OK2".to_string()));
        assert_eq!(get_response_body(port, "/3").await, Some("OK3".to_string()));
        assert_eq!(get_response_body(port, "/4").await, None);
        assert_eq!(get_response_body(port, "/5").await, None);

        
        println!("Writing Stage 2 (FS modification)...");
        {
            let mut file = File::create(&config_path).unwrap();
            let content = config_stage_2.replace("__PORT__", &port.to_string());
            file.write_all(content.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }

        
        wait_for_route_update(port, "/4", Some("OK4")).await;

        println!("Verifying Stage 2...");
        
        assert_eq!(get_response_body(port, "/1").await, None, "Route /1 should be removed");
        assert_eq!(get_response_body(port, "/2").await, Some("BAD".to_string()), "Route /2 should be updated");
        assert_eq!(get_response_body(port, "/3").await, None, "Route /3 should be removed");
        assert_eq!(get_response_body(port, "/4").await, Some("OK4".to_string()));
        assert_eq!(get_response_body(port, "/5").await, Some("OK5".to_string()));

        println!("Writing Stage 3 (Merge)...");
        {
            let mut file = File::create(&config_path).unwrap();
            let content = config_stage_3.replace("__PORT__", &port.to_string());
            file.write_all(content.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }

        wait_for_route_update(port, "/1", Some("OK1")).await;

        println!("Verifying Stage 3...");
        assert_eq!(get_response_body(port, "/1").await, Some("OK1".to_string()));
        assert_eq!(get_response_body(port, "/2").await, Some("OK NOW".to_string()));
        assert_eq!(get_response_body(port, "/3").await, Some("OK3".to_string())); 
        assert_eq!(get_response_body(port, "/4").await, Some("OK4".to_string()));
        assert_eq!(get_response_body(port, "/5").await, Some("OK5".to_string()));
    }
}