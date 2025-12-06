#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::thread;
    use std::net::TcpListener;
    
    use motya_config::cli::cli::{Cli, Commands};
    use reqwest::Client;
    
    use motya::app_context::AppContext;

    fn get_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn wait_for_service(url: &str) {
        let client = Client::new();
        for _ in 0..20 { 
            if client.get(url).send().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("Service at {} did not start in time", url);
    }

    // --- ТЕСТ HELLO MODE ---
    #[tokio::test]
    async fn test_cli_hello_mode_direct() {
        let port = get_free_port();
        let expected_text = "Direct API Test";

        let cli = Cli {
            validate_configs: false,
            threads_per_service: None,
            config_toml: None, 
            config_entry: None,
            daemonize: false,
            upgrade: false,
            pidfile: None,
            upgrade_socket: None,
            command: Some(Commands::Hello {
                port,
                text: expected_text.to_string(),
            }),
        };

        let mut app_ctx = AppContext::bootstrap(cli).await.expect("Bootstrap failed");

        let services = app_ctx.build_services().await.expect("Build services failed");

        let (mut server, _watcher) = app_ctx.ready();
        server.add_services(services);
        server.bootstrap(); 

        thread::spawn(move || {
            server.run_forever();
        });

        let url = format!("http://127.0.0.1:{}", port);
        wait_for_service(&url).await;

        let resp = Client::new().get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), expected_text);
    }

    // --- ТЕСТ SERVE MODE ---
    #[tokio::test]
    async fn test_cli_serve_mode_direct() {
        let port = get_free_port();
        
        let backend = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("Backend OK"))
            .mount(&backend)
            .await;

        let cli = Cli {
            validate_configs: false,
            threads_per_service: None,
            config_toml: None,
            config_entry: None,
            daemonize: false,
            upgrade: false,
            pidfile: None,
            upgrade_socket: None,
            command: Some(Commands::Serve {
                port,
                map: vec![
                    format!("/proxy={}", backend.uri()),
                    "/static=StaticData".to_string()
                ],
            }),
        };

        let mut app_ctx = AppContext::bootstrap(cli).await.expect("Bootstrap failed");
        
        let services = app_ctx.build_services().await.expect("Build services failed");
        let (mut server, _watcher) = app_ctx.ready();
        server.add_services(services);
        server.bootstrap();

        thread::spawn(move || {
            server.run_forever();
        });

        let base = format!("http://127.0.0.1:{}", port);
        
        wait_for_service(&format!("{}/static", base)).await;
        let resp = Client::new().get(format!("{}/static", base)).send().await.unwrap();
        assert_eq!(resp.text().await.unwrap(), "StaticData");

        let resp = Client::new().get(format!("{}/proxy", base)).send().await.unwrap();
        assert_eq!(resp.text().await.unwrap(), "Backend OK");
    }
    #[tokio::test]
    async fn test_cli_serve_multiple_upstreams_routing() {
        
        let proxy_port = get_free_port();
        
        
        let service_users = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/users/list")) 
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("UserList JSON"))
            .mount(&service_users)
            .await;

            
        let service_orders = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/orders/create"))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_string("Order Created"))
            .mount(&service_orders)
            .await;

        let cli = Cli {
            validate_configs: false,
            threads_per_service: None,
            config_toml: None,
            config_entry: None,
            daemonize: false,
            upgrade: false,
            pidfile: None,
            upgrade_socket: None,
            command: Some(Commands::Serve {
                port: proxy_port,
                map: vec![
                    format!("/users={}", service_users.uri()),
                    format!("/orders={}", service_orders.uri()),
                    "/health=OK".to_string(),
                ],
            }),
        };
        dbg!(&cli);
        let mut app_ctx = AppContext::bootstrap(cli).await.expect("Bootstrap failed");
        let services = app_ctx.build_services().await.expect("Build services failed");
        let (mut server, _watcher) = app_ctx.ready();
        
        server.add_services(services);
        server.bootstrap();

        thread::spawn(move || {
            server.run_forever();
        });

        let base_url = format!("http://127.0.0.1:{}", proxy_port);
        wait_for_service(&format!("{}/health", base_url)).await;

        let client = Client::new();

        
        let resp_health = client.get(format!("{}/health", base_url)).send().await.unwrap();
        assert_eq!(resp_health.status(), 200);
        assert_eq!(resp_health.text().await.unwrap(), "OK");

        let resp_users = client.get(format!("{}/users/list", base_url)).send().await.unwrap();
        assert_eq!(resp_users.status(), 200);
        assert_eq!(resp_users.text().await.unwrap(), "UserList JSON");

        let resp_orders = client.post(format!("{}/orders/create", base_url)).send().await.unwrap();
        assert_eq!(resp_orders.status(), 201);
        assert_eq!(resp_orders.text().await.unwrap(), "Order Created");

        let resp_404 = client.get(format!("{}/unknown", base_url)).send().await.unwrap();
        assert!(!resp_404.status().is_success(), "Should fail on unmapped route");
    }
}
