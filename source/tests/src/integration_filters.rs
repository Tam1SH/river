use motya::proxy::filters::chain_resolver::ChainResolver;
use motya::proxy::filters::generate_registry::load_registry;
use motya::proxy::motya_proxy_service;
use motya_config::builder::ConfigLoader;
use motya_config::builder::FileConfigLoaderProvider;
use motya_config::common_types::definitions_table::DefinitionsTable;
use motya_config::internal::Config;
use pingora::server::Server;
use reqwest::Client;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_CONFIG: &str = r#"
    definitions {
        modifiers {
            chain-filters "filter-a" {
                filter name="motya.request.upsert-header" key="X-Service" value="A"
            }
            chain-filters "filter-b" {
                filter name="motya.request.upsert-header" key="X-Service" value="B"
            }
        }
    }

    services {
        TestService {
            connectors {
                section "/service-a" {
                    use-chain "filter-a"
                    proxy "__SERVICE_A__"
                }
                
                section "/service-b" {
                    use-chain "filter-b"
                    proxy "__SERVICE_B__"
                }
            }
            listeners {
                "127.0.0.1:__PORT__"
            }
        }
    }
"#;

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn wait_for_proxy_start(url: &str) {
    let client = Client::new();
    for _ in 0..30 {
        if client.get(url).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Proxy failed to start/respond at {}", url);
}

async fn start_server_from_config_path(config_path: &std::path::Path) -> thread::JoinHandle<()> {
    let mut definitions_table = DefinitionsTable::default();
    let registry = load_registry(&mut definitions_table);

    let conf = Config::default();

    let loader = ConfigLoader::default();

    let config = loader
        .load_entry_point(Some(config_path.to_path_buf()), &mut definitions_table)
        .await
        .unwrap()
        .unwrap();

    let resolver = ChainResolver::new(definitions_table.clone(), Arc::new(registry.into()))
        .await
        .unwrap();

    let proxy = config.basic_proxies.first().cloned().unwrap();

    let mut app_server =
        Server::new_with_opt_and_conf(conf.pingora_opt(), conf.pingora_server_conf());
    let (proxy_service, _) = motya_proxy_service(proxy, resolver, &app_server)
        .await
        .unwrap();
    app_server.bootstrap();
    app_server.add_services(vec![proxy_service]);

    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        tx.send(()).expect("Failed to send ready signal");
        app_server.run_forever();
    });

    rx.recv().expect("Server failed to start");

    handle
}

#[tokio::test]
async fn test_routes_apply_different_filters_internal_file() {
    let mock_server_a = MockServer::start().await;
    let mock_server_b = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/service-a"))
        .and(header("X-Service", "A"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Response from A"))
        .mount(&mock_server_a)
        .await;
    Mock::given(method("GET"))
        .and(path("/service-b"))
        .and(header("X-Service", "B"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Response from B"))
        .mount(&mock_server_b)
        .await;

    let proxy_port = get_free_port();

    let config_content = TEST_CONFIG
        .replace("__SERVICE_A__", &mock_server_a.uri().to_string())
        .replace("__SERVICE_B__", &mock_server_b.uri().to_string())
        .replace("__PORT__", &proxy_port.to_string());

    let mut config_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(config_file, "{}", config_content).expect("Failed to write config");

    let handle = start_server_from_config_path(config_file.path()).await;

    let proxy_base = format!("http://127.0.0.1:{}", proxy_port);
    let url_a = format!("{}/service-a", proxy_base);
    let url_b = format!("{}/service-b", proxy_base);

    wait_for_proxy_start(&url_a).await;

    let client = Client::new();

    let resp_a = client.get(&url_a).send().await.expect("Request A failed");
    assert_eq!(resp_a.status(), 200, "Service A status mismatch");
    assert_eq!(resp_a.text().await.unwrap(), "Response from A");

    let resp_b = client.get(&url_b).send().await.expect("Request B failed");
    assert_eq!(resp_b.status(), 200, "Service B status mismatch");
    assert_eq!(resp_b.text().await.unwrap(), "Response from B");

    handle.thread().unpark();
}
