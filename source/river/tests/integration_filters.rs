use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::io::Write;
use std::net::TcpListener;

use http::Uri;
use reqwest::Client;
use river::config::builder::ConfigLoader;
use river::proxy::filters::generate_registry;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use tempfile::NamedTempFile;

use pingora::{prelude::HttpPeer, server::Server, services::Service};
use river::{config::{common_types::{connectors::{Connectors, HttpPeerOptions, Upstream, UpstreamConfig}, definitions::{ConfiguredFilter, DefinitionsTable, FilterChain, Modificator, NamedFilterChain}, listeners::{ListenerConfig, ListenerKind, Listeners}}, internal::{Config, ProxyConfig}}, proxy::{filters::{chain_resolver::ChainResolver, generate_registry::load_registry}, river_proxy_service}};
use fqdn::fqdn;
use tokio::runtime::Runtime;

const TEST_CONFIG: &str = r#"
    definitions {
        modifiers {
            chain-filters "filter-a" {
                filter name="river.request.upsert-header" key="X-Service" value="A"
            }
            chain-filters "filter-b" {
                filter name="river.request.upsert-header" key="X-Service" value="B"
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


async fn start_server_from_config_path(
    config_path: &std::path::Path
) -> thread::JoinHandle<()> {
    
    let mut definitions_table = DefinitionsTable::default();
    let registry = load_registry(&mut definitions_table);

    let filter_a = FilterChain { filters: vec![ConfiguredFilter {
        name: fqdn!("river.request.upsert-header"),
        args: HashMap::from([("key".to_string(), "X-Service".to_string()), ("value".to_string(), "A".to_string())]),
    }]};
    definitions_table.insert_chain("filter-a", filter_a.clone());

    let filter_b = FilterChain { filters: vec![ConfiguredFilter {
        name: fqdn!("river.request.upsert-header"),
        args: HashMap::from([("key".to_string(), "X-Service".to_string()), ("value".to_string(), "B".to_string())]),
    }]};
    definitions_table.insert_chain("filter-b", filter_b.clone());

    let resolver = ChainResolver::new(definitions_table, registry).unwrap();
    let conf = Config::default(); 
    
    let loader = ConfigLoader::new();

    let mut global_definitions = DefinitionsTable::default();
    let mut registry = generate_registry::load_registry(&mut global_definitions);
    
    let config = loader.load_entry_point(Some(config_path), &mut global_definitions, &mut registry).await
        .unwrap()
        .unwrap();

    let proxy = config.basic_proxies.first().cloned().unwrap();

    let mut app_server = Server::new_with_opt_and_conf(conf.pingora_opt(), conf.pingora_server_conf());
    let proxy_service = river_proxy_service(proxy, &resolver, &app_server).unwrap();
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

    Mock::given(method("GET")).and(path("/service-a")).and(header("X-Service", "A")).respond_with(ResponseTemplate::new(200).set_body_string("Response from A")).mount(&mock_server_a).await;
    Mock::given(method("GET")).and(path("/service-b")).and(header("X-Service", "B")).respond_with(ResponseTemplate::new(200).set_body_string("Response from B")).mount(&mock_server_b).await;
    
    let proxy_port = get_free_port();
    
    let config_content = TEST_CONFIG
        .replace("__SERVICE_A__", &mock_server_a.uri().to_string()) 
        .replace("__SERVICE_B__", &mock_server_b.uri().to_string())
        .replace("__PORT__", &proxy_port.to_string());

    let mut config_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(config_file, "{}", config_content).expect("Failed to write config");
    
    let handle = start_server_from_config_path(
        config_file.path()
    ).await;
    
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