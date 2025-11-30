use assert_cmd::cargo::{CommandCargoExt, cargo_bin};
use reqwest::Client;
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;
use tempfile::NamedTempFile;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use std::io::Write;

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

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}


#[tokio::test]
async fn test_routes_apply_different_filters_templated() {
    
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

    
    let mut cmd = Command::new(cargo_bin!("river"));
    cmd.arg("--config-entry").arg(config_file.path());
    
    #[allow(clippy::zombie_processes)]
    let mut child = cmd.spawn().expect("Failed to start river process");

    
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

    
    let _ = child.kill();
}