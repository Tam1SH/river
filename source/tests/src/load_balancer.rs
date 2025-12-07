use std::{io::Write, net::TcpListener, thread, time::Duration};

use reqwest::Client;
use tempfile::NamedTempFile;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

use motya::app_context::AppContext;
use motya_config::cli::cli_struct::Cli;

const LB_CONFIG_TEMPLATE: &str = r#"
services {
    LoadBalancerTest {
        listeners {
            "127.0.0.1:__PROXY_PORT__"
        }
        connectors {
        
            load-balance {
                selection "RoundRobin"
            }
            
            section "/" {
                proxy {
                    server "__BACKEND_1__"
                    server "__BACKEND_2__"
                    server "__BACKEND_3__"
                }
            }
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

async fn wait_for_proxy(url: &str) {
    let client = Client::new();
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(5) {
        if client.get(url).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Proxy did not start at {} within timeout", url);
}

#[tokio::test]
async fn test_load_balancer_round_robin_distribution() {
    let backend1 = MockServer::start().await;
    let backend2 = MockServer::start().await;
    let backend3 = MockServer::start().await;

    let mock_response = ResponseTemplate::new(200).set_body_string("OK");
    Mock::given(method("GET"))
        .respond_with(mock_response.clone())
        .mount(&backend1)
        .await;
    Mock::given(method("GET"))
        .respond_with(mock_response.clone())
        .mount(&backend2)
        .await;
    Mock::given(method("GET"))
        .respond_with(mock_response.clone())
        .mount(&backend3)
        .await;

    let proxy_port = get_free_port();

    let addr1 = backend1.address();
    let addr2 = backend2.address();
    let addr3 = backend3.address();

    let b1_str = format!("{}:{}", addr1.ip(), addr1.port());
    let b2_str = format!("{}:{}", addr2.ip(), addr2.port());
    let b3_str = format!("{}:{}", addr3.ip(), addr3.port());

    let config_content = LB_CONFIG_TEMPLATE
        .replace("__PROXY_PORT__", &proxy_port.to_string())
        .replace("__BACKEND_1__", &b1_str)
        .replace("__BACKEND_2__", &b2_str)
        .replace("__BACKEND_3__", &b3_str);

    let mut config_file = NamedTempFile::new().expect("Failed to create temp config file");
    write!(config_file, "{}", config_content).expect("Failed to write config content");
    let config_path = config_file.path().to_path_buf();

    let cli = Cli {
        validate_configs: false,
        threads_per_service: None,
        config_toml: None,
        config_entry: Some(config_path),
        daemonize: false,
        upgrade: false,
        pidfile: None,
        upgrade_socket: None,
        command: None,
    };

    let mut app_ctx = AppContext::bootstrap(cli)
        .await
        .expect("Failed to bootstrap AppContext");
    let services = app_ctx
        .build_services()
        .await
        .expect("Failed to build services");

    let (mut server, _watcher) = app_ctx.ready();
    server.add_services(services);
    server.bootstrap();

    thread::spawn(move || {
        server.run_forever();
    });

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    wait_for_proxy(&proxy_url).await;

    let client = Client::new();
    for _ in 0..30 {
        client
            .get(&proxy_url)
            .header("X-Test-Req", "true")
            .send()
            .await
            .expect("Failed to send request");
    }

    fn count_test_requests(requests: &[wiremock::Request]) -> usize {
        requests
            .iter()
            .filter(|r| r.headers.contains_key("x-test-req"))
            .count()
    }

    let reqs1 = backend1.received_requests().await.unwrap();
    let reqs2 = backend2.received_requests().await.unwrap();
    let reqs3 = backend3.received_requests().await.unwrap();

    let count1 = count_test_requests(&reqs1);
    let count2 = count_test_requests(&reqs2);
    let count3 = count_test_requests(&reqs3);

    assert_eq!(count1, 10, "Backend 1 received wrong amount of requests");
    assert_eq!(count2, 10, "Backend 2 received wrong amount of requests");
    assert_eq!(count3, 10, "Backend 3 received wrong amount of requests");
}
