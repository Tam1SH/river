use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use motya::app_context::AppContext;
use motya_config::cli::cli_struct::Cli;
use reqwest::Client;
use tempfile::NamedTempFile;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

const KETAMA_CONFIG_TEMPLATE: &str = r#"
services {
    KetamaService {
        listeners {
            "127.0.0.1:__PROXY_PORT__"
        }
        connectors {
            load-balance {
                selection "Ketama" {
                    key "${header-x-part-one}-${header-x-part-two}"
                    
                    algorithm name="xxhash64"

                    transforms-order {
                        lowercase
                    }
                }
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
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn wait_for_proxy(url: &str) {
    let client = Client::new();
    for _ in 0..30 {
        if client.get(url).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Proxy did not start at {}", url);
}

async fn find_server_addr_with_request(
    req_id: &str,
    backends: &[&MockServer],
) -> Option<std::net::SocketAddr> {
    for backend in backends.iter() {
        let requests = backend.received_requests().await.unwrap();

        let found = requests.iter().any(|r| {
            r.headers
                .get("x-req-id")
                .map(|v| v.to_str().unwrap() == req_id)
                .unwrap_or(false)
        });

        if found {
            return Some(*backend.address());
        }
    }
    None
}

// NOTE ON STABILITY:
// I cannot guarantee stable numerical results for load distribution
// across different test runs because the Ketama hashing algorithm (as implemented here
// and in Nginx/Memcached) depends on the Backend's `IP:Port` address.
// Since MockServer uses random, ephemeral ports for the backends, the
// hash ring is built differently on every run.
//
// Therefore, instead of hardcoding expected counts (e.g., 18/16/16), i limit
// my distribution check to asserting that no single backend is "starved"
// and that the overall distribution is not severely skewed (e.g., one server
// receiving less than 50% of the total bulk traffic).
//
// While it would be possible to "mock" the Ketama logic by faking the
// SocketAddr objects, the current "black box" approach is sufficient to
// validate the key consistency (e.g., 'Alpha' and 'alpha' go to the same server)
// and overall load distribution properties.
#[tokio::test]
async fn test_ketama_hashing_with_transforms() {
    let b1 = MockServer::start().await;
    let b2 = MockServer::start().await;
    let b3 = MockServer::start().await;

    let resp = ResponseTemplate::new(200).set_body_string("OK");
    for s in [&b1, &b2, &b3] {
        Mock::given(any()).respond_with(resp.clone()).mount(s).await;
    }

    let proxy_port = get_free_port();
    let config_str = KETAMA_CONFIG_TEMPLATE
        .replace("__PROXY_PORT__", &proxy_port.to_string())
        .replace(
            "__BACKEND_1__",
            &format!("{}:{}", b1.address().ip(), b1.address().port()),
        )
        .replace(
            "__BACKEND_2__",
            &format!("{}:{}", b2.address().ip(), b2.address().port()),
        )
        .replace(
            "__BACKEND_3__",
            &format!("{}:{}", b3.address().ip(), b3.address().port()),
        );

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let config_path = file.path().to_path_buf();

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

    let mut app_ctx = AppContext::bootstrap(cli).await.unwrap();
    let services = app_ctx.build_services().await.unwrap();
    let (mut server, _watcher) = app_ctx.ready();
    server.add_services(services);
    server.bootstrap();
    thread::spawn(move || server.run_forever());

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    wait_for_proxy(&proxy_url).await;
    let client = Client::new();
    let backends = vec![&b1, &b2, &b3];

    client
        .get(&proxy_url)
        .header("X-Part-One", "Alpha")
        .header("X-Part-Two", "Beta")
        .header("X-Req-ID", "req-1")
        .send()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let winner_addr = find_server_addr_with_request("req-1", &backends)
        .await
        .expect("Request 1 was lost!");

    println!("Winner for 'Alpha-Beta' is Backend at {}", winner_addr);

    client
        .get(&proxy_url)
        .header("X-Part-One", "ALPHA")
        .header("X-Part-Two", "BETA")
        .header("X-Req-ID", "req-2")
        .send()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let winner_2_addr = find_server_addr_with_request("req-2", &backends)
        .await
        .unwrap();

    assert_eq!(
        winner_addr, winner_2_addr,
        "Transforms failed! UPPER case went to a different server."
    );

    client
        .get(&proxy_url)
        .header("X-Part-One", "alpha")
        .header("X-Part-Two", "beta")
        .header("X-Req-ID", "req-3")
        .send()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let winner_3_addr = find_server_addr_with_request("req-3", &backends)
        .await
        .unwrap();

    assert_eq!(
        winner_addr, winner_3_addr,
        "Transforms failed! lower case went to a different server."
    );

    let total_requests = 300;

    let mut hit_counts: HashMap<std::net::SocketAddr, usize> = HashMap::new();
    hit_counts.insert(*b1.address(), 0);
    hit_counts.insert(*b2.address(), 0);
    hit_counts.insert(*b3.address(), 0);

    for i in 0..total_requests {
        let req_id = format!("bulk-req-{}", i);
        client
            .get(&proxy_url)
            .header("X-Part-One", format!("Key{}", i))
            .header("X-Part-Two", "Val")
            .header("X-Req-ID", &req_id)
            .send()
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let c1_total = b1.received_requests().await.unwrap().len();
    let c2_total = b2.received_requests().await.unwrap().len();
    let c3_total = b3.received_requests().await.unwrap().len();

    let total_received = c1_total + c2_total + c3_total;

    assert!(total_received >= 3 + total_requests, "Lost requests!");

    let limit = total_requests * 5 / 10; // 50%
    assert!(
        c1_total < limit + 3 && c2_total < limit + 3 && c3_total < limit + 3,
        "Distribution is too skewed! (One server got > 50% of traffic)"
    );
}
