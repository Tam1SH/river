use std::{fs::File, path::PathBuf, sync::mpsc, thread, time::Duration};
use criterion::{criterion_group, criterion_main, Criterion};
use pprof::ProfilerGuardBuilder;
use reqwest::Client;

use wiremock::{Mock, ResponseTemplate, matchers::{any, header, method}};
use std::collections::HashMap;


use http::Uri;
use pingora::{prelude::HttpPeer, server::Server};
use wiremock::MockServer;
use river::{
    config::{
        common_types::{
            connectors::{Connectors, HttpPeerOptions, Upstream, UpstreamConfig},
            definitions::{ConfiguredFilter, DefinitionsTable, FilterChain, Modificator, NamedFilterChain},
            listeners::{ListenerConfig, ListenerKind, Listeners},
        },
        internal::{Config, ProxyConfig},
    },
    proxy::{
        filters::{chain_resolver::ChainResolver, generate_registry::load_registry},
        river_proxy_service,
    },
};


async fn setup_filters() -> (MockServer, Server) {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(wiremock::matchers::path("/test"))
        .and(header("X-Test", "TEST")) 
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

        
    Mock::given(any())
        .respond_with(ResponseTemplate::new(400))
        .mount(&mock_server)
        .await;


    let mut definitions_table = DefinitionsTable::default();
    let registry = load_registry(&mut definitions_table);

    let chain = FilterChain {
        filters: vec![ConfiguredFilter {
            name: "river.request.upsert-header".to_string(),
            args: HashMap::from([
                ("key".to_string(), "X-Test".to_string()),
                ("value".to_string(), "TEST".to_string()),
            ]),
        }],
    };

    definitions_table.insert_chain("insert", chain.clone());

    let resolver = ChainResolver::new(definitions_table, registry).unwrap();

    let config = Config::default();
    
    
    let proxy_addr = "127.0.0.1:8080";

    let chains = (1..100)
        .map(|_| Modificator::Chain(NamedFilterChain {
            name: "insert".to_string(),
            chain: chain.clone(),
        }))
        .collect::<Vec<_>>();

    let proxy = ProxyConfig {
        connectors: Connectors {
            upstreams: vec![UpstreamConfig {
                lb_options: Default::default(),
                chains,
                upstream: Upstream::Service(HttpPeerOptions {
                    peer: HttpPeer::new(mock_server.address().to_string(), false, "".to_string()),
                    
                    prefix_path: Uri::from_static("/test"),
                    target_path: Uri::from_static("/"),
                }),
            }],
            anonymous_chains: Default::default(),
        },
        listeners: Listeners {
            list_cfgs: vec![ListenerConfig {
                source: ListenerKind::Tcp {
                    addr: proxy_addr.to_string(),
                    offer_h2: false,
                    tls: None,
                },
            }],
        },
        name: "TestServer".to_string(),
        rate_limiting: Default::default(),
    };

    let mut app_server = Server::new_with_opt_and_conf(config.pingora_opt(), config.pingora_server_conf());

    let proxy_service = river_proxy_service(proxy, &resolver, &app_server).unwrap();

    app_server.bootstrap();
    app_server.add_services(vec![proxy_service]);

    (mock_server, app_server)
}



fn criterion_benchmark(c: &mut Criterion) {
    
    let (tx, rx) = mpsc::channel();

    
    thread::spawn(move || {
        
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build runtime");

        let (_mock_guard, server) = rt.block_on(async move {
            
            let (_mock_guard, server) = setup_filters().await;
            
            (_mock_guard, server)
        });

        tx.send(()).expect("Failed to send ready signal");
        server.run_forever();
    });

    
    rx.recv().expect("Server failed to start");

    
    let client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(100)
        .build()
        .unwrap();
    
    let url = "http://127.0.0.1:8080/test";

    let guard = ProfilerGuardBuilder::default()
        .frequency(1000)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .unwrap();

        
    c.bench_function("http_proxy_throughput", |b| {
        
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let resp = client.get(url).send().await.expect("Failed to send request");
                
                assert_eq!(resp.status(), 200); 
            });
    });


    if let Ok(report) = guard.report().build() {
        let file = File::create("flamegraph.svg").unwrap();
        report.flamegraph(file).unwrap();
    };
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);