use std::{collections::HashMap, sync::mpsc, thread};

use http::Uri;
use pingora::{prelude::HttpPeer, server::Server};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{header, method}};

use river::{config::{common_types::{connectors::{Connectors, HttpPeerOptions, Upstream, UpstreamConfig}, definitions::{ConfiguredFilter, DefinitionsTable, FilterChain, Modificator, NamedFilterChain}, listeners::{ListenerConfig, ListenerKind, Listeners}}, internal::{Config, ProxyConfig}}, proxy::{filters::{chain_resolver::ChainResolver, generate_registry::load_registry}, river_proxy_service}};
use fqdn::fqdn;
use wiremock::matchers::any;

pub async fn setup_filters() {
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
            name: fqdn!("river.request.upsert-header"),
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


    let (tx, rx) = mpsc::channel();

    
    thread::spawn(move || {
        
        let (_mock_server, app_server) = (mock_server, app_server);

        tx.send(()).expect("Failed to send ready signal");
        app_server.run_forever();
    });

    
    rx.recv().expect("Server failed to start");
}



pub async fn setup_check_cidr() -> thread::JoinHandle<()> {
    let mock_server = MockServer::start().await;
        
    Mock::given(any())
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;


    let mut definitions_table = DefinitionsTable::default();
    let registry = load_registry(&mut definitions_table);

    let chain = FilterChain {
        filters: vec![
            ConfiguredFilter {
                name: fqdn!("river.filters.block-cidr-range"),
                args: HashMap::from([
                    ("addrs".to_string(), "127.0.0.0/8".to_string()), 
                ]),
            }]
    };

    definitions_table.insert_chain("block-noob", chain.clone());

    let resolver = ChainResolver::new(definitions_table, registry).unwrap();

    let config = Config::default();
    
    
    let proxy_addr = "127.0.0.1:8081";

    let proxy = ProxyConfig {
        connectors: Connectors {
            upstreams: vec![UpstreamConfig {
                lb_options: Default::default(),
                chains: vec![Modificator::Chain(NamedFilterChain {
                    name: "block-noob".to_string(),
                    chain: chain.clone(),
                })],
                upstream: Upstream::Service(HttpPeerOptions {
                    peer: HttpPeer::new(mock_server.address().to_string(), false, "".to_string()),
                    prefix_path: Uri::from_static("/"),
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


    let (tx, rx) = mpsc::channel();

    
    let handle = thread::spawn(move || {
        
        let (_mock_server, app_server) = (mock_server, app_server);

        tx.send(()).expect("Failed to send ready signal");
        app_server.run_forever();
    });

    
    rx.recv().expect("Server failed to start");

    handle

}


pub async fn setup_check_cidr_accept() -> thread::JoinHandle<()> {
    let mock_server = MockServer::start().await;
        
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;


    let mut definitions_table = DefinitionsTable::default();
    let registry = load_registry(&mut definitions_table);

    let chain = FilterChain {
        filters: vec![
            ConfiguredFilter {
                name: fqdn!("river.filters.block-cidr-range"),
                args: HashMap::from([
                    ("addrs".to_string(), "10.0.0.0/8".to_string()), 
                ]),
            }]
    };

    definitions_table.insert_chain("block-noob", chain.clone());

    let resolver = ChainResolver::new(definitions_table, registry).unwrap();

    let config = Config::default();
    
    
    let proxy_addr = "127.0.0.1:8082";

    let proxy = ProxyConfig {
        connectors: Connectors {
            upstreams: vec![UpstreamConfig {
                lb_options: Default::default(),
                chains: vec![Modificator::Chain(NamedFilterChain {
                    name: "block-noob".to_string(),
                    chain: chain.clone(),
                })],
                upstream: Upstream::Service(HttpPeerOptions {
                    peer: HttpPeer::new(mock_server.address().to_string(), false, "".to_string()),
                    prefix_path: Uri::from_static("/"),
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


    let (tx, rx) = mpsc::channel();

    
    let handle = thread::spawn(move || {
        
        let (_mock_server, app_server) = (mock_server, app_server);

        tx.send(()).expect("Failed to send ready signal");
        app_server.run_forever();
    });

    
    rx.recv().expect("Server failed to start");

    handle
}


