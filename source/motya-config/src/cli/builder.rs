use std::{collections::HashMap, net::ToSocketAddrs};
use http::{StatusCode, Uri, uri::PathAndQuery};
use miette::IntoDiagnostic;
use pingora::prelude::HttpPeer;
use crate::{common_types::{
    connectors::{Connectors, HttpPeerOptions, Upstream, UpstreamConfig}, listeners::{ListenerConfig, ListenerKind, Listeners}, rate_limiter::RateLimitingConfig, simple_response_type::SimpleResponseConfig 
}, internal::{ProxyConfig, UpstreamOptions}};
use crate::internal::Config;

pub enum RouteAction {
    
    Static(String),
    
    Proxy(String),
}

pub struct SyntheticRoute {
    pub path: String,
    pub action: RouteAction,
}

pub struct CliConfigBuilder;

impl CliConfigBuilder {
    
    pub fn build_routes(port: u16, routes: Vec<SyntheticRoute>) -> miette::Result<Config> {
        
        let listener = ListenerConfig {
            source: ListenerKind::Tcp {
                addr: format!("0.0.0.0:{}", port),
                tls: None,
                offer_h2: false, 
            },
        };

        let mut upstreams = Vec::new();

        for route in routes {
            let prefix_path = route.path.parse::<PathAndQuery>()
                .map_err(|e| miette::miette!("Invalid route path '{}': {}", route.path, e))?;

            let upstream = match route.action {
                
                RouteAction::Static(text) => {
                    Upstream::Static(SimpleResponseConfig {
                        http_code: StatusCode::OK,
                        response_body: text,
                        prefix_path,
                    })
                },
                
                RouteAction::Proxy(url_str) => {
                    let uri = url_str.parse::<Uri>()
                        .map_err(|e| miette::miette!("Invalid proxy url '{}': {}", url_str, e))?;
                    
                    let host = uri.host().ok_or_else(|| miette::miette!("Proxy url must have a host"))?;
                    let port = uri.port_u16().unwrap_or(80);
                    let addr = format!("{}:{}", host, port);
                    
                    let socket_addr = addr.to_socket_addrs().into_diagnostic()?.next()
                         .ok_or_else(|| miette::miette!("Could not resolve address: {}", addr))?;

                    let peer = HttpPeer::new(socket_addr, false, "".to_string());
                    
                    Upstream::Service(HttpPeerOptions {
                        peer,
                        prefix_path,
                        target_path: uri.path().parse().into_diagnostic()?,
                        matcher: Default::default()
                    })
                }
            };

            upstreams.push(UpstreamConfig {
                upstream,
                chains: vec![],
                lb_options: UpstreamOptions::default(),
            });
        }

        let proxy_config = ProxyConfig {
            name: "CLI-Router".to_string(),
            listeners: Listeners {
                list_cfgs: vec![listener],
            },
            connectors: Connectors {
                upstreams,
                anonymous_chains: HashMap::new(),
            },
            rate_limiting: RateLimitingConfig::default(),
        };

        Ok(Config {
            validate_configs: false,
            threads_per_service: 1, 
            daemonize: false,
            pid_file: None,
            upgrade_socket: None,
            upgrade: false,
            basic_proxies: vec![proxy_config],
            file_servers: vec![],
        })
    }

    
    pub fn build_hello(port: u16, text: String) -> miette::Result<Config> {
        Self::build_routes(port, vec![
            SyntheticRoute {
                path: "/".to_string(),
                action: RouteAction::Static(text)
            }
        ])
    }

}