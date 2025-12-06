use std::{collections::HashMap, net::ToSocketAddrs, str::FromStr};
use http::{StatusCode, Uri, uri::PathAndQuery};
use miette::IntoDiagnostic;
use pingora::prelude::HttpPeer;
use crate::{common_types::{
    connectors::{Connectors, HttpPeerOptions, RouteMatcher, Upstream, UpstreamConfig}, listeners::{ListenerConfig, ListenerKind, Listeners}, rate_limiter::RateLimitingConfig, simple_response_type::SimpleResponseConfig 
}, internal::{ProxyConfig, UpstreamOptions}};
use crate::internal::Config;

pub enum RouteAction {
    Static(String),
    Proxy(String)
}

pub struct RouteMatch {
    pub path: PathAndQuery,
    pub match_type: RouteMatcher,
}

pub struct SyntheticRoute {
    pub route_match: RouteMatch,
    pub action: RouteAction,
}

pub struct CliConfigBuilder;
impl CliConfigBuilder {
    
    pub fn parse_map_string(s: &str) -> miette::Result<SyntheticRoute> {
        
        let mut parts = s.splitn(2, '=');
        let path_and_options_str = parts.next()
            .ok_or_else(|| miette::miette!("Invalid map format: expected 'path=target'"))?;
        let target_str = parts.next()
            .ok_or_else(|| miette::miette!("Invalid map format: target is missing"))?;

        let mut path_parts = path_and_options_str.splitn(2, ':');
        
        let first_part = path_parts.next().unwrap(); 
        let (match_type, path_str) = match path_parts.next() {
            Some(path) if first_part.eq_ignore_ascii_case("prefix") => {
                (RouteMatcher::Prefix, path)
            },
            _ => {
                (RouteMatcher::Exact, first_part)
            }
        };

        let path_and_query = PathAndQuery::from_str(path_str)
            .map_err(|e| miette::miette!("Invalid route path '{}': {}", path_str, e))?;

        let action = if target_str.to_lowercase().starts_with("http") {
            RouteAction::Proxy(target_str.to_string())
        } else {
            RouteAction::Static(target_str.to_string())
        };

        Ok(SyntheticRoute {
            route_match: RouteMatch { path: path_and_query, match_type },
            action,
        })
    }
    
    
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
            
            let prefix_path = route.route_match.path; 

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
                        matcher: route.route_match.match_type
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
                route_match: RouteMatch { 
                    path: PathAndQuery::from_str("/").into_diagnostic()?, 
                    match_type: RouteMatcher::Exact
                },
                action: RouteAction::Static(text)
            }
        ])
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exact() {
        let route = CliConfigBuilder::parse_map_string("/api=http://target").unwrap();
        assert_eq!(route.route_match.match_type, RouteMatcher::Exact);
        assert_eq!(route.route_match.path.path(), "/api");
    }

    #[test]
    fn test_parse_prefix() {
        let route = CliConfigBuilder::parse_map_string("prefix:/api=Welcome!").unwrap();
        assert_eq!(route.route_match.match_type, RouteMatcher::Prefix);
        assert_eq!(route.route_match.path.path(), "/api");
        
        match route.action {
            RouteAction::Static(s) => assert_eq!(s, "Welcome!"),
            _ => panic!("Expected Static"),
        }
    }
}
