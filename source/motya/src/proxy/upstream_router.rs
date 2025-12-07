use http::uri::PathAndQuery;
use matchit::{InsertError, Router};
use pingora::{prelude::HttpPeer, ErrorType};

use crate::proxy::{
    balancer::key_selector::Balancer,
    context::{ContextInfo, SessionInfo},
    filters::chain_resolver::RuntimeChain,
};
use motya_config::common_types::connectors::{RouteMatcher, UpstreamConfig};

pub struct UpstreamContext {
    pub upstream: UpstreamConfig,
    pub chains: Vec<RuntimeChain>,
    pub balancer: Balancer,
}

pub trait UpstreamContextTrait {
    fn get_prefix_path(&self) -> &PathAndQuery;
    fn get_route_type(&self) -> RouteMatcher;
    fn get_balancer(&self) -> &Balancer;
}

pub struct UpstreamRouter<TUpstream: UpstreamContextTrait> {
    pub router: Router<TUpstream>,
}

impl<TUpstream: UpstreamContextTrait> UpstreamRouter<TUpstream> {
    pub fn build(paths: Vec<TUpstream>) -> Result<Self, InsertError> {
        let mut router = Router::new();

        for item in paths {
            let raw_path = item.get_prefix_path().path().to_string();

            match item.get_route_type() {
                RouteMatcher::Exact => {
                    router.insert(raw_path, item)?;
                }
                RouteMatcher::Prefix => {
                    let clean_path = raw_path.trim_end_matches('/');

                    let wildcard_path = if clean_path.is_empty() {
                        "/{*catch_all}".to_string()
                    } else {
                        format!("{}/{{*catch_all}}", clean_path)
                    };

                    router.insert(wildcard_path, item)?;
                }
            }
        }

        Ok(Self { router })
    }

    pub fn pick_peer(
        &self,
        _: &mut ContextInfo,
        session: &mut SessionInfo,
    ) -> Result<Option<HttpPeer>, pingora::BError> {
        let Some(upstream) = self.get_upstream_by_path(session.path.path()) else {
            return Ok(None);
        };

        let backend = upstream.get_balancer().select_backend(session);

        let backend = backend.ok_or_else(|| {
            pingora::Error::explain(ErrorType::HTTPStatus(500), "Unable to determine backend")
        })?;

        Ok(Some(
            backend
                .ext
                .get::<HttpPeer>()
                .cloned()
                .expect("HttpPeer should exist in backend.ext"),
        ))
    }

    pub fn get_upstream_by_path(&self, path: &str) -> Option<&TUpstream> {
        self.router.at(path).ok().map(|v| v.value)
    }
}


impl UpstreamContextTrait for UpstreamContext {
    fn get_prefix_path(&self) -> &PathAndQuery {
        match &self.upstream {
            UpstreamConfig::Service(peer_options) => &peer_options.prefix_path,
            UpstreamConfig::Static(peer_options) => &peer_options.prefix_path,
            UpstreamConfig::MultiServer(m) => &m.prefix_path,
        }
    }

    fn get_balancer(&self) -> &Balancer {
        &self.balancer
    }

    fn get_route_type(&self) -> RouteMatcher {
        match &self.upstream {
            UpstreamConfig::Service(peer_options) => peer_options.matcher,
            UpstreamConfig::Static(_) => RouteMatcher::Exact,
            UpstreamConfig::MultiServer(m) => m.matcher,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeSet;

    use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery, prelude::RoundRobin};

    use crate::proxy::balancer::key_selector::BalancerType;

    use super::*;

    pub struct MockUpstreamContext {
        pub prefix: PathAndQuery,
        pub matcher: RouteMatcher,
        pub balancer: Balancer,
    }

    impl UpstreamContextTrait for MockUpstreamContext {
        fn get_prefix_path(&self) -> &PathAndQuery {
            &self.prefix
        }

        fn get_route_type(&self) -> RouteMatcher {
            self.matcher
        }

        fn get_balancer(&self) -> &Balancer {
            &self.balancer
        }
    }

    fn mock_context(path: &str, matcher: RouteMatcher) -> MockUpstreamContext {
        let backend = Backend::new("0.0.0.0:0").unwrap();
        let disco = discovery::Static::new(BTreeSet::from([backend]));
        let backends = Backends::new(disco);

        let lb = LoadBalancer::<RoundRobin>::from_backends(backends);

        MockUpstreamContext {
            prefix: path.parse().unwrap(),
            matcher,
            balancer: Balancer {
                selector: None,
                balancer_type: BalancerType::RoundRobin(lb),
            },
        }
    }

    #[test]
    pub fn test_router_configuration_modes() {
        let paths = vec![
            mock_context("/health", RouteMatcher::Exact),
            mock_context("/api", RouteMatcher::Prefix),
            mock_context("/", RouteMatcher::Prefix),
        ];

        let router = UpstreamRouter::build(paths).expect("Router build failed");

        // --- Test Strict ---
        let elem = router.get_upstream_by_path("/health").unwrap();
        assert_eq!(elem.get_prefix_path(), "/health");

        let elem = router.get_upstream_by_path("/health/foo");

        assert_eq!(elem.unwrap().get_prefix_path(), "/");

        // --- Test Prefix ---
        let elem = router.get_upstream_by_path("/api/users").unwrap();
        assert_eq!(elem.get_prefix_path(), "/api");

        let elem = router.get_upstream_by_path("/api").unwrap();
        assert_eq!(elem.get_prefix_path(), "/");

        // --- Test Fallback (Root) ---
        let elem = router.get_upstream_by_path("/random/stuff").unwrap();
        assert_eq!(elem.get_prefix_path(), "/");
    }

    #[test]
    fn test_manual_wildcard_override() {
        let paths = vec![mock_context("/custom/{*foo}", RouteMatcher::Exact)];
        let router = UpstreamRouter::build(paths).expect("Router build failed");

        let elem = router.get_upstream_by_path("/custom/bar").unwrap();
        assert_eq!(elem.get_prefix_path(), "/custom/{*foo}");
    }
}
