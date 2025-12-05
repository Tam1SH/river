use std::collections::{BTreeSet, HashMap};
use futures_util::FutureExt;
use http::Uri;
use matchit::{InsertError, Router};
use pingora::{ErrorType, prelude::HttpPeer};
use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery, prelude::RoundRobin, selection::{FNVHash, Random, consistent::KetamaHashing}};

use crate::proxy::filters::chain_resolver::RuntimeChain;
use motya_config::{common_types::connectors::Upstream, legacy::request_selector::{ContextInfo, RequestSelector, SessionInfo}};

pub struct UpstreamContext {
    pub upstream: Upstream,
    pub chains: Vec<RuntimeChain>,
    pub balancer: Balancer
}

pub trait UpstreamContextTrait {
    fn get_path(&self) -> &Uri;
    fn get_balancer(&self) -> &Balancer;
}

pub enum RouteType<'a> {
    Strict(&'a str),
    Prefix(&'a str)
}

pub struct UpstreamRouter<TUpstream: UpstreamContextTrait> {
    pub router: Router<TUpstream>
}

impl<TUpstream: UpstreamContextTrait> UpstreamRouter<TUpstream> {

    pub fn build(paths: Vec<TUpstream>) -> Result<Self, InsertError>
    {
        let mut router = Router::new();

        paths
            .into_iter()
            .map(|path| (path.get_path().clone(), path))
            .try_for_each(|(route, elem)| router.insert(route.path(), elem))?;
            
        Ok(Self { router })
    }

    pub fn pick_peer(&self, ctx: &mut ContextInfo, session: &mut SessionInfo) -> Result<HttpPeer, pingora::BError> {
        
        let upstream = self
            .get_upstream_by_path(RouteType::Strict(session.uri.path()))
            .ok_or_else(|| pingora::Error::explain(ErrorType::HTTPStatus(404),"Cannot find a peer"))?;

        let key = upstream.get_balancer().selector(ctx, session);

        let backend = upstream.get_balancer().select(key);

        // Manually clear the selector buf to avoid accidental leaks
        ctx.selector_buf.clear();

        let backend = 
            backend.ok_or_else(|| pingora::Error::explain(ErrorType::HTTPStatus(500), "Unable to determine backend"))?;

        Ok(backend.ext
            .get::<HttpPeer>()
            .cloned()
            .expect("HttpPeer should exist in backend.ext"))
    }

    pub fn get_upstream_by_path(&self, route: RouteType) -> Option<&TUpstream> {
        match route {
            RouteType::Strict(route) | RouteType::Prefix(route) => self.router
                .at(route)
                .ok()
                .map(|v| v.value)
        }
    }
}

impl UpstreamContextTrait for UpstreamContext {
    fn get_path(&self) -> &Uri {
        match &self.upstream {
            Upstream::Service(peer_options) => &peer_options.prefix_path,
            Upstream::Static(peer_options) => &peer_options.prefix_path
        }
    }

    fn get_balancer(&self) -> &Balancer {
        &self.balancer
    }
}

pub struct Balancer {
    pub selector: RequestSelector,
    pub balancer_type: BalancerType
}

pub enum BalancerType {
    RoundRobin(LoadBalancer<RoundRobin>),
    Random(LoadBalancer<Random>),
    FNVHash(LoadBalancer<FNVHash>),
    KetamaHashing(LoadBalancer<KetamaHashing>)
}

impl Balancer {
    pub fn selector<'a>(&self, ctx: &'a mut ContextInfo, session: &'a mut SessionInfo) -> &'a [u8] {
        (self.selector)(ctx, session)
    }

    pub fn select(&self, key: &[u8]) -> Option<Backend> {
        match &self.balancer_type {
            BalancerType::FNVHash(b) => b.select(key, 256),
            BalancerType::Random(b) => b.select(key, 256),
            BalancerType::KetamaHashing(b) => b.select(key, 256),
            BalancerType::RoundRobin(b) => b.select(key, 256)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use http::StatusCode;

    fn mock_context(path: &str) -> UpstreamContext {
        
        let backend = Backend::new("0.0.0.0:0").unwrap();
        let disco = discovery::Static::new(BTreeSet::from([backend]));
        let backends = Backends::new(disco);
        
        
        let lb = LoadBalancer::<RoundRobin>::from_backends(backends);
        lb.update().now_or_never().expect("static discovery should not block").unwrap();

        UpstreamContext {
            
            upstream: Upstream::Static(SimpleResponse {
                prefix_path: path.parse().unwrap(),
                http_code: StatusCode::OK,
                response_body: String::new(),
            }),
            chains: vec![],
            balancer: Balancer {
                selector: |_, _| &[],
                balancer_type: BalancerType::RoundRobin(lb),
            },
        }
    }

    #[test]
    pub fn test_router() {
        
        let paths = vec![
            mock_context("/first"),
            mock_context("/second"),
            mock_context("/first/{*anything}"),
        ];

        let router = UpstreamRouter::build(paths).expect("Router build failed");

        
        let elem = router.get_upstream_by_path(RouteType::Strict("/first")).unwrap();
        assert_eq!(elem.get_path().path(), "/first");

        let elem = router.get_upstream_by_path(RouteType::Strict("/second")).unwrap();
        assert_eq!(elem.get_path().path(), "/second");

        
        let elem = router.get_upstream_by_path(RouteType::Prefix("/first/a/b/c/d")).unwrap();
        assert_eq!(elem.get_path().path(), "/first/{*anything}");
        
        
        let elem = router.get_upstream_by_path(RouteType::Strict("/not-found"));
        assert!(elem.is_none());
    }
}