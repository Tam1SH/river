use std::collections::BTreeSet;

use futures_util::FutureExt;
use miette::Result;
use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery, prelude::RoundRobin, selection::{FNVHash, Random, consistent::KetamaHashing}};

use crate::{config::{common_types::{connectors::{Upstream, UpstreamConfig}, definitions::Modificator}, internal::SelectionKind}, proxy::{filters::chain_resolver::ChainResolver, upstream_router::{Balancer, BalancerType, UpstreamContext}}};


pub struct UpstreamFactory<'a> {
    resolver: &'a ChainResolver,
}

impl<'a> UpstreamFactory<'a> {
    pub fn new(resolver: &'a ChainResolver) -> Self {
        Self { resolver }
    }

    pub fn create_context(&self, config: UpstreamConfig) -> Result<UpstreamContext> {
        let addr = match &config.upstream {
            Upstream::Static(_) => &"0.0.0.0:0".parse().unwrap(),
            Upstream::Service(peer) => &peer.peer._address
        };

        let mut backend = Backend::new(&addr.to_string()).unwrap();
        
        if let Upstream::Service(peer_options) = &config.upstream {
            assert!(backend.ext.insert(peer_options.peer.clone()).is_none());
        }

        let backends = BTreeSet::from([backend]);
        let disco = discovery::Static::new(backends);
        
        let balancer_type = match config.lb_options.selection {
            SelectionKind::FvnHash => BalancerType::FNVHash(LoadBalancer::<FNVHash>::from_backends(Backends::new(disco))),
            SelectionKind::RoundRobin => BalancerType::RoundRobin(LoadBalancer::<RoundRobin>::from_backends(Backends::new(disco))),
            SelectionKind::Random => BalancerType::Random(LoadBalancer::<Random>::from_backends(Backends::new(disco))),
            SelectionKind::KetamaHashing => BalancerType::KetamaHashing(LoadBalancer::<KetamaHashing>::from_backends(Backends::new(disco))),
        };

        match &balancer_type {
            BalancerType::FNVHash(b) => b.update().now_or_never(),
            BalancerType::KetamaHashing(b) => b.update().now_or_never(),
            BalancerType::Random(b) => b.update().now_or_never(),
            BalancerType::RoundRobin(b) => b.update().now_or_never()
        }
            .expect("static should not block")
            .expect("static should not error");

        let mut chains = Vec::new();
        
        for modificator in config.chains {
            match modificator {
                Modificator::Chain(named_chain) => {
                    let chain = self.resolver.resolve(&named_chain.name)?;
                    chains.push(chain);
                }
            }
        }

        let ctx = UpstreamContext { 
            balancer: Balancer { selector: config.lb_options.selector, balancer_type }, 
            upstream: config.upstream, 
            chains
        };

        Ok(ctx)
    }
}