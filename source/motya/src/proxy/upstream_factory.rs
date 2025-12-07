use std::collections::BTreeSet;

use miette::{miette, Result};
use pingora::prelude::HttpPeer;
use pingora_load_balancing::{
    discovery,
    prelude::RoundRobin,
    selection::{consistent::KetamaHashing, FNVHash, Random},
    Backend, Backends, LoadBalancer,
};

use motya_config::{
    common_types::{
        connectors::{UpstreamConfig, UpstreamContextConfig},
        definitions::Modificator,
    },
    internal::SelectionKind,
};

use crate::proxy::{
    balancer::key_selector::{Balancer, BalancerType, KeySelector},
    filters::chain_resolver::ChainResolver,
    upstream_router::UpstreamContext,
};


#[derive(Clone)]
pub struct UpstreamFactory {
    resolver: ChainResolver,
}

impl UpstreamFactory {
    pub fn new(resolver: ChainResolver) -> Self {
        Self { resolver }
    }

    pub async fn create_context(&self, config: UpstreamContextConfig) -> Result<UpstreamContext> {
        let backends = match &config.upstream {
            UpstreamConfig::Static(_) | UpstreamConfig::Service(_) => {
                let addr = if let UpstreamConfig::Service(p) = &config.upstream {
                    &p.peer._address
                } else {
                    &"0.0.0.0:0".parse().unwrap()
                };

                let mut backend = Backend::new(&addr.to_string()).unwrap();

                if let UpstreamConfig::Service(peer_options) = &config.upstream {
                    backend.ext.insert(peer_options.peer.clone());
                }

                BTreeSet::from([backend])
            }
            UpstreamConfig::MultiServer(m) => {
                let addrs = m.servers.iter().map(|s| (&s.address, s.weight));

                let mut backends = addrs
                    .clone()
                    .map(|(addr, weight)| {
                        Backend::new_with_weight(&addr.to_string(), weight)
                            .expect("never fail because addr is already IpAddr")
                    })
                    .collect::<Vec<_>>();

                for (backend, (addr, _)) in backends.iter_mut().zip(addrs) {
                    assert!(backend
                        .ext
                        .insert(HttpPeer::new(
                            addr,
                            //sni is https only
                            //https://github.com/cloudflare/pingora/blob/main/docs/user_guide/peer.md
                            m.tls_sni.is_some(),
                            m.tls_sni.clone().unwrap_or("".to_string())
                        ))
                        .is_none());
                }
                BTreeSet::from_iter(backends)
            }
        };

        let disco = discovery::Static::new(backends);

        let balancer_type = match config.lb_options.selection {
            SelectionKind::FvnHash => {
                BalancerType::FNVHash(LoadBalancer::<FNVHash>::from_backends(Backends::new(disco)))
            }
            SelectionKind::RoundRobin => BalancerType::RoundRobin(
                LoadBalancer::<RoundRobin>::from_backends(Backends::new(disco)),
            ),
            SelectionKind::Random => {
                BalancerType::Random(LoadBalancer::<Random>::from_backends(Backends::new(disco)))
            }
            SelectionKind::KetamaHashing => {
                BalancerType::KetamaHashing(LoadBalancer::<KetamaHashing>::from_backends(
                    Backends::new(disco),
                ))
            }
        };

        let mut chains = Vec::new();

        for modificator in config.chains {
            match modificator {
                Modificator::Chain(named_chain) => {
                    let chain = self.resolver.resolve(&named_chain.name).await?;
                    chains.push(chain);
                }
            }
        }

        let ctx = UpstreamContext {
            balancer: Balancer {
                selector: config
                    .lb_options
                    .template
                    .map(KeySelector::try_from)
                    .transpose()
                    .map_err(|err| miette!("{err}"))?,
                balancer_type,
            },
            upstream: config.upstream,
            chains,
        };

        Ok(ctx)
    }
}
