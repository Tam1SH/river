//! Proxy handling
//!
//! This module contains the primary proxying logic for River. At the moment,
//! this includes creation of HTTP proxy services, as well as Path Control
//! modifiers.

use std::sync::Arc;

use async_trait::async_trait;

use pingora::server::Server;
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

use crate::{
    config::{common_types::{connectors::{Upstream, UpstreamConfig}, listeners::Listeners, rate_limiter::{AllRateConfig, RateLimitingConfig}}, internal::{ProxyConfig, SelectionKind, UpstreamOptions}},
    proxy::{
        filters::{chain_resolver::ChainResolver, types::{RequestFilterMod, RequestModifyMod, ResponseModifyMod}}, plugins::module::WasmModule, populate_listeners::populate_listners, request_selector::{ContextInfo, RequestSelector, SessionInfo, null_selector}, upstream_factory::UpstreamFactory, upstream_router::{RouteType, UpstreamContext, UpstreamRouter}
    },
};

use self::{
    rate_limiting::{multi::MultiRaterInstance, single::SingleInstance, Outcome},
};

pub mod rate_limiting;
pub mod request_selector;
pub mod upstream_router;
pub mod filters;
pub mod plugins;
pub mod upstream_factory;
pub mod populate_listeners;

pub struct RateLimiters {
    request_filter_stage_multi: Vec<MultiRaterInstance>,
    request_filter_stage_single: Vec<SingleInstance>,
}

/// The [RiverProxyService] is intended to capture the behaviors used to extend
/// the [HttpProxy] functionality by providing a [ProxyHttp] trait implementation.
///
/// The [ProxyHttp] trait allows us to provide callback-like control of various stages
/// of the [request/response lifecycle].
///
/// [request/response lifecycle]: https://github.com/cloudflare/pingora/blob/7ce6f4ac1c440756a63b0766f72dbeca25c6fc94/docs/user_guide/phase_chart.md
pub struct RiverProxyService {
    /// All modifiers used when implementing the [ProxyHttp] trait.
    pub rate_limiters: RateLimiters,
    pub router: Arc<UpstreamRouter<UpstreamContext>>
}

/// Create a proxy service, with the type parameters chosen based on the config file
pub fn river_proxy_service(
    conf: ProxyConfig,
    chain_resolver: &ChainResolver,
    server: &Server,
) -> miette::Result<Box<dyn pingora::services::Service>> {
    
    let factory = UpstreamFactory::new(chain_resolver);

    RiverProxyService::from_basic_conf(
        conf.connectors.upstreams,  
        &conf.rate_limiting,
        &conf.listeners,
        factory,
    server)
}




impl RiverProxyService
{
    /// Create a new [RiverProxyService] from the given [ProxyConfig]
    pub fn from_basic_conf(
        upstream_configs: Vec<UpstreamConfig>,
        rate_limiting: &RateLimitingConfig,
        listeners: &Listeners,
        upstream_factory: UpstreamFactory,
        server: &Server,
    ) -> miette::Result<Box<dyn pingora::services::Service>> {

        let upstream_ctx = upstream_configs
            .into_iter()
            .map(|cfg| upstream_factory.create_context(cfg))
            .collect::<Result<Vec<_>, _>>()?; 
        
        let router = UpstreamRouter::build(upstream_ctx)
            .expect("Paths must be valid after parsing the configuration");
            

        let mut request_filter_stage_multi = vec![];
        let mut request_filter_stage_single = vec![];

        for rule in rate_limiting.rules.clone() {
            match rule {
                AllRateConfig::Single { kind, config } => {
                    let rater = SingleInstance::new(config, kind);
                    request_filter_stage_single.push(rater);
                }
                AllRateConfig::Multi { kind, config } => {
                    let rater = MultiRaterInstance::new(config, kind);
                    request_filter_stage_multi.push(rater);
                }
            }
        }

        
        let mut my_proxy = pingora_proxy::http_proxy_service_with_name(
            &server.configuration,
            Self {
                rate_limiters: RateLimiters {
                    request_filter_stage_multi,
                    request_filter_stage_single,
                },
                router: Arc::new(router)
            },
            "ADADWDWDWDW",
        );

        populate_listners(listeners, &mut my_proxy);

        Ok(Box::new(my_proxy))
    }
}

//
// MODIFIERS
//
// This section implements "Path Control Modifiers". As an overview of the initially
// planned control points:
//
//             ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐  ┌ ─ ─ ─ ─ ─ ─ ┐
//                  ┌───────────┐    ┌───────────┐    ┌───────────┐
//             │    │  Request  │    │           │    │  Request  │    │  │             │
// Request  ═══════▶│  Arrival  │═══▶│Which Peer?│═══▶│ Forwarded │═══════▶
//             │    │           │    │           │    │           │    │  │             │
//                  └───────────┘    └───────────┘    └───────────┘
//             │          │                │                │          │  │             │
//                        │                │                │
//             │          ├───On Error─────┼────────────────┤          │  │  Upstream   │
//                        │                │                │
//             │          │          ┌───────────┐    ┌───────────┐    │  │             │
//                        ▼          │ Response  │    │ Response  │
//             │                     │Forwarding │    │  Arrival  │    │  │             │
// Response ◀════════════════════════│           │◀═══│           │◀═══════
//             │                     └───────────┘    └───────────┘    │  │             │
//               ┌────────────────────────┐
//             └ ┤ Simplified Phase Chart │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘  └ ─ ─ ─ ─ ─ ─ ┘
//               └────────────────────────┘
//
// At the moment, "Request Forwarded" corresponds with "upstream_request_filters".
//


pub struct RiverContext {
    selector_buf: Vec<u8>,
    router: Arc<UpstreamRouter<UpstreamContext>>
}

#[async_trait]
impl ProxyHttp for RiverProxyService
{
    type CTX = RiverContext;

    fn new_ctx(&self) -> Self::CTX {
        RiverContext {
            selector_buf: Vec::new(),
            router: self.router.clone()
        }
    }

    /// Handle the "Request filter" stage
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let router = ctx.router.clone();
        let path = session.req_header().uri.path();

        if let Some(upstream_ctx) = router.get_upstream_by_path(RouteType::Strict(path)) {
            
            let multis = self
                .rate_limiters
                .request_filter_stage_multi
                .iter()
                .filter_map(|l| l.get_ticket(session));

            let singles = self
                .rate_limiters
                .request_filter_stage_single
                .iter()
                .filter_map(|l| l.get_ticket(session));

            // Attempt to get all tokens
            //
            // TODO: If https://github.com/udoprog/leaky-bucket/issues/17 is resolved we could
            // remember the buckets that we did get approved for, and "return" the unused tokens.
            //
            // For now, if some tickets succeed but subsequent tickets fail, the preceeding
            // approved tokens are just "burned".
            //
            // TODO: If https://github.com/udoprog/leaky-bucket/issues/34 is resolved we could
            // support a "max debt" number, allowing us to delay if acquisition of the token
            // would happen soon-ish, instead of immediately 429-ing if the token we need is
            // about to become available.
            if singles
                .chain(multis)
                .any(|t| t.now_or_never() == Outcome::Declined)
            {
                tracing::trace!("Rejecting due to rate limiting failure");
                session.downstream_session.respond_error(429).await?;
                return Ok(true);
            }

            for chain in &upstream_ctx.chains {
                for filter in &chain.actions {
                    match filter.request_filter(session, ctx).await {
                        // If Ok true: we're done handling this request
                        o @ Ok(true) => return o,
                        // If Err: we return that
                        e @ Err(_) => return e,
                        // If Ok(false), we move on to the next filter
                        Ok(false) => {}
                    }
                }
            }
            
            if let Upstream::Static(response) = &upstream_ctx.upstream {
                let _ = response.request_filter(session, ctx).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Handle the "upstream peer" phase, where we pick which upstream to proxy to.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
    
        let peer = ctx.router.pick_peer(
            &mut ContextInfo { selector_buf: &mut ctx.selector_buf }, 
            &mut SessionInfo { client_addr: session.client_addr(), uri: &session.req_header().uri }
        )?;
        
        Ok(Box::new(peer))
    }

    /// Handle the "upstream request filter" phase, where we can choose to make
    /// modifications to the request, prior to it being passed along to the
    /// upstream.
    ///
    /// We can also *reject* requests here, though in the future we might do that
    /// via the `request_filter` stage, as that rejection can be done prior to
    /// paying any potential cost `upstream_peer` may incur.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {

        let router = ctx.router.clone();
        let path = session.req_header().uri.path();

        if let Some(upstream_ctx) = router.get_upstream_by_path(RouteType::Strict(path)) {
            
            for chain in &upstream_ctx.chains {
                for filter in &chain.req_mods {
                    filter.upstream_request_filter(session, header, ctx).await?;
                }
            }
        }
        
        Ok(())
    }

    /// Handle the "upstream response filter" phase, where we can choose to make
    /// modifications to the response, prior to it being passed along downstream
    ///
    /// We may want to also support `upstream_response` stage, as that may interact
    /// with cache differently.
    fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let router = ctx.router.clone();
        let path = session.req_header().uri.path();

        if let Some(upstream_ctx) = router.get_upstream_by_path(RouteType::Strict(path)) {
            
            for chain in &upstream_ctx.chains {
                for filter in &chain.res_mods {
                    filter.upstream_response_filter(session, upstream_response, ctx);
                }
            }
        }
        Ok(())
    }
}

