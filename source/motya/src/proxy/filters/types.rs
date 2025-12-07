use async_trait::async_trait;
use pingora::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::proxy::MotyaContext;


/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::upstream_response_filter] methods
pub trait ResponseModifyMod: Send + Sync {
    /// See [ProxyHttp::upstream_response_filter] for more details
    fn upstream_response_filter(
        &self,
        session: &mut Session,
        header: &mut ResponseHeader,
        ctx: &mut MotyaContext,
    );
}

/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::upstream_request_filter] methods
#[async_trait]
pub trait RequestModifyMod: Send + Sync {
    /// See [ProxyHttp::upstream_request_filter] for more details
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut MotyaContext,
    ) -> Result<()>;
}

/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::request_filter] methods
#[async_trait]
pub trait RequestFilterMod: Send + Sync {
    /// See [ProxyHttp::request_filter] for more details
    async fn request_filter(&self, session: &mut Session, ctx: &mut MotyaContext) -> Result<bool>;
}
