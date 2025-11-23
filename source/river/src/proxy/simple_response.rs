use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use cidr::IpCidr;
use http::StatusCode;
use pingora::ErrorType;
use pingora_core::{protocols::l4::socket::SocketAddr, Error, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

use crate::{config::internal::SimpleResponse, proxy::{RiverContext, extract_val, request_filters::RequestFilterMod}};



#[async_trait]
impl RequestFilterMod for SimpleResponse {
    async fn request_filter(&self, session: &mut Session, _ctx: &mut RiverContext) -> Result<bool> {
        let mut response = ResponseHeader::build(self.http_code, None)?;
        response.append_header("Content-Type", "text/plain; charset=utf-8")?;
        
        session.downstream_session.write_response_header(Box::new(response)).await?;
        session.downstream_session.write_response_body(Bytes::from(self.response_body.clone()), true).await?;
        session.downstream_session.set_keepalive(None);
        session.downstream_session.finish_body().await?;
        return Ok(true);
    }
}
