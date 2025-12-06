use async_trait::async_trait;
use bytes::Bytes;
use http::uri::PathAndQuery;
use motya_config::common_types::simple_response_type::SimpleResponseConfig;
use pingora::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;


use crate::proxy::{MotyaContext, filters::types::RequestFilterMod};

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleResponse {
    pub http_code: http::StatusCode,
    pub response_body: String,
    pub prefix_path: PathAndQuery
}

#[async_trait]
impl RequestFilterMod for SimpleResponse {
    async fn request_filter(&self, session: &mut Session, _: &mut MotyaContext) -> Result<bool> {

        let body = self.response_body.clone();
        let mut response = ResponseHeader::build(self.http_code, None)?;
        response.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        
        session.downstream_session.write_response_header(Box::new(response)).await?;
        session.downstream_session.write_response_body(Bytes::from(body), true).await?;
        session.downstream_session.set_keepalive(None);
        return Ok(true);
    }
}


impl From<SimpleResponseConfig> for SimpleResponse {
    fn from(value: SimpleResponseConfig) -> Self {
        Self {
            http_code: value.http_code,
            prefix_path: value.prefix_path,
            response_body: value.response_body
        }
    }
}