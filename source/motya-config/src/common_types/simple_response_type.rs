use http::uri::PathAndQuery;


#[derive(Debug, Clone, PartialEq)]
pub struct SimpleResponseConfig {
    pub http_code: http::StatusCode,
    pub response_body: String,
    pub prefix_path: PathAndQuery
}