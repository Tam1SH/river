use std::net::IpAddr;

use http::uri::PathAndQuery;
use pingora_http::RequestHeader;

use crate::proxy::balancer::key_selector::KeySourceContext;
use pingora::protocols::l4::socket::SocketAddr;

pub struct SessionInfo<'a> {
    pub headers: &'a RequestHeader,
    pub client_addr: Option<&'a SocketAddr>,
    pub path: &'a PathAndQuery,
}

pub struct ContextInfo {}

impl KeySourceContext for SessionInfo<'_> {
    fn get_path(&self) -> &PathAndQuery {
        self.path
    }

    fn get_cookie(&self, name: &str) -> Option<&str> {
        for header_value in self.headers.headers.get_all("cookie") {
            let s = header_value.to_str().ok()?;

            for part in s.split(';') {
                let part = part.trim();

                if let Some(rest) = part.strip_prefix(name) {
                    if let Some(value) = rest.strip_prefix('=') {
                        return Some(value);
                    }
                }
            }
        }
        None
    }

    fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn get_ip(&self) -> Option<IpAddr> {
        self.client_addr
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip())
    }
}
