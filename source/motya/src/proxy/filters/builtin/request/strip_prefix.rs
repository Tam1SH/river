use std::collections::BTreeMap;
use std::str::FromStr;

use async_trait::async_trait;
use pingora::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use http::uri::{Uri, Parts, PathAndQuery};

use crate::proxy::{MotyaContext, filters::{builtin::helpers::{ensure_empty, extract_val}, types::RequestModifyMod}};


pub struct StripPrefix {
    prefix: String,
}

impl StripPrefix {
    pub fn from_settings(mut settings: BTreeMap<String, String>) -> Result<Self> {
        let prefix = extract_val("prefix", &mut settings)?;
        ensure_empty(&settings)?;
        Ok(Self { prefix })
    }
}

#[async_trait]
impl RequestModifyMod for StripPrefix {
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        header: &mut RequestHeader,
        _ctx: &mut MotyaContext,
    ) -> Result<()> {
        match strip_uri_path_prefix(&header.uri, &self.prefix) {
            Ok(Some(new_uri)) => {
                tracing::debug!("StripPrefix: {} -> {}", header.uri.path(), new_uri.path());
                header.set_uri(new_uri);
                Ok(())
            },
            Ok(None) => {
                Ok(())
            },
            Err(e) => {
                tracing::error!("StripPrefix failed: {}", e);
                Err(Error::new_str("Failed to strip prefix and build new URI"))
            }
        }
    }
}

fn strip_uri_path_prefix(original_uri: &Uri, prefix: &str) -> Result<Option<Uri>, String> {
    let current_path = original_uri.path();

    if let Some(new_path_str) = current_path.strip_prefix(prefix) {
        
        let final_path = if new_path_str.is_empty() { "/" } else { new_path_str };
        
        let query = original_uri.query();
        
        let new_p_and_q_str = match query {
            Some(q) => format!("{}?{}", final_path, q),
            None => final_path.to_string(),
        };

        let new_p_and_q = PathAndQuery::from_str(&new_p_and_q_str)
            .map_err(|e| format!("Failed to build new PathAndQuery: {}", e))?;
        
        let mut parts = original_uri.clone().into_parts();
        parts.path_and_query = Some(new_p_and_q);

        let new_uri = Uri::from_parts(parts)
            .map_err(|e| format!("Failed to reassemble URI: {}", e))?;
        
        Ok(Some(new_uri))
    } else {
        Ok(None)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    type StripResult<T> = Result<T, String>;
    fn create_uri(s: &str) -> Uri {
        s.parse().expect("Failed to parse URI for test")
    }

    #[test]
    fn test_strip_prefix_success_to_root() -> StripResult<()> {
        let original_uri = create_uri("/api/v1");
        let prefix = "/api/v1";
        
        let result = strip_uri_path_prefix(&original_uri, prefix)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/");
        assert_eq!(new_uri.to_string(), "/");

        Ok(())
    }

    #[test]
    fn test_strip_prefix_success_with_remaining_path() -> StripResult<()> {
        let original_uri = create_uri("/api/v1/users/123");
        let prefix = "/api/v1";
        
        let result = strip_uri_path_prefix(&original_uri, prefix)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/users/123");
        assert_eq!(new_uri.to_string(), "/users/123");

        Ok(())
    }

    #[test]
    fn test_strip_prefix_success_with_query_to_root() -> StripResult<()> {
        let original_uri = create_uri("/api/v1?page=1&limit=10");
        let prefix = "/api/v1";
        
        let result = strip_uri_path_prefix(&original_uri, prefix)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/");
        assert_eq!(new_uri.query(), Some("page=1&limit=10"));
        assert_eq!(new_uri.to_string(), "/?page=1&limit=10");

        Ok(())
    }

    #[test]
    fn test_strip_prefix_success_with_query_and_remaining_path() -> StripResult<()> {
        let original_uri = create_uri("/api/v1/users?active=true");
        let prefix = "/api/v1";
        
        let result = strip_uri_path_prefix(&original_uri, prefix)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/users");
        assert_eq!(new_uri.query(), Some("active=true"));
        assert_eq!(new_uri.to_string(), "/users?active=true");

        Ok(())
    }

    #[test]
    fn test_strip_prefix_no_change() -> StripResult<()> {
        let original_uri = create_uri("/app/v1/users");
        let prefix = "/api/v1";
        
        let result = strip_uri_path_prefix(&original_uri, prefix)?;
        
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_strip_prefix_only_slash() -> StripResult<()> {
        let original_uri = create_uri("/");
        let prefix = "/api/v1";
        
        let result = strip_uri_path_prefix(&original_uri, prefix)?;
        
        assert!(result.is_none());

        Ok(())
    }
}
