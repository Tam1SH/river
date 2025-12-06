use std::collections::BTreeMap;
use std::str::FromStr;

use async_trait::async_trait;
use pingora::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use regex::Regex;
use http::uri::{Uri, Parts, PathAndQuery};

use crate::proxy::{MotyaContext, filters::{builtin::helpers::{ensure_empty, extract_val}, types::RequestModifyMod}};


/// Filter: Rewrite Path Regex
/// Replaces path based on regex pattern. Supports capture groups ($1, $2).
/// Example: pattern="^/api/v1/(.*)", replace="/v2/$1"
pub struct RewritePathRegex {
    regex: Regex,
    replace: String,
}

impl RewritePathRegex {
    pub fn from_settings(mut settings: BTreeMap<String, String>) -> Result<Self> {
        let pattern = extract_val("pattern", &mut settings)?;
        let replace = extract_val("replace", &mut settings)?;

        let regex = Regex::new(&pattern).map_err(|e| {
            tracing::error!("Bad regex pattern: '{pattern}': {e:?}");
            Error::new_str("Error building regex for rewrite")
        })?;

        ensure_empty(&settings)?;

        Ok(Self { regex, replace })
    }
}

#[async_trait]
impl RequestModifyMod for RewritePathRegex {
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        header: &mut RequestHeader,
        _ctx: &mut MotyaContext,
    ) -> Result<()> {
        match rewrite_uri_path_regex(&header.uri, &self.regex, &self.replace) {
            Ok(Some(new_uri)) => {
                tracing::debug!("RewritePath: {} -> {}", header.uri.path(), new_uri.path());
                header.set_uri(new_uri);
                Ok(())
            },
            Ok(None) => {
                Ok(())
            },
            Err(e) => {
                tracing::error!("RewritePath failed: {}", e);
                Err(Error::new_str("Failed to rewrite path and build new URI"))
            }
        }
    }
}

fn rewrite_uri_path_regex(
    original_uri: &Uri,
    regex: &Regex,
    replace: &str,
) -> Result<Option<Uri>, String> {
    let current_path = original_uri.path();

    if regex.is_match(current_path) {
        
        let new_path_cow = regex.replace(current_path, replace);
        let new_path = new_path_cow.as_ref();

        if new_path != current_path {
            
            let query = original_uri.query();
            let new_p_and_q_str = match query {
                Some(q) => format!("{}?{}", new_path, q),
                None => new_path.to_string(),
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
    } else {
        Ok(None)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn create_uri(s: &str) -> Uri {
        s.parse().expect("Failed to parse URI for test")
    }

    type RewriteResult<T> = Result<T, String>;

    #[test]
    fn test_rewrite_path_with_capture_groups() -> RewriteResult<()> {
        let original_uri = create_uri("/api/v1/users/123/posts");
        let regex = Regex::new("^/api/v1/(.*)/posts$").unwrap();
        let replace = "/new_api/$1/data";
        
        let result = rewrite_uri_path_regex(&original_uri, &regex, replace)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/new_api/users/123/data");
        assert_eq!(new_uri.to_string(), "/new_api/users/123/data");

        Ok(())
    }

    #[test]
    fn test_rewrite_path_with_query() -> RewriteResult<()> {
        let original_uri = create_uri("/old/path?a=1&b=2");
        let regex = Regex::new("^/old/path$").unwrap();
        let replace = "/new/path";
        
        let result = rewrite_uri_path_regex(&original_uri, &regex, replace)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/new/path");
        assert_eq!(new_uri.query(), Some("a=1&b=2"));
        assert_eq!(new_uri.to_string(), "/new/path?a=1&b=2");

        Ok(())
    }

    #[test]
    fn test_rewrite_no_match() -> RewriteResult<()> {
        let original_uri = create_uri("/prod/v1/data");
        let regex = Regex::new("^/staging/v1/(.*)$").unwrap();
        let replace = "/new/$1";
        
        let result = rewrite_uri_path_regex(&original_uri, &regex, replace)?;
        
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_rewrite_match_but_no_change() -> RewriteResult<()> {
        let original_uri = create_uri("/path/to/data");
        let regex = Regex::new("^/path/to/data$").unwrap();
        let replace = "/path/to/data"; 
        
        let result = rewrite_uri_path_regex(&original_uri, &regex, replace)?;
        
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_rewrite_to_root() -> RewriteResult<()> {
        let original_uri = create_uri("/some/deep/path");
        let regex = Regex::new("^/some/.*$").unwrap();
        let replace = "/";
        
        let result = rewrite_uri_path_regex(&original_uri, &regex, replace)?;
        
        assert!(result.is_some());
        let new_uri = result.unwrap();
        
        assert_eq!(new_uri.path(), "/");
        assert_eq!(new_uri.to_string(), "/");

        Ok(())
    }
}