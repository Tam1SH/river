use std::collections::BTreeMap;

use pingora::{Error, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use regex::Regex;

use crate::proxy::{
    filters::{
        builtin::helpers::{ensure_empty, extract_val},
        types::ResponseModifyMod,
    },
    MotyaContext,
};


pub struct RemoveHeaderKeyRegex {
    regex: Regex,
}

impl RemoveHeaderKeyRegex {
    
    pub fn from_settings(mut settings: BTreeMap<String, String>) -> Result<Self> {
        let mat = extract_val("pattern", &mut settings)?;

        let reg = Regex::new(&mat).map_err(|e| {
            tracing::error!("Bad pattern: '{mat}': {e:?}");
            Error::new_str("Error building regex")
        })?;

        ensure_empty(&settings)?;

        Ok(Self { regex: reg })
    }
}

impl ResponseModifyMod for RemoveHeaderKeyRegex {
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        header: &mut ResponseHeader,
        _ctx: &mut MotyaContext,
    ) {
        
        let headers = header
            .headers
            .keys()
            .filter_map(|k| {
                if self.regex.is_match(k.as_str()) {
                    tracing::debug!("Removing header: {k:?}");
                    Some(k.to_owned())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

            
        for h in headers {
            assert!(header.remove_header(&h).is_some());
        }
    }
}
