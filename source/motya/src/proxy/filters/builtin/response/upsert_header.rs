use std::collections::BTreeMap;

use pingora::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

use crate::proxy::{
    filters::{builtin::helpers::extract_val, types::ResponseModifyMod},
    MotyaContext,
};


pub struct UpsertHeader {
    key: String,
    value: String,
}

impl UpsertHeader {
    
    pub fn from_settings(mut settings: BTreeMap<String, String>) -> Result<Self> {
        let key = extract_val("key", &mut settings)?;
        let value = extract_val("value", &mut settings)?;
        Ok(Self { key, value })
    }
}

impl ResponseModifyMod for UpsertHeader {
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        header: &mut ResponseHeader,
        _ctx: &mut MotyaContext,
    ) {
        if let Some(h) = header.remove_header(&self.key) {
            tracing::debug!("Removed header: {h:?}");
        }
        let _ = header.append_header(self.key.clone(), &self.value);
        tracing::debug!("Inserted header: {}: {}", self.key, self.value);
    }
}
