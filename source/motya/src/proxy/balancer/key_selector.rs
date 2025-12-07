use http::uri::PathAndQuery;
use pingora_load_balancing::{
    prelude::RoundRobin,
    selection::{consistent::KetamaHashing, FNVHash, Random},
    Backend, LoadBalancer,
};
use std::hash::Hasher;
use std::{io::Cursor, net::IpAddr};

pub struct Balancer {
    pub selector: Option<KeySelector>,
    pub balancer_type: BalancerType,
}

pub trait KeySourceContext {
    fn get_header(&self, name: &str) -> Option<&str>;
    fn get_cookie(&self, name: &str) -> Option<&str>;
    fn get_ip(&self) -> Option<IpAddr>;
    fn get_path(&self) -> &PathAndQuery;
}

#[derive(Debug, Clone)]
pub struct KeySelector {
    pub extraction_strategies: Vec<ExtractionChain>,
    pub transforms: Vec<TransformOp>,
    pub hasher: HashOp,
}

impl KeySelector {
    pub fn select<C: KeySourceContext>(&self, ctx: &C, buffer: &mut Vec<u8>) -> Option<u64> {
        buffer.clear();
        let mut extracted = false;

        for strategy in &self.extraction_strategies {
            let start_len = buffer.len();

            for part in &strategy.parts {
                match part {
                    KeyPart::Literal(s) => {
                        buffer.extend_from_slice(s.as_bytes());
                    }
                    KeyPart::Header(name) => {
                        if let Some(val) = ctx.get_header(name) {
                            buffer.extend_from_slice(val.as_bytes());
                        }
                    }
                    KeyPart::Cookie(name) => {
                        if let Some(val) = ctx.get_cookie(name) {
                            buffer.extend_from_slice(val.as_bytes());
                        }
                    }
                    KeyPart::UriPath => {
                        buffer.extend_from_slice(ctx.get_path().path().as_bytes());
                    }
                    KeyPart::ClientIp => {
                        if let Some(val) = ctx.get_ip() {
                            buffer.extend_from_slice(val.to_string().as_bytes());
                        }
                    }
                    KeyPart::QueryParams(config_str) => {
                        if let Some(request_query) = ctx.get_path().query() {
                            for required_key in config_str.split('&') {
                                let found_val = request_query.split('&').find_map(|pair| {
                                    let mut parts = pair.splitn(2, '=');
                                    let key = parts.next()?;
                                    let val = parts.next().unwrap_or("");

                                    if key == required_key {
                                        Some(val)
                                    } else {
                                        None
                                    }
                                });

                                if let Some(val) = found_val {
                                    buffer.extend_from_slice(val.as_bytes());
                                }
                            }
                        }
                    }
                    KeyPart::UserAgent => {
                        if let Some(val) = ctx.get_header("user-agent") {
                            buffer.extend_from_slice(val.as_bytes());
                        }
                    }
                }
            }

            if buffer.len() > start_len {
                extracted = true;
                break;
            } else {
                buffer.truncate(start_len);
            }
        }

        if !extracted {
            return None;
        }

        for transform in &self.transforms {
            apply_transform(transform, buffer);
        }

        Some(self.hasher.hash(buffer))
    }
}

fn apply_transform(op: &TransformOp, buf: &mut Vec<u8>) {
    match op {
        TransformOp::Lowercase => {
            for b in buf.iter_mut() {
                b.make_ascii_lowercase();
            }
        }
        TransformOp::Truncate { length } => {
            if buf.len() > *length {
                buf.truncate(*length);
            }
        }
        TransformOp::RemoveQueryParams => {
            if let Some(pos) = buf.iter().position(|&b| b == b'?') {
                buf.truncate(pos);
            }
        }
        _ => {}
    }
}

impl HashOp {
    pub fn hash(&self, bytes: &[u8]) -> u64 {
        match self {
            HashOp::XxHash32(seed) => {
                let s = seed.unwrap_or(0);
                xxhash_rust::xxh32::xxh32(bytes, s) as u64
            }
            HashOp::XxHash64(seed) => {
                let s = seed.unwrap_or(0);
                xxhash_rust::xxh64::xxh64(bytes, s)
            }
            HashOp::Murmur3_32(seed) => {
                let s = seed.unwrap_or(0);
                let mut cursor = Cursor::new(bytes);
                murmur3::murmur3_32(&mut cursor, s).unwrap_or(0) as u64
            }
            HashOp::Fnv1a => {
                let mut hasher = fnv::FnvHasher::default();
                hasher.write(bytes);
                hasher.finish()
            }
        }
    }
}

impl Balancer {
    pub fn select_backend<C: KeySourceContext>(&self, ctx: &C) -> Option<Backend> {
        if let Some(selector) = &self.selector {
            //TODO: Profiling.
            let mut buffer = vec![];
            let key = selector.select(ctx, &mut buffer).unwrap_or(0);

            self.select(&key.to_le_bytes())
        } else {
            self.select(&0u64.to_le_bytes())
        }
    }

    fn select(&self, key: &[u8]) -> Option<Backend> {
        match &self.balancer_type {
            BalancerType::FNVHash(b) => b.select(key, 256),
            BalancerType::Random(b) => b.select(key, 256),
            BalancerType::KetamaHashing(b) => b.select(key, 256),
            BalancerType::RoundRobin(b) => b.select(key, 256),
        }
    }
}

pub enum BalancerType {
    RoundRobin(LoadBalancer<RoundRobin>),
    Random(LoadBalancer<Random>),
    FNVHash(LoadBalancer<FNVHash>),
    KetamaHashing(LoadBalancer<KetamaHashing>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionChain {
    pub parts: Vec<KeyPart>,
}

//TODO: move to parse time.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyPart {
    Literal(String),
    Header(String),
    Cookie(String),
    QueryParams(String),
    UriPath,
    ClientIp,
    UserAgent,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransformOp {
    Lowercase,
    RemoveQueryParams,
    StripTrailingSlash,
    Truncate { length: usize },
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashOp {
    XxHash32(Option<u32>),
    XxHash64(Option<u64>),
    Murmur3_32(Option<u32>),
    Fnv1a,
}

#[cfg(test)]
mod execution_tests {
    use motya_config::common_types::definitions::{HashAlgorithm, KeyTemplateConfig, Transform};

    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    struct MockContext {
        headers: HashMap<String, String>,
        cookies: HashMap<String, String>,
        ip: Option<IpAddr>,
        uri: PathAndQuery,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                headers: HashMap::new(),
                cookies: HashMap::new(),
                ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                uri: PathAndQuery::from_static("/"),
            }
        }

        fn with_header(mut self, k: &str, v: &str) -> Self {
            self.headers.insert(k.to_lowercase(), v.to_string());
            self
        }

        fn with_cookie(mut self, k: &str, v: &str) -> Self {
            self.cookies.insert(k.to_string(), v.to_string());
            self
        }
        fn with_path(mut self, path: PathAndQuery) -> Self {
            self.uri = path;
            self
        }
    }

    impl KeySourceContext for MockContext {
        fn get_header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).map(|s| s.as_str())
        }
        fn get_cookie(&self, name: &str) -> Option<&str> {
            self.cookies.get(name).map(|s| s.as_str())
        }
        fn get_ip(&self) -> Option<IpAddr> {
            self.ip
        }
        fn get_path(&self) -> &PathAndQuery {
            &self.uri
        }
    }

    fn build_manual_selector(parts: Vec<KeyPart>, transforms: Vec<TransformOp>) -> KeySelector {
        KeySelector {
            extraction_strategies: vec![ExtractionChain { parts }],
            transforms,
            hasher: HashOp::XxHash64(None),
        }
    }

    fn make_config(source: &str, transforms: Vec<&str>) -> KeyTemplateConfig {
        let trans_objs = transforms
            .into_iter()
            .map(|name| {
                let mut params = HashMap::new();
                if name == "truncate" {
                    params.insert("length".to_string(), "3".to_string());
                }
                Transform {
                    name: name.to_string(),
                    params,
                }
            })
            .collect();

        KeyTemplateConfig {
            source: source.to_string(),
            fallback: None,
            transforms: trans_objs,
            algorithm: HashAlgorithm {
                name: "xxhash64".to_string(),
                seed: None,
            },
        }
    }

    #[test]
    fn test_case_sensitivity_without_transform() {
        let selector = build_manual_selector(vec![KeyPart::Header("x-id".to_string())], vec![]);

        let ctx_upper = MockContext::new().with_header("x-id", "User123");
        let ctx_lower = MockContext::new().with_header("x-id", "user123");

        let mut buf1 = Vec::new();
        let hash1 = selector.select(&ctx_upper, &mut buf1).unwrap();

        let mut buf2 = Vec::new();
        let hash2 = selector.select(&ctx_lower, &mut buf2).unwrap();

        assert_eq!(String::from_utf8(buf1).unwrap(), "User123");
        assert_eq!(String::from_utf8(buf2).unwrap(), "user123");

        assert_ne!(
            hash1, hash2,
            "Without 'lowercase' transform, hashes MUST differ for different case"
        );
    }

    #[test]
    fn test_query_params_extraction() {
        let selector =
            build_manual_selector(vec![KeyPart::QueryParams("id&type".to_string())], vec![]);

        let ctx = MockContext::new().with_path(PathAndQuery::from_static(
            "/api?garbage=true&type=admin&id=100",
        ));

        let mut buf = Vec::new();
        selector.select(&ctx, &mut buf).unwrap();

        assert_eq!(String::from_utf8(buf).unwrap(), "100admin");
    }

    #[test]
    fn test_extraction_basic_headers() {
        let conf = make_config("${header-x-a}---${header-x-b}", vec![]);
        let selector = KeySelector::try_from(conf).unwrap();

        let ctx = MockContext::new()
            .with_header("x-a", "Hello")
            .with_header("x-b", "World");

        let mut buf = Vec::new();
        let hash = selector.select(&ctx, &mut buf);

        assert!(hash.is_some(), "Hash should be generated");

        assert_eq!(String::from_utf8(buf).unwrap(), "Hello---World");
    }

    #[test]
    fn test_query_params_partial_missing() {
        let selector =
            build_manual_selector(vec![KeyPart::QueryParams("id&token".to_string())], vec![]);

        let ctx = MockContext::new().with_path(PathAndQuery::from_static("/?id=555"));

        let mut buf = Vec::new();
        selector.select(&ctx, &mut buf).unwrap();

        assert_eq!(String::from_utf8(buf).unwrap(), "555");
    }

    #[test]
    fn test_fallback_strategy() {
        let mut conf = make_config("${header-x-missing}", vec![]);
        conf.fallback = Some("${cookie-session}".to_string());

        let selector = KeySelector::try_from(conf).unwrap();

        let ctx = MockContext::new().with_cookie("session", "my-cookie-id");

        let mut buf = Vec::new();
        let hash = selector.select(&ctx, &mut buf);

        assert!(hash.is_some());
        assert_eq!(String::from_utf8(buf).unwrap(), "my-cookie-id");
    }

    #[test]
    fn test_transform_lowercase_and_stability() {
        let conf = make_config("${header-x-key}", vec!["lowercase"]);
        let selector = KeySelector::try_from(conf).unwrap();

        let ctx_upper = MockContext::new().with_header("x-key", "VALUE");
        let ctx_lower = MockContext::new().with_header("x-key", "value");
        let ctx_mixed = MockContext::new().with_header("x-key", "VaLuE");

        let mut buf1 = Vec::new();
        let hash1 = selector.select(&ctx_upper, &mut buf1).unwrap();
        assert_eq!(String::from_utf8(buf1).unwrap(), "value");

        let mut buf2 = Vec::new();
        let hash2 = selector.select(&ctx_lower, &mut buf2).unwrap();

        let mut buf3 = Vec::new();
        let hash3 = selector.select(&ctx_mixed, &mut buf3).unwrap();

        assert_eq!(
            hash1, hash2,
            "Hashing MUST be consistent regardless of case"
        );
        assert_eq!(
            hash2, hash3,
            "Hashing MUST be consistent regardless of case"
        );
    }

    #[test]
    fn test_transform_remove_query_params() {
        let conf = make_config("${header-x-url}", vec!["remove-query-params"]);
        let selector = KeySelector::try_from(conf).unwrap();

        let ctx = MockContext::new().with_header("x-url", "/path/to/resource?foo=bar&baz=1");

        let mut buf = Vec::new();
        selector.select(&ctx, &mut buf).unwrap();

        assert_eq!(String::from_utf8(buf).unwrap(), "/path/to/resource");
    }

    #[test]
    fn test_transform_truncate() {
        let conf = make_config("${header-x-long}", vec!["truncate"]);
        let selector = KeySelector::try_from(conf).unwrap();

        let ctx = MockContext::new().with_header("x-long", "1234567890");

        let mut buf = Vec::new();
        selector.select(&ctx, &mut buf).unwrap();

        assert_eq!(String::from_utf8(buf).unwrap(), "123");
    }
}
