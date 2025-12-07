use motya_config::common_types::definitions::{HashAlgorithm, KeyTemplateConfig, Transform};
use regex::Regex;
use std::sync::OnceLock;
use std::{convert::TryFrom, str::FromStr};

use crate::proxy::balancer::key_selector::{
    ExtractionChain, HashOp, KeyPart, KeySelector, TransformOp,
};

fn variable_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"\$\{([^}]+)\}").unwrap())
}

impl TryFrom<KeyTemplateConfig> for KeySelector {
    type Error = String;

    fn try_from(conf: KeyTemplateConfig) -> Result<Self, Self::Error> {
        let mut strategies = Vec::new();

        strategies.push(parse_template_string(&conf.source)?);

        if let Some(fallback_str) = conf.fallback {
            strategies.push(parse_template_string(&fallback_str)?);
        }

        let mut transforms = Vec::new();
        for t in conf.transforms {
            transforms.push(parse_transform(&t)?);
        }

        let hasher = parse_hasher(&conf.algorithm)?;

        Ok(KeySelector {
            extraction_strategies: strategies,
            transforms,
            hasher,
        })
    }
}

fn parse_template_string(template: &str) -> Result<ExtractionChain, String> {
    let re = variable_regex();
    let mut parts = Vec::new();
    let mut last_pos = 0;
    for caps in re.captures_iter(template) {
        let m = caps.get(0).unwrap();
        let var_name = &caps[1];

        if m.start() > last_pos {
            parts.push(KeyPart::Literal(template[last_pos..m.start()].to_string()));
        }

        let part = match var_name {
            "uri-path" => KeyPart::UriPath,
            "client-ip" => KeyPart::ClientIp,
            "user-agent" => KeyPart::UserAgent,
            s if s.starts_with("header-") => {
                let header_name = s.strip_prefix("header-").unwrap().to_lowercase();

                KeyPart::Header(header_name)
            }
            s if s.starts_with("cookie-") => {
                let cookie_name = s.strip_prefix("cookie-").unwrap();
                KeyPart::Cookie(cookie_name.to_string())
            }
            s if s.starts_with("query?") => {
                let params = s.strip_prefix("query?").unwrap();
                KeyPart::QueryParams(params.to_string())
            }
            unknown => return Err(format!("Unknown variable in key template: {}", unknown)),
        };
        parts.push(part);

        last_pos = m.end();
    }

    if last_pos < template.len() {
        parts.push(KeyPart::Literal(template[last_pos..].to_string()));
    }

    Ok(ExtractionChain { parts })
}

fn parse_transform(t: &Transform) -> Result<TransformOp, String> {
    match t.name.as_str() {
        "lowercase" => Ok(TransformOp::Lowercase),
        "remove-query-params" => Ok(TransformOp::RemoveQueryParams),
        "strip-trailing-slash" => Ok(TransformOp::StripTrailingSlash),
        "truncate" => {
            let len_str = t
                .params
                .get("length")
                .ok_or("Missing length param for truncate")?;
            let length = len_str.parse::<usize>().map_err(|_| "Invalid length")?;
            Ok(TransformOp::Truncate { length })
        }
        _ => Err(format!("Unknown transform: {}", t.name)),
    }
}

fn parse_hasher(algo: &HashAlgorithm) -> Result<HashOp, String> {
    fn get_seed<T: FromStr>(seed_opt: &Option<String>, def: T) -> T {
        seed_opt
            .as_ref()
            .and_then(|s| s.parse::<T>().ok())
            .unwrap_or(def)
    }

    match algo.name.as_str() {
        "xxhash32" => Ok(HashOp::XxHash32(Some(get_seed(&algo.seed, 0)))),
        "xxhash64" => Ok(HashOp::XxHash64(Some(get_seed(&algo.seed, 0)))),
        "murmur3_32" => Ok(HashOp::Murmur3_32(Some(get_seed(&algo.seed, 0)))),
        "fnv1a" => Ok(HashOp::Fnv1a),
        _ => Err(format!("Unknown hash algorithm: {}", algo.name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use motya_config::common_types::definitions::{HashAlgorithm, KeyTemplateConfig, Transform};
    use std::collections::HashMap;

    fn create_config(
        source: &str,
        fallback: Option<&str>,
        transforms: Vec<Transform>,
        algo_name: &str,
        seed: Option<&str>,
    ) -> KeyTemplateConfig {
        KeyTemplateConfig {
            source: source.to_string(),
            fallback: fallback.map(|s| s.to_string()),
            transforms,
            algorithm: HashAlgorithm {
                name: algo_name.to_string(),
                seed: seed.map(|s| s.to_string()),
            },
        }
    }

    #[test]
    fn test_parse_simple_literals_and_vars() {
        let conf = create_config("prefix-${client-ip}-suffix", None, vec![], "xxhash32", None);

        let selector = KeySelector::try_from(conf).expect("Should parse successfully");

        let chain = &selector.extraction_strategies[0];
        assert_eq!(chain.parts.len(), 3);
        assert_eq!(chain.parts[0], KeyPart::Literal("prefix-".to_string()));
        assert_eq!(chain.parts[1], KeyPart::ClientIp);
        assert_eq!(chain.parts[2], KeyPart::Literal("-suffix".to_string()));
    }

    #[test]
    fn test_parse_headers_and_cookies() {
        let conf = create_config(
            "${header-x-my-custom-id}:${cookie-session-id}",
            None,
            vec![],
            "xxhash32",
            None,
        );

        let selector = KeySelector::try_from(conf).unwrap();
        let chain = &selector.extraction_strategies[0];

        assert_eq!(chain.parts.len(), 3);

        assert_eq!(
            chain.parts[0],
            KeyPart::Header("x-my-custom-id".to_string())
        );

        assert_eq!(chain.parts[1], KeyPart::Literal(":".to_string()));

        assert_eq!(chain.parts[2], KeyPart::Cookie("session-id".to_string()));
    }

    #[test]
    fn test_known_variables() {
        let conf = create_config("${uri-path}|${user-agent}", None, vec![], "xxhash32", None);
        let selector = KeySelector::try_from(conf).unwrap();
        let chain = &selector.extraction_strategies[0];

        assert_eq!(chain.parts[0], KeyPart::UriPath);
        assert_eq!(chain.parts[1], KeyPart::Literal("|".to_string()));
        assert_eq!(chain.parts[2], KeyPart::UserAgent);
    }

    #[test]
    fn test_fallback_strategy() {
        let conf = create_config(
            "${cookie-sid}",
            Some("${client-ip}"),
            vec![],
            "xxhash32",
            None,
        );

        let selector = KeySelector::try_from(conf).unwrap();

        assert_eq!(selector.extraction_strategies.len(), 2);

        assert_eq!(
            selector.extraction_strategies[0].parts[0],
            KeyPart::Cookie("sid".to_string())
        );

        assert_eq!(
            selector.extraction_strategies[1].parts[0],
            KeyPart::ClientIp
        );
    }

    #[test]
    fn test_transforms_parsing() {
        let mut params = HashMap::new();
        params.insert("length".to_string(), "64".to_string());

        let transforms = vec![
            Transform {
                name: "lowercase".to_string(),
                params: HashMap::new(),
            },
            Transform {
                name: "remove-query-params".to_string(),
                params: HashMap::new(),
            },
            Transform {
                name: "truncate".to_string(),
                params,
            },
        ];

        let conf = create_config("${uri-path}", None, transforms, "xxhash32", None);
        let selector = KeySelector::try_from(conf).unwrap();

        assert_eq!(selector.transforms.len(), 3);
        assert_eq!(selector.transforms[0], TransformOp::Lowercase);
        assert_eq!(selector.transforms[1], TransformOp::RemoveQueryParams);

        match selector.transforms[2] {
            TransformOp::Truncate { length } => assert_eq!(length, 64),
            _ => panic!("Expected Truncate"),
        }
    }

    #[test]
    fn test_truncate_missing_or_invalid_param() {
        let t1 = vec![Transform {
            name: "truncate".to_string(),
            params: HashMap::new(),
        }];
        let conf1 = create_config("k", None, t1, "xxhash32", None);
        assert!(KeySelector::try_from(conf1).is_err());

        let mut params = HashMap::new();
        params.insert("length".to_string(), "foo".to_string());
        let t2 = vec![Transform {
            name: "truncate".to_string(),
            params,
        }];
        let conf2 = create_config("k", None, t2, "xxhash32", None);
        assert!(KeySelector::try_from(conf2).is_err());
    }

    #[test]
    fn test_hasher_xxhash32_defaults() {
        let conf = create_config("k", None, vec![], "xxhash32", None);
        let selector = KeySelector::try_from(conf).unwrap();

        match selector.hasher {
            HashOp::XxHash32(seed) => assert_eq!(seed, Some(0)),
            _ => panic!("Expected XxHash32"),
        }
    }

    #[test]
    fn test_hasher_xxhash32_with_seed() {
        let conf = create_config("k", None, vec![], "xxhash32", Some("12345"));
        let selector = KeySelector::try_from(conf).unwrap();

        match selector.hasher {
            HashOp::XxHash32(seed) => assert_eq!(seed, Some(12345)),
            _ => panic!("Expected XxHash32 with seed"),
        }
    }

    #[test]
    fn test_hasher_xxhash32_invalid_seed_fallback() {
        let conf = create_config("k", None, vec![], "xxhash32", Some("not-a-number"));
        let selector = KeySelector::try_from(conf).unwrap();

        match selector.hasher {
            HashOp::XxHash32(seed) => assert_eq!(seed, Some(0)),
            _ => panic!("Expected XxHash32"),
        }
    }

    #[test]
    fn test_unknown_variable() {
        let conf = create_config("${what-is-this}", None, vec![], "xxhash32", None);
        let res = KeySelector::try_from(conf);

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Unknown variable in key template: what-is-this"
        );
    }

    #[test]
    fn test_unknown_transform() {
        let t = vec![Transform {
            name: "rotate-180".to_string(),
            params: HashMap::new(),
        }];
        let conf = create_config("k", None, t, "xxhash32", None);
        let res = KeySelector::try_from(conf);

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unknown transform"));
    }
}
