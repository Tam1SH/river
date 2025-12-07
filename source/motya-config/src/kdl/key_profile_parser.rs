use std::collections::HashMap;

use kdl::{KdlDocument, KdlEntry, KdlNode};

use crate::common_types::{
    bad::Bad,
    definitions::{HashAlgorithm, KeyTemplateConfig, Transform},
};
use crate::kdl::utils::{self, HashMapValidationExt};

pub struct KeyProfileParser;

impl KeyProfileParser {
    pub fn parse(doc: &KdlDocument, node: &KdlDocument) -> miette::Result<KeyTemplateConfig> {
        let mut key_source: Option<String> = None;
        let mut fallback: Option<String> = None;
        let mut algorithm: Option<HashAlgorithm> = None;
        let mut transforms: Vec<Transform> = Vec::new();

        let nodes = utils::data_nodes(doc, node)?;
        for (child_node, name, args) in nodes {
            match name {
                "key" => {
                    let (source, fb) = Self::parse_key_directive(doc, child_node, args)?;
                    key_source = Some(source);
                    fallback = fb;
                }
                "algorithm" => {
                    algorithm = Some(Self::parse_algorithm_directive(doc, child_node, args)?);
                }
                "transforms-order" => {
                    transforms = Self::parse_transforms_order(doc, child_node)?;
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown directive in key profile: '{name}'"),
                        doc,
                        &child_node.span(),
                    )
                    .into())
                }
            }
        }

        let key_source = key_source.ok_or_else(|| {
            Bad::docspan("Key profile must have 'key' directive", doc, &node.span())
        })?;

        let algorithm = algorithm.unwrap_or_else(|| HashAlgorithm {
            name: "xxhash64".to_string(),
            seed: None,
        });

        Ok(KeyTemplateConfig {
            source: key_source,
            fallback,
            algorithm,
            transforms,
        })
    }

    fn parse_key_directive(
        doc: &KdlDocument,
        node: &KdlNode,
        args: &[KdlEntry],
    ) -> miette::Result<(String, Option<String>)> {
        let named_args = &args[1..];

        let args_map = utils::str_str_args(doc, named_args)?
            .into_iter()
            .collect::<HashMap<&str, &str>>()
            .ensure_only_keys(&["fallback"], doc, node)?;

        let source = if let Some(entry) = args.first() {
            entry
                .value()
                .as_string()
                .ok_or_else(|| {
                    Bad::docspan("key directive requires a string value", doc, &entry.span())
                })?
                .to_string()
        } else {
            return Err(Bad::docspan("key directive requires a value", doc, &node.span()).into());
        };

        let fallback = args_map.get("fallback").map(|s| s.to_string());

        Ok((source, fallback))
    }

    fn parse_algorithm_directive(
        doc: &KdlDocument,
        node: &KdlNode,
        args: &[KdlEntry],
    ) -> miette::Result<HashAlgorithm> {
        let args_map = utils::str_str_args(doc, args)?
            .into_iter()
            .collect::<HashMap<&str, &str>>()
            .ensure_only_keys(&["name", "seed"], doc, node)?;

        let name = args_map
            .get("name")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "xxhash64".to_string());

        let seed = args_map.get("seed").map(|s| s.to_string());

        Ok(HashAlgorithm { name, seed })
    }

    fn parse_transforms_order(doc: &KdlDocument, node: &KdlNode) -> miette::Result<Vec<Transform>> {
        let children_doc = node.children().ok_or_else(|| {
            Bad::docspan("transforms-order must have children", doc, &node.span())
        })?;

        let mut transforms = Vec::new();
        let nodes = utils::data_nodes(doc, children_doc)?;

        for (_, name, args) in nodes {
            let params = utils::str_str_args(doc, args)?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            transforms.push(Transform {
                name: name.to_string(),
                params,
            });
        }

        Ok(transforms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdl::KdlDocument;

    #[test]
    fn test_parse_key_profile() {
        let kdl_input = r#"
            key "${cookie_session}" fallback="${client_ip}:${user_agent}"
            algorithm name="xxhash32" seed="idk"
            transforms-order {
                remove-query-params
                lowercase
                truncate length="256"
            }
        "#;

        let doc: KdlDocument = kdl_input.parse().unwrap();

        let template = KeyProfileParser::parse(&doc, &doc).expect("Should parse");

        assert_eq!(template.source, "${cookie_session}");
        assert_eq!(
            template.fallback.as_deref(),
            Some("${client_ip}:${user_agent}")
        );
        assert_eq!(template.algorithm.name, "xxhash32");
        assert_eq!(template.algorithm.seed.as_deref(), Some("idk"));

        assert_eq!(template.transforms.len(), 3);
        assert_eq!(template.transforms[0].name, "remove-query-params");
        assert_eq!(template.transforms[1].name, "lowercase");
        assert_eq!(template.transforms[2].name, "truncate");
        assert_eq!(
            template.transforms[2].params.get("length"),
            Some(&"256".to_string())
        );
    }

    #[test]
    fn test_parse_minimal_profile() {
        let kdl_input = r#"key "${uri_path}""#;
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let template = KeyProfileParser::parse(&doc, &doc).unwrap();

        assert_eq!(template.source, "${uri_path}");
        assert!(template.fallback.is_none());
        assert_eq!(template.algorithm.name, "xxhash64");
        assert!(template.algorithm.seed.is_none());
        assert!(template.transforms.is_empty());
    }

    #[test]
    fn test_missing_key_error() {
        let kdl_input = r#"algorithm name="xxhash32""#;
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let result = KeyProfileParser::parse(&doc, &doc);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .help()
            .unwrap()
            .to_string()
            .contains("Key profile must have 'key' directive"));
    }
}
