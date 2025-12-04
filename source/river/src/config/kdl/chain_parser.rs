use std::{collections::HashMap, str::FromStr};
use fqdn::FQDN;
use kdl::KdlDocument;
use crate::config::{
    common_types::{
        bad::Bad, definitions::{ConfiguredFilter, FilterChain},
    },
    kdl::utils,
};

pub struct ChainParser;

impl ChainParser {
    pub fn parse(doc: &KdlDocument, block: &KdlDocument) -> miette::Result<FilterChain> {
        let nodes = utils::data_nodes(doc, block)?;
        let mut filters = Vec::new();

        for (node, name, args) in nodes {
            if name != "filter" {
                return Err(Bad::docspan(
                    format!("Expected 'filter' directive, found '{name}'"),
                    doc,
                    &node.span(),
                ).into());
            } 

            let mut args_map: HashMap<String, String> = utils::str_str_args(doc, args)?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            let filter_name = FQDN::from_str(&args_map.remove("name")
                .ok_or_else(|| {
                    Bad::docspan(
                        "filter requires a 'name' argument",
                        doc,
                        &node.span(),
                    )
                })?)
                .map_err(|err| {
                    Bad::docspan(
                        format!("name is not FQDN, err: '{err}'"),
                        doc,
                        &node.span(),
                    )
                })?;

            filters.push(ConfiguredFilter {
                name: filter_name,
                args: args_map,
            });
        }

        Ok(FilterChain { filters })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdl::KdlDocument;

    #[test]
    fn test_chain_parser_success_happy_path() {
        
        let kdl_input = r#"
            filter name="com.example.auth"
            filter name="com.example.logger" level="debug" format="json"
        "#;
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let chain = ChainParser::parse(&doc, &doc).expect("Should parse valid chain");

        assert_eq!(chain.filters.len(), 2);

        let f1 = &chain.filters[0];
        assert_eq!(f1.name.to_string(), "com.example.auth");
        assert!(f1.args.is_empty());

        let f2 = &chain.filters[1];
        assert_eq!(f2.name.to_string(), "com.example.logger");
        assert_eq!(f2.args.get("level").unwrap(), "debug");
        assert_eq!(f2.args.get("format").unwrap(), "json");
    }

    #[test]
    fn test_chain_parser_empty_block() {
        
        let kdl_input = "";
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let chain = ChainParser::parse(&doc, &doc).expect("Should parse empty block");
        assert!(chain.filters.is_empty());
    }

    #[test]
    fn test_chain_parser_invalid_directive_name() { 
        let kdl_input = r#"
            filter name="good.filter"
            not-filter name="bad.one"
        "#;
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let result = ChainParser::parse(&doc, &doc);
        let msg_err = result.unwrap_err().help().unwrap().to_string();

        crate::assert_err_contains!(msg_err, "Expected 'filter' directive, found 'not-filter'");
    }

    #[test]
    fn test_chain_parser_missing_name_argument() {
        
        let kdl_input = r#"
            filter arg="value"
        "#;
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let result = ChainParser::parse(&doc, &doc);
        let msg_err = result.unwrap_err().help().unwrap().to_string();
        crate::assert_err_contains!(msg_err, "filter requires a 'name' argument");
    }

    #[test]
    fn test_chain_parser_invalid_fqdn() {
        
        let kdl_input = r#"
            filter name="invalid name with spaces"
        "#;
        let doc: KdlDocument = kdl_input.parse().unwrap();

        let result = ChainParser::parse(&doc, &doc);
        let msg_err = result.unwrap_err().help().unwrap().to_string();

        crate::assert_err_contains!(msg_err, "name is not FQDN");
    }
}
