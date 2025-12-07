use std::{collections::HashMap, path::PathBuf, str::FromStr};

use fqdn::FQDN;
use kdl::{KdlDocument, KdlEntry, KdlNode};

use crate::{
    common_types::{
        bad::Bad,
        definitions::{KeyTemplateConfig, PluginDefinition, PluginSource},
        definitions_table::DefinitionsTable,
        section_parser::SectionParser,
    },
    kdl::{
        chain_parser::ChainParser,
        key_profile_parser::KeyProfileParser,
        utils::{self, HashMapValidationExt},
    },
};

pub struct DefinitionsSection<'a> {
    doc: &'a KdlDocument,
}

impl SectionParser<KdlDocument, DefinitionsTable> for DefinitionsSection<'_> {
    fn parse_node(&self, node: &KdlDocument) -> miette::Result<DefinitionsTable> {
        self.extract_definitions(node)
    }
}

impl<'a> DefinitionsSection<'a> {
    pub fn new(doc: &'a KdlDocument) -> Self {
        Self { doc }
    }

    fn extract_definitions(&self, node: &KdlDocument) -> miette::Result<DefinitionsTable> {
        let mut table = DefinitionsTable::default();

        let def_nodes = utils::wildcard_argless_child_docs(self.doc, node)?;
        let definitions_blocks: Vec<&KdlDocument> = def_nodes
            .iter()
            .filter(|(name, _)| *name == "definitions")
            .map(|(_, doc)| *doc)
            .collect();

        for block in definitions_blocks {
            if let Some(modifiers) = utils::optional_child_doc(self.doc, block, "modifiers") {
                self.parse_modifiers(&mut table, modifiers)?;
            }

            if let Some(plugins) = utils::optional_child_doc(self.doc, block, "plugins") {
                self.parse_plugins(&mut table, plugins)?;
            }

            if let Some(key_profiles) = utils::optional_child_doc(self.doc, block, "key-profiles") {
                self.parse_key_profiles(&mut table, key_profiles)?;
            }
        }

        Ok(table)
    }

    fn parse_key_profiles(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlDocument,
    ) -> miette::Result<()> {
        let nodes = utils::data_nodes(self.doc, node)?;

        for (node, name, args) in nodes {
            match name {
                "namespace" => {
                    let ns_name =
                        utils::extract_one_str_arg(self.doc, node, "namespace", args, |s| {
                            Some(s.to_string())
                        })?;
                    self.parse_key_profile_namespace(table, node, &ns_name)?;
                }
                "template" => {
                    let (name, template) = self.parse_key_profile_template(node, args, "")?;
                    if table.get_key_templates().contains_key(&name) {
                        return Err(Bad::docspan(
                            format!("Duplicate key template: '{}'", name),
                            self.doc,
                            &node.span(),
                        )
                        .into());
                    }
                    table.insert_key_profile(name.clone(), template);
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown directive in key-profiles: '{name}'"),
                        self.doc,
                        &node.span(),
                    )
                    .into())
                }
            }
        }

        Ok(())
    }

    fn parse_key_profile_namespace(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlNode,
        prefix: &str,
    ) -> miette::Result<()> {
        let children_doc = node
            .children()
            .ok_or_else(|| Bad::docspan("namespace must have children", self.doc, &node.span()))?;

        let nodes = utils::data_nodes(self.doc, children_doc)?;

        for (child_node, name, args) in nodes {
            match name {
                "namespace" => {
                    let sub_name =
                        utils::extract_one_str_arg(self.doc, child_node, "namespace", args, |s| {
                            Some(s.to_string())
                        })?;
                    let new_prefix = if prefix.is_empty() {
                        sub_name
                    } else {
                        format!("{}.{}", prefix, sub_name)
                    };
                    self.parse_key_profile_namespace(table, child_node, &new_prefix)?;
                }
                "template" => {
                    let (name, template) =
                        self.parse_key_profile_template(child_node, args, prefix)?;
                    if table.get_key_templates().contains_key(&name) {
                        return Err(Bad::docspan(
                            format!("Duplicate key template: '{}'", name),
                            self.doc,
                            &child_node.span(),
                        )
                        .into());
                    }
                    table.insert_key_profile(name.clone(), template);
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown directive in key-profile namespace: '{name}'"),
                        self.doc,
                        &child_node.span(),
                    )
                    .into())
                }
            }
        }

        Ok(())
    }

    fn parse_key_profile_template(
        &self,
        node: &KdlNode,
        args: &[KdlEntry],
        namespace_prefix: &str,
    ) -> miette::Result<(String, KeyTemplateConfig)> {
        let template_name =
            utils::extract_one_str_arg(self.doc, node, "template", args, |s| Some(s.to_string()))?;

        let full_name = if namespace_prefix.is_empty() {
            template_name
        } else {
            format!("{}.{}", namespace_prefix, template_name)
        };

        let children = node.children().ok_or_else(|| {
            Bad::docspan(
                "template block must have children (e.g. { ... })",
                self.doc,
                &node.span(),
            )
        })?;

        let key_template = KeyProfileParser::parse(self.doc, children)?;

        Ok((full_name, key_template))
    }

    fn parse_modifiers(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlDocument,
    ) -> miette::Result<()> {
        let nodes = utils::data_nodes(self.doc, node)?;
        for (node, name, args) in nodes {
            match name {
                "namespace" => {
                    let ns_name =
                        utils::extract_one_str_arg(self.doc, node, "namespace", args, |s| {
                            Some(s.to_string())
                        })
                        .map_err(|_| {
                            Bad::docspan(
                                "Expected a valid name string argument after 'namespace'",
                                self.doc,
                                &node.span(),
                            )
                        })?;
                    self.parse_namespace_recursive(table, node, &ns_name)?;
                }
                "chain-filters" => {
                    let chain_name =
                        utils::extract_one_str_arg(self.doc, node, "chain-filters", args, |s| {
                            Some(s.to_string())
                        })
                        .map_err(|_| {
                            Bad::docspan(
                                "Expected a valid name string argument after 'chain-filters'",
                                self.doc,
                                &node.span(),
                            )
                        })?;
                    self.parse_chain(table, node, chain_name)?;
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown directive: '{name}'"),
                        self.doc,
                        &node.span(),
                    )
                    .into())
                }
            }
        }
        Ok(())
    }

    fn parse_plugins(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlDocument,
    ) -> miette::Result<()> {
        let nodes = utils::data_nodes(self.doc, node)?;

        for (plugin_node, name, _) in nodes {
            if name != "plugin" {
                return Err(Bad::docspan(
                    format!("Expected 'plugin', found '{name}'"),
                    self.doc,
                    &plugin_node.span(),
                )
                .into());
            }

            let plugin_def = self.parse_single_plugin(plugin_node)?;

            if table.get_plugins().contains_key(&plugin_def.name) {
                return Err(Bad::docspan(
                    format!("Duplicate plugin definition: '{}'", plugin_def.name),
                    self.doc,
                    &plugin_node.span(),
                )
                .into());
            }

            table.insert_plugin(plugin_def.name.clone(), plugin_def);
        }

        Ok(())
    }

    fn parse_single_plugin(&self, node: &KdlNode) -> miette::Result<PluginDefinition> {
        let children = node.children().ok_or_else(|| {
            Bad::docspan("plugin block must have children", self.doc, &node.span())
        })?;

        let nodes = utils::data_nodes(self.doc, children)?;

        let mut name: Option<String> = None;
        let mut source: Option<PluginSource> = None;

        for (child_node, child_name, args) in nodes {
            match child_name {
                "name" => {
                    let val =
                        utils::extract_one_str_arg(self.doc, child_node, "name", args, |s| {
                            Some(s.to_string())
                        })?;
                    name = Some(val);
                }
                "load" => {
                    if source.is_some() {
                        return Err(Bad::docspan(
                            "Duplicate 'load' directive",
                            self.doc,
                            &child_node.span(),
                        )
                        .into());
                    }

                    let args_map = utils::str_str_args(self.doc, args)?
                        .into_iter()
                        .collect::<HashMap<&str, &str>>()
                        .ensure_only_keys(&["path", "url"], self.doc, child_node)?;

                    if let Some(path) = args_map.get("path") {
                        source = Some(PluginSource::File(PathBuf::from(path)));
                    } else if let Some(url) = args_map.get("url") {
                        source = Some(PluginSource::Url(url.to_string()));
                    } else {
                        return Err(Bad::docspan(
                            "'load' must provide either 'path' or 'url'",
                            self.doc,
                            &child_node.span(),
                        )
                        .into());
                    }
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown plugin property: '{child_name}'"),
                        self.doc,
                        &child_node.span(),
                    )
                    .into());
                }
            }
        }

        let name =
            FQDN::from_str(&name.ok_or_else(|| {
                Bad::docspan("Plugin must have a 'name'", self.doc, &node.span())
            })?)
            .map_err(|err| {
                Bad::docspan(
                    format!("Plugin name must be a valid FQDN, err: '{err}'"),
                    self.doc,
                    &node.span(),
                )
            })?;
        let source = source.ok_or_else(|| {
            Bad::docspan(
                "Plugin must have a 'load' directive",
                self.doc,
                &node.span(),
            )
        })?;

        Ok(PluginDefinition { name, source })
    }

    fn parse_namespace_recursive(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlNode,
        prefix: &str,
    ) -> miette::Result<()> {
        let children_doc = node
            .children()
            .ok_or_else(|| Bad::docspan("namespace must have children", self.doc, &node.span()))?;

        let nodes = utils::data_nodes(self.doc, children_doc)?;

        for (child_node, name, args) in nodes {
            match name {
                "namespace" => {
                    let sub_name =
                        utils::extract_one_str_arg(self.doc, child_node, "namespace", args, |s| {
                            Some(s.to_string())
                        })?;
                    let new_prefix = format!("{}.{}", prefix, sub_name);
                    self.parse_namespace_recursive(table, child_node, &new_prefix)?;
                }
                "def" => {
                    let def_name = utils::str_str_args(self.doc, args)?
                        .into_iter()
                        .collect::<HashMap<&str, &str>>()
                        .ensure_only_keys(&["name"], self.doc, child_node)?
                        .get("name")
                        .ok_or_else(|| {
                            Bad::docspan(
                                "def requires 'name' argument",
                                self.doc,
                                &child_node.span(),
                            )
                        })?
                        .to_string();

                    let fqdn = FQDN::from_str(&format!("{}.{}", prefix, def_name))
                        .map_err(|err|
                            Bad::docspan(format!("prefix('{prefix}') or def name('{def_name}') not valid FQDN, err: '{err}'"), self.doc, &child_node.span())
                        )?;

                    if !table.insert_filter(fqdn.clone()) {
                        return Err(Bad::docspan(
                            format!("Duplicate filter definition: '{}'", fqdn),
                            self.doc,
                            &child_node.span(),
                        )
                        .into());
                    }
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown directive in namespace: '{name}'. Expected 'namespace' or 'def'"),
                        self.doc,
                        &child_node.span(),
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    fn parse_chain(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlNode,
        chain_name: String,
    ) -> miette::Result<()> {
        if table.get_chains().contains_key(&chain_name) {
            return Err(Bad::docspan(
                format!("Duplicate chain-filters name: '{}'", chain_name),
                self.doc,
                &node.span(),
            )
            .into());
        }

        let children_doc = node.children().ok_or_else(|| {
            Bad::docspan("chain-filters must have children", self.doc, &node.span())
        })?;

        let chain = ChainParser::parse(self.doc, children_doc)?;

        table.insert_chain(chain_name, chain);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdl::KdlDocument;

    const VALID_BASIC_PROFILE: &str = r#"
    definitions {
        key-profiles {
            template "basic" {
                key "${cookie_session}"
            }
        }
    }
    "#;

    #[test]
    fn test_minimal_valid_profile() {
        let doc: KdlDocument = VALID_BASIC_PROFILE.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser
            .parse_node(&doc)
            .expect("Should parse minimal profile");

        let key_template = table
            .get_key_templates()
            .get("basic")
            .expect("Profile should exist");
        assert_eq!(key_template.source, "${cookie_session}");
        assert!(key_template.fallback.is_none());
        assert_eq!(key_template.algorithm.name, "xxhash64");
        assert!(key_template.algorithm.seed.is_none());
        assert!(key_template.transforms.is_empty());
    }

    const MISSING_KEY_PROFILE: &str = r#"
    definitions {
        key-profiles {
            template "broken" {
                algorithm name="xxhash32"
            }
        }
    }
    "#;

    #[test]
    fn test_missing_key_required() {
        let doc: KdlDocument = MISSING_KEY_PROFILE.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let result = parser.parse_node(&doc);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().help().unwrap().to_string();

        assert!(err_msg.contains("Key profile must have 'key' directive"));
    }

    const EMPTY_KEY_PROFILE: &str = r#"
    definitions {
        key-profiles {
            template "broken" {
                key "" 
            }
        }
    }
    "#;

    #[test]
    fn test_key_cannot_be_empty() {
        let doc: KdlDocument = EMPTY_KEY_PROFILE.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser
            .parse_node(&doc)
            .expect("Should parse even with empty key");

        let key_template = table.get_key_templates().get("broken").unwrap();
        assert_eq!(key_template.source, "");
    }

    const KEY_WITH_FALLBACK: &str = r#"
    definitions {
        key-profiles {
            template "with-fallback" {
                key "${cookie_session}" fallback="${client_ip}"
                algorithm name="murmur3_32" seed="123"
            }
        }
    }
    "#;

    #[test]
    fn test_key_with_fallback_and_algorithm() {
        let doc: KdlDocument = KEY_WITH_FALLBACK.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).unwrap();

        let key_template = table.get_key_templates().get("with-fallback").unwrap();
        assert_eq!(key_template.source, "${cookie_session}");
        assert_eq!(key_template.fallback.as_deref(), Some("${client_ip}"));
        assert_eq!(key_template.algorithm.name, "murmur3_32");
        assert_eq!(key_template.algorithm.seed.as_deref(), Some("123"));
    }

    const ALGORITHM_NAME_REQUIRED: &str = r#"
    definitions {
        key-profiles {
            template "bad-algo" {
                key "${test}"
                algorithm
            }
        }
    }
    "#;

    #[test]
    fn test_algorithm_requires_name_param() {
        let doc: KdlDocument = ALGORITHM_NAME_REQUIRED.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let result = parser.parse_node(&doc);

        let table = result.expect("Should use default algorithm");
        let key_template = table.get_key_templates().get("bad-algo").unwrap();
        assert_eq!(key_template.algorithm.name, "xxhash64");
    }

    const ALGORITHM_WITH_SEED_ONLY: &str = r#"
    definitions {
        key-profiles {
            template "seed-only" {
                key "${test}"
                algorithm seed="myseed"
            }
        }
    }
    "#;

    #[test]
    fn test_algorithm_with_seed_but_no_name() {
        let doc: KdlDocument = ALGORITHM_WITH_SEED_ONLY.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).unwrap();

        let key_template = table.get_key_templates().get("seed-only").unwrap();
        assert_eq!(key_template.algorithm.name, "xxhash64");
        assert_eq!(key_template.algorithm.seed.as_deref(), Some("myseed"));
    }

    const TRANSFORMS_ORDER_EMPTY: &str = r#"
    definitions {
        key-profiles {
            template "empty-transforms" {
                key "${test}"
                transforms-order {
                }
            }
        }
    }
    "#;

    #[test]
    fn test_transforms_order_can_be_empty() {
        let doc: KdlDocument = TRANSFORMS_ORDER_EMPTY.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).unwrap();

        let key_template = table.get_key_templates().get("empty-transforms").unwrap();
        assert!(key_template.transforms.is_empty());
    }

    const TRANSFORMS_ORDER_WITH_STEPS: &str = r#"
    definitions {
        key-profiles {
            template "with-transforms" {
                key "${uri_path}"
                transforms-order {
                    remove-query-params
                    lowercase
                    truncate length="256"
                }
            }
        }
    }
    "#;

    #[test]
    fn test_transforms_order_parsing() {
        let doc: KdlDocument = TRANSFORMS_ORDER_WITH_STEPS.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).unwrap();

        let key_template = table.get_key_templates().get("with-transforms").unwrap();
        let transforms = &key_template.transforms;

        assert_eq!(transforms.len(), 3);

        assert_eq!(transforms[0].name, "remove-query-params");
        assert!(transforms[0].params.is_empty());

        assert_eq!(transforms[1].name, "lowercase");
        assert!(transforms[1].params.is_empty());

        assert_eq!(transforms[2].name, "truncate");
        assert_eq!(transforms[2].params.get("length"), Some(&"256".to_string()));
        assert_eq!(transforms[2].params.len(), 1);
    }

    const DUPLICATE_TEMPLATE_NAME: &str = r#"
    definitions {
        key-profiles {
            template "duplicate" {
                key "${first}"
            }
        }
    }
    definitions {
        key-profiles {
            template "duplicate" {
                key "${second}"
            }
        }
    }
    "#;

    #[test]
    fn test_duplicate_template_name_error() {
        let doc: KdlDocument = DUPLICATE_TEMPLATE_NAME.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let result = parser.parse_node(&doc);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().help().unwrap().to_string();
        assert!(err_msg.contains("Duplicate key template: 'duplicate'"));
    }

    const NAMESPACED_TEMPLATES: &str = r#"
    definitions {
        key-profiles {
            namespace "motya" {
                template "session" {
                    key "${cookie_session}"
                }
                
                namespace "cdn" {
                    template "static" {
                        key "${uri_path}"
                    }
                }
            }
        }
    }
    "#;

    #[test]
    fn test_namespaced_templates() {
        let doc: KdlDocument = NAMESPACED_TEMPLATES.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).unwrap();

        assert!(table.get_key_templates().contains_key("motya.session"));
        assert!(table.get_key_templates().contains_key("motya.cdn.static"));

        let key_template = table.get_key_templates().get("motya.session").unwrap();
        assert_eq!(key_template.source, "${cookie_session}");

        let key_template = table.get_key_templates().get("motya.cdn.static").unwrap();
        assert_eq!(key_template.source, "${uri_path}");
    }

    const KEY_PROFILES_TEST: &str = r#"
    definitions {
        key-profiles {
            namespace "motya" {
                template "session-sticky" {
                    key "${cookie_session}" fallback="${client_ip}:${user_agent}"
                    
                    algorithm name="xxhash32" seed="idk"

                    transforms-order {
                        remove-query-params
                        lowercase
                        truncate length="256" 
                    }

                }

                namespace "cdn" {
                    template "static-files" {
                        key "${uri_path}"
                        algorithm name="xxhash64"
                        transforms-order {
                            remove-query-params
                            strip-trailing-slash
                        }

                    }
                }
            }

            template "global-api" {
                key "${header_authorization}"
                algorithm name="murmur3_32" seed="12345"
            }
        }
    }
    "#;

    #[test]
    fn test_parse_key_profiles() {
        let doc: KdlDocument = KEY_PROFILES_TEST.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).expect("Parsing failed");

        assert_eq!(table.get_key_templates().len(), 3);

        let key_template = table
            .get_key_templates()
            .get("motya.session-sticky")
            .unwrap();
        assert_eq!(key_template.source, "${cookie_session}");
        assert_eq!(
            key_template.fallback.as_deref(),
            Some("${client_ip}:${user_agent}")
        );
        assert_eq!(key_template.algorithm.name, "xxhash32");
        assert_eq!(key_template.algorithm.seed.as_deref(), Some("idk"));
        assert_eq!(key_template.transforms.len(), 3);

        assert_eq!(key_template.transforms[0].name, "remove-query-params");
        assert_eq!(key_template.transforms[2].name, "truncate");
        assert_eq!(
            key_template.transforms[2].params.get("length"),
            Some(&"256".to_string())
        );

        let key_template = table
            .get_key_templates()
            .get("motya.cdn.static-files")
            .unwrap();
        assert_eq!(key_template.source, "${uri_path}");
        assert_eq!(key_template.algorithm.name, "xxhash64");
        assert_eq!(key_template.transforms.len(), 2);

        let key_template = table.get_key_templates().get("global-api").unwrap();
        assert_eq!(key_template.algorithm.seed.as_deref(), Some("12345"));
    }

    const DUPLICATE_KEY_PROFILE: &str = r#"
    definitions {
        key-profiles {
            template "same" { key "${a}" }
        }
    }
    definitions {
        key-profiles {
            template "same" { key "${b}" }
        }
    }
    "#;

    #[test]
    fn test_duplicate_key_profile_error() {
        let doc: KdlDocument = DUPLICATE_KEY_PROFILE.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let result = parser.parse_node(&doc);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .help()
            .unwrap()
            .to_string()
            .contains("Duplicate key template: 'same'"));
    }

    const PLUGINS_CONFIG: &str = r#"
    definitions {
        plugins {
            plugin {
                name "local-wasm"
                load path="./assets/filter.wasm"
            }

            plugin {
                name "remote-wasm"
                load url="https://example.com/filter.wasm"
            }
        }
    }
    "#;

    #[test]
    fn test_parse_plugins() {
        let doc: KdlDocument = PLUGINS_CONFIG.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).expect("Parsing failed");

        assert_eq!(table.get_plugins().len(), 2);

        let local = table
            .get_plugins()
            .get(&FQDN::from_str("local-wasm").unwrap())
            .unwrap();
        assert_eq!(local.name, "local-wasm");
        assert_eq!(
            local.source,
            PluginSource::File(PathBuf::from("./assets/filter.wasm"))
        );

        let remote = table
            .get_plugins()
            .get(&FQDN::from_str("remote-wasm").unwrap())
            .unwrap();
        assert_eq!(remote.name, "remote-wasm");
        if let PluginSource::Url(u) = &remote.source {
            assert_eq!(u, "https://example.com/filter.wasm");
        } else {
            panic!("Expected URL source");
        }
    }

    const INVALID_PLUGIN_NO_LOAD: &str = r#"
    definitions {
        plugins {
            plugin {
                name "broken"
            }
        }
    }
    "#;

    #[test]
    fn test_plugin_missing_load() {
        let doc: KdlDocument = INVALID_PLUGIN_NO_LOAD.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let res = parser.parse_node(&doc);

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .help()
            .unwrap()
            .to_string()
            .contains("Plugin must have a 'load' directive"));
    }

    const INVALID_PLUGIN_BAD_LOAD: &str = r#"
    definitions {
        plugins {
            plugin {
                name "broken"
                load foo="bar"
            }
        }
    }
    "#;

    #[test]
    fn test_plugin_bad_load_key() {
        let doc: KdlDocument = INVALID_PLUGIN_BAD_LOAD.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let res = parser.parse_node(&doc);

        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .help()
            .unwrap()
            .to_string()
            .contains("Unknown configuration key: 'foo'"));
    }

    const DUPLICATE_CHAIN_TEST: &str = r#"
    definitions {
        modifiers {
            chain-filters "my-chain" {
                filter name="foo"
            }
        }
    }
    definitions {
        modifiers {
            chain-filters "my-chain" {
                filter name="bar"
            }
        }
    }
    "#;

    #[test]
    fn test_duplicate_chain() {
        let doc: KdlDocument = DUPLICATE_CHAIN_TEST.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let result = parser.parse_node(&doc);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .help()
            .unwrap()
            .to_string()
            .contains("Duplicate chain-filters name: 'my-chain'"));
    }

    const NAMESPACE_MERGE_TEST: &str = r#"
    definitions {
        modifiers {
            namespace "motya" {
                namespace "inner" {
                    def name="one"
                }
            }
        }
    }
    definitions {
        modifiers {
            namespace "motya" {
                namespace "inner" {
                    def name="two"
                }
            }
        }
    }
    "#;

    #[test]
    fn test_namespace_merge() {
        let doc: KdlDocument = NAMESPACE_MERGE_TEST.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let table = parser.parse_node(&doc).unwrap();

        assert!(table
            .get_available_filters()
            .contains(&FQDN::from_str("motya.inner.one").unwrap()));
        assert!(table
            .get_available_filters()
            .contains(&FQDN::from_str("motya.inner.two").unwrap()));
    }

    const DUPLICATE_DEF_TEST: &str = r#"
    definitions {
        modifiers {
            namespace "motya" {
                def name="one"
                def name="one"
            }
        }
    }
    "#;

    #[test]
    fn test_duplicate_def() {
        let doc: KdlDocument = DUPLICATE_DEF_TEST.parse().unwrap();
        let parser = DefinitionsSection::new(&doc);
        let result = parser.parse_node(&doc);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .help()
            .unwrap()
            .to_string()
            .contains("Duplicate filter definition: 'motya.one'"));
    }
}
