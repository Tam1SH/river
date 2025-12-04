use std::{collections::HashMap, path::PathBuf, str::FromStr};

use fqdn::FQDN;
use kdl::{KdlDocument, KdlNode};

use crate::config::{
    common_types::{
        SectionParser, bad::Bad, definitions::{DefinitionsTable, PluginDefinition, PluginSource}
    },
    kdl::{chain_parser::ChainParser, utils::{self, HashMapValidationExt}},
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
        }

        Ok(table)
    }

    fn parse_modifiers(&self, table: &mut DefinitionsTable, node: &KdlDocument) -> miette::Result<()> {
        let nodes = utils::data_nodes(self.doc, node)?;
        for (node, name, args) in nodes {
            match name {
                "namespace" => {
                    let ns_name = utils::extract_one_str_arg(
                        self.doc, node, "namespace", args, |s| Some(s.to_string())
                    ).map_err(|_| {
                        Bad::docspan(
                            "Expected a valid name string argument after 'namespace'",
                            self.doc,
                            &node.span(),
                        )
                    })?;
                    self.parse_namespace_recursive(table, node, &ns_name)?;
                }
                "chain-filters" => {
                    let chain_name = utils::extract_one_str_arg(
                        self.doc, node, "chain-filters", args, |s| Some(s.to_string())
                    ).map_err(|_| {
                        Bad::docspan(
                            "Expected a valid name string argument after 'chain-filters'",
                            self.doc,
                            &node.span(),
                        )
                    })?;
                    self.parse_chain(table, node, chain_name)?;
                }
                _ => return Err(Bad::docspan(format!("Unknown directive: '{name}'"), self.doc, &node.span()).into()),
            }
        }
        Ok(())
    }

    fn parse_plugins(&self, table: &mut DefinitionsTable, node: &KdlDocument) -> miette::Result<()> {
        let nodes = utils::data_nodes(self.doc, node)?;

        for (plugin_node, name, _) in nodes {
            if name != "plugin" {
                return Err(Bad::docspan(
                    format!("Expected 'plugin', found '{name}'"),
                    self.doc,
                    &plugin_node.span(),
                ).into());
            }

            let plugin_def = self.parse_single_plugin(plugin_node)?;

            if table.plugins.contains_key(&plugin_def.name) {
                return Err(Bad::docspan(
                    format!("Duplicate plugin definition: '{}'", plugin_def.name),
                    self.doc,
                    &plugin_node.span(),
                ).into());
            }

            table.plugins.insert(plugin_def.name.clone(), plugin_def);
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
                    let val = utils::extract_one_str_arg(
                        self.doc, child_node, "name", args, |s| Some(s.to_string())
                    )?;
                    name = Some(val);
                }
                "load" => {
                    if source.is_some() {
                        return Err(Bad::docspan("Duplicate 'load' directive", self.doc, &child_node.span()).into());
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
                        ).into());
                    }
                }
                _ => {
                    return Err(Bad::docspan(
                        format!("Unknown plugin property: '{child_name}'"),
                        self.doc,
                        &child_node.span(),
                    ).into());
                }
            }
        }

        let name = FQDN::from_str(&name
            .ok_or_else(|| Bad::docspan("Plugin must have a 'name'", self.doc, &node.span()))?)
            .map_err(|err| Bad::docspan(format!("Plugin name must be a valid FQDN, err: '{err}'"), self.doc, &node.span()))?;
        let source = source.ok_or_else(|| Bad::docspan("Plugin must have a 'load' directive", self.doc, &node.span()))?;

        Ok(PluginDefinition { name, source })
    }
    
    fn parse_namespace_recursive(
        &self,
        table: &mut DefinitionsTable,
        node: &KdlNode,
        prefix: &str,
    ) -> miette::Result<()> {
        let children_doc = node.children().ok_or_else(|| {
            Bad::docspan(
                "namespace must have children",
                self.doc,
                &node.span(),
            )
        })?;

        let nodes = utils::data_nodes(self.doc, children_doc)?;

        for (child_node, name, args) in nodes {
            match name {
                "namespace" => {
                    let sub_name = utils::extract_one_str_arg(
                        self.doc, child_node, "namespace", args, |s| Some(s.to_string())
                    )?;
                    let new_prefix = format!("{}.{}", prefix, sub_name);
                    self.parse_namespace_recursive(table, child_node, &new_prefix)?;
                }
                "def" => {
                    
                    let def_name = utils::str_str_args(self.doc, args)?
                        .into_iter()
                        .collect::<HashMap<&str, &str>>()
                        .ensure_only_keys(&["name"], self.doc, child_node)?
                        .get("name")
                        .ok_or_else(|| Bad::docspan("def requires 'name' argument", self.doc, &child_node.span()))?
                        .to_string();

                    let fqdn = FQDN::from_str(&format!("{}.{}", prefix, def_name))
                        .map_err(|err| 
                            Bad::docspan(format!("prefix('{prefix}') or def name('{def_name}') not valid FQDN, err: '{err}'"), self.doc, &child_node.span())
                        )?;

                    if !table.available_filters.insert(fqdn.clone()) {
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
            Bad::docspan(
                "chain-filters must have children",
                self.doc,
                &node.span(),
            )
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

        assert_eq!(table.plugins.len(), 2);

        let local = table.plugins.get(&FQDN::from_str("local-wasm").unwrap()).unwrap();
        assert_eq!(local.name, "local-wasm");
        assert_eq!(local.source, PluginSource::File(PathBuf::from("./assets/filter.wasm")));

        let remote = table.plugins.get(&FQDN::from_str("remote-wasm").unwrap()).unwrap();
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
        assert!(res.unwrap_err().help().unwrap().to_string().contains("Plugin must have a 'load' directive"));
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
        assert!(res.unwrap_err().help().unwrap().to_string().contains("Unknown configuration key: 'foo'"));
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
        assert!(result.unwrap_err().help().unwrap().to_string().contains("Duplicate chain-filters name: 'my-chain'"));
    }

    const NAMESPACE_MERGE_TEST: &str = r#"
    definitions {
        modifiers {
            namespace "river" {
                namespace "inner" {
                    def name="one"
                }
            }
        }
    }
    definitions {
        modifiers {
            namespace "river" {
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

        assert!(table.available_filters.contains(&FQDN::from_str("river.inner.one").unwrap()));
        assert!(table.available_filters.contains(&FQDN::from_str("river.inner.two").unwrap()));
    }
    
    const DUPLICATE_DEF_TEST: &str = r#"
    definitions {
        modifiers {
            namespace "river" {
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
        assert!(result.unwrap_err().help().unwrap().to_string().contains("Duplicate filter definition: 'river.one'"));
    }
}
