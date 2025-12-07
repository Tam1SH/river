use fqdn::FQDN;
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct FilterChain {
    pub filters: Vec<ConfiguredFilter>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfiguredFilter {
    pub name: FQDN,
    pub args: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PluginDefinition {
    pub name: FQDN,
    pub source: PluginSource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PluginSource {
    File(PathBuf),
    Url(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyTemplateConfig {
    pub source: String,
    pub fallback: Option<String>,
    pub algorithm: HashAlgorithm,
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HashAlgorithm {
    pub name: String,
    pub seed: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transform {
    pub name: String,
    pub params: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamedFilterChain {
    pub name: String,
    pub chain: FilterChain,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Modificator {
    Chain(NamedFilterChain),
}
