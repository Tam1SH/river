use std::{
    collections::HashMap,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use http::{uri::PathAndQuery, StatusCode, Uri};
use kdl::{KdlDocument, KdlEntry, KdlNode};
use miette::SourceSpan;
use pingora::{prelude::HttpPeer, protocols::l4::socket::SocketAddr};

use crate::{
    common_types::{
        bad::{Bad, OptExtParse},
        connectors::{
            Connectors, ConnectorsLeaf, HttpPeerConfig, MultiServerUpstreamConfig, RouteMatcher,
            UpstreamConfig, UpstreamContextConfig, UpstreamServer, ALPN,
        },
        definitions::{KeyTemplateConfig, Modificator, NamedFilterChain},
        definitions_table::DefinitionsTable,
        section_parser::SectionParser,
        simple_response_type::SimpleResponseConfig,
    },
    internal::{DiscoveryKind, HealthCheckKind, SelectionKind, UpstreamOptions},
    kdl::{
        chain_parser::ChainParser,
        key_profile_parser::KeyProfileParser,
        utils::{self, HashMapValidationExt},
    },
};

pub struct ConnectorsSection<'a> {
    table: &'a DefinitionsTable,
    doc: &'a KdlDocument,
    anon_counter: AtomicUsize,
}

impl SectionParser<KdlDocument, Connectors> for ConnectorsSection<'_> {
    fn parse_node(&self, node: &KdlDocument) -> miette::Result<Connectors> {
        let mut anonymous_definitions = DefinitionsTable::default();

        let root_nodes = self.parse_connections_node(node, &mut anonymous_definitions)?;

        let upstreams = flatten_nodes(root_nodes, &[], None);

        if upstreams.is_empty() {
            return Err(
                Bad::docspan("We require at least one connector", self.doc, &node.span()).into(),
            );
        }

        Ok(Connectors {
            upstreams,
            anonymous_definitions,
        })
    }
}

impl<'a> ConnectorsSection<'a> {
    pub fn new(doc: &'a KdlDocument, table: &'a DefinitionsTable) -> Self {
        Self {
            table,
            doc,
            anon_counter: AtomicUsize::new(0),
        }
    }

    pub fn parse_connections_node(
        &self,
        node: &KdlDocument,
        anonymous_definitions: &mut DefinitionsTable,
    ) -> miette::Result<Vec<ConnectorsLeaf>> {
        let conn_node = utils::required_child_doc(self.doc, node, "connectors")?;

        self.process_nodes_recursive(
            conn_node,
            anonymous_definitions,
            "/".parse().unwrap(),
            RouteMatcher::Exact,
        )
    }

    fn process_nodes_recursive(
        &self,
        parent_node: &KdlDocument,
        anonymous_definitions: &mut DefinitionsTable,
        base_path: PathAndQuery,
        current_matcher: RouteMatcher,
    ) -> miette::Result<Vec<ConnectorsLeaf>> {
        let nodes = utils::data_nodes(self.doc, parent_node)?;
        let mut result = Vec::new();

        let mut exclusive_handler: Option<(&str, SourceSpan)> = None;
        let mut has_load_balance = false;

        for (node, name, args) in nodes {
            let processed_node = match name {
                "return" | "proxy" => {
                    if let Some((prev_name, _)) = exclusive_handler {
                        return Err(Bad::docspan(
                            format!("Directive '{name}' conflicts with previously defined '{prev_name}' in this section"), 
                            self.doc,
                            &node.span()
                        ).into());
                    }

                    exclusive_handler = Some((name, node.span()));

                    match name {
                        "return" => self.extract_static_response(node, args, base_path.clone())?,
                        "proxy" => {
                            self.extract_connector(node, args, base_path.clone(), current_matcher)?
                        }
                        _ => unreachable!(),
                    }
                }

                "load-balance" => {
                    if has_load_balance {
                        return Err(Bad::docspan(
                            "Duplicate 'load-balance' directive",
                            self.doc,
                            &node.span(),
                        )
                        .into());
                    }
                    has_load_balance = true;
                    self.extract_load_balance(node, anonymous_definitions)?
                }

                "section" => self.extract_section(
                    node,
                    args,
                    anonymous_definitions,
                    base_path.clone(),
                    current_matcher,
                )?,
                "use-chain" => {
                    self.extract_chain_usage(node, args, anonymous_definitions, base_path.clone())?
                }

                unknown => {
                    return Err(Bad::docspan(
                        format!("Unknown directive: {unknown}"),
                        self.doc,
                        &node.span(),
                    )
                    .into())
                }
            };

            result.push(processed_node);
        }

        Ok(result)
    }

    fn extract_chain_usage(
        &self,
        node: &KdlNode,
        args: &[KdlEntry],
        anonymous_definitions: &mut DefinitionsTable,
        path: PathAndQuery,
    ) -> miette::Result<ConnectorsLeaf> {
        //named use-chain
        if let Some(arg) = args.first() {
            let name = arg.value().as_string().ok_or_else(|| {
                Bad::docspan("Chain reference must be a string", self.doc, &arg.span())
            })?;

            if node.children().is_some() {
                return Err(Bad::docspan(
                    "use-chain cannot have both a name argument and a code block. Choose one.",
                    self.doc,
                    &node.span(),
                )
                .into());
            }

            let chain = self.table.get_chain_by_name(name).ok_or_else(|| {
                Bad::docspan(
                    format!("Chain '{}' not found in definitions", name),
                    self.doc,
                    &arg.span(),
                )
            })?;

            return Ok(ConnectorsLeaf::Modificator(Modificator::Chain(
                NamedFilterChain {
                    chain,
                    name: name.to_string(),
                },
            )));
        }

        //anonymous use-chain
        if let Some(children) = node.children() {
            let chain = ChainParser::parse(self.doc, children)?;

            let id = self.anon_counter.fetch_add(1, Ordering::Relaxed);
            let path_slug = path.path().replace('/', "_");
            let generated_name = format!("__anon_{id}_{path_slug}");

            anonymous_definitions.insert_chain(generated_name.clone(), chain.clone());

            return Ok(ConnectorsLeaf::Modificator(Modificator::Chain(
                NamedFilterChain {
                    chain,
                    name: generated_name,
                },
            )));
        }

        Err(Bad::docspan(
            "use-chain requires either a name argument or a block of filters",
            self.doc,
            &node.span(),
        )
        .into())
    }

    fn extract_section(
        &self,
        node: &KdlNode,
        args: &[KdlEntry],
        anonymous_definitions: &mut DefinitionsTable,
        base_path: PathAndQuery,
        parent_matcher: RouteMatcher,
    ) -> miette::Result<ConnectorsLeaf> {
        let path_arg = args
            .iter()
            .find(|entry| entry.name().is_none())
            .ok_or_else(|| {
                Bad::docspan(
                    "Section node requires a path argument",
                    self.doc,
                    &node.span(),
                )
            })?;

        let path_segment = path_arg.value().as_string().ok_or_else(|| {
            Bad::docspan(
                "Section path argument must be a string",
                self.doc,
                &path_arg.span(),
            )
        })?;

        let mode_arg = args
            .iter()
            .find(|entry| entry.name().map(|n| n.value()) == Some("as"));

        let next_matcher = if let Some(entry) = mode_arg {
            match entry.value().as_string() {
                Some("prefix") => RouteMatcher::Prefix,
                Some("exact") => RouteMatcher::Exact,
                Some(other) => {
                    return Err(Bad::docspan(
                        format!("Unknown routing mode '{other}'. Use 'prefix' or 'exact'"),
                        self.doc,
                        &entry.span(),
                    )
                    .into())
                }
                None => {
                    return Err(Bad::docspan(
                        "Routing mode must be a string",
                        self.doc,
                        &entry.span(),
                    )
                    .into())
                }
            }
        } else {
            parent_matcher
        };

        let children_doc = node.children().ok_or_else(|| {
            Bad::docspan("Section node must have children", self.doc, &node.span())
        })?;

        if next_matcher == RouteMatcher::Exact {
            for child in children_doc.nodes() {
                if child.name().value() == "section" {
                    return Err(Bad::docspan(
                        "A section with 'exact' routing mode cannot contain nested sections.",
                        self.doc,
                        &child.span(),
                    )
                    .into());
                }
            }
        }

        let full_path = if base_path.path().is_empty() || base_path.path() == "/" {
            if path_segment.starts_with('/') {
                path_segment.to_string()
            } else {
                format!("/{}", path_segment)
            }
        } else {
            format!(
                "{}/{}",
                base_path.path().trim_end_matches('/'),
                path_segment.trim_start_matches('/')
            )
        };

        let path = full_path.parse().map_err(|err| {
            Bad::docspan(
                format!("Bad path: {full_path}, error: {err}"),
                self.doc,
                &path_arg.span(),
            )
        })?;

        Ok(ConnectorsLeaf::Section(self.process_nodes_recursive(
            children_doc,
            anonymous_definitions,
            path,
            next_matcher,
        )?))
    }

    fn extract_static_response(
        &self,
        node: &KdlNode,
        args: &[KdlEntry],
        base_path: PathAndQuery,
    ) -> miette::Result<ConnectorsLeaf> {
        let args = utils::str_str_args(self.doc, args)
            .map_err(|err| {
                Bad::docspan(
                    format!(
                        "The return directive must have code and response keys, error: '{err}'"
                    ),
                    self.doc,
                    &node.span(),
                )
            })?
            .into_iter()
            .collect::<HashMap<&str, &str>>()
            .ensure_only_keys(&["code", "response"], self.doc, node)?;

        let http_code_raw = args.get("code").unwrap_or(&"200");
        let response = args.get("response").unwrap_or(&"");

        let http_code = StatusCode::from_str(http_code_raw).map_err(|err| {
            Bad::docspan(
                format!("Not a valid http code, reason: '{err}'"),
                self.doc,
                &node.span(),
            )
        })?;

        Ok(ConnectorsLeaf::Upstream(UpstreamConfig::Static(
            SimpleResponseConfig {
                http_code,
                response_body: response.to_string(),
                prefix_path: base_path,
            },
        )))
    }

    fn extract_connector(
        &self,
        node: &KdlNode,
        args: &[KdlEntry],
        base_path: PathAndQuery,
        parent_matcher: RouteMatcher,
    ) -> miette::Result<ConnectorsLeaf> {
        if let Some(children) = node.children() {
            if !args.is_empty() {
                return Err(Bad::docspan(
                    "The block-style 'proxy' cannot have arguments (like address) on the main node.",
                    self.doc,
                    &args[0].span(),
                ).into());
            }

            let children_nodes = utils::data_nodes(self.doc, children)?;
            let mut servers: Vec<UpstreamServer> = Vec::new();
            let mut common_options = HashMap::new();

            let parse_block_option = |common_options: &HashMap<&str, String>,
                                      child_node: &KdlNode,
                                      name: &str,
                                      child_args: &[KdlEntry]|
             -> miette::Result<String> {
                let value_entry =
                    child_args
                        .iter()
                        .find(|e| e.name().is_none())
                        .ok_or_else(|| {
                            Bad::docspan(
                                format!("'{name}' requires a value argument"),
                                self.doc,
                                &child_node.span(),
                            )
                        })?;

                let value = value_entry.value().as_string().ok_or_else(|| {
                    Bad::docspan(
                        format!("'{name}' value must be a string"),
                        self.doc,
                        &value_entry.span(),
                    )
                })?;

                if common_options.contains_key(name) {
                    return Err(Bad::docspan(
                        format!("Duplicate '{name}' directive in proxy block"),
                        self.doc,
                        &child_node.span(),
                    )
                    .into());
                }
                Ok(value.to_string())
            };

            for (child_node, name, child_args) in children_nodes {
                match name {
                    "server" => {
                        let addr_entry = child_args
                            .iter()
                            .find(|e| e.name().is_none())
                            .ok_or_else(|| {
                                Bad::docspan(
                                    "server node requires an address argument",
                                    self.doc,
                                    &child_node.span(),
                                )
                            })?;

                        let addr_str = addr_entry.value().as_string().ok_or_else(|| {
                            Bad::docspan(
                                "server address must be a string",
                                self.doc,
                                &addr_entry.span(),
                            )
                        })?;

                        let address =
                            str::parse::<std::net::SocketAddr>(addr_str).map_err(|err| {
                                Bad::docspan(
                                    format!("Invalid server address '{addr_str}': {err}"),
                                    self.doc,
                                    &addr_entry.span(),
                                )
                            })?;

                        let weight_entry = child_args
                            .iter()
                            .find(|e| e.name().map(|n| n.value()) == Some("weight"));

                        let weight = match weight_entry {
                            Some(entry) => entry.value().as_integer().ok_or_else(|| {
                                Bad::docspan(
                                    "server weight must be an integer",
                                    self.doc,
                                    &entry.span(),
                                )
                            })? as usize,
                            None => 1,
                        };

                        servers.push(UpstreamServer { address, weight });
                    }
                    "tls-sni" => {
                        let value =
                            parse_block_option(&common_options, child_node, name, child_args)?;
                        common_options.insert("tls-sni", value);
                    }
                    "proto" => {
                        let value =
                            parse_block_option(&common_options, child_node, name, child_args)?;
                        common_options.insert("proto", value);
                    }
                    unknown => {
                        return Err(Bad::docspan(
                            format!("Unknown directive in proxy block: {unknown}"),
                            self.doc,
                            &child_node.span(),
                        )
                        .into())
                    }
                }
            }

            if servers.is_empty() {
                return Err(Bad::docspan(
                    "Proxy block must contain at least one 'server' directive",
                    self.doc,
                    &node.span(),
                )
                .into());
            }

            let proto = self.extract_proto(node, &common_options)?;
            let tls_sni_val = common_options.get("tls-sni");

            let (_tls, sni, alpn) = match (proto, tls_sni_val) {
                (None, None) | (Some(ALPN::H1), None) => (false, String::new(), ALPN::H1),
                (None, Some(sni)) => (true, sni.to_string(), ALPN::H2H1),
                (Some(_), None) => {
                    return Err(Bad::docspan(
                        "'tls-sni' is required for HTTP2 support in proxy block",
                        self.doc,
                        &node.span(),
                    )
                    .into());
                }
                (Some(p), Some(sni)) => (true, sni.to_string(), p),
            };

            let final_sni = if sni.is_empty() { None } else { Some(sni) };

            return Ok(ConnectorsLeaf::Upstream(UpstreamConfig::MultiServer(
                MultiServerUpstreamConfig {
                    servers,
                    tls_sni: final_sni,
                    alpn,
                    prefix_path: base_path,
                    target_path: PathAndQuery::from_static("/"),
                    matcher: parent_matcher,
                },
            )));
        }

        let first_arg = args.first().ok_or_else(|| {
            Bad::docspan(
                "Connector node must provide an address or a block",
                self.doc,
                &node.span(),
            )
        })?;

        let named_args = &args[1..];

        let args = utils::str_str_args(self.doc, named_args)?
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect::<HashMap<&str, String>>()
            .ensure_only_keys(&["tls-sni", "proto"], self.doc, node)?;

        let Some(Ok(uri)) = first_arg.value().as_string().map(str::parse::<Uri>) else {
            return Err(Bad::docspan("Not a valid url", self.doc, &node.span()).into());
        };

        let Some(Ok(host_addr)) = uri
            .host()
            .and_then(|host| uri.port().map(|port| format!("{host}:{port}")))
            .map(|str| str::parse::<SocketAddr>(&str))
        else {
            return Err(Bad::docspan("Not a valid host address", self.doc, &node.span()).into());
        };

        let proto = self.extract_proto(node, &args)?;

        let tls_sni = args.get("tls-sni");

        let (tls, sni, alpn) = match (proto, tls_sni) {
            (None, None) | (Some(ALPN::H1), None) => (false, String::new(), ALPN::H1),
            (None, Some(sni)) => (true, sni.to_string(), ALPN::H2H1),
            (Some(_), None) => {
                return Err(Bad::docspan(
                    "'tls-sni' is required for HTTP2 support",
                    self.doc,
                    &node.span(),
                )
                .into());
            }
            (Some(p), Some(sni)) => (true, sni.to_string(), p),
        };

        let mut peer = HttpPeer::new(host_addr, tls, sni);
        peer.options.alpn = alpn.into();

        Ok(ConnectorsLeaf::Upstream(UpstreamConfig::Service(
            HttpPeerConfig {
                peer,
                prefix_path: base_path,
                target_path: uri
                    .path()
                    .parse::<PathAndQuery>()
                    .unwrap_or(PathAndQuery::from_static("/")),
                matcher: parent_matcher,
            },
        )))
    }

    fn extract_proto(
        &self,
        node: &KdlNode,
        args: &HashMap<&str, String>,
    ) -> Result<Option<ALPN>, miette::Error> {
        let proto = match args.get("proto") {
            None => None,
            Some(value) => parse_proto_value(value).map_err(|msg| {
                Bad::docspan(format!("{msg}, found '{value}'"), self.doc, &node.span())
            })?,
        };
        Ok(proto)
    }

    fn extract_load_balance(
        &self,
        node: &KdlNode,
        anonymous_definitions: &mut DefinitionsTable,
    ) -> miette::Result<ConnectorsLeaf> {
        let items = utils::data_nodes(
            self.doc,
            node.children().or_bail(
                "'load-balance' should have children",
                self.doc,
                &node.span(),
            )?,
        )?;

        let mut selection: Option<SelectionKind> = None;
        let mut health: Option<HealthCheckKind> = None;
        let mut discover: Option<DiscoveryKind> = None;
        let mut template: Option<KeyTemplateConfig> = None;

        for (node, name, args) in items {
            match name {
                "selection" => {
                    let (sel, key_src) = self.parse_selection(node, args, anonymous_definitions)?;
                    selection = Some(sel);
                    template = key_src;
                }
                "health-check" => {
                    health = Some(utils::extract_one_str_arg(
                        self.doc,
                        node,
                        name,
                        args,
                        |val| match val {
                            "None" => Some(HealthCheckKind::None),
                            _ => None,
                        },
                    )?);
                }
                "discovery" => {
                    discover = Some(utils::extract_one_str_arg(
                        self.doc,
                        node,
                        name,
                        args,
                        |val| match val {
                            "Static" => Some(DiscoveryKind::Static),
                            _ => None,
                        },
                    )?);
                }
                other => {
                    return Err(Bad::docspan(
                        format!("Unknown setting: '{other}'"),
                        self.doc,
                        &node.span(),
                    )
                    .into());
                }
            }
        }
        Ok(ConnectorsLeaf::LoadBalance(UpstreamOptions {
            selection: selection.unwrap_or(SelectionKind::RoundRobin),
            template,
            health_checks: health.unwrap_or(HealthCheckKind::None),
            discovery: discover.unwrap_or(DiscoveryKind::Static),
        }))
    }

    fn parse_selection(
        &self,
        node: &KdlNode,
        args: &[KdlEntry],
        anonymous_definitions: &mut DefinitionsTable,
    ) -> miette::Result<(SelectionKind, Option<KeyTemplateConfig>)> {
        let (selection_kind, kv_args) =
            utils::extract_one_str_arg_with_kv_args(self.doc, node, "selection", args, |val| {
                match val {
                    "RoundRobin" => Some(SelectionKind::RoundRobin),
                    "Random" => Some(SelectionKind::Random),
                    "FNV" => Some(SelectionKind::FvnHash),
                    "Ketama" => Some(SelectionKind::KetamaHashing),
                    _ => None,
                }
            })?;

        let key_source = if let Some(template_name) = kv_args.get("use-key-profile") {
            if let Some(template) = self.table.get_key_templates().get(template_name) {
                Some(template.clone())
            } else {
                return Err(Bad::docspan(
                    format!("Key profile '{}' not found", template_name),
                    self.doc,
                    &node.span(),
                )
                .into());
            }
        } else if let Some(nodes) = node.children() {
            let template = KeyProfileParser::parse(self.doc, nodes)?;
            let id = self.anon_counter.fetch_add(1, Ordering::Relaxed);
            let generated_name = format!("__anon_key_{id}");

            anonymous_definitions.insert_key_profile(generated_name.clone(), template.clone());

            Some(template)
        } else {
            match selection_kind {
                SelectionKind::KetamaHashing | SelectionKind::FvnHash => {
                    return Err(Bad::docspan(
                        format!("selection '{:?}' requires a key source. Use 'use-key-profile' or inline key configuration.", selection_kind),
                        self.doc,
                        &node.span(),
                    ).into());
                }
                _ => None,
            }
        };

        Ok((selection_kind, key_source))
    }
}

/// Recursive function to flatten the node tree
fn flatten_nodes(
    nodes: Vec<ConnectorsLeaf>,
    parent_rules: &[Modificator],        // Rules inherited from parents
    parent_lb: Option<&UpstreamOptions>, // LB options inherited from parents
) -> Vec<UpstreamContextConfig> {
    let mut results = Vec::new();

    // 1. Build context for the current level
    let mut current_rules = parent_rules.to_vec();
    let mut current_lb = parent_lb.cloned();

    // Partition nodes into structural elements (Upstream, Section) and modifiers (Rule, LB).
    // This is important so that declaration order within a block doesn't affect logic
    // (settings should apply to the whole block).
    let (structure, modifiers): (Vec<_>, Vec<_>) = nodes
        .into_iter()
        .partition(|n| matches!(n, ConnectorsLeaf::Section(_) | ConnectorsLeaf::Upstream(_)));

    // Apply current level modifiers to the context
    for node in modifiers {
        match node {
            ConnectorsLeaf::Modificator(rule) => current_rules.push(rule),
            // If LB is defined at this level, it overrides the parent's LB
            ConnectorsLeaf::LoadBalance(lb) => current_lb = Some(lb),
            _ => {}
        }
    }

    // 2. Traverse structural elements with the fully prepared context
    for node in structure {
        match node {
            ConnectorsLeaf::Upstream(up) => {
                // Leaf node: create the final object combining upstream and context
                results.push(UpstreamContextConfig {
                    upstream: up,
                    chains: current_rules.clone(),
                    lb_options: current_lb.clone().unwrap_or_default(),
                });
            }
            ConnectorsLeaf::Section(children) => {
                // Branch node: recursively descend, passing the current context
                let children_flat = flatten_nodes(children, &current_rules, current_lb.as_ref());
                results.extend(children_flat);
            }
            _ => unreachable!(), // Modifiers have already been filtered out
        }
    }

    results
}

fn parse_proto_value(value: &str) -> Result<Option<ALPN>, String> {
    match value {
        "h1-only" => Ok(Some(ALPN::H1)),
        "h2-only" => Ok(Some(ALPN::H2)),
        "h1-or-h2" => {
            tracing::warn!("accepting 'h1-or-h2' as meaning 'h2-or-h1'");
            Ok(Some(ALPN::H2H1))
        }
        "h2-or-h1" => Ok(Some(ALPN::H2H1)),
        other => Err(format!(
            "'proto' should be one of 'h1-only', 'h2-only', or 'h2-or-h1', found '{other}'"
        )),
    }
}

#[cfg(test)]
mod tests {

    use crate::kdl::definitions::DefinitionsSection;

    use super::*;

    fn parse_config(input: &str) -> miette::Result<Connectors> {
        let doc: KdlDocument = input.parse().unwrap();

        let def_parser = DefinitionsSection::new(&doc);
        let table = def_parser.parse_node(&doc)?;

        let conn_parser = ConnectorsSection::new(&doc, &table);
        conn_parser.parse_node(&doc)
    }

    const LOAD_BALANCE_BASIC: &str = r#"
        connectors {
            load-balance {
                selection "RoundRobin"
                health-check "None"
                discovery "Static"
            }
            proxy "http://127.0.0.1:8080"
        }
    "#;

    #[test]
    fn test_load_balance_basic() {
        let connectors = parse_config(LOAD_BALANCE_BASIC).expect("Parsing failed");

        assert_eq!(connectors.upstreams.len(), 1);
        let upstream = &connectors.upstreams[0];

        assert_eq!(upstream.lb_options.selection, SelectionKind::RoundRobin);
        assert_eq!(upstream.lb_options.health_checks, HealthCheckKind::None);
        assert_eq!(upstream.lb_options.discovery, DiscoveryKind::Static);
        assert!(upstream.lb_options.template.is_none());
    }

    const LOAD_BALANCE_ALL_SELECTION_TYPES: &str = r#"
        connectors {
            load-balance {
                selection "Random"
            }
            proxy "http://127.0.0.1:8080"
        }
    "#;

    #[test]
    fn test_load_balance_random_selection() {
        let connectors = parse_config(LOAD_BALANCE_ALL_SELECTION_TYPES).expect("Parsing failed");

        let upstream = &connectors.upstreams[0];
        assert_eq!(upstream.lb_options.selection, SelectionKind::Random);
    }

    const LOAD_BALANCE_FNV_HASH: &str = r#"
        connectors {
            load-balance {
                selection "FNV" use-key-profile="ip-profile"
            }
            proxy "http://127.0.0.1:8080"
        }
    "#;

    #[test]
    fn test_load_balance_fnv_hash_with_key_profile() {
        let result = parse_config(LOAD_BALANCE_FNV_HASH);

        assert!(result.is_err());
    }

    const LOAD_BALANCE_WITH_KEY_PROFILE: &str = r#"
        definitions {
            key-profiles {
                template "ip-profile" {
                    key "amogus"
                }
            }
        }
        
        connectors {
            load-balance {
                selection "FNV" use-key-profile="ip-profile"
            }
            proxy "http://127.0.0.1:8080"
        }
    "#;

    #[test]
    fn test_load_balance_with_defined_key_profile() {
        let connectors = parse_config(LOAD_BALANCE_WITH_KEY_PROFILE).expect("Parsing failed");

        let upstream = &connectors.upstreams[0];
        assert_eq!(upstream.lb_options.selection, SelectionKind::FvnHash);
        assert!(upstream.lb_options.template.is_some());

        let template = upstream.lb_options.template.as_ref().unwrap();
        assert_eq!(template.source, "amogus".to_string());
    }

    const LOAD_BALANCE_HASH_WITHOUT_KEY_SOURCE: &str = r#"
        connectors {
            load-balance {
                selection "Ketama"
            }
            proxy "http://127.0.0.1:8080"
        }
    "#;

    #[test]
    fn test_error_hash_selection_without_key_source() {
        let result = parse_config(LOAD_BALANCE_HASH_WITHOUT_KEY_SOURCE);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().help().unwrap().to_string();
        assert!(err_msg.contains("requires a key source"));
    }

    const LOAD_BALANCE_INHERITANCE: &str = r#"
        connectors {
            load-balance {
                selection "RoundRobin"
            }
            
            section "/api" {
                load-balance {
                    selection "Random"
                }
                proxy "http://127.0.0.1:8081"
            }
            
            section "/static" {
                proxy "http://127.0.0.1:8082"
            }
        }
    "#;

    #[test]
    fn test_load_balance_inheritance() {
        let connectors = parse_config(LOAD_BALANCE_INHERITANCE).expect("Parsing failed");

        assert_eq!(connectors.upstreams.len(), 2);

        let api_upstream = connectors
            .upstreams
            .iter()
            .find(|u| match &u.upstream {
                UpstreamConfig::Service(s) => s.prefix_path == "/api",
                _ => false,
            })
            .expect("API upstream not found");

        assert_eq!(api_upstream.lb_options.selection, SelectionKind::Random);

        let static_upstream = connectors
            .upstreams
            .iter()
            .find(|u| match &u.upstream {
                UpstreamConfig::Service(s) => s.prefix_path == "/static",
                _ => false,
            })
            .expect("Static upstream not found");

        assert_eq!(
            static_upstream.lb_options.selection,
            SelectionKind::RoundRobin
        );
    }

    const LOAD_BALANCE_DUPLICATE: &str = r#"
        connectors {
            load-balance {
                selection "RoundRobin"
            }
            load-balance {
                selection "Random"
            }
            proxy "http://127.0.0.1:8080"
        }
    "#;

    #[test]
    fn test_error_duplicate_load_balance() {
        let result = parse_config(LOAD_BALANCE_DUPLICATE);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().help().unwrap().to_string();
        assert!(err_msg.contains("Duplicate 'load-balance' directive"));
    }

    const MULTI_SERVER_PROXY_CONFIG: &str = r#"
        connectors {
            proxy { 
                tls-sni "onevariable.com" 
                proto "h2-or-h1"
                server "91.107.223.4:443" 
                server "91.107.223.5:443" 
                server "91.107.223.6:443"
            }
        }
    "#;

    #[test]
    fn test_multi_server_proxy_parsing() {
        let connectors = parse_config(MULTI_SERVER_PROXY_CONFIG).expect("Parsing failed");

        assert_eq!(
            connectors.upstreams.len(),
            1,
            "Should have one UpstreamConfig"
        );

        let upstream_config = &connectors.upstreams[0];

        let UpstreamConfig::MultiServer(upstream) = &upstream_config.upstream else {
            panic!(
                "Expected MultiServer upstream, got {:?}",
                upstream_config.upstream
            );
        };

        assert_eq!(
            upstream.servers.len(),
            3,
            "Should parse 3 server directives"
        );
        assert_eq!(
            upstream.tls_sni.as_deref(),
            Some("onevariable.com"),
            "Should parse tls-sni"
        );
        assert_eq!(upstream.alpn, ALPN::H2H1, "Should parse proto h2-or-h1");
        assert_eq!(upstream.prefix_path, "/", "Should have default prefix path");
        assert_eq!(
            upstream.matcher,
            RouteMatcher::Exact,
            "Should have default matcher"
        );

        assert_eq!(
            upstream.servers[0].address,
            "91.107.223.4:443".parse().unwrap()
        );
        assert_eq!(
            upstream.servers[2].address,
            "91.107.223.6:443".parse().unwrap()
        );
    }

    const SINGLE_SERVER_BLOCK_PROXY_CONFIG: &str = r#"
        connectors {
            proxy {
                server "127.0.0.1:8080"
            }
        }
    "#;

    #[test]
    fn test_single_server_block_proxy_parsing() {
        let connectors = parse_config(SINGLE_SERVER_BLOCK_PROXY_CONFIG).expect("Parsing failed");

        let UpstreamConfig::MultiServer(upstream) = &connectors.upstreams[0].upstream else {
            panic!("Expected MultiServer upstream (even for a single server in block)");
        };

        assert_eq!(upstream.servers.len(), 1, "Should parse 1 server directive");
        assert!(
            upstream.tls_sni.is_none(),
            "tls-sni should be None by default"
        );
        assert_eq!(
            upstream.alpn,
            ALPN::H1,
            "ALPN should be H1 by default (no sni/proto)"
        );
        assert_eq!(
            upstream.servers[0].address,
            "127.0.0.1:8080".parse().unwrap()
        );
    }

    const ERROR_DUPLICATE_PROTO: &str = r#"
        connectors {
            proxy {
                proto "h2-or-h1"
                proto "h1-only"
                server "127.0.0.1:8080"
            }
        }
    "#;

    #[test]
    fn test_error_on_duplicate_options() {
        let result = parse_config(ERROR_DUPLICATE_PROTO);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().help().unwrap().to_string();
        crate::assert_err_contains!(err_msg, "Duplicate 'proto' directive in proxy block");
    }

    const ERROR_NO_SERVERS: &str = r#"
        connectors {
            proxy {
                tls-sni "a.com"
            }
        }
    "#;

    #[test]
    fn test_error_on_no_servers() {
        let result = parse_config(ERROR_NO_SERVERS);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().help().unwrap().to_string();
        crate::assert_err_contains!(
            err_msg,
            "Proxy block must contain at least one 'server' directive"
        );
    }

    const ERROR_BLOCK_WITH_ARG: &str = r#"
        connectors {
            proxy "http://invalid.com" {
                server "127.0.0.1:8080"
            }
        }
    "#;

    #[test]
    fn test_error_block_with_top_arg() {
        let result = parse_config(ERROR_BLOCK_WITH_ARG);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().help().unwrap().to_string();
        crate::assert_err_contains!(err_msg, "The block-style 'proxy' cannot have arguments");
    }

    const INVALID_STRICT_NESTING: &str = r#"
    connectors {
        section "/api" as="exact" {
            // This should fail because parent is exact
            section "/v1" {
                return code="200" response="fail"
            }
        }
    }
    "#;

    #[test]
    fn test_strict_section_cannot_have_children() {
        let result = parse_config(INVALID_STRICT_NESTING);

        let err_msg = result.err().unwrap().help().unwrap().to_string();

        crate::assert_err_contains!(
            err_msg,
            "A section with 'exact' routing mode cannot contain nested sections"
        );
    }

    const VALID_STRICT_CONFIG: &str = r#"
    connectors {
        section "/api" as="exact" {
            // Non-section children are allowed
            return code="200" response="OK"
        }
    }
    "#;

    #[test]
    fn test_strict_section_allowed_directives() {
        let result = parse_config(VALID_STRICT_CONFIG);
        assert!(result.is_ok());
    }

    const ARGS_PARSING_TEST: &str = r#"
    definitions {
        modifiers {
            chain-filters "defined_with_args" {
                filter name="set-header" key="X-Region" value="EU"
                filter name="log-request"
            }
        }
    }

    connectors {
        use-chain {
            filter name="rate-limit" rps="100" burst="20"
        }
        use-chain "defined_with_args"
        proxy "http://127.0.0.1:8080"
    }
    "#;

    #[test]
    fn test_filter_args_parsing() {
        let connectors = parse_config(ARGS_PARSING_TEST).expect("Parsing failed");
        let upstream = &connectors.upstreams[0];

        assert_eq!(upstream.chains.len(), 2);

        match &upstream.chains[0] {
            Modificator::Chain(named_chain) => {
                assert!(named_chain.name.contains("__anon_"), "Should be anonymous");
                let filter = &named_chain.chain.filters[0];

                assert_eq!(filter.name, "rate-limit");
                assert_eq!(filter.args.len(), 2);
                assert_eq!(filter.args.get("rps").map(|s| s.as_str()), Some("100"));
                assert_eq!(filter.args.get("burst").map(|s| s.as_str()), Some("20"));
            }
        }

        match &upstream.chains[1] {
            Modificator::Chain(named_chain) => {
                assert_eq!(named_chain.name, "defined_with_args");
                assert_eq!(named_chain.chain.filters.len(), 2);

                let filter1 = &named_chain.chain.filters[0];
                assert_eq!(filter1.name, "set-header");
                assert_eq!(filter1.args.len(), 2);
                assert_eq!(
                    filter1.args.get("key").map(|s| s.as_str()),
                    Some("X-Region")
                );
                assert_eq!(filter1.args.get("value").map(|s| s.as_str()), Some("EU"));

                let filter2 = &named_chain.chain.filters[1];
                assert_eq!(filter2.name, "log-request");
                assert!(filter2.args.is_empty(), "Args should be empty");
            }
        }
    }

    const ANONYMOUS_CHAIN_TEST: &str = r#"
    connectors {
        section "/anon" {
            use-chain {
                filter name="logger" level="debug"
            }
            proxy "http://127.0.0.1:8080"
        }
    }
    "#;

    #[test]
    fn test_anonymous_chain() {
        let connectors = parse_config(ANONYMOUS_CHAIN_TEST).expect("Parsing failed");
        let upstream = &connectors.upstreams[0];

        match &upstream.chains[0] {
            Modificator::Chain(named_chain) => {
                assert_eq!(named_chain.chain.filters.len(), 1);
                let filter = &named_chain.chain.filters[0];

                assert_eq!(filter.name, "logger");

                let level_arg = filter.args.get("level").expect("Argument 'level' missing");
                assert_eq!(level_arg, "debug");

                assert_eq!(filter.args.len(), 1);
            }
        }
    }

    const SIMPLE_CHAIN: &str = r#"
    definitions {
        modifiers {
            chain-filters "security" {
                filter name="block-ip"
                filter name="auth-check"
            }
        }
    }

    connectors {
        use-chain "security"
        proxy "http://127.0.0.1:8080"
    }
    "#;

    #[test]
    fn test_use_chain_simple() {
        let connectors = parse_config(SIMPLE_CHAIN).expect("Parsing failed");
        let upstream = &connectors.upstreams[0];

        assert_eq!(upstream.chains.len(), 1, "Should have 1 rule (the chain)");

        match &upstream.chains[0] {
            Modificator::Chain(named_chain) => {
                assert_eq!(named_chain.chain.filters.len(), 2);
                assert_eq!(named_chain.chain.filters[0].name, "block-ip");
                assert_eq!(named_chain.chain.filters[1].name, "auth-check");
            }
        }
    }

    const NESTED_INHERITANCE: &str = r#"
    definitions {
        modifiers {
            chain-filters "global-log" {
                filter name="logger"
            }
            chain-filters "api-protection" {
                filter name="rate-limit"
            }
        }
    }

    connectors {
        use-chain "global-log"

        section "/api" {
            use-chain "api-protection"
            proxy "http://127.0.0.1:8081"
        }

        section "/public" {
            proxy "http://127.0.0.1:8082"
        }
    }
    "#;

    #[test]
    fn test_use_chain_inheritance() {
        let connectors = parse_config(NESTED_INHERITANCE).expect("Parsing failed");

        let api_upstream = connectors.upstreams.iter()
            .find(|u|
                match &u.upstream {
                    UpstreamConfig::Service(s) => &s.prefix_path,
                    _ => panic!("not for this test")
                } == "/api")
            .expect("API upstream not found");

        assert_eq!(api_upstream.chains.len(), 2);

        let Modificator::Chain(r1) = &api_upstream.chains[0];

        assert_eq!(r1.chain.filters[0].name, "logger");

        let Modificator::Chain(r2) = &api_upstream.chains[1];
        assert_eq!(r2.chain.filters[0].name, "rate-limit");

        let public_upstream = connectors.upstreams.iter()
            .find(|u| match &u.upstream {
                    UpstreamConfig::Service(s) => &s.prefix_path,
                    _ => panic!("not for this test")
                } == "/public")
            .expect("Public upstream not found");

        assert_eq!(public_upstream.chains.len(), 1);

        let Modificator::Chain(r1) = &public_upstream.chains[0];
        assert_eq!(r1.chain.filters[0].name, "logger");
    }

    const MULTIPLE_CHAINS_IN_SCOPE: &str = r#"
    definitions {
        modifiers {
            chain-filters "a" { filter name="A" }
            chain-filters "b" { filter name="B" }
        }
    }

    connectors {
        section "/combo" {
            use-chain "a"
            use-chain "b"
            proxy "http://127.0.0.1:9000"
        }
    }
    "#;

    #[test]
    fn test_multiple_chains_same_level() {
        let connectors = parse_config(MULTIPLE_CHAINS_IN_SCOPE).expect("Parsing failed");
        let upstream = &connectors.upstreams[0];

        assert_eq!(upstream.chains.len(), 2);

        let Modificator::Chain(r) = &upstream.chains[0];
        assert_eq!(r.chain.filters[0].name, "A");
        let Modificator::Chain(r) = &upstream.chains[1];
        assert_eq!(r.chain.filters[0].name, "B");
    }

    const MISSING_CHAIN: &str = r#"
    definitions {
        modifiers {
            chain-filters "exists" { filter name="ok" }
        }
    }

    connectors {
        use-chain "GHOST"
        proxy "http://127.0.0.1:8080"
    }
    "#;

    #[test]
    fn test_missing_chain_error() {
        let result = parse_config(MISSING_CHAIN);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().help().unwrap().to_string();

        assert!(err_msg.contains("Chain 'GHOST' not found in definitions"));
    }

    const CONNECTORS_NESTED_SECTIONS: &str = r#"
        connectors {
            proxy "http://0.0.0.0:8000"
            section "/first" as="prefix" {
                proxy "http://0.0.0.0:8000"
                section "/second" {
                    proxy "http://0.0.0.0:8001/something"
                }
            }
        }
    "#;

    #[test]
    fn connectors_with_nested_sections() {
        let doc: KdlDocument = CONNECTORS_NESTED_SECTIONS.parse().unwrap();
        let table = DefinitionsTable::default();
        let section = ConnectorsSection::new(&doc, &table);
        let mut anon = DefinitionsTable::default();

        let nodes = section.parse_connections_node(&doc, &mut anon).unwrap();
        let ConnectorsLeaf::Upstream(UpstreamConfig::Service(first)) = &nodes[0] else {
            unreachable!()
        };
        let ConnectorsLeaf::Section(second_section) = &nodes[1] else {
            unreachable!()
        };
        let ConnectorsLeaf::Section(third_section) = &second_section[1] else {
            unreachable!()
        };

        assert_eq!(first.prefix_path, "/");
        assert_eq!(first.target_path, "/");

        let ConnectorsLeaf::Upstream(UpstreamConfig::Service(second)) =
            second_section.first().unwrap()
        else {
            unreachable!()
        };
        assert_eq!(second.prefix_path, "/first");
        assert_eq!(second.target_path, "/");

        let ConnectorsLeaf::Upstream(UpstreamConfig::Service(third)) =
            third_section.first().unwrap()
        else {
            unreachable!()
        };
        assert_eq!(third.prefix_path, "/first/second");
        assert_eq!(third.target_path, "/something");
    }

    const CONNECTORS_SECTION_WITH_PATH: &str = r#"
        connectors {
            section "/old-path" {
                proxy "http://0.0.0.0:8000/new-path"
            }
        }
    "#;

    #[test]
    fn service_section_with_path() {
        let doc: KdlDocument = CONNECTORS_SECTION_WITH_PATH.parse().unwrap();
        let table = DefinitionsTable::default();
        let section = ConnectorsSection::new(&doc, &table);

        let mut anon = DefinitionsTable::default();
        let ConnectorsLeaf::Section(simple) =
            &section.parse_connections_node(&doc, &mut anon).unwrap()[0]
        else {
            unreachable!()
        };

        let ConnectorsLeaf::Upstream(UpstreamConfig::Service(s)) = &simple[0] else {
            unreachable!()
        };

        assert_eq!(s.prefix_path, "/old-path");
        assert_eq!(s.target_path, "/new-path");
    }

    const CONNECTORS_SECTION: &str = r#"
        connectors {
            section "/" {
                proxy "http://0.0.0.0:8000"
            }
        }
    "#;

    #[test]
    fn service_section() {
        let doc: KdlDocument = CONNECTORS_SECTION.parse().unwrap();
        let table = DefinitionsTable::default();
        let section = ConnectorsSection::new(&doc, &table);

        let mut anon = DefinitionsTable::default();
        let ConnectorsLeaf::Section(simple) =
            &section.parse_connections_node(&doc, &mut anon).unwrap()[0]
        else {
            unreachable!()
        };

        let ConnectorsLeaf::Upstream(UpstreamConfig::Service(s)) = &simple[0] else {
            unreachable!()
        };

        assert_eq!(
            s.peer._address,
            SocketAddr::Inet(std::net::SocketAddr::V4("0.0.0.0:8000".parse().unwrap()))
        );
    }

    const CONNECTORS_PROXY: &str = r#"
        connectors {
            proxy "http://0.0.0.0:8000"
        }
    "#;

    #[test]
    fn service_proxy() {
        let doc: KdlDocument = CONNECTORS_PROXY.parse().unwrap();
        let table = DefinitionsTable::default();
        let section = ConnectorsSection::new(&doc, &table);

        let mut anon = DefinitionsTable::default();
        let simple = &section.parse_connections_node(&doc, &mut anon).unwrap()[0];

        if let ConnectorsLeaf::Upstream(UpstreamConfig::Service(s)) = simple {
            assert_eq!(
                s.peer._address,
                SocketAddr::Inet(std::net::SocketAddr::V4("0.0.0.0:8000".parse().unwrap()))
            )
        } else {
            panic!("Expected Service variant, got");
        }
    }

    const CONNECTORS_RETURN_SIMPLE_RESPONSE: &str = r#"
        connectors {
            return code="200" response="OK"
        }
    "#;

    #[test]
    fn service_return_simple_response() {
        let doc: KdlDocument = CONNECTORS_RETURN_SIMPLE_RESPONSE.parse().unwrap();
        let table = DefinitionsTable::default();
        let section = ConnectorsSection::new(&doc, &table);

        let mut anon = DefinitionsTable::default();
        let simple = &section.parse_connections_node(&doc, &mut anon).unwrap()[0];

        if let ConnectorsLeaf::Upstream(UpstreamConfig::Static(response)) = simple {
            assert_eq!(response.http_code, http::StatusCode::OK);
            assert_eq!(response.response_body, "OK");
        } else {
            panic!("Expected Static variant, got");
        }
    }
}
