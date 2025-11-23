use std::{
    collections::{BTreeMap, HashMap, HashSet}, net::SocketAddr, num::NonZeroUsize, path::PathBuf
};

use crate::{
    config::{internal::{
        Config, DiscoveryKind, FileServerConfig, HealthCheckKind, ListenerConfig, ListenerKind,
        PathControl, ProxyConfig, SelectionKind, TlsConfig, UpstreamOptions,
    }, kdl::parser::ConfigParser},
    proxy::{
        rate_limiting::{
            AllRateConfig, RegexShim, multi::{MultiRaterConfig, MultiRequestKeyKind}, single::{SingleInstanceConfig, SingleRequestKeyKind}
        },
        request_selector::{
            RequestSelector, null_selector, source_addr_and_uri_path_selector, uri_path_selector
        },
    },
};
use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use miette::{bail, Diagnostic, SourceSpan};
use pingora::{protocols::ALPN, upstreams::peer::HttpPeer};

use super::internal::RateLimitingConfig;

mod utils;
mod parser;

/// This is the primary interface for parsing the document.
impl TryFrom<&KdlDocument> for Config {
    type Error = miette::Error;

    fn try_from(value: &KdlDocument) -> Result<Self, Self::Error> {
        let SystemData {
            threads_per_service,
            daemonize,
            upgrade_socket,
            pid_file,
        } = extract_system_data(value)?;
        let (basic_proxies, file_servers) = extract_services(threads_per_service, value)?;

        Ok(Config {
            threads_per_service,
            daemonize,
            upgrade_socket,
            pid_file,
            basic_proxies,
            file_servers,
            ..Config::default()
        })
    }
}

struct SystemData {
    threads_per_service: usize,
    daemonize: bool,
    upgrade_socket: Option<PathBuf>,
    pid_file: Option<PathBuf>,
}

impl Default for SystemData {
    fn default() -> Self {
        Self {
            threads_per_service: 8,
            daemonize: false,
            upgrade_socket: None,
            pid_file: None,
        }
    }
}

/// Extract all services from the top level document
fn extract_services(
    threads_per_service: usize,
    doc: &KdlDocument,
) -> miette::Result<(Vec<ProxyConfig>, Vec<FileServerConfig>)> {
    let service_node = utils::required_child_doc(doc, doc, "services")?;
    let services = utils::wildcard_argless_child_docs(doc, service_node)?;

    let proxy_node_set =
        HashSet::from(["listeners", "connectors", "path-control", "rate-limiting"]);
    let file_server_node_set = HashSet::from(["listeners", "file-server"]);

    let mut proxies = vec![];
    let mut file_servers = vec![];

    for (name, service) in services {
        // First, visit all of the children nodes, and make sure each child
        // node only appears once. This is used to detect duplicate sections
        let mut fingerprint_set: HashSet<&str> = HashSet::new();
        for ch in service.nodes() {
            let name = ch.name().value();
            let dupe = !fingerprint_set.insert(name);
            if dupe {
                return Err(Bad::docspan(format!("Duplicate section: '{name}'!"), doc, &ch.span()).into());
            }
        }

        // Now: what do we do with this node?
        if fingerprint_set.is_subset(&proxy_node_set) {
            // If the contained nodes are a strict subset of proxy node config fields,
            // then treat this section as a proxy node
            proxies.push(extract_service(threads_per_service, doc, name, service)?);
        } else if fingerprint_set.is_subset(&file_server_node_set) {
            // If the contained nodes are a strict subset of the file server config
            // fields, then treat this section as a file server node
            file_servers.push(extract_file_server(doc, name, service)?);
        } else {
            // Otherwise, we're not sure what this node is supposed to be!
            //
            // Obtain the superset of ALL potential nodes, which is essentially
            // our configuration grammar.
            let superset: HashSet<&str> = proxy_node_set
                .union(&file_server_node_set)
                .cloned()
                .collect();

            // Then figure out what fields our fingerprint set contains that
            // is "novel", or basically fields we don't know about
            let what = fingerprint_set
                .difference(&superset)
                .copied()
                .collect::<Vec<&str>>()
                .join(", ");

            // Then inform the user about the reason for our discontent
            return Err(Bad::docspan(
                format!("Unknown configuration section(s): '{what}'"),
                doc,
                &service.span(),
            )
            .into());
        }
    }

    if proxies.is_empty() && file_servers.is_empty() {
        return Err(Bad::docspan("No services defined", doc, &service_node.span()).into());
    }

    Ok((proxies, file_servers))
}

/// Collects all the filters, where the node name must be "filter", and the rest of the args
/// are collected as a BTreeMap of String:String values
///
/// ```kdl
/// upstream-request {
///     filter kind="remove-header-key-regex" pattern=".*SECRET.*"
///     filter kind="remove-header-key-regex" pattern=".*secret.*"
///     filter kind="upsert-header" key="x-proxy-friend" value="river"
/// }
/// ```
///
/// creates something like:
///
/// ```json
/// [
///     { kind: "remove-header-key-regex", pattern: ".*SECRET.*" },
///     { kind: "remove-header-key-regex", pattern: ".*secret.*" },
///     { kind: "upsert-header", key: "x-proxy-friend", value: "river" }
/// ]
/// ```
fn collect_filters(
    doc: &KdlDocument,
    node: &KdlDocument,
) -> miette::Result<Vec<BTreeMap<String, String>>> {
    let filters = utils::data_nodes(doc, node)?;
    let mut fout = vec![];
    for (_node, name, args) in filters {
        if name != "filter" {
            bail!("Invalid Filter Rule");
        }
        let args = utils::str_str_args(doc, args)?;
        fout.push(
            args.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
    }
    Ok(fout)
}

/// Extracts a single file server from the `services` block
fn extract_file_server(
    doc: &KdlDocument,
    name: &str,
    node: &KdlDocument,
) -> miette::Result<FileServerConfig> {
    // Listeners
    //
    let listener_node = utils::required_child_doc(doc, node, "listeners")?;
    let listeners = utils::data_nodes(doc, listener_node)?;
    if listeners.is_empty() {
        return Err(Bad::docspan("nonzero listeners required", doc, &listener_node.span()).into());
    }
    let mut list_cfgs = vec![];
    for (node, name, args) in listeners {
        let listener = extract_listener(doc, node, name, args)?;
        list_cfgs.push(listener);
    }

    // Base Path
    //
    let fs_node = utils::required_child_doc(doc, node, "file-server")?;
    let data_nodes = utils::data_nodes(doc, fs_node)?;
    let mut map = HashMap::new();
    for (node, name, args) in data_nodes {
        map.insert(name, (node, args));
    }

    let base_path = if let Some((bpnode, bpargs)) = map.get("base-path") {
        let val =
            utils::extract_one_str_arg(doc, bpnode, "base-path", bpargs, |a| Some(a.to_string()))?;
        Some(val.into())
    } else {
        None
    };

    Ok(FileServerConfig {
        name: name.to_string(),
        listeners: list_cfgs,
        base_path,
    })
}

/// Extracts a single service from the `services` block
fn extract_service(
    threads_per_service: usize,
    doc: &KdlDocument,
    name: &str,
    node: &KdlDocument,
) -> miette::Result<ProxyConfig> {
    // Listeners
    //
    let listener_node = utils::required_child_doc(doc, node, "listeners")?;
    let listeners = utils::data_nodes(doc, listener_node)?;
    if listeners.is_empty() {
        return Err(Bad::docspan("nonzero listeners required", doc, &listener_node.span()).into());
    }
    let mut list_cfgs = vec![];
    for (node, name, args) in listeners {
        let listener = extract_listener(doc, node, name, args)?;
        list_cfgs.push(listener);
    }

    // Connectors
    //
    let (conn_cfgs, load_balance) = ConfigParser::process_connectors_node(doc, node)?;

    // Path Control (optional)
    let pc = extract_path_control(doc, node)?;

    // Rate limiting
    let mut rl = RateLimitingConfig::default();
    if let Some(rl_node) = utils::optional_child_doc(doc, node, "rate-limiting") {
        let nodes = utils::data_nodes(doc, rl_node)?;
        for (node, name, args) in nodes.iter() {
            if *name == "rule" {
                let vals = utils::str_value_args(doc, args)?;
                let valslice = vals
                    .iter()
                    .map(|(k, v)| (*k, v.value()))
                    .collect::<BTreeMap<&str, &KdlValue>>();
                rl.rules
                    .push(make_rate_limiter(threads_per_service, doc, node, valslice)?);
            } else {
                return Err(
                    Bad::docspan(format!("Unknown name: '{name}'"), doc, &node.span()).into(),
                );
            }
        }
    }

    Ok(ProxyConfig {
        name: name.to_string(),
        listeners: list_cfgs,
        upstreams: conn_cfgs,
        path_control: pc,
        upstream_options: load_balance.unwrap_or_default(),
        rate_limiting: rl,
    })
}

fn extract_path_control(doc: &KdlDocument, node: &KdlDocument) -> Result<PathControl, miette::Error> {

    let mut pc = PathControl::default();
    if let Some(pc_node) = utils::optional_child_doc(doc, node, "path-control") {
        // request-filters (optional)
        if let Some(ureq_node) = utils::optional_child_doc(doc, pc_node, "request-filters") {
            pc.request_filters = collect_filters(doc, ureq_node)?;
        }

        // upstream-request (optional)
        if let Some(ureq_node) = utils::optional_child_doc(doc, pc_node, "upstream-request") {
            pc.upstream_request_filters = collect_filters(doc, ureq_node)?;
        }

        // upstream-response (optional)
        if let Some(uresp_node) = utils::optional_child_doc(doc, pc_node, "upstream-response") {
            pc.upstream_response_filters = collect_filters(doc, uresp_node)?
        }
    }
    Ok(pc)
}

fn make_rate_limiter(
    threads_per_service: usize,
    doc: &KdlDocument,
    node: &KdlNode,
    args: BTreeMap<&str, &KdlValue>,
) -> miette::Result<AllRateConfig> {
    let take_num = |key: &str| -> miette::Result<usize> {
        let Some(val) = args.get(key) else {
            return Err(Bad::docspan(format!("Missing key: '{key}'"), doc, &node.span()).into());
        };
        let Some(val) = val.as_integer().and_then(|v| usize::try_from(v).ok()) else {
            return Err(Bad::docspan(
                format!(
                    "'{key} should have a positive integer value, got '{:?}' instead",
                    val
                ),
                doc,
                &node.span(),
            )
            .into());
        };
        Ok(val)
    };
    let take_str = |key: &str| -> miette::Result<&str> {
        let Some(val) = args.get(key) else {
            return Err(Bad::docspan(format!("Missing key: '{key}'"), doc, &node.span()).into());
        };
        let Some(val) = val.as_string() else {
            return Err(Bad::docspan(
                format!("'{key} should have a string value, got '{:?}' instead", val),
                doc,
                &node.span(),
            )
            .into());
        };
        Ok(val)
    };

    // mandatory/common fields
    let kind = take_str("kind")?;
    let tokens_per_bucket = NonZeroUsize::new(take_num("tokens-per-bucket")?)
        .ok_or_else(|| {
            Bad::docspan(
                "'tokens-per-bucket' must be a positive",
                doc,
                &node.span(),
            )
        })?;

    let refill_qty = NonZeroUsize::new(take_num("refill-qty")?)
        .ok_or_else(|| {
            Bad::docspan(
                "'refill-qty' must be a positive",
                doc,
                &node.span(),
            )
        })?;

    let refill_rate_ms = NonZeroUsize::new(take_num("refill-rate-ms")?)
        .ok_or_else(|| {
            Bad::docspan(
                "'refill-rate-ms' must be a positive",
                doc,
                &node.span(),
            )
        })?;

    let multi_cfg = || -> miette::Result<MultiRaterConfig> {
        let max_buckets = take_num("max-buckets")?;
        Ok(MultiRaterConfig {
            threads: threads_per_service,
            max_buckets,
            max_tokens_per_bucket: tokens_per_bucket,
            refill_interval_millis: refill_rate_ms,
            refill_qty,
        })
    };

    let single_cfg = || SingleInstanceConfig {
        max_tokens_per_bucket: tokens_per_bucket,
        refill_interval_millis: refill_rate_ms,
        refill_qty,
    };

    let regex_pattern = || -> miette::Result<RegexShim> {
        let pattern = take_str("pattern")?;
        let Ok(pattern) = RegexShim::new(pattern) else {
            return Err(Bad::docspan(
                format!("'{pattern} should be a valid regular expression"),
                doc,
                &node.span(),
            )
            .into());
        };
        Ok(pattern)
    };

    match kind {
        "source-ip" => Ok(AllRateConfig::Multi {
            kind: MultiRequestKeyKind::SourceIp,
            config: multi_cfg()?,
        }),
        "specific-uri" => Ok(AllRateConfig::Multi {
            kind: MultiRequestKeyKind::Uri {
                pattern: regex_pattern()?,
            },
            config: multi_cfg()?,
        }),
        "any-matching-uri" => Ok(AllRateConfig::Single {
            kind: SingleRequestKeyKind::UriGroup {
                pattern: regex_pattern()?,
            },
            config: single_cfg(),
        }),
        other => Err(Bad::docspan(
            format!("'{other} is not a known kind of rate limiting"),
            doc,
            &node.span(),
        )
        .into()),
    }
}

/// Extracts the `load-balance` structure from the `connectors` section
fn extract_load_balance(doc: &KdlDocument, node: &KdlNode) -> miette::Result<UpstreamOptions> {
    let items = utils::data_nodes(
        doc,
        node.children()
            .or_bail("'load-balance' should have children", doc, &node.span())?,
    )?;

    let mut selection: Option<SelectionKind> = None;
    let mut health: Option<HealthCheckKind> = None;
    let mut discover: Option<DiscoveryKind> = None;
    let mut selector: RequestSelector = null_selector;

    for (node, name, args) in items {
        match name {
            "selection" => {
                let (sel, args) = utils::extract_one_str_arg_with_kv_args(
                    doc,
                    node,
                    name,
                    args,
                    |val| match val {
                        "RoundRobin" => Some(SelectionKind::RoundRobin),
                        "Random" => Some(SelectionKind::Random),
                        "FNV" => Some(SelectionKind::Fnv),
                        "Ketama" => Some(SelectionKind::Ketama),
                        _ => None,
                    },
                )?;
                match sel {
                    SelectionKind::RoundRobin | SelectionKind::Random => {
                        // No key required, selection is random
                    }
                    SelectionKind::Fnv | SelectionKind::Ketama => {
                        let sel_ty = args.get("key").or_bail(
                            format!("selection {sel:?} requires a 'key' argument"),
                            doc,
                            &node.span(),
                        )?;

                        selector = match sel_ty.as_str() {
                            "UriPath" => uri_path_selector,
                            "SourceAddrAndUriPath" => source_addr_and_uri_path_selector,
                            other => {
                                return Err(Bad::docspan(
                                    format!("Unknown key: '{other}'"),
                                    doc,
                                    &node.span(),
                                )
                                .into())
                            }
                        };
                    }
                }

                selection = Some(sel);
            }
            "health-check" => {
                health = Some(utils::extract_one_str_arg(
                    doc,
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
                    doc,
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
                return Err(
                    Bad::docspan(format!("Unknown setting: '{other}'"), doc, &node.span()).into(),
                );
            }
        }
    }
    Ok(UpstreamOptions {
        selection: selection.unwrap_or(SelectionKind::RoundRobin),
        selector,
        health_checks: health.unwrap_or(HealthCheckKind::None),
        discovery: discover.unwrap_or(DiscoveryKind::Static),
    })
}

/// Extracts a single connector from the `connectors` section
fn extract_connector(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<HttpPeer> {
    let Ok(sadd) = name.parse::<SocketAddr>() else {
        return Err(Bad::docspan("Not a valid socket address", doc, &node.span()).into());
    };

    // TODO: consistent enforcement of only-known args?
    let args = utils::str_str_args(doc, args)?
        .into_iter()
        .collect::<HashMap<&str, &str>>();

    let proto = match args.get("proto").copied() {
        None => None,
        Some("h1-only") => Some(ALPN::H1),
        Some("h2-only") => Some(ALPN::H2),
        Some("h1-or-h2") => {
            tracing::warn!("accepting 'h1-or-h2' as meaning 'h2-or-h1'");
            Some(ALPN::H2H1)
        }
        Some("h2-or-h1") => Some(ALPN::H2H1),
        Some(other) => {
            return Err(Bad::docspan(
                format!(
                    "'proto' should be one of 'h1-only', 'h2-only', or 'h2-or-h1', found '{other}'"
                ),
                doc,
                &node.span(),
            )
            .into());
        }
    };
    let tls_sni = args.get("tls-sni");

    let (tls, sni, alpn) = match (proto, tls_sni) {
        (None, None) | (Some(ALPN::H1), None) => (false, String::new(), ALPN::H1),
        (None, Some(sni)) => (true, sni.to_string(), ALPN::H2H1),
        (Some(_), None) => {
            return Err(
                Bad::docspan("'tls-sni' is required for HTTP2 support", doc, &node.span()).into(),
            );
        }
        (Some(p), Some(sni)) => (true, sni.to_string(), p),
    };

    let mut peer = HttpPeer::new(sadd, tls, sni);
    peer.options.alpn = alpn;

    Ok(peer)
}

// services { Service { listeners { ... } } }
fn extract_listener(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<ListenerConfig> {
    let args = utils::str_value_args(doc, args)?
        .into_iter()
        .collect::<HashMap<&str, &KdlEntry>>();
    
    // Is this a bindable name?
    if name.parse::<SocketAddr>().is_ok() {
        // Cool: do we have reasonable args for this?
        let cert_path = utils::map_ensure_str(doc, args.get("cert-path").copied())?;
        let key_path = utils::map_ensure_str(doc, args.get("key-path").copied())?;
        let offer_h2 = utils::map_ensure_bool(doc, args.get("offer-h2").copied())?;

        match (cert_path, key_path, offer_h2) {
            // No config? No problem!
            (None, None, None) => Ok(ListenerConfig {
                source: ListenerKind::Tcp {
                    addr: name.to_string(),
                    tls: None,
                    offer_h2: false,
                },
            }),
            // We must have both of cert-path and key-path if both are present
            // ignore "offer-h2" if this is incorrect
            (None, Some(_), _) | (Some(_), None, _) => {
                Err(Bad::docspan(
                    "'cert-path' and 'key-path' must either BOTH be present, or NEITHER should be present",
                    doc,
                    &node.span(),
                )
                .into())
            }
            // We can't offer H2 if we don't have TLS (at least for now, unless we
            // expose H2C settings in pingora)
            (None, None, Some(_)) => {
                Err(Bad::docspan(
                    "'offer-h2' requires TLS, specify 'cert-path' and 'key-path'",
                    doc,
                    &node.span(),
                )
                .into())
            }
            (Some(cpath), Some(kpath), offer_h2) => Ok(ListenerConfig {
                source: ListenerKind::Tcp {
                    addr: name.to_string(),
                    tls: Some(TlsConfig {
                        cert_path: cpath.into(),
                        key_path: kpath.into(),
                    }),
                    // Default to enabling H2 if unspecified
                    offer_h2: offer_h2.unwrap_or(true),
                },
            }),
        }
    } else if let Ok(pb) = name.parse::<PathBuf>() {
        // TODO: Should we check that this path exists? Otherwise it seems to always match
        Ok(ListenerConfig {
            source: ListenerKind::Uds(pb),
        })
    } else {
        Err(Bad::docspan("'{name}' is not a socketaddr or path?", doc, &node.span()).into())
    }
}

// system { threads-per-service N }
fn extract_system_data(doc: &KdlDocument) -> miette::Result<SystemData> {
    // Get the top level system doc
    let Some(sys) = utils::optional_child_doc(doc, doc, "system") else {
        return Ok(SystemData::default());
    };
    let tps = extract_threads_per_service(doc, sys)?;

    let daemonize = if let Some(n) = sys.get("daemonize") {
        utils::extract_one_bool_arg(doc, n, "daemonize", n.entries())?
    } else {
        false
    };

    let upgrade_socket = if let Some(n) = sys.get("upgrade-socket") {
        let x = utils::extract_one_str_arg(doc, n, "upgrade-socket", n.entries(), |s| {
            Some(PathBuf::from(s))
        })?;
        Some(x)
    } else {
        None
    };

    let pid_file = if let Some(n) = sys.get("pid-file") {
        let x = utils::extract_one_str_arg(doc, n, "pid-file", n.entries(), |s| {
            Some(PathBuf::from(s))
        })?;
        Some(x)
    } else {
        None
    };

    Ok(SystemData {
        threads_per_service: tps,
        daemonize,
        upgrade_socket,
        pid_file,
    })
}

fn extract_threads_per_service(doc: &KdlDocument, sys: &KdlDocument) -> miette::Result<usize> {
    let Some(tps) = sys.get("threads-per-service") else {
        return Ok(8);
    };

    let [tps_node] = tps.entries() else {
        return Err(Bad::docspan(
            "system > threads-per-service should have exactly one entry",
            doc,
            &tps.span(),
        )
        .into());
    };

    let val = tps_node.value().as_integer().or_bail(
        "system > threads-per-service should be an integer",
        doc,
        &tps_node.span(),
    )?;
    val.try_into().ok().or_bail(
        "system > threads-per-service should fit in a usize",
        doc,
        &tps_node.span(),
    )
}

#[derive(thiserror::Error, Debug, Diagnostic)]
#[error("Incorrect configuration contents")]
struct Bad {
    #[help]
    error: String,

    #[source_code]
    src: String,

    #[label("incorrect")]
    err_span: SourceSpan,
}

trait OptExtParse {
    type Good;

    fn or_bail(
        self,
        msg: impl Into<String>,
        doc: &KdlDocument,
        span: &SourceSpan,
    ) -> miette::Result<Self::Good>;
}

impl<T> OptExtParse for Option<T> {
    type Good = T;

    fn or_bail(
        self,
        msg: impl Into<String>,
        doc: &KdlDocument,
        span: &SourceSpan,
    ) -> miette::Result<Self::Good> {
        match self {
            Some(t) => Ok(t),
            None => Err(Bad::docspan(msg, doc, span).into()),
        }
    }
}

impl Bad {
    /// Helper function for creating a miette span from a given error
    fn docspan(msg: impl Into<String>, doc: &KdlDocument, span: &SourceSpan) -> Self {
        Self {
            error: msg.into(),
            src: doc.to_string(),
            err_span: span.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr, num::NonZeroUsize};
    use kdl::{KdlDocument, KdlError};
    use lazy_static::lazy_static;
    use pingora::upstreams::peer::HttpPeer;

    pub type Result<T> = miette::Result<T>;
    use crate::{
        config::internal::{
            Config, FileServerConfig, ListenerConfig, ListenerKind, ProxyConfig, Upstream, UpstreamOptions
        },
        proxy::{
            rate_limiting::{AllRateConfig, RegexShim, multi::MultiRaterConfig},
            request_selector::uri_path_selector,
        },
    };

    lazy_static! {
        static ref RESOURCE: kdl::KdlDocument = {
            let kdl_contents = std::fs::read_to_string("./assets/test-config.kdl").unwrap();

            kdl_contents.parse().unwrap_or_else(|e| {
                panic!("Error parsing KDL file: {e:?}");
            })
        };
    }

    #[test]
    fn load_test() {
        let doc = &*RESOURCE;

        let val: crate::config::internal::Config = doc.try_into().unwrap_or_else(|e| {
            panic!("Error rendering config from KDL file: {e:?}");
        });

        let expected = crate::config::internal::Config {
            validate_configs: false,
            threads_per_service: 8,
            basic_proxies: vec![
                ProxyConfig {
                    name: "Example1".into(),
                    listeners: vec![
                        ListenerConfig {
                            source: crate::config::internal::ListenerKind::Tcp {
                                addr: "0.0.0.0:8080".into(),
                                tls: None,
                                offer_h2: false,
                            },
                        },
                        ListenerConfig {
                            source: crate::config::internal::ListenerKind::Tcp {
                                addr: "0.0.0.0:4443".into(),
                                tls: Some(crate::config::internal::TlsConfig {
                                    cert_path: "./assets/test.crt".into(),
                                    key_path: "./assets/test.key".into(),
                                }),
                                offer_h2: true,
                            },
                        },
                    ],
                    upstreams: vec![Upstream::Service(HttpPeer::new(
                        "91.107.223.4:443",
                        true,
                        String::from("onevariable.com"),
                    ))],
                    path_control: crate::config::internal::PathControl {
                        upstream_request_filters: vec![
                            BTreeMap::from([
                                ("kind".to_string(), "remove-header-key-regex".to_string()),
                                ("pattern".to_string(), ".*(secret|SECRET).*".to_string()),
                            ]),
                            BTreeMap::from([
                                ("key".to_string(), "x-proxy-friend".to_string()),
                                ("kind".to_string(), "upsert-header".to_string()),
                                ("value".to_string(), "river".to_string()),
                            ]),
                        ],
                        upstream_response_filters: vec![
                            BTreeMap::from([
                                ("kind".to_string(), "remove-header-key-regex".to_string()),
                                ("pattern".to_string(), ".*ETag.*".to_string()),
                            ]),
                            BTreeMap::from([
                                ("key".to_string(), "x-with-love-from".to_string()),
                                ("kind".to_string(), "upsert-header".to_string()),
                                ("value".to_string(), "river".to_string()),
                            ]),
                        ],
                        request_filters: vec![BTreeMap::from([
                            ("kind".to_string(), "block-cidr-range".to_string()),
                            (
                                "addrs".to_string(),
                                "192.168.0.0/16, 10.0.0.0/8, 2001:0db8::0/32".to_string(),
                            ),
                        ])],
                    },
                    upstream_options: UpstreamOptions {
                        selection: crate::config::internal::SelectionKind::Ketama,
                        selector: uri_path_selector,
                        health_checks: crate::config::internal::HealthCheckKind::None,
                        discovery: crate::config::internal::DiscoveryKind::Static,
                    },
                    rate_limiting: crate::config::internal::RateLimitingConfig {
                        rules: vec![
                            AllRateConfig::Multi {
                                config: MultiRaterConfig {
                                    threads: 8,
                                    max_buckets: 4000,
                                    max_tokens_per_bucket: NonZeroUsize::new(10).unwrap(),
                                    refill_interval_millis: NonZeroUsize::new(10).unwrap(),
                                    refill_qty: NonZeroUsize::new(1).unwrap(),
                                },
                                kind: crate::proxy::rate_limiting::multi::MultiRequestKeyKind::SourceIp,
                            },
                            AllRateConfig::Multi {
                                config: MultiRaterConfig {
                                    threads: 8,
                                    max_buckets: 2000,
                                    max_tokens_per_bucket: NonZeroUsize::new(20).unwrap(),
                                    refill_interval_millis: NonZeroUsize::new(1).unwrap(),
                                    refill_qty: NonZeroUsize::new(5).unwrap(),
                                },
                                kind: crate::proxy::rate_limiting::multi::MultiRequestKeyKind::Uri {
                                    pattern: RegexShim::new("static/.*").unwrap(),
                                },
                            },
                            AllRateConfig::Single {
                                config: crate::proxy::rate_limiting::single::SingleInstanceConfig {
                                    max_tokens_per_bucket: NonZeroUsize::new(50).unwrap(),
                                    refill_interval_millis: NonZeroUsize::new(3).unwrap(),
                                    refill_qty: NonZeroUsize::new(2).unwrap(),
                                },
                                kind: crate::proxy::rate_limiting::single::SingleRequestKeyKind::UriGroup {
                                    pattern: RegexShim::new(r".*\.mp4").unwrap(),
                                },
                            },
                        ],
                    },
                },
                ProxyConfig {
                    name: "Example2".into(),
                    listeners: vec![ListenerConfig {
                        source: crate::config::internal::ListenerKind::Tcp {
                            addr: "0.0.0.0:8000".into(),
                            tls: None,
                            offer_h2: false,
                        },
                    }],
                    upstreams: vec![Upstream::Service(HttpPeer::new("91.107.223.4:80", false, String::new()))],
                    path_control: crate::config::internal::PathControl {
                        upstream_request_filters: vec![],
                        upstream_response_filters: vec![],
                        request_filters: vec![],
                    },
                    upstream_options: UpstreamOptions::default(),
                    rate_limiting: crate::config::internal::RateLimitingConfig { rules: vec![] },
                },
            ],
            file_servers: vec![FileServerConfig {
                name: "Example3".into(),
                listeners: vec![
                    ListenerConfig {
                        source: crate::config::internal::ListenerKind::Tcp {
                            addr: "0.0.0.0:9000".into(),
                            tls: None,
                            offer_h2: false,
                        },
                    },
                    ListenerConfig {
                        source: crate::config::internal::ListenerKind::Tcp {
                            addr: "0.0.0.0:9443".into(),
                            tls: Some(crate::config::internal::TlsConfig {
                                cert_path: "./assets/test.crt".into(),
                                key_path: "./assets/test.key".into(),
                            }),
                            offer_h2: true,
                        },
                    },
                ],
                base_path: Some(".".into()),
            }],
            daemonize: false,
            pid_file: Some("/tmp/river.pidfile".into()),
            upgrade_socket: Some("/tmp/river-upgrade.sock".into()),
            upgrade: false,
        };

        assert_eq!(val.validate_configs, expected.validate_configs);
        assert_eq!(val.threads_per_service, expected.threads_per_service);
        assert_eq!(val.basic_proxies.len(), expected.basic_proxies.len());
        assert_eq!(val.file_servers.len(), expected.file_servers.len());

        for (abp, ebp) in val.basic_proxies.iter().zip(expected.basic_proxies.iter()) {
            let ProxyConfig {
                name,
                listeners,
                upstream_options,
                upstreams,
                path_control,
                rate_limiting,
            } = abp;
            assert_eq!(*name, ebp.name);
            assert_eq!(*listeners, ebp.listeners);
            assert_eq!(*upstream_options, ebp.upstream_options);
            upstreams
                .iter()
                .zip(ebp.upstreams.iter())
                .for_each(|(a, e)| {
                    let a = match a {
                        Upstream::Service(s) => s,
                        _ => unreachable!()
                    };
                    let e = match e {
                        Upstream::Service(s) => s,
                        _ => unreachable!()
                    };
                    assert_eq!(a._address, e._address);
                    assert_eq!(a.scheme, e.scheme);
                    assert_eq!(a.sni, e.sni);
                });
            assert_eq!(*path_control, ebp.path_control);
            assert_eq!(*rate_limiting, ebp.rate_limiting);
        }

        for (afs, efs) in val.file_servers.iter().zip(expected.file_servers.iter()) {
            let FileServerConfig {
                name,
                listeners,
                base_path,
            } = afs;
            assert_eq!(*name, efs.name);
            assert_eq!(*listeners, efs.listeners);
            assert_eq!(*base_path, efs.base_path);
        }
    }

    fn err_parse_handler(e: KdlError) -> KdlDocument  {
        panic!("Error parsing KDL file: {e:?}");
    }

    fn err_render_config_handler(e: miette::Error) -> Config {
        panic!("Error rendering config from KDL file: {e:?}");
    }

    const SERVICE_WITH_WASM_MODULE : &str = r#"
    services {
        Example {
            listeners {
                "0.0.0.0:8080"
                "0.0.0.0:4443" cert-path="./assets/test.crt" key-path="./assets/test.key" offer-h2=#true
            }
            connectors {
                "127.0.0.1:8000"
            }
            path-control {
                request-filters {
                    filter kind="module" path="./assets/request_filter.wasm"
                }
            }
        }
    }"#;
    #[test]
    fn service_with_wasm_module() {
        let doc = &SERVICE_WITH_WASM_MODULE.parse().unwrap_or_else(err_parse_handler);
        let val: Config = doc.try_into().unwrap_or_else(err_render_config_handler);
        let request_filters = &val.basic_proxies[0].path_control.request_filters[0];

        dbg!(&request_filters);
        assert_eq!(
            val.basic_proxies[0].path_control.request_filters.len(), 1
        );

    }
    const SERVICE_WITHOUT_CONNECTOR: &str = r#"
    services {
        Example {
            listeners {
                "127.0.0.1:80"
            }
            connectors { }
        }
    }
    "#;
    #[test]
    fn service_without_connector() {
        let doc = &SERVICE_WITHOUT_CONNECTOR.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();
        let msg = val
            .unwrap_err()
            .help()
            .unwrap()
            .to_string();

        assert!(msg.contains("We require at least one connector"));
    }

    const SERVICE_DUPLICATE_LOAD_BALANCE_SECTIONS: &str = r#"
    services {
        Example {
            listeners {
                "127.0.0.1:80"
            }
            connectors {
                load-balance {
                    selection "Ketama" key="UriPath"
                    discovery "Static"
                    health-check "None"
                }
                load-balance {
                    selection "Ketama" key="UriPath"
                    discovery "Static"
                    health-check "None"
                }
                "127.0.0.1:8000"
            }
        }
    }
    "#;
    #[test]
    fn service_duplicate_load_balance_sections() {
        let doc = &SERVICE_DUPLICATE_LOAD_BALANCE_SECTIONS.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();

        let msg = val
            .unwrap_err()
            .help()
            .unwrap()
            .to_string();

        assert!(msg.contains("Duplicate 'load-balance' section"));
    }

    const SERVICE_BASE_PATH_NOT_EXIST_TEST: &str = r#"
    services {
        Example {
            listeners {
                "127.0.0.1:80"
            }
            file-server { }
        }
    }
    "#;

    #[test]
    fn service_base_path_not_exist() {
        let doc = &SERVICE_BASE_PATH_NOT_EXIST_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Config = doc.try_into().unwrap_or_else(err_render_config_handler);
        assert_eq!(val.file_servers.len(), 1);
        assert_eq!(val.file_servers[0].base_path, None);
    }

    const SERVICE_EMPTY_LISTENERS_TEST: &str = r#"
    services {
        Example {
            listeners { }
        }
    }
    "#;

    #[test]
    fn service_empty_listeners() {
        let doc = &SERVICE_EMPTY_LISTENERS_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();
        let msg = val
            .unwrap_err()
            .help()
            .unwrap()
            .to_string();

        assert!(msg.contains("nonzero listeners required"));
    }

    const SERVICE_INVALID_NODE_TEST: &str = r#"
    services {
        Example {
            invalid-node { }
        }
    }
    "#;

    #[test]
    fn service_invalid_node() {
        let doc = &SERVICE_INVALID_NODE_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();
        let msg = val
            .unwrap_err()
            .help()
            .unwrap()
            .to_string();
        
        assert!(msg.contains("Unknown configuration section(s): 'invalid-node'"));
    }

    
    const DUPLICATE_SERVICE_NODES_TEST: &str = r#"
    services {
        Example {
            listeners { }
            listeners { } 
        }
    }
    "#;

    #[test]
    fn duplicate_services() {
        let doc = &DUPLICATE_SERVICE_NODES_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();
        let msg = val
            .unwrap_err()
            .help()
            .unwrap()
            .to_string();
        
        assert!(msg.contains("Duplicate section: 'listeners'!"));
    }

    const EMPTY_TEST: &str = "
    ";

    #[test]
    fn empty() {
        let doc = &EMPTY_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();
        assert!(val.is_err());
    }

    
    const SERVICES_EMPTY_TEST: &str = "
        services {

        }
    ";

    #[test]
    fn services_empty() {
        let doc = &SERVICES_EMPTY_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Result<Config> = doc.try_into();
        assert!(val.is_err());
    }

    /// The most minimal config is single services block
    const ONE_SERVICE_TEST: &str = r#"
    services {
        Example {
            listeners {
                "127.0.0.1:80"
            }
            connectors {
                "127.0.0.1:8000"
            }
        }
    }
    "#;

    #[test]
    fn one_service() {
        let doc: &::kdl::KdlDocument = &ONE_SERVICE_TEST.parse().unwrap_or_else(err_parse_handler);
        let val: Config = doc.try_into().unwrap_or_else(err_render_config_handler);
        assert_eq!(val.basic_proxies.len(), 1);
        assert_eq!(val.basic_proxies[0].listeners.len(), 1);
        assert_eq!(
            val.basic_proxies[0].listeners[0].source,
            ListenerKind::Tcp {
                addr: "127.0.0.1:80".into(),
                tls: None,
                offer_h2: false,
            }
        );
        let upstream = &val.basic_proxies[0].upstreams[0];
        let upstream  = match upstream {
            Upstream::Service(s) => s,
            _ => unreachable!()
        };

        assert_eq!(
            upstream._address,
            ("127.0.0.1:8000".parse::<SocketAddr>().unwrap()).into()
        );
    }
}