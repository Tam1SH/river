use std::{
    collections::{BTreeMap, HashMap, HashSet}, net::SocketAddr, num::NonZeroUsize, path::PathBuf, str::FromStr
};

use crate::{
    config::{internal::{
        Config, DiscoveryKind, FileServerConfig, HealthCheckKind, ListenerConfig, ListenerKind, PathControl, ProxyConfig, SelectionKind, SimpleResponse, TlsConfig, Upstream, UpstreamOptions
    }, kdl::{Bad, SystemData, extract_load_balance, extract_services, extract_system_data, utils}},
    proxy::{
        rate_limiting::{
            AllRateConfig, RegexShim, multi::{MultiRaterConfig, MultiRequestKeyKind}, single::{SingleInstanceConfig, SingleRequestKeyKind}
        },
        request_selector::{
            RequestSelector, null_selector, source_addr_and_uri_path_selector, uri_path_selector
        },
    },
};
use http::StatusCode;
use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use miette::{bail, Diagnostic, SourceSpan};
use pingora::{protocols::ALPN, upstreams::peer::HttpPeer};

pub struct ConfigParser;


impl ConfigParser {
    pub fn parse(&self, doc: KdlDocument) -> Result<Config, miette::Error> {
        let SystemData {
            threads_per_service,
            daemonize,
            upgrade_socket,
            pid_file,
        } = extract_system_data(&doc)?;
        
        let (basic_proxies, file_servers) = extract_services(threads_per_service, &doc)?;

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
    
    pub fn process_connectors_node(doc: &KdlDocument, node: &KdlDocument) -> miette::Result<(Vec<Upstream>, Option<UpstreamOptions>)> {

        let conn_node = utils::required_child_doc(doc, node, "connectors")?;
        let conns = utils::data_nodes(doc, conn_node)?;
        let mut conn_cfgs = vec![];
        let mut load_balance: Option<UpstreamOptions> = None;
        
        for (node, name, args) in conns {
            if name == "load-balance" {
                if load_balance.is_some() {
                    return Err(Bad::docspan("Duplicate 'load-balance' section", doc, &node.span()).into());
                }
                load_balance = Some(extract_load_balance(doc, node)?);
                continue;
            }
            let conn = extract_connector(doc, node, name, args)?;
            conn_cfgs.push(conn);
        }

        if conn_cfgs.is_empty() {
            return Err(
                Bad::docspan("We require at least one connector", doc, &conn_node.span()).into(),
            );
        }

        Ok((conn_cfgs, load_balance))
    }
}





fn extract_connector(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<Upstream> {

    // TODO: consistent enforcement of only-known args?
    let args = utils::str_str_args(doc, args)?
        .into_iter()
        .collect::<HashMap<&str, &str>>();

    if name == "return" {
        let http_code_raw = args.get("code").unwrap_or(&"200");
        let response = args.get("response").unwrap_or(&"");
        
        let http_code = StatusCode::from_str(http_code_raw)
            .map_err(|err| Bad::docspan(format!("Not a valid http code, reason: '{err}'"), doc, &node.span()))?;

        Ok(Upstream::Static(SimpleResponse { http_code, response_body: response.to_string() }))
    }
    else {
        let Ok(sadd) = name.parse::<SocketAddr>() else {
            return Err(Bad::docspan("Not a valid socket address", doc, &node.span()).into());
        };

        let proto = extract_proto(doc, node, &args)?;

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

        Ok(Upstream::Service(peer))
    }
    
}


fn extract_proto(doc: &KdlDocument, node: &KdlNode, args: &HashMap<&str, &str>) -> Result<Option<ALPN>, miette::Error> {
    let proto = match args.get("proto").copied() {
        None => None,
        Some(value) => {
            parse_proto_value(value).map_err(|msg| {
                Bad::docspan(format!("{msg}, found '{value}'"), doc, &node.span())
            })?
        }
    };
    Ok(proto)
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
        other => Err(format!("'proto' should be one of 'h1-only', 'h2-only', or 'h2-or-h1', found '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::*;
    const CONNECTORS_RETURN_SIMPLE_RESPONSE: &str = r#"
        connectors {
            return code="200" response="OK"
        }
    "#;

    #[test]
    fn service_return_simple_response() {
        let parser = ConfigParser;

        let doc: KdlDocument = CONNECTORS_RETURN_SIMPLE_RESPONSE.parse().unwrap();

        let simple = &ConfigParser::process_connectors_node(&doc, &doc).unwrap().0[0];
        
        if let Upstream::Static(response) = simple {
            assert_eq!(response.http_code, http::StatusCode::OK);
            assert_eq!(response.response_body, "OK");
        } else {
            panic!("Expected Static variant, got");
        }
    }
}

