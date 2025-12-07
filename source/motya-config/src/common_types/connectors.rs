use std::fmt::Debug;
use std::hash::{DefaultHasher, Hash, Hasher};

use http::uri::PathAndQuery;
use pingora::{prelude::HttpPeer, protocols::l4::socket::SocketAddr, upstreams::peer::Proxy};

use crate::common_types::{
    definitions::Modificator, definitions_table::DefinitionsTable,
    simple_response_type::SimpleResponseConfig,
};
use crate::internal::UpstreamOptions;

#[derive(Hash, Clone, Debug, PartialEq)]
pub enum ALPN {
    H1,
    H2,
    H2H1,
}

impl From<pingora::protocols::ALPN> for ALPN {
    fn from(value: pingora::protocols::ALPN) -> Self {
        match value {
            pingora::protocols::ALPN::H1 => ALPN::H1,
            pingora::protocols::ALPN::H2 => ALPN::H2,
            pingora::protocols::ALPN::H2H1 => ALPN::H2H1,
        }
    }
}

impl From<ALPN> for pingora::protocols::ALPN {
    fn from(value: ALPN) -> Self {
        match value {
            ALPN::H1 => pingora::protocols::ALPN::H1,
            ALPN::H2 => pingora::protocols::ALPN::H2,
            ALPN::H2H1 => pingora::protocols::ALPN::H2H1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMatcher {
    #[default]
    Exact,
    Prefix,
}

#[derive(Debug, Clone)]
pub struct HttpPeerConfig {
    //TODO: do separate type
    pub peer: HttpPeer,
    pub prefix_path: PathAndQuery,
    pub target_path: PathAndQuery,
    pub matcher: RouteMatcher,
}

impl PartialEq for HttpPeerConfig {
    fn eq(&self, other: &Self) -> bool {
        if self.prefix_path != other.prefix_path
            || self.target_path != other.target_path
            || self.peer.scheme != other.peer.scheme
            || self.peer.sni != other.peer.sni
        {
            return false;
        }

        match (&self.peer._address, &other.peer._address) {
            (SocketAddr::Inet(a), SocketAddr::Inet(b)) if a == b => {}
            _ => return false,
        }

        let hash_proxy = |p: &Option<Proxy>| -> u64 {
            let mut hasher = DefaultHasher::new();
            p.hash(&mut hasher);
            hasher.finish()
        };

        hash_proxy(&self.peer.proxy) == hash_proxy(&other.peer.proxy)
    }
}

//TODO: Convert to ConfigType
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamConfig {
    Service(HttpPeerConfig),
    Static(SimpleResponseConfig),
    MultiServer(MultiServerUpstreamConfig),
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamServer {
    pub address: std::net::SocketAddr,
    pub weight: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MultiServerUpstreamConfig {
    pub servers: Vec<UpstreamServer>,
    pub tls_sni: Option<String>,
    pub alpn: ALPN,
    pub prefix_path: PathAndQuery,
    pub target_path: PathAndQuery,
    pub matcher: RouteMatcher,
}

#[allow(clippy::large_enum_variant)]
pub enum ConnectorsLeaf {
    Upstream(UpstreamConfig),
    Modificator(Modificator),
    LoadBalance(UpstreamOptions),
    Section(Vec<ConnectorsLeaf>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connectors {
    pub upstreams: Vec<UpstreamContextConfig>,
    pub anonymous_definitions: DefinitionsTable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamContextConfig {
    pub upstream: UpstreamConfig,
    pub chains: Vec<Modificator>,
    pub lb_options: UpstreamOptions,
}
