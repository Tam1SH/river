use std::hash::{Hash, Hasher};
use std::{collections::HashMap, hash::DefaultHasher};
use std::fmt::Debug;

use http::uri::PathAndQuery;
use pingora::{prelude::HttpPeer, upstreams::peer::Proxy, protocols::l4::socket::SocketAddr};

use crate::common_types::simple_response_type::SimpleResponseConfig;
use crate::{
    common_types::definitions::{FilterChain, Modificator},
    internal::UpstreamOptions,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMatcher {
    #[default]
    Prefix,
    Exact,
}

#[derive(Debug, Clone)]
pub struct HttpPeerOptions {
    //TODO: do separate type
    pub peer: HttpPeer,
    pub prefix_path: PathAndQuery,
    pub target_path: PathAndQuery,
    pub matcher: RouteMatcher
}

impl PartialEq for HttpPeerOptions {
    fn eq(&self, other: &Self) -> bool {
        
        if self.prefix_path != other.prefix_path 
           || self.target_path != other.target_path 
           || self.peer.scheme != other.peer.scheme 
           || self.peer.sni != other.peer.sni 
        {
            return false;
        }

        
        match (&self.peer._address, &other.peer._address) {
            (SocketAddr::Inet(a), SocketAddr::Inet(b)) if a == b => { },
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
pub enum Upstream {
    Service(HttpPeerOptions),
    Static(SimpleResponseConfig)
}



#[allow(clippy::large_enum_variant)]
pub enum ConnectorsLeaf {
    Upstream(Upstream),
    Modificator(Modificator),
    LoadBalance(UpstreamOptions),
    Section(Vec<ConnectorsLeaf>)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connectors { 
    pub upstreams: Vec<UpstreamConfig>,
    pub anonymous_chains: HashMap<String, FilterChain>, 
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamConfig {
    pub upstream: Upstream,
    pub chains: Vec<Modificator>,
    pub lb_options: UpstreamOptions,
}

