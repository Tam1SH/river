use std::collections::HashMap;
use std::fmt::Debug;

use http::Uri;
use pingora::prelude::HttpPeer;

use crate::{config::{
    common_types::definitions::{FilterChain, Modificator},
    internal::{SimpleResponse, UpstreamOptions},
}};

#[derive(Debug, Clone)]
pub struct HttpPeerOptions {
    pub peer: HttpPeer,
    pub prefix_path: Uri,
    pub target_path: Uri
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Upstream {
    Service(HttpPeerOptions),
    Static(SimpleResponse)
}

#[allow(clippy::large_enum_variant)]
pub enum ConnectorsLeaf {
    Upstream(Upstream),
    Modificator(Modificator),
    LoadBalance(UpstreamOptions),
    Section(Vec<ConnectorsLeaf>)
}

#[derive(Debug, Clone)]
pub struct Connectors { 
    pub upstreams: Vec<UpstreamConfig>,
    pub anonymous_chains: HashMap<String, FilterChain>, 
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub upstream: Upstream,
    pub chains: Vec<Modificator>,
    pub lb_options: UpstreamOptions,
}
