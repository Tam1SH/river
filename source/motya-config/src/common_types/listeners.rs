use std::path::PathBuf;

#[derive(Debug, PartialEq, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ListenerKind {
    Tcp {
        addr: String,
        tls: Option<TlsConfig>,
        offer_h2: bool,
    },
    Uds(PathBuf),
}

#[derive(Debug, PartialEq, Clone)]
pub struct ListenerConfig {
    pub source: ListenerKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Listeners {
    pub list_cfgs: Vec<ListenerConfig>,
}
