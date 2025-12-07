use crate::{common_types::file_server::FileServerConfig, internal::ProxyConfig};

#[derive(Clone, Debug, PartialEq)]
pub struct ServicesConfig {
    pub proxies: Vec<ProxyConfig>,
    pub file_servers: Vec<FileServerConfig>,
}
