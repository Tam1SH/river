use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigProvider {
    Files(FilesProviderConfig),
    S3(S3ProviderConfig),
    Http(HttpProviderConfig),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilesProviderConfig {
    pub watch: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct S3ProviderConfig {
    pub bucket: String,
    pub key: String,
    pub region: String,
    pub interval: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpProviderConfig {
    pub address: SocketAddr,
    pub path: String,
    pub persist: bool,
}

#[derive(Debug)]
pub struct SystemData {
    pub threads_per_service: usize,
    pub daemonize: bool,
    pub upgrade_socket: Option<PathBuf>,
    pub pid_file: Option<PathBuf>,
    pub provider: Option<ConfigProvider>,
}

impl Default for SystemData {
    fn default() -> Self {
        Self {
            threads_per_service: 8,
            daemonize: false,
            upgrade_socket: None,
            pid_file: None,
            provider: None,
        }
    }
}
