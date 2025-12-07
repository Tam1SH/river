//! Configuration sourced from the CLI

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct Cli {
    /// Validate all configuration data and exit
    #[arg(long)]
    pub validate_configs: bool,

    /// Path to the configuration file in TOML format
    #[arg(long)]
    pub config_toml: Option<PathBuf>,

    /// Path to the configuration file in KDL format
    #[arg(long)]
    pub config_entry: Option<PathBuf>,

    /// Number of threads used in the worker pool for EACH service
    #[arg(long)]
    pub threads_per_service: Option<usize>,

    /// Should the server be daemonized after starting?
    #[arg(long)]
    pub daemonize: bool,

    /// Should the server take over an existing server?
    #[arg(long)]
    pub upgrade: bool,

    /// Path to upgrade socket
    #[arg(long)]
    pub upgrade_socket: Option<PathBuf>,

    /// Path to the pidfile, used for upgrade
    #[arg(long)]
    pub pidfile: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    Hello {
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        #[arg(short, long, default_value = "Hello from Motya!")]
        text: String,
    },

    Serve {
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// Route mappings in "path=target" format.
        /// If the target starts with "http", it acts as a proxy.
        /// Otherwise, it is treated as a static text response.
        /// Example: --map "/api=http://127.0.0.1:9000" --map "/=Welcome!"
        #[arg(short, long)]
        map: Vec<String>,
    },
}

pub const BANNER: &str = r#"
   __  __       _              
  |  \/  | ___ | |_ _   _ __ _ 
  | |\/| |/ _ \| __| | | / _` |
  | |  | | (_) | |_| |_| \__,_|
  |_|  |_|\___/ \__|\__, |_____|
                    |___/       
      /\_/\  
     ( o.o )  Motya Proxy v __p__
      > ^ <   Watching you...
"#;
