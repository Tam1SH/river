//! Configuration sourced from the CLI

use clap::Parser;
use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches};

use crate::{config::{builder::ConfigLoader, common_types::definitions::DefinitionsTable, internal::{self, Config}}, proxy::filters::{chain_resolver::ChainResolver, generate_registry}};


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
}


const BANNER: &str = r#"
    ____  _____    ____________ 
   / __ \/  _/ |  / / ____/ __ \
  / /_/ // / | | / / __/ / /_/ /
 / _, _// /  | |/ / /___/ _, _/ 
/_/ |_/___/  |___/_____/_/ |_|  

River: A reverse proxy from Prossimo
"#;

pub async fn render_config() -> miette::Result<(Config, ChainResolver)> {
    // To begin with, start with the blank internal config. We will layer on top of that.

    // Then, obtain the command line information, as that may
    // change the paths to look for configuration files. It also handles
    // bailing immediately if the user passes `--help`.

    let command = Cli::command().before_help(BANNER).get_matches();

    tracing::info!("Parsing CLI options");
    let c = Cli::from_arg_matches(&command).expect("Failed to parse args");
    tracing::info!(
        config = ?c,
        "CLI config"
    );

    let loader = ConfigLoader::new();


    let mut global_definitions = DefinitionsTable::default();
    let mut registry = generate_registry::load_registry(&mut global_definitions);
    
    // 2.6.7: River MUST give the following priority to configuration:
    //   1. Command Line Options (highest priority)
    //   2. Environment Variable Options
    //   3. Configuration File Options (lowest priority)
    let mut config = loader.load_entry_point(c.config_entry.as_ref(), &mut global_definitions, &mut registry).await?
        .inspect(|_| {
            tracing::info!("Applying config");
        })
        .unwrap_or_else(|| {
            tracing::info!("No configuration file provided");
            Config::default()
        });

            
    let resolver = ChainResolver::new(global_definitions, registry)?;
    tracing::info!("Applying CLI options");
    apply_cli(&mut config, &c);

    // We always validate the configuration - if the user selected "validate"
    // then pingora will exit when IT also validates the config.
    tracing::info!(?config, "Full configuration",);
    tracing::info!("Validating...");
    config.validate();
    tracing::info!("Validation complete");
    Ok((config, resolver))
}

fn apply_cli(conf: &mut internal::Config, cli: &Cli) {
    let Cli {
        validate_configs,
        threads_per_service,
        config_toml: _,
        config_entry: _,
        daemonize,
        upgrade,
        pidfile,
        upgrade_socket,
    } = cli;

    conf.validate_configs |= validate_configs;
    conf.daemonize |= daemonize;
    conf.upgrade |= upgrade;

    if let Some(pidfile) = pidfile {
        if let Some(current_pidfile) = conf.pid_file.as_ref() {
            if pidfile != current_pidfile {
                panic!(
                    "Mismatched commanded PID files. CLI: {pidfile:?}, Config: {current_pidfile:?}"
                );
            }
        }
        conf.pid_file = Some(pidfile.into());
    }

    if let Some(upgrade_socket) = upgrade_socket {
        if let Some(current_upgrade_socket) = conf.upgrade_socket.as_ref() {
            if upgrade_socket != current_upgrade_socket {
                panic!(
                    "Mismatched commanded upgrade sockets. CLI: {upgrade_socket:?}, Config: {current_upgrade_socket:?}"
                );
            }
        }
        conf.upgrade_socket = Some(upgrade_socket.into());
    }

    if let Some(tps) = threads_per_service {
        conf.threads_per_service = *tps;
    }
}


