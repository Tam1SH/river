use std::{path::PathBuf, sync::Arc};

use crate::{
    files::motya_file_server,
    proxy::{
        filters::{chain_resolver::ChainResolver, generate_registry},
        motya_proxy_service,
        plugins::store::WasmPluginStore,
        upstream_factory::UpstreamFactory,
        watcher::file_watcher::ConfigWatcher,
    },
};
use motya_config::{
    builder::{ConfigLoader, FileConfigLoaderProvider},
    internal::Config,
};
use motya_config::{
    cli::{
        builder::CliConfigBuilder,
        cli_struct::{Cli, Commands},
    },
    common_types::definitions_table::DefinitionsTable,
};
use pingora::{server::Server, services::Service};
use tokio::sync::Mutex;

pub struct AppContext {
    config: Config,
    resolver: ChainResolver,
    watcher: ConfigWatcher,
    server: Server,
}

fn resolve_config_path(cli: &Cli) -> PathBuf {
    if let Some(path) = &cli.config_entry {
        return path.clone();
    }

    if let Ok(env_path) = std::env::var("MOTYA_CONFIG_PATH") {
        return env_path.into();
    }

    "/etc/motya/entry.kdl".into()
}

impl AppContext {
    pub async fn bootstrap(cli_args: Cli) -> miette::Result<AppContext> {
        let config_path = resolve_config_path(&cli_args);

        tracing::info!(config = ?cli_args, "CLI config parsed");

        // 2. Load Registry & Global Definitions
        let mut global_definitions = DefinitionsTable::default();
        let mut registry_map = generate_registry::load_registry(&mut global_definitions);

        // 3. Load Config File
        let config = Self::load_config(&cli_args, &config_path, &mut global_definitions).await?;

        // 4. Compile WASM & Setup Resolver
        let store = WasmPluginStore::compile(&global_definitions).await?;
        store.register_into(&mut registry_map);

        let registry = Arc::new(Mutex::new(registry_map));
        let resolver = ChainResolver::new(global_definitions.clone(), registry.clone()).await?;

        // 5. Setup Watcher
        let watcher = ConfigWatcher::new(
            config.clone(),
            global_definitions,
            config_path,
            UpstreamFactory::new(resolver.clone()),
            ConfigLoader::default(),
        );

        // 6. Prepare Server instance (Pingora)
        let server =
            Server::new_with_opt_and_conf(config.pingora_opt(), config.pingora_server_conf());

        Ok(AppContext {
            config,
            resolver,
            watcher,
            server,
        })
    }

    pub async fn build_services(&mut self) -> miette::Result<Vec<Box<dyn Service>>> {
        let mut services: Vec<Box<dyn Service>> = vec![];

        tracing::info!("Configuring Basic Proxies...");

        for proxy_conf in &self.config.basic_proxies {
            tracing::info!("Configuring Basic Proxy: {}", proxy_conf.name);

            let (motya_service, shared_state) =
                motya_proxy_service(proxy_conf.clone(), self.resolver.clone(), &self.server)
                    .await
                    .map_err(|e| {
                        miette::miette!("Failed create service {}: {}", proxy_conf.name, e)
                    })?;

            self.watcher
                .insert_proxy_state(motya_service.name().to_string(), shared_state);
            services.push(motya_service);
        }

        for fs_conf in &self.config.file_servers {
            tracing::info!("Configuring File Server: {}", fs_conf.name);
            let service = motya_file_server(fs_conf.clone(), &self.server);
            services.push(service);
        }

        Ok(services)
    }

    pub fn ready(self) -> (Server, ConfigWatcher) {
        (self.server, self.watcher)
    }

    async fn load_config(
        cli_args: &Cli,
        config_path: &PathBuf,
        global_definitions: &mut DefinitionsTable,
    ) -> miette::Result<Config> {
        let mut config = match &cli_args.command {
            Some(Commands::Hello { port, text }) => {
                CliConfigBuilder::build_hello(*port, text.clone())?
            }

            Some(Commands::Serve { port, map }) => {
                let mut routes = Vec::new();

                for mapping in map {
                    let syntetic_route = CliConfigBuilder::parse_map_string(mapping)
                        .map_err(|err| miette::miette!("{err}"))?;

                    routes.push(syntetic_route);
                }

                tracing::info!(
                    "🚀 Starting in SERVE mode on port {} with {} routes",
                    port,
                    routes.len()
                );

                CliConfigBuilder::build_routes(*port, routes)?
            }
            None => {
                let loader = ConfigLoader::default();
                loader
                    .load_entry_point(Some(config_path.into()), global_definitions)
                    .await?
                    .inspect(|_| tracing::info!("Applying config"))
                    .unwrap_or_else(|| {
                        tracing::warn!("No configuration file provided, using default");
                        Config::default()
                    })
            }
        };

        tracing::info!("Loading config from: {:?}", config_path);

        // Apply CLI overrides & Validate
        apply_cli(&mut config, cli_args);
        tracing::debug!(?config, "Full configuration");

        tracing::info!("Validating configuration...");
        config.validate();
        tracing::info!("Validation complete");

        Ok(config)
    }
}

fn apply_cli(conf: &mut Config, cli: &Cli) {
    let Cli {
        validate_configs,
        threads_per_service,
        config_toml: _,
        config_entry: _,
        daemonize,
        upgrade,
        pidfile,
        upgrade_socket,
        command: _,
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
