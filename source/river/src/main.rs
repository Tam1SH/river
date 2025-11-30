mod config;
mod files;
mod proxy;

use std::{error::Error, fs, os::unix::{fs::PermissionsExt, net::UnixListener}, path::{Path, PathBuf}, process, thread};

use crate::{config::{cli::render_config, common_types::listeners::{ListenerKind, Listeners}, config_aggregator::{ConfigAggregator, ConfigChange}}, files::river_file_server, proxy::river_proxy_service};
use async_trait::async_trait;
use pingora::{server::{Server, ShutdownSignal, ShutdownSignalWatch}, services::Service};
use pingora_core::listeners::tls::TlsSettings;
use miette::{Diagnostic, miette};

use river::config::common_types::bad::Bad;
use tokio::{runtime::Runtime, sync::mpsc};
fn main() -> miette::Result<()> {
    // Set up tracing, including catching `log` crate logs from pingora crates
    tracing_subscriber::fmt().with_thread_ids(true).init();
    let (tx, rx) = mpsc::channel::<ConfigChange>(5);

    let config_aggregator = ConfigAggregator::new(rx);

    thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime for admin task");

        tracing::info!("Config Aggregator started in background thread");

        rt.block_on(async move {
            config_aggregator.run().await;
        });
        
        tracing::error!("Config Aggregator died!");
    });

    // Read from the various configuration files
    let rt = Runtime::new().unwrap();
    let (conf, resolver) = rt.block_on(render_config())?;
    
    // Start the Server, which we will add services to.
    let mut my_server =
        Server::new_with_opt_and_conf(conf.pingora_opt(), conf.pingora_server_conf());
    // let path = conf.upgrade_socket.clone().unwrap();
    // let path = path.to_str().unwrap();

    // tracing::info!("path to sock: {}", path);

    // create_socket_safely(path);

    tracing::info!("Applying Basic Proxies...");
    let mut services: Vec<Box<dyn Service>> = vec![];

    // At the moment, we only support basic proxy services. These have some path
    // control, but don't support things like load balancing, health checks, etc.
    for beep in conf.basic_proxies {
        tracing::info!("Configuring Basic Proxy: {}", beep.name);
        let river_service = river_proxy_service(beep, &resolver, &my_server)
            .unwrap_or_else(|err| panic!("failed create services, err: '{err}'"));
        services.push(river_service);
    }

    for fs in conf.file_servers {
        tracing::info!("Configuring File Server: {}", fs.name);
        let service = river_file_server(fs, &my_server);
        services.push(service);
    }

    // Now we hand it over to pingora to run forever.
    tracing::info!("Server running (PID: {})", process::id());
    tracing::info!("Bootstrapping...");
    my_server.bootstrap();
    tracing::info!("Bootstrapped. Adding Services...");
    my_server.add_services(services);
    
    tracing::info!("Starting Server...");
    my_server.run_forever();
}

fn create_socket_safely(path_str: &str) -> UnixListener {
    let path = Path::new(path_str);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    if path.exists() {
        fs::remove_file(path).expect("Failed to remove old socket");
    }

    let listener = UnixListener::bind(path).expect("Failed to bind");

    let perms = fs::Permissions::from_mode(0o777); // rwxrwxrwx
    fs::set_permissions(path, perms).expect("Failed to set permissions");

    listener
}

struct Signal;
#[async_trait]
impl ShutdownSignalWatch for Signal {
    
    async fn recv(&self) -> ShutdownSignal {
        ShutdownSignal::GracefulUpgrade
    }
}

