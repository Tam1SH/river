mod files;
mod proxy;
mod app_context;

use std::process;

use clap::{CommandFactory, FromArgMatches};
use motya_config::cli::cli::{BANNER, Cli};
use tokio::{runtime::Runtime, sync::mpsc};

use crate::app_context::AppContext;

fn main() -> miette::Result<()> {
    tracing_subscriber::fmt().with_thread_ids(true).init();

    let rt = Runtime::new().expect("Failed to build Tokio runtime");

    let command = Cli::command().before_help(BANNER).get_matches();
    let cli_args = Cli::from_arg_matches(&command).expect("Failed to parse args");
        
    let mut ctx = rt.block_on(AppContext::bootstrap(cli_args))?;
    
    let services = rt.block_on(ctx.build_services())?;

    tracing::info!("Server running (PID: {})", process::id());
    
    let (mut server, mut watcher) = ctx.ready();

    server.bootstrap();
    server.add_services(services);

    rt.spawn(async move {
        watcher.watch().await
    });

    tracing::info!("Starting Pingora Server...");

    server.run_forever();
}
