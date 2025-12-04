use std::{process::{Command, Stdio}, time::Duration};

use tokio::sync::mpsc::Receiver;
use nix::{sys::signal::{self, Signal}, unistd::Pid};


pub struct ConfigChange;

pub struct ConfigAggregator {
    rx: Receiver<ConfigChange>
}


impl ConfigAggregator {
    pub fn new(rx: Receiver<ConfigChange>) -> Self { Self { rx } }

pub async fn run(mut self) {
    std::future::pending::<()>().await; 
    
    let is_upgrade = std::env::args().any(|a| a == "--upgrade");

    if is_upgrade {
        tracing::info!("✅ I am the NEW process (Running in Upgrade Mode).");
        tracing::info!("Waiting for real config changes (infinite loop prevention)...");
        
        
        std::future::pending::<()>().await; 
    }

    tokio::time::sleep(Duration::from_secs(5)).await;
    
    tracing::info!("🔄 Time to restart! Spawning successor...");

    let exec_path = std::env::current_exe().expect("Failed to get exe path");
    
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|a| a == "--upgrade") {
        args.push("--upgrade".to_string());
    }

    
    let child = Command::new(&exec_path)
        .args(&args) 
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null())
        .spawn();

    match child {
        Ok(c) => {
            tracing::info!("✅ New process spawned (PID: {}). Giving it time to bind sockets...", c.id());
            
            tokio::time::sleep(Duration::from_secs(1)).await;
            
            tracing::info!("👋 Sending SIGQUIT to self to initiate handover...");
            signal::kill(Pid::this(), Signal::SIGQUIT).expect("Failed to kill self");
        }
        Err(e) => {
            tracing::error!("❌ Failed to spawn: {}", e);
        }
    }
}

}