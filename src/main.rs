mod attestation;
mod config;
mod container;
mod init;
mod process;
mod socket;
mod workload;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    // 1. PID 1 init (mount filesystems, parse kernel cmdline, reap zombies)
    init::maybe_init();

    // 2. Load config
    let cfg = match config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("easyenclave: configuration error: {e}");
            std::process::exit(1);
        }
    };

    // Ensure data directory exists
    let _ = std::fs::create_dir_all(&cfg.data_dir);
    let _ = std::fs::create_dir_all(format!("{}/workloads/logs", cfg.data_dir));

    // 3. Detect attestation backend
    let attestation = attestation::detect().unwrap_or_else(|e| {
        eprintln!("easyenclave: FATAL: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "easyenclave: attestation backend: {}",
        attestation.attestation_type()
    );

    // 4. Create empty deployments
    let deployments: workload::Deployments = Arc::new(Mutex::new(HashMap::new()));

    // 5. Deploy boot workloads from config
    for bw in &cfg.boot_workloads {
        eprintln!("easyenclave: boot workload: {}", bw.app_name);
        let req = workload::DeployRequest {
            cmd: bw.cmd.clone().unwrap_or_default(),
            image: bw.image.clone(),
            env: bw.env.clone(),
            volumes: bw.volumes.clone(),
            app_name: Some(bw.app_name.clone()),
            tty: false,
            post_deploy: None,
        };
        let (id, _status) = workload::execute_deploy(&deployments, req).await;
        eprintln!("easyenclave: boot workload {} -> {id}", bw.app_name);
    }

    let start_time = std::time::Instant::now();

    // 6. Start socket server (with SIGTERM handler for clean shutdown)
    let deployments_shutdown = deployments.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("easyenclave: shutting down (SIGINT)...");
        workload::stop_all(&deployments_shutdown).await;
        std::process::exit(0);
    });

    let deployments_sigterm = deployments.clone();
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        sigterm.recv().await;
        eprintln!("easyenclave: shutting down (SIGTERM)...");
        workload::stop_all(&deployments_sigterm).await;
        std::process::exit(0);
    });

    let server = socket::SocketServer {
        socket_path: cfg.socket_path.clone(),
        deployments,
        attestation: Arc::new(attestation),
        start_time,
    };

    if let Err(e) = server.run().await {
        eprintln!("easyenclave: socket server error: {e}");
        std::process::exit(1);
    }
}
