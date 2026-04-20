mod attestation;
mod capture;
mod config;
mod init;
mod process;
mod release;
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

    // Ensure data directories exist
    let _ = std::fs::create_dir_all(&cfg.data_dir);
    let _ = std::fs::create_dir_all(format!("{}/workloads/logs", cfg.data_dir));
    let bin_dir = format!("{}/bin", cfg.data_dir);
    let _ = std::fs::create_dir_all(&bin_dir);

    // 3. Detect attestation backend
    let attestation = attestation::detect().unwrap_or_else(|e| {
        eprintln!("easyenclave: FATAL: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "easyenclave: attestation backend: {}",
        attestation.attestation_type()
    );

    // 4. Pre-fetch all github_release assets before any workload starts.
    // Boot workloads spawn asynchronously, so without this phase a
    // workload could shell out to a tool (e.g. cloudflared) before its
    // download completes. Fail fast if any asset can't be fetched —
    // the VM is useless without its binaries.
    for bw in &cfg.boot_workloads {
        if let Some(gh) = bw.github_release.clone() {
            eprintln!("easyenclave: pre-fetching {} for {}", gh.asset, bw.app_name);
            let bin = bin_dir.clone();
            let res = tokio::task::spawn_blocking(move || release::download(&gh, &bin))
                .await
                .map_err(|e| format!("join: {e}"));
            match res.and_then(|r| r) {
                Ok(path) => eprintln!("easyenclave: fetched {}", path.display()),
                Err(e) => {
                    eprintln!(
                        "easyenclave: FATAL: failed to fetch asset for {}: {e}",
                        bw.app_name
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    // Put the bin dir on PATH so workloads can shell out by name.
    let existing_path = std::env::var("PATH").unwrap_or_default();
    if existing_path.is_empty() {
        std::env::set_var("PATH", &bin_dir);
    } else {
        std::env::set_var("PATH", format!("{bin_dir}:{existing_path}"));
    }

    // 5. Create empty deployments
    let deployments: workload::Deployments = Arc::new(Mutex::new(HashMap::new()));

    // 6. Deploy boot workloads from config.
    for bw in &cfg.boot_workloads {
        eprintln!("easyenclave: boot workload: {}", bw.app_name);
        let req = workload::DeployRequest {
            cmd: bw.cmd.clone().unwrap_or_default(),
            env: bw.env.clone(),
            app_name: Some(bw.app_name.clone()),
            tty: bw.tty,
            github_release: bw.github_release.clone(),
        };
        let (id, _status) = workload::execute_deploy(&deployments, req).await;
        eprintln!("easyenclave: boot workload {} -> {id}", bw.app_name);
    }

    let start_time = std::time::Instant::now();

    // 7. Start socket server (with signal handlers for clean shutdown)
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
