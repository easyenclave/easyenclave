pub mod config;
pub mod error;
pub mod images;
pub mod resources;
pub mod server;
pub mod vm;

use config::HostdConfig;
use resources::HostResources;
use server::AppState;
use vm::VmManager;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::info;

/// Handle to a running hostd.
pub struct HostdHandle {
    pub url: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl HostdHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// Start the host daemon.
pub async fn start(config: HostdConfig) -> anyhow::Result<HostdHandle> {
    let resources = HostResources::discover();
    info!(?resources, "host resources discovered");

    let vm_manager = VmManager::new(config.clone());

    let state = Arc::new(Mutex::new(AppState {
        config: config.clone(),
        vm_manager,
        resources,
        start_time: Instant::now(),
    }));

    let app = server::router(state);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let url = format!("http://{}", listener.local_addr()?);
    info!(%url, "hostd listening");

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    Ok(HostdHandle { url, shutdown: tx })
}
