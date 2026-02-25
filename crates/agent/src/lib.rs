pub mod config;
pub mod deployment;
pub mod error;
pub mod registration;
pub mod server;
pub mod tunnel;

use config::AgentConfig;
use deployment::DeploymentManager;
use ee_common::types::AgentId;
use server::AppState;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::info;

/// Handle to a running agent.
pub struct AgentHandle {
    pub url: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl AgentHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// Start the agent. Returns a handle that can be used to shut it down.
pub async fn start(config: AgentConfig) -> anyhow::Result<AgentHandle> {
    let agent_id = AgentId::new();
    info!(%agent_id, "starting agent");

    let deployment_manager = DeploymentManager::new()?;
    let state = Arc::new(Mutex::new(AppState {
        config: config.clone(),
        deployment_manager,
        start_time: Instant::now(),
    }));

    let app = server::router(state);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let url = format!("http://{}", listener.local_addr()?);
    info!(%url, "agent listening");

    let (tx, rx) = tokio::sync::oneshot::channel();

    // Registration task
    let client = ee_common::http::build_client();
    let reg_config = config.clone();
    let reg_id = agent_id.clone();
    tokio::spawn(async move {
        if let Err(e) = registration::register(&client, &reg_config, &reg_id).await {
            tracing::error!(?e, "registration failed permanently");
        }
    });

    // HTTP server
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    Ok(AgentHandle { url, shutdown: tx })
}
