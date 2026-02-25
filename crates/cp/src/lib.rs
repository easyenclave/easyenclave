pub mod config;
pub mod db;
pub mod error;
pub mod proxy;
pub mod releases;
pub mod scraper;
pub mod server;

use config::CpConfig;
use db::Database;
use server::AppState;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Handle to a running CP.
pub struct CpHandle {
    pub url: String,
    pub builtin_aggregator: Option<ee_aggregator::AggregatorHandle>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl CpHandle {
    pub async fn shutdown(self) {
        if let Some(agg) = self.builtin_aggregator {
            agg.shutdown().await;
        }
        let _ = self.shutdown.send(());
    }
}

/// Start the control plane. Returns a handle.
pub async fn start(config: CpConfig) -> anyhow::Result<CpHandle> {
    let db = Database::open(&config.db_path)?;

    // Seed trusted aggregators from env
    for id in &config.trusted_aggregator_ids {
        db.add_trusted_aggregator(id, "env").await?;
    }

    let cp_state = Arc::new(AppState {
        config: config.clone(),
        db: db.clone(),
        start_time: Instant::now(),
    });

    let app = server::router(cp_state);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let url = format!("http://{}", listener.local_addr()?);
    info!(%url, "CP listening");

    let (tx, rx) = tokio::sync::oneshot::channel();

    // Start HTTP server
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    // Start built-in aggregator if enabled
    let builtin_aggregator = if config.builtin_aggregator {
        info!("starting built-in aggregator");
        let agg_config =
            ee_aggregator::config::AggregatorConfig::builtin(config.listen_addr);
        // The built-in aggregator shares the CP's address conceptually.
        // In practice it uses the same listen addr — agent registrations
        // go through the CP's routes which delegate to the aggregator.
        let handle = ee_aggregator::start(agg_config).await?;
        info!(url = %handle.url, "built-in aggregator started");
        Some(handle)
    } else {
        None
    };

    Ok(CpHandle {
        url,
        builtin_aggregator,
        shutdown: tx,
    })
}
