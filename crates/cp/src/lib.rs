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
    pub db: Database,
    pub builtin_aggregator: Option<ee_aggregator::EmbeddedAggregator>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl CpHandle {
    pub async fn shutdown(self) {
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

    // Build built-in aggregator if enabled
    let (aggregator_state, embedded) = if config.builtin_aggregator {
        info!("initializing built-in aggregator");
        let agg_config = ee_aggregator::config::AggregatorConfig::builtin(config.listen_addr);
        let embedded = ee_aggregator::build(agg_config).await?;
        let state = embedded.state.clone();
        (Some(state), Some(embedded))
    } else {
        (None, None)
    };

    // Build router: CP routes + optional aggregator routes merged in
    let app = server::router(cp_state, aggregator_state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let url = format!("http://{}", listener.local_addr()?);

    if embedded.is_some() {
        info!(%url, "CP listening (with built-in aggregator)");
    } else {
        info!(%url, "CP listening");
    }

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    Ok(CpHandle {
        url,
        db,
        builtin_aggregator: embedded,
        shutdown: tx,
    })
}
