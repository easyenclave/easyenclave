pub mod billing;
pub mod config;
pub mod cp_client;
pub mod error;
pub mod measurement;
pub mod proxy;
pub mod registry;
pub mod scraper;
pub mod server;

use billing::marketplace::Marketplace;
use billing::provider::stub::StubProvider;
use config::AggregatorConfig;
use cp_client::CpClient;
use measurement::MeasurementObserver;
use registry::AgentRegistry;
use server::AppState;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Handle to a running standalone aggregator.
pub struct AggregatorHandle {
    pub url: String,
    pub inner: EmbeddedAggregator,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl AggregatorHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// An aggregator's core components (no HTTP listener).
/// Used both standalone and embedded inside CP.
pub struct EmbeddedAggregator {
    pub registry: AgentRegistry,
    pub measurement: MeasurementObserver,
    pub marketplace: Arc<Marketplace>,
    pub state: Arc<AppState>,
}

/// Build the aggregator core without starting an HTTP server.
/// Returns components that can be embedded into another server (e.g. CP).
pub async fn build(config: AggregatorConfig) -> anyhow::Result<EmbeddedAggregator> {
    let client = ee_common::http::build_client();
    let registry = AgentRegistry::new();

    let cp_client = CpClient::new(
        config.cp_url.clone().unwrap_or_default(),
        config.api_key.clone(),
        client.clone(),
    );

    let measurement = MeasurementObserver::new(config.clone(), cp_client.clone());

    // Try to load known MRTDs (will fail gracefully if CP isn't up yet)
    measurement.load_known_mrtds().await.ok();

    // Set up billing provider
    let provider: Arc<dyn billing::provider::PaymentProvider> =
        if let Some(ref btcpay_config) = config.btcpay {
            Arc::new(billing::provider::btcpay::BtcPayProvider::new(
                btcpay_config.clone(),
                client.clone(),
            ))
        } else {
            Arc::new(StubProvider::new())
        };
    let marketplace = Arc::new(Marketplace::new(provider));

    let state = Arc::new(AppState {
        config: config.clone(),
        registry: registry.clone(),
        measurement: measurement.clone(),
        marketplace: marketplace.clone(),
        client: client.clone(),
        start_time: Instant::now(),
    });

    // Start scraping tasks
    scraper::start_health_scraper(
        registry.clone(),
        client.clone(),
        config.health_interval_secs,
    );
    scraper::start_attestation_scraper(registry.clone(), config.clone(), client);

    Ok(EmbeddedAggregator {
        registry,
        measurement,
        marketplace,
        state,
    })
}

/// Get the full aggregator Router (standalone, includes /api/health).
pub fn router(state: Arc<AppState>) -> axum::Router {
    server::router(state)
}

/// Get aggregator routes that can be merged into another router (no /api/health overlap).
pub fn mergeable_routes(state: Arc<AppState>) -> axum::Router {
    server::mergeable_routes(state)
}

/// Start the aggregator as a standalone HTTP server.
pub async fn start(config: AggregatorConfig) -> anyhow::Result<AggregatorHandle> {
    let listen_addr = config.listen_addr;
    let embedded = build(config).await?;
    let app = server::router(embedded.state.clone());

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let url = format!("http://{}", listener.local_addr()?);
    info!(%url, "aggregator listening");

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    Ok(AggregatorHandle {
        url,
        inner: embedded,
        shutdown: tx,
    })
}
