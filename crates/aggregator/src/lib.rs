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

/// Handle to a running aggregator.
pub struct AggregatorHandle {
    pub url: String,
    pub registry: AgentRegistry,
    pub measurement: MeasurementObserver,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl AggregatorHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// Start the aggregator. Returns a handle.
pub async fn start(config: AggregatorConfig) -> anyhow::Result<AggregatorHandle> {
    let client = ee_common::http::build_client();
    let registry = AgentRegistry::new();

    let cp_client = CpClient::new(
        config.cp_url.clone().unwrap_or_default(),
        config.api_key.clone(),
        client.clone(),
    );

    let measurement = MeasurementObserver::new(config.clone(), cp_client.clone());

    // Try to load known MRTDs
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
        marketplace,
        client: client.clone(),
        start_time: Instant::now(),
    });

    let app = server::router(state);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let url = format!("http://{}", listener.local_addr()?);
    info!(%url, "aggregator listening");

    let (tx, rx) = tokio::sync::oneshot::channel();

    // Start scraping tasks
    scraper::start_health_scraper(registry.clone(), client.clone(), config.health_interval_secs);
    scraper::start_attestation_scraper(registry.clone(), config.clone(), client);

    // HTTP server
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
        registry,
        measurement,
        shutdown: tx,
    })
}
