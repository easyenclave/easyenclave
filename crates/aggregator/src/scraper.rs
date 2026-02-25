//! Agent health and attestation scraping.

use crate::config::AggregatorConfig;
use crate::registry::AgentRegistry;
use ee_common::types::HealthResponse;
use std::time::Duration;
use tracing::{debug, warn};

/// Start the health check scraping loop.
pub fn start_health_scraper(
    registry: AgentRegistry,
    client: reqwest::Client,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            scrape_health(&registry, &client).await;
        }
    })
}

async fn scrape_health(registry: &AgentRegistry, client: &reqwest::Client) {
    let agents = registry.all_agents().await;
    for agent in agents {
        let agent_id = agent.id.to_string();
        // We don't know the agent's URL from registration alone.
        // In the full system, registration includes the agent's URL.
        // For now this is a placeholder for the scraping logic.
        debug!(agent_id = %agent_id, "health check placeholder");
    }
}

/// Start the attestation re-verify loop.
pub fn start_attestation_scraper(
    registry: AgentRegistry,
    config: AggregatorConfig,
    client: reqwest::Client,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(config.attestation_interval_secs));
        loop {
            interval.tick().await;
            debug!("attestation re-verify cycle");
            // Re-verify attestation tokens for all agents
            // This will be fleshed out when ITA integration is complete
        }
    })
}
