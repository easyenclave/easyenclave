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
        let url = format!("{}/api/health", agent.url.trim_end_matches('/'));

        let healthy = match client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<HealthResponse>().await {
                Ok(health) => {
                    debug!(
                        agent_id = %agent_id,
                        status = %health.status,
                        uptime = health.uptime_secs,
                        "agent health OK"
                    );
                    health.status == "ok"
                }
                Err(e) => {
                    warn!(agent_id = %agent_id, ?e, "failed to parse health response");
                    false
                }
            },
            Ok(resp) => {
                warn!(agent_id = %agent_id, status = %resp.status(), "agent health check failed");
                false
            }
            Err(e) => {
                warn!(agent_id = %agent_id, ?e, "agent unreachable");
                false
            }
        };

        registry.update_health(&agent_id, healthy).await;
    }
}

/// Start the attestation re-verify loop.
pub fn start_attestation_scraper(
    _registry: AgentRegistry,
    config: AggregatorConfig,
    _client: reqwest::Client,
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
