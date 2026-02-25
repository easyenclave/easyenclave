//! Scrapes external aggregators for state and caches in SQLite.

use crate::db::Database;
use ee_common::types::AggregatorState;
use std::time::Duration;
use tracing::{debug, warn};

/// Start the aggregator scraping loop.
pub fn start_aggregator_scraper(
    db: Database,
    client: reqwest::Client,
    aggregator_urls: Vec<String>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            for url in &aggregator_urls {
                if let Err(e) = scrape_aggregator(&db, &client, url).await {
                    warn!(url = %url, ?e, "scrape failed");
                }
            }
        }
    })
}

async fn scrape_aggregator(
    db: &Database,
    client: &reqwest::Client,
    base_url: &str,
) -> anyhow::Result<()> {
    let url = format!("{}/api/state", base_url.trim_end_matches('/'));
    debug!(%url, "scraping aggregator");

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("aggregator returned {}", resp.status());
    }

    let state: AggregatorState = resp.json().await?;

    // Cache agents
    for agent in &state.agents {
        db.upsert_agent(agent, Some(&state.id.to_string())).await?;
    }

    debug!(
        aggregator_id = %state.id,
        agent_count = state.agents.len(),
        "scraped aggregator"
    );

    Ok(())
}
