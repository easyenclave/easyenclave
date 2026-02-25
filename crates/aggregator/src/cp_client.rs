//! Typed client for CP API calls.

use ee_common::types::{MeasurementSubmission, TrustedMrtd};
use tracing::debug;

#[derive(Clone)]
pub struct CpClient {
    base_url: String,
    api_key: String,
    client: reqwest::Client,
}

impl CpClient {
    pub fn new(base_url: String, api_key: String, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            client,
        }
    }

    /// Submit a new measurement to CP.
    pub async fn submit_measurement(
        &self,
        submission: &MeasurementSubmission,
    ) -> Result<(), anyhow::Error> {
        let url = format!("{}/api/v1/measurements", self.base_url);
        debug!(%url, "submitting measurement to CP");

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(submission)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("CP returned {status}: {body}");
        }

        Ok(())
    }

    /// Get all known measurements from CP.
    pub async fn get_measurements(&self) -> Result<Vec<TrustedMrtd>, anyhow::Error> {
        let url = format!("{}/api/v1/measurements", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("CP returned {}", resp.status());
        }

        Ok(resp.json().await?)
    }

    /// Register this aggregator with CP.
    pub async fn register_aggregator(
        &self,
        registration: &ee_common::types::AggregatorRegistration,
    ) -> Result<(), anyhow::Error> {
        let url = format!("{}/api/v1/aggregators/register", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(registration)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("CP returned {status}: {body}");
        }

        Ok(())
    }

    /// Relay a deploy request to an agent.
    pub async fn relay_deploy(
        &self,
        agent_url: &str,
        req: &ee_common::types::DeployRequest,
    ) -> Result<ee_common::types::DeploymentInfo, anyhow::Error> {
        let url = format!("{agent_url}/api/deploy");
        let resp = self.client.post(&url).json(req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("agent returned {status}: {body}");
        }

        Ok(resp.json().await?)
    }

    /// Relay an undeploy request to an agent.
    pub async fn relay_undeploy(
        &self,
        agent_url: &str,
        req: &ee_common::types::UndeployRequest,
    ) -> Result<(), anyhow::Error> {
        let url = format!("{agent_url}/api/undeploy");
        let resp = self.client.post(&url).json(req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("agent returned {status}: {body}");
        }

        Ok(())
    }
}
