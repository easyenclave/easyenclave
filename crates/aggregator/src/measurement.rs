//! MRTD observer: extract measurements from agent attestation,
//! submit unknown MRTDs to CP if this aggregator is trusted.

use crate::config::AggregatorConfig;
use crate::cp_client::CpClient;
use crate::error::AggregatorError;
use ee_attestation::ita::ItaClaims;
use ee_attestation::mrtd;
use ee_common::types::{Cloud, MeasurementSubmission, VmSize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Tracks known MRTDs and submits new ones to CP.
#[derive(Clone)]
pub struct MeasurementObserver {
    known_mrtds: Arc<RwLock<HashSet<String>>>,
    config: AggregatorConfig,
    cp_client: CpClient,
}

impl MeasurementObserver {
    pub fn new(config: AggregatorConfig, cp_client: CpClient) -> Self {
        Self {
            known_mrtds: Arc::new(RwLock::new(HashSet::new())),
            config,
            cp_client,
        }
    }

    /// Load known MRTDs from CP at startup.
    pub async fn load_known_mrtds(&self) -> Result<(), AggregatorError> {
        match self.cp_client.get_measurements().await {
            Ok(measurements) => {
                let mut known = self.known_mrtds.write().await;
                for m in measurements {
                    known.insert(m.mrtd);
                }
                info!(count = known.len(), "loaded known MRTDs from CP");
                Ok(())
            }
            Err(e) => {
                warn!(?e, "failed to load known MRTDs, starting empty");
                Ok(())
            }
        }
    }

    /// Observe an agent's attestation. If the MRTD is unknown and we're trusted,
    /// submit it to CP.
    pub async fn observe(
        &self,
        claims: &ItaClaims,
        size: VmSize,
        cloud: Cloud,
    ) -> Result<bool, AggregatorError> {
        let mrtd_value = match mrtd::extract_mrtd(claims) {
            Ok(m) => m,
            Err(e) => {
                warn!(?e, "could not extract MRTD from claims");
                return Ok(false);
            }
        };

        // Check if already known
        {
            let known = self.known_mrtds.read().await;
            if known.contains(&mrtd_value) {
                return Ok(true);
            }
        }

        // Unknown MRTD
        if !self.config.is_trusted {
            warn!(
                mrtd = %mrtd_value,
                "unknown MRTD and aggregator is not trusted — rejecting"
            );
            return Err(AggregatorError::AgentRejected(format!(
                "unknown MRTD {mrtd_value} and aggregator is not trusted"
            )));
        }

        // We're trusted — submit to CP
        info!(mrtd = %mrtd_value, %size, %cloud, "new MRTD observed, submitting to CP");
        let submission = MeasurementSubmission {
            size,
            cloud,
            mrtd: mrtd_value.clone(),
            release_tag: None,
        };

        self.cp_client
            .submit_measurement(&submission)
            .await
            .map_err(|e| {
                AggregatorError::MeasurementSubmission(format!("CP submission failed: {e}"))
            })?;

        // Add to local known set
        self.known_mrtds.write().await.insert(mrtd_value);

        Ok(true)
    }

    /// Check if an MRTD is known.
    pub async fn is_known(&self, mrtd_value: &str) -> bool {
        self.known_mrtds.read().await.contains(mrtd_value)
    }
}
