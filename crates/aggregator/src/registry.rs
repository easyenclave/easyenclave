//! Agent registration and state tracking.

use chrono::Utc;
use ee_common::types::{AgentId, AgentInfo, AgentRegistration, AgentStatus, DeploymentInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Tracks registered agents and their state.
#[derive(Clone)]
pub struct AgentRegistry {
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register or re-register an agent. Returns the agent info.
    pub async fn register(&self, agent_id: AgentId, registration: AgentRegistration) -> AgentInfo {
        let info = AgentInfo {
            id: agent_id.clone(),
            status: AgentStatus::Registering,
            url: registration.url,
            size: registration.size,
            cloud: registration.cloud,
            region: registration.region,
            tags: registration.tags,
            attestation_token: registration.attestation_token,
            registered_at: Utc::now(),
            last_health_check: None,
            deployment: None,
        };

        let mut agents = self.agents.write().await;
        agents.insert(agent_id.to_string(), info.clone());
        info
    }

    /// Update agent health status.
    pub async fn update_health(&self, agent_id: &str, healthy: bool) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.status = if healthy {
                AgentStatus::Healthy
            } else {
                AgentStatus::Unhealthy
            };
            agent.last_health_check = Some(Utc::now());
        }
    }

    /// Update agent attestation status.
    pub async fn update_attestation(&self, agent_id: &str, attested: bool) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.status = if attested {
                AgentStatus::Attested
            } else {
                AgentStatus::AttestationFailed
            };
        }
    }

    /// Get a snapshot of all agents.
    pub async fn all_agents(&self) -> Vec<AgentInfo> {
        self.agents.read().await.values().cloned().collect()
    }

    /// Get a specific agent.
    pub async fn get_agent(&self, agent_id: &str) -> Option<AgentInfo> {
        self.agents.read().await.get(agent_id).cloned()
    }

    /// Update agent deployment info.
    pub async fn update_deployment(&self, agent_id: &str, deployment: Option<DeploymentInfo>) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.deployment = deployment;
        }
    }

    /// Remove an agent.
    pub async fn remove_agent(&self, agent_id: &str) {
        self.agents.write().await.remove(agent_id);
    }

    /// Get healthy agents matching tags.
    pub async fn healthy_agents_with_tags(&self, tags: &[String]) -> Vec<AgentInfo> {
        self.agents
            .read()
            .await
            .values()
            .filter(|a| {
                matches!(a.status, AgentStatus::Healthy | AgentStatus::Attested)
                    && (tags.is_empty() || tags.iter().all(|t| a.tags.contains(t)))
            })
            .cloned()
            .collect()
    }
}
