use std::{collections::HashMap, sync::Arc};

use chrono::Utc;
use dashmap::DashMap;
use ee_common::{
    api::PublishVersionRequest,
    config::CpConfig,
    error::AppResult,
    types::{AgentRecord, AgentStatus, AppRecord, AppVersionRecord},
};

use crate::{mrtd::TrustedMrtdRegistry, nonce::NonceStore, tunnel::CloudflareClient};

pub struct AppState {
    pub config: CpConfig,
    pub nonces: NonceStore,
    pub agents: DashMap<String, AgentRecord>,
    pub apps: DashMap<String, AppRecord>,
    pub app_versions: DashMap<String, Vec<AppVersionRecord>>,
    pub trusted_mrtds: TrustedMrtdRegistry,
    pub cloudflare: CloudflareClient,
}

impl AppState {
    pub fn new(config: CpConfig) -> AppResult<Self> {
        Ok(Self {
            nonces: NonceStore::default(),
            agents: DashMap::new(),
            apps: DashMap::new(),
            app_versions: DashMap::new(),
            trusted_mrtds: TrustedMrtdRegistry::default(),
            cloudflare: CloudflareClient::new(config.clone()),
            config,
        })
    }

    pub fn upsert_agent(&self, agent: AgentRecord) {
        self.agents.insert(agent.agent_id.clone(), agent);
    }

    pub fn set_agent_heartbeat(&self, agent_id: &str, mrtd: String) -> AppResult<()> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| ee_common::error::AppError::NotFound("unknown agent".to_owned()))?;

        entry.last_heartbeat = Utc::now();
        entry.mrtd = mrtd;
        Ok(())
    }

    pub fn store_app(
        &self,
        app: AppRecord,
        version: PublishVersionRequest,
    ) -> (AppRecord, AppVersionRecord) {
        let now = Utc::now();
        let version_record = AppVersionRecord {
            version_id: uuid::Uuid::new_v4().to_string(),
            app_name: app.name.clone(),
            version: version.version,
            image: version.image,
            mrtd: version.mrtd,
            node_size: version.node_size,
            published_at: now,
        };

        self.apps.insert(app.name.clone(), app.clone());
        self.app_versions
            .entry(app.name.clone())
            .or_default()
            .push(version_record.clone());

        (app, version_record)
    }

    pub fn list_apps_with_versions(&self) -> HashMap<String, Vec<AppVersionRecord>> {
        self.app_versions
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn undeploy_agent(&self, agent_id: &str) -> AppResult<()> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| ee_common::error::AppError::NotFound("unknown agent".to_owned()))?;

        entry.status = AgentStatus::Undeployed;
        Ok(())
    }
}

pub type SharedState = Arc<AppState>;
