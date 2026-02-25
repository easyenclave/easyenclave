//! Container deployment via bollard (Docker API).

use crate::error::AgentError;
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use ee_common::types::{DeployRequest, DeploymentInfo, DeploymentStatus};
use futures_util::TryStreamExt;
use std::collections::HashMap;
use tracing::info;

/// Manage container deployments on this agent.
pub struct DeploymentManager {
    docker: Docker,
}

impl DeploymentManager {
    pub fn new() -> Result<Self, AgentError> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|e| AgentError::Container(e.to_string()))?;
        Ok(Self { docker })
    }

    /// Deploy a container.
    pub async fn deploy(&self, req: &DeployRequest) -> Result<DeploymentInfo, AgentError> {
        info!(app = %req.app_name, image = %req.image, "deploying container");

        // Pull image
        let opts = CreateImageOptions {
            from_image: req.image.clone(),
            ..Default::default()
        };
        let mut stream = self.docker.create_image(Some(opts), None, None);
        while let Some(_info) = stream
            .try_next()
            .await
            .map_err(|e| AgentError::Container(format!("pull: {e}")))?
        {}

        // Build env vars
        let env: Vec<String> = req
            .env_vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        // Create container
        let container_name = format!("ee-{}", req.app_name);
        let config = Config {
            image: Some(req.image.clone()),
            env: Some(env),
            host_config: Some(bollard::models::HostConfig {
                publish_all_ports: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Remove existing container with same name if any
        let _ = self
            .docker
            .remove_container(
                &container_name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;

        self.docker
            .create_container(
                Some(CreateContainerOptions {
                    name: container_name.as_str(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|e| AgentError::Container(format!("create: {e}")))?;

        // Start container
        self.docker
            .start_container(&container_name, None::<StartContainerOptions<String>>)
            .await
            .map_err(|e| AgentError::Container(format!("start: {e}")))?;

        info!(app = %req.app_name, "container started");

        Ok(DeploymentInfo {
            app_name: req.app_name.clone(),
            image: req.image.clone(),
            status: DeploymentStatus::Running,
            tunnel_url: None,
            deployed_at: chrono::Utc::now(),
        })
    }

    /// Undeploy (stop + remove) a container.
    pub async fn undeploy(&self, app_name: &str) -> Result<(), AgentError> {
        let container_name = format!("ee-{app_name}");
        info!(app = %app_name, "undeploying container");

        let _ = self
            .docker
            .stop_container(&container_name, Some(StopContainerOptions { t: 10 }))
            .await;

        self.docker
            .remove_container(
                &container_name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| AgentError::Container(format!("remove: {e}")))?;

        info!(app = %app_name, "container removed");
        Ok(())
    }

    /// Get the current deployment if any.
    pub async fn current_deployment(&self) -> Result<Option<DeploymentInfo>, AgentError> {
        let mut filters = HashMap::new();
        filters.insert("name".to_string(), vec!["ee-".to_string()]);

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await
            .map_err(|e| AgentError::Container(format!("list: {e}")))?;

        if let Some(container) = containers.first() {
            let name = container
                .names
                .as_ref()
                .and_then(|n| n.first())
                .map(|n| {
                    n.trim_start_matches('/')
                        .trim_start_matches("ee-")
                        .to_string()
                })
                .unwrap_or_default();

            let image = container.image.clone().unwrap_or_default();
            let running = container.state.as_deref() == Some("running");

            Ok(Some(DeploymentInfo {
                app_name: name,
                image,
                status: if running {
                    DeploymentStatus::Running
                } else {
                    DeploymentStatus::Stopped
                },
                tunnel_url: None,
                deployed_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    }
}
