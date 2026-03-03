use std::collections::HashMap;

use bollard::container::{
    Config as ContainerConfig, CreateContainerOptions, RemoveContainerOptions,
    StartContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};
use bollard::Docker;
use easyenclave::common::error::{AppError, AppResult};
use futures_util::TryStreamExt;
use tokio::runtime::Runtime;

#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub name: String,
    pub image: String,
    pub env: Vec<(String, String)>,
    pub ports: Vec<PortMapping>,
    pub binds: Vec<String>,
    pub restart_unless_stopped: bool,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

impl PortMapping {
    pub fn tcp(host_port: u16, container_port: u16) -> Self {
        Self {
            host_port,
            container_port,
            protocol: "tcp".to_string(),
        }
    }
}

#[allow(dead_code)]
pub trait OciRuntimeEngine {
    fn backend_name(&self) -> &'static str;
    fn launch(&self, request: &LaunchRequest) -> AppResult<()>;
    fn stop(&self, name: &str) -> AppResult<()>;
}

#[derive(Debug, Clone)]
pub struct DockerOciRuntime;

impl DockerOciRuntime {
    pub fn new() -> Self {
        Self
    }
}

impl OciRuntimeEngine for DockerOciRuntime {
    fn backend_name(&self) -> &'static str {
        "docker-api"
    }

    fn launch(&self, request: &LaunchRequest) -> AppResult<()> {
        let req = request.clone();
        with_runtime(async move {
            let docker = Docker::connect_with_local_defaults()
                .map_err(|e| AppError::External(format!("docker connect failed: {e}")))?;

            let _ = docker
                .remove_container(
                    &req.name,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;

            let opts = Some(CreateImageOptions {
                from_image: req.image.as_str(),
                ..Default::default()
            });
            let mut stream = docker.create_image(opts, None, None);
            while stream
                .try_next()
                .await
                .map_err(|e| AppError::External(format!("docker image pull failed: {e}")))?
                .is_some()
            {}

            let mut exposed_ports: HashMap<String, HashMap<(), ()>> = HashMap::new();
            let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
            for mapping in &req.ports {
                let key = format!("{}/{}", mapping.container_port, mapping.protocol);
                exposed_ports.insert(key.clone(), HashMap::new());
                port_bindings.insert(
                    key,
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_string()),
                        host_port: Some(mapping.host_port.to_string()),
                    }]),
                );
            }

            let env: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let host_config = HostConfig {
                binds: if req.binds.is_empty() {
                    None
                } else {
                    Some(req.binds.clone())
                },
                port_bindings: if port_bindings.is_empty() {
                    None
                } else {
                    Some(port_bindings)
                },
                restart_policy: if req.restart_unless_stopped {
                    Some(RestartPolicy {
                        name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                        maximum_retry_count: None,
                    })
                } else {
                    None
                },
                ..Default::default()
            };

            let config = ContainerConfig {
                image: Some(req.image.clone()),
                env: if env.is_empty() { None } else { Some(env) },
                exposed_ports: if exposed_ports.is_empty() {
                    None
                } else {
                    Some(exposed_ports)
                },
                host_config: Some(host_config),
                ..Default::default()
            };

            docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: req.name.as_str(),
                        platform: None,
                    }),
                    config,
                )
                .await
                .map_err(|e| AppError::External(format!("docker create container failed: {e}")))?;

            docker
                .start_container(&req.name, None::<StartContainerOptions<String>>)
                .await
                .map_err(|e| AppError::External(format!("docker start container failed: {e}")))?;

            Ok(())
        })
    }

    fn stop(&self, name: &str) -> AppResult<()> {
        let name = name.to_string();
        with_runtime(async move {
            let docker = Docker::connect_with_local_defaults()
                .map_err(|e| AppError::External(format!("docker connect failed: {e}")))?;
            docker
                .remove_container(
                    &name,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
                .map_err(|e| AppError::External(format!("docker remove container failed: {e}")))?;
            Ok(())
        })
    }
}

fn with_runtime<F>(future: F) -> AppResult<()>
where
    F: std::future::Future<Output = AppResult<()>>,
{
    let rt = Runtime::new()
        .map_err(|e| AppError::External(format!("failed to initialize tokio runtime: {e}")))?;
    rt.block_on(future)
}
