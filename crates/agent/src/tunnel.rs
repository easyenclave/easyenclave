//! Cloudflared tunnel management.
//!
//! Creates and manages Cloudflare Argo Tunnels for exposing deployed containers.

use crate::error::AgentError;
use tracing::{info, warn};

/// Manages a cloudflared tunnel for a deployment.
pub struct TunnelManager {
    api_token: String,
    account_id: String,
    domain: String,
    active_tunnel: Option<ActiveTunnel>,
}

struct ActiveTunnel {
    app_name: String,
    tunnel_id: String,
    hostname: String,
    child: Option<tokio::process::Child>,
}

impl TunnelManager {
    pub fn new(api_token: String, account_id: String, domain: String) -> Self {
        Self {
            api_token,
            account_id,
            domain,
            active_tunnel: None,
        }
    }

    /// Create a tunnel for the given app and local port.
    pub async fn create(
        &mut self,
        app_name: &str,
        local_port: u16,
    ) -> Result<String, AgentError> {
        let hostname = format!("{app_name}.{}", self.domain);
        info!(app = %app_name, %hostname, "creating cloudflare tunnel");

        // Use cloudflared quick tunnel or named tunnel
        let child = tokio::process::Command::new("cloudflared")
            .args([
                "tunnel",
                "--url",
                &format!("http://localhost:{local_port}"),
                "--hostname",
                &hostname,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| AgentError::Tunnel(format!("spawn cloudflared: {e}")))?;

        let tunnel_url = format!("https://{hostname}");

        self.active_tunnel = Some(ActiveTunnel {
            app_name: app_name.to_string(),
            tunnel_id: String::new(), // populated after tunnel creation
            hostname: hostname.clone(),
            child: Some(child),
        });

        info!(app = %app_name, %tunnel_url, "tunnel created");
        Ok(tunnel_url)
    }

    /// Destroy the active tunnel.
    pub async fn destroy(&mut self) -> Result<(), AgentError> {
        if let Some(mut tunnel) = self.active_tunnel.take() {
            info!(app = %tunnel.app_name, "destroying tunnel");
            if let Some(mut child) = tunnel.child.take() {
                let _ = child.kill().await;
            }
        }
        Ok(())
    }

    /// Get the active tunnel URL if any.
    pub fn active_url(&self) -> Option<String> {
        self.active_tunnel
            .as_ref()
            .map(|t| format!("https://{}", t.hostname))
    }
}
