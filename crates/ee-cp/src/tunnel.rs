use ee_common::{config::CpConfig, error::AppResult};

#[derive(Clone)]
pub struct CloudflareClient {
    _config: CpConfig,
}

#[derive(Debug, Clone)]
pub struct TunnelAssignment {
    pub tunnel_token: String,
    pub hostname: String,
}

impl CloudflareClient {
    pub fn new(config: CpConfig) -> Self {
        Self { _config: config }
    }

    pub async fn create_agent_tunnel(
        &self,
        vm_name: &str,
        domain: &str,
    ) -> AppResult<TunnelAssignment> {
        let slug = vm_name.replace('_', "-");
        Ok(TunnelAssignment {
            tunnel_token: format!("local-token-{slug}"),
            hostname: format!("{slug}.{domain}"),
        })
    }

    pub async fn delete_agent_tunnel(&self, _agent_id: &str) -> AppResult<()> {
        Ok(())
    }
}
