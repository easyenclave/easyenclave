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
        owner: &str,
        domain: &str,
    ) -> AppResult<TunnelAssignment> {
        let vm_slug = slugify(vm_name, 24);
        let owner_slug = slugify(owner, 20);
        let label = format!("{}-{}", owner_slug, vm_slug);
        let short = &label[..label.len().min(32)];
        // Keep all PR/runtime hostnames in a dedicated subspace under easyenclave.com.
        let hostname = format!("{short}.weave.{domain}");

        Ok(TunnelAssignment {
            tunnel_token: format!("local-token-{short}"),
            hostname,
        })
    }

    pub async fn delete_agent_tunnel(&self, _agent_id: &str) -> AppResult<()> {
        Ok(())
    }
}

fn slugify(raw: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' || ch == ':' || ch == '/' || ch == '.' {
            out.push('-');
        }
    }
    let compact = out.trim_matches('-').replace("--", "-");
    let fallback = if compact.is_empty() {
        "node".to_owned()
    } else {
        compact
    };
    fallback[..fallback.len().min(max_len)].to_owned()
}
