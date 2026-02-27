use std::env;

use base64::Engine as _;
use ee_common::error::{AppError, AppResult};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareConfig {
    pub account_id: String,
    pub zone_id: String,
    pub api_token: String,
    pub domain: String,
    pub api_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRegistration {
    pub tunnel_id: String,
    pub tunnel_token: String,
    pub hostname: String,
}

#[derive(Clone)]
pub struct TunnelService {
    config: Option<CloudflareConfig>,
    client: reqwest::Client,
    runtime_env: RuntimeEnv,
}

impl TunnelService {
    pub fn from_env() -> Self {
        let runtime_env = RuntimeEnv::from_env();
        Self {
            config: load_config_from_env(runtime_env),
            client: reqwest::Client::new(),
            runtime_env,
        }
    }

    pub fn disabled_for_tests() -> Self {
        Self {
            config: None,
            client: reqwest::Client::new(),
            runtime_env: RuntimeEnv::Local,
        }
    }

    pub fn with_config(config: CloudflareConfig) -> Self {
        Self {
            config: Some(config),
            client: reqwest::Client::new(),
            runtime_env: RuntimeEnv::Local,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.config.is_some()
    }

    pub fn validate_runtime_requirements(&self) -> AppResult<()> {
        if self.runtime_env.is_protected() && self.config.is_none() {
            return Err(AppError::Config(
                "cloudflare tunnel configuration is required in staging/production; set env vars for account_id, zone_id, api_token, and domain"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub async fn create_tunnel_for_agent(
        &self,
        agent_id: Uuid,
        label_hint: Option<&str>,
    ) -> AppResult<TunnelRegistration> {
        let Some(config) = &self.config else {
            if self.runtime_env.is_protected() {
                return Err(AppError::Config(
                    "cloudflare tunnel configuration is required in staging/production".to_string(),
                ));
            }
            let short = agent_id.simple().to_string();
            let fallback_label = format!("agent-{}", &short[..12]);
            let label = sanitize_dns_label(label_hint, &fallback_label);
            return Ok(TunnelRegistration {
                tunnel_id: format!("pending-{short}"),
                tunnel_token: format!("pending-tunnel-token-{short}"),
                hostname: format!("{label}.pending.easyenclave.invalid"),
            });
        };

        let short = agent_id.simple().to_string();
        let fallback_label = format!("agent-{}", &short[..12]);
        let label = sanitize_dns_label(label_hint, &fallback_label);
        let tunnel_name = label.clone();
        let secret = base64::engine::general_purpose::STANDARD.encode(Uuid::new_v4().as_bytes());

        let tunnel_id = self.create_tunnel(config, &tunnel_name, &secret).await?;
        let tunnel_token = match self.get_tunnel_token(config, &tunnel_id).await {
            Ok(token) => token,
            Err(err) => {
                let _ = self.delete_tunnel(config, &tunnel_id).await;
                return Err(err);
            }
        };

        let hostname = format!("{label}.{}", config.domain);
        if let Err(err) = self
            .create_dns_record(
                config,
                &hostname,
                &format!("{}.cfargotunnel.com", tunnel_id),
            )
            .await
        {
            let _ = self.delete_tunnel(config, &tunnel_id).await;
            return Err(err);
        }

        Ok(TunnelRegistration {
            tunnel_id,
            tunnel_token,
            hostname,
        })
    }

    pub async fn delete_tunnel_for_agent(&self, tunnel_id: &str, hostname: &str) -> AppResult<()> {
        let Some(config) = &self.config else {
            if self.runtime_env.is_protected() {
                return Err(AppError::Config(
                    "cloudflare tunnel configuration is required in staging/production".to_string(),
                ));
            }
            return Ok(());
        };

        if let Some(dns_record_id) = self.find_dns_record_id(config, hostname).await? {
            self.delete_dns_record(config, &dns_record_id).await?;
        }
        self.delete_tunnel(config, tunnel_id).await
    }

    async fn create_tunnel(
        &self,
        cfg: &CloudflareConfig,
        name: &str,
        secret: &str,
    ) -> AppResult<String> {
        let url = format!(
            "{}/accounts/{}/cfd_tunnel",
            cfg.api_base_url, cfg.account_id
        );
        let res = self
            .client
            .post(url)
            .bearer_auth(&cfg.api_token)
            .json(&json!({"name": name, "secret": secret, "config_src": "local"}))
            .send()
            .await
            .map_err(|e| AppError::External(format!("cloudflare create tunnel failed: {e}")))?;

        let body = parse_success_json(res).await?;
        body.get("result")
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| {
                AppError::External("cloudflare create tunnel missing result.id".to_string())
            })
    }

    async fn get_tunnel_token(&self, cfg: &CloudflareConfig, tunnel_id: &str) -> AppResult<String> {
        let url = format!(
            "{}/accounts/{}/cfd_tunnel/{}/token",
            cfg.api_base_url, cfg.account_id, tunnel_id
        );
        let res = self
            .client
            .get(url)
            .bearer_auth(&cfg.api_token)
            .send()
            .await
            .map_err(|e| AppError::External(format!("cloudflare get tunnel token failed: {e}")))?;

        let body = parse_success_json(res).await?;
        body.get("result")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| {
                AppError::External("cloudflare tunnel token missing result string".to_string())
            })
    }

    async fn create_dns_record(
        &self,
        cfg: &CloudflareConfig,
        name: &str,
        content: &str,
    ) -> AppResult<()> {
        let url = format!("{}/zones/{}/dns_records", cfg.api_base_url, cfg.zone_id);
        let res = self
            .client
            .post(url)
            .bearer_auth(&cfg.api_token)
            .json(&json!({
                "type": "CNAME",
                "name": name,
                "content": content,
                "proxied": true,
                "ttl": 1
            }))
            .send()
            .await
            .map_err(|e| AppError::External(format!("cloudflare create dns failed: {e}")))?;

        let _ = parse_success_json(res).await?;
        Ok(())
    }

    async fn find_dns_record_id(
        &self,
        cfg: &CloudflareConfig,
        name: &str,
    ) -> AppResult<Option<String>> {
        let url = format!("{}/zones/{}/dns_records", cfg.api_base_url, cfg.zone_id);
        let res = self
            .client
            .get(url)
            .bearer_auth(&cfg.api_token)
            .query(&[("type", "CNAME"), ("name", name)])
            .send()
            .await
            .map_err(|e| AppError::External(format!("cloudflare list dns failed: {e}")))?;

        let body = parse_success_json(res).await?;
        let record_id = body
            .get("result")
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("id"))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        Ok(record_id)
    }

    async fn delete_dns_record(
        &self,
        cfg: &CloudflareConfig,
        dns_record_id: &str,
    ) -> AppResult<()> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            cfg.api_base_url, cfg.zone_id, dns_record_id
        );
        let res = self
            .client
            .delete(url)
            .bearer_auth(&cfg.api_token)
            .send()
            .await
            .map_err(|e| AppError::External(format!("cloudflare delete dns failed: {e}")))?;
        let _ = parse_success_json(res).await?;
        Ok(())
    }

    async fn delete_tunnel(&self, cfg: &CloudflareConfig, tunnel_id: &str) -> AppResult<()> {
        let url = format!(
            "{}/accounts/{}/cfd_tunnel/{}",
            cfg.api_base_url, cfg.account_id, tunnel_id
        );
        let res = self
            .client
            .delete(url)
            .bearer_auth(&cfg.api_token)
            .send()
            .await
            .map_err(|e| AppError::External(format!("cloudflare delete tunnel failed: {e}")))?;
        let _ = parse_success_json(res).await?;
        Ok(())
    }
}

fn load_config_from_env(runtime_env: RuntimeEnv) -> Option<CloudflareConfig> {
    let account_id = first_env(account_id_keys(runtime_env))?;
    let zone_id = first_env(zone_id_keys(runtime_env))?;
    let api_token = first_env(api_token_keys(runtime_env))?;
    let domain = first_env(domain_keys(runtime_env)).or_else(|| default_domain(runtime_env))?;
    let api_base_url = first_env(api_base_url_keys(runtime_env))
        .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".to_string());

    Some(CloudflareConfig {
        account_id,
        zone_id,
        api_token,
        domain,
        api_base_url,
    })
}

async fn parse_success_json(res: reqwest::Response) -> AppResult<Value> {
    let status = res.status();
    let body: Value = res
        .json()
        .await
        .map_err(|e| AppError::External(format!("cloudflare response parse failed: {e}")))?;

    if !status.is_success() {
        return Err(AppError::External(format!(
            "cloudflare http {}: {}",
            status, body
        )));
    }

    let success = body
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !success {
        return Err(AppError::External(format!("cloudflare api error: {body}")));
    }

    Ok(body)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeEnv {
    Local,
    Staging,
    Production,
}

impl RuntimeEnv {
    fn from_env() -> Self {
        let value = env::var("EASYENCLAVE_ENV")
            .or_else(|_| env::var("CP_ENV"))
            .unwrap_or_else(|_| "local".to_string())
            .to_ascii_lowercase();
        match value.as_str() {
            "staging" => Self::Staging,
            "production" | "prod" => Self::Production,
            _ => Self::Local,
        }
    }

    fn is_protected(self) -> bool {
        matches!(self, Self::Staging | Self::Production)
    }
}

fn first_env(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn default_domain(env_name: RuntimeEnv) -> Option<String> {
    match env_name {
        RuntimeEnv::Staging => Some("stage.app.easyenclave.com".to_string()),
        RuntimeEnv::Production => Some("prod.app.easyenclave.com".to_string()),
        RuntimeEnv::Local => None,
    }
}

fn sanitize_dns_label(label_hint: Option<&str>, fallback: &str) -> String {
    let raw = label_hint.unwrap_or(fallback);
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if prev_dash || out.is_empty() {
                continue;
            }
            prev_dash = true;
            out.push('-');
        } else {
            prev_dash = false;
            out.push(mapped);
        }
        if out.len() >= 63 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

fn account_id_keys(env_name: RuntimeEnv) -> &'static [&'static str] {
    match env_name {
        RuntimeEnv::Staging => &["STAGING_CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID"],
        RuntimeEnv::Production => &["PRODUCTION_CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID"],
        RuntimeEnv::Local => &["CLOUDFLARE_ACCOUNT_ID"],
    }
}

fn zone_id_keys(env_name: RuntimeEnv) -> &'static [&'static str] {
    match env_name {
        RuntimeEnv::Staging => &["STAGING_CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ZONE_ID"],
        RuntimeEnv::Production => &["PRODUCTION_CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ZONE_ID"],
        RuntimeEnv::Local => &["CLOUDFLARE_ZONE_ID"],
    }
}

fn api_token_keys(env_name: RuntimeEnv) -> &'static [&'static str] {
    match env_name {
        RuntimeEnv::Staging => &["STAGING_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN"],
        RuntimeEnv::Production => &["PRODUCTION_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN"],
        RuntimeEnv::Local => &["CLOUDFLARE_API_TOKEN"],
    }
}

fn domain_keys(env_name: RuntimeEnv) -> &'static [&'static str] {
    match env_name {
        RuntimeEnv::Staging => &[
            "STAGING_CLOUDFLARE_DOMAIN",
            "CLOUDFLARE_DOMAIN",
            "CP_DOMAIN",
        ],
        RuntimeEnv::Production => &[
            "PRODUCTION_CLOUDFLARE_DOMAIN",
            "CLOUDFLARE_DOMAIN",
            "CP_DOMAIN",
        ],
        RuntimeEnv::Local => &["CLOUDFLARE_DOMAIN", "CP_DOMAIN"],
    }
}

fn api_base_url_keys(env_name: RuntimeEnv) -> &'static [&'static str] {
    match env_name {
        RuntimeEnv::Staging => &["STAGING_CLOUDFLARE_API_BASE_URL", "CLOUDFLARE_API_BASE_URL"],
        RuntimeEnv::Production => &[
            "PRODUCTION_CLOUDFLARE_API_BASE_URL",
            "CLOUDFLARE_API_BASE_URL",
        ],
        RuntimeEnv::Local => &["CLOUDFLARE_API_BASE_URL"],
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::sync::Mutex;

    use ee_common::error::AppError;
    use mockito::Server;

    use super::{CloudflareConfig, TunnelService};
    use uuid::Uuid;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn configured_service_creates_tunnel_dns_and_returns_token() {
        let mut server = Server::new_async().await;

        let _create_tunnel = server
            .mock("POST", "/accounts/acct/cfd_tunnel")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"tunnel-123"}}"#)
            .create_async()
            .await;

        let _get_token = server
            .mock("GET", "/accounts/acct/cfd_tunnel/tunnel-123/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":"token-abc"}"#)
            .create_async()
            .await;

        let _create_dns = server
            .mock("POST", "/zones/zone/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"dns-1"}}"#)
            .create_async()
            .await;

        let svc = TunnelService::with_config(CloudflareConfig {
            account_id: "acct".to_string(),
            zone_id: "zone".to_string(),
            api_token: "token".to_string(),
            domain: "example.com".to_string(),
            api_base_url: server.url(),
        });

        let reg = svc
            .create_tunnel_for_agent(Uuid::new_v4(), None)
            .await
            .expect("register");

        assert_eq!(reg.tunnel_id, "tunnel-123");
        assert_eq!(reg.tunnel_token, "token-abc");
        assert!(reg.hostname.ends_with(".example.com"));
    }

    #[tokio::test]
    async fn disabled_service_returns_placeholder_values() {
        let svc = TunnelService::disabled_for_tests();
        let reg = svc
            .create_tunnel_for_agent(Uuid::new_v4(), None)
            .await
            .expect("register");

        assert!(reg.tunnel_id.starts_with("pending-"));
        assert!(reg.hostname.ends_with(".pending.easyenclave.invalid"));
    }

    #[tokio::test]
    async fn configured_service_deletes_dns_and_tunnel() {
        let mut server = Server::new_async().await;

        let _find_dns = server
            .mock("GET", "/zones/zone/dns_records")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("type".to_string(), "CNAME".to_string()),
                mockito::Matcher::UrlEncoded(
                    "name".to_string(),
                    "agent-abc.example.com".to_string(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":[{"id":"dns-1"}]}"#)
            .create_async()
            .await;

        let _delete_dns = server
            .mock("DELETE", "/zones/zone/dns_records/dns-1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"dns-1"}}"#)
            .create_async()
            .await;

        let _delete_tunnel = server
            .mock("DELETE", "/accounts/acct/cfd_tunnel/tunnel-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"tunnel-123"}}"#)
            .create_async()
            .await;

        let svc = TunnelService::with_config(CloudflareConfig {
            account_id: "acct".to_string(),
            zone_id: "zone".to_string(),
            api_token: "token".to_string(),
            domain: "example.com".to_string(),
            api_base_url: server.url(),
        });

        svc.delete_tunnel_for_agent("tunnel-123", "agent-abc.example.com")
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn create_tunnel_rolls_back_on_token_failure() {
        let mut server = Server::new_async().await;

        let _create_tunnel = server
            .mock("POST", "/accounts/acct/cfd_tunnel")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"tunnel-123"}}"#)
            .create_async()
            .await;

        let _get_token = server
            .mock("GET", "/accounts/acct/cfd_tunnel/tunnel-123/token")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":false,"errors":[{"message":"boom"}]}"#)
            .create_async()
            .await;

        let _delete_tunnel = server
            .mock("DELETE", "/accounts/acct/cfd_tunnel/tunnel-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"tunnel-123"}}"#)
            .create_async()
            .await;

        let svc = TunnelService::with_config(CloudflareConfig {
            account_id: "acct".to_string(),
            zone_id: "zone".to_string(),
            api_token: "token".to_string(),
            domain: "example.com".to_string(),
            api_base_url: server.url(),
        });

        let err = svc
            .create_tunnel_for_agent(Uuid::new_v4(), None)
            .await
            .expect_err("create should fail");
        assert!(err.to_string().contains("cloudflare http 500"));
    }

    #[tokio::test]
    async fn create_tunnel_rolls_back_on_dns_failure() {
        let mut server = Server::new_async().await;

        let _create_tunnel = server
            .mock("POST", "/accounts/acct/cfd_tunnel")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"tunnel-123"}}"#)
            .create_async()
            .await;

        let _get_token = server
            .mock("GET", "/accounts/acct/cfd_tunnel/tunnel-123/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":"token-abc"}"#)
            .create_async()
            .await;

        let _create_dns = server
            .mock("POST", "/zones/zone/dns_records")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":false,"errors":[{"message":"boom"}]}"#)
            .create_async()
            .await;

        let _delete_tunnel = server
            .mock("DELETE", "/accounts/acct/cfd_tunnel/tunnel-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"result":{"id":"tunnel-123"}}"#)
            .create_async()
            .await;

        let svc = TunnelService::with_config(CloudflareConfig {
            account_id: "acct".to_string(),
            zone_id: "zone".to_string(),
            api_token: "token".to_string(),
            domain: "example.com".to_string(),
            api_base_url: server.url(),
        });

        let err = svc
            .create_tunnel_for_agent(Uuid::new_v4(), None)
            .await
            .expect_err("create should fail");
        assert!(err.to_string().contains("cloudflare http 500"));
    }

    #[test]
    fn staging_requires_cloudflare_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old_env = env::var("EASYENCLAVE_ENV").ok();
        let old_account = env::var("STAGING_CLOUDFLARE_ACCOUNT_ID").ok();
        let old_zone = env::var("STAGING_CLOUDFLARE_ZONE_ID").ok();
        let old_token = env::var("STAGING_CLOUDFLARE_API_TOKEN").ok();
        let old_domain = env::var("STAGING_CLOUDFLARE_DOMAIN").ok();
        let old_generic_account = env::var("CLOUDFLARE_ACCOUNT_ID").ok();
        let old_generic_zone = env::var("CLOUDFLARE_ZONE_ID").ok();
        let old_generic_token = env::var("CLOUDFLARE_API_TOKEN").ok();
        let old_generic_domain = env::var("CLOUDFLARE_DOMAIN").ok();

        env::set_var("EASYENCLAVE_ENV", "staging");
        env::remove_var("STAGING_CLOUDFLARE_ACCOUNT_ID");
        env::remove_var("STAGING_CLOUDFLARE_ZONE_ID");
        env::remove_var("STAGING_CLOUDFLARE_API_TOKEN");
        env::remove_var("STAGING_CLOUDFLARE_DOMAIN");
        env::remove_var("CLOUDFLARE_ACCOUNT_ID");
        env::remove_var("CLOUDFLARE_ZONE_ID");
        env::remove_var("CLOUDFLARE_API_TOKEN");
        env::remove_var("CLOUDFLARE_DOMAIN");

        let svc = TunnelService::from_env();
        assert!(!svc.is_configured());
        let err = svc
            .validate_runtime_requirements()
            .expect_err("should require cloudflare config");
        match err {
            AppError::Config(message) => {
                assert!(message.contains("required in staging/production"))
            }
            other => panic!("expected config error, got {other}"),
        }

        restore("EASYENCLAVE_ENV", old_env);
        restore("STAGING_CLOUDFLARE_ACCOUNT_ID", old_account);
        restore("STAGING_CLOUDFLARE_ZONE_ID", old_zone);
        restore("STAGING_CLOUDFLARE_API_TOKEN", old_token);
        restore("STAGING_CLOUDFLARE_DOMAIN", old_domain);
        restore("CLOUDFLARE_ACCOUNT_ID", old_generic_account);
        restore("CLOUDFLARE_ZONE_ID", old_generic_zone);
        restore("CLOUDFLARE_API_TOKEN", old_generic_token);
        restore("CLOUDFLARE_DOMAIN", old_generic_domain);
    }

    #[test]
    fn staging_prefixed_cloudflare_vars_are_accepted() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old_env = env::var("EASYENCLAVE_ENV").ok();
        let old_account = env::var("STAGING_CLOUDFLARE_ACCOUNT_ID").ok();
        let old_zone = env::var("STAGING_CLOUDFLARE_ZONE_ID").ok();
        let old_token = env::var("STAGING_CLOUDFLARE_API_TOKEN").ok();
        let old_domain = env::var("STAGING_CLOUDFLARE_DOMAIN").ok();
        let old_generic_account = env::var("CLOUDFLARE_ACCOUNT_ID").ok();
        let old_generic_zone = env::var("CLOUDFLARE_ZONE_ID").ok();
        let old_generic_token = env::var("CLOUDFLARE_API_TOKEN").ok();
        let old_generic_domain = env::var("CLOUDFLARE_DOMAIN").ok();

        env::set_var("EASYENCLAVE_ENV", "staging");
        env::set_var("STAGING_CLOUDFLARE_ACCOUNT_ID", "acct-staging");
        env::set_var("STAGING_CLOUDFLARE_ZONE_ID", "zone-staging");
        env::set_var("STAGING_CLOUDFLARE_API_TOKEN", "token-staging");
        env::set_var("STAGING_CLOUDFLARE_DOMAIN", "staging.example.com");
        env::remove_var("CLOUDFLARE_ACCOUNT_ID");
        env::remove_var("CLOUDFLARE_ZONE_ID");
        env::remove_var("CLOUDFLARE_API_TOKEN");
        env::remove_var("CLOUDFLARE_DOMAIN");

        let svc = TunnelService::from_env();
        assert!(svc.is_configured());
        svc.validate_runtime_requirements()
            .expect("staging vars should satisfy requirements");

        restore("EASYENCLAVE_ENV", old_env);
        restore("STAGING_CLOUDFLARE_ACCOUNT_ID", old_account);
        restore("STAGING_CLOUDFLARE_ZONE_ID", old_zone);
        restore("STAGING_CLOUDFLARE_API_TOKEN", old_token);
        restore("STAGING_CLOUDFLARE_DOMAIN", old_domain);
        restore("CLOUDFLARE_ACCOUNT_ID", old_generic_account);
        restore("CLOUDFLARE_ZONE_ID", old_generic_zone);
        restore("CLOUDFLARE_API_TOKEN", old_generic_token);
        restore("CLOUDFLARE_DOMAIN", old_generic_domain);
    }

    #[test]
    fn staging_uses_default_domain_when_missing() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old_env = env::var("EASYENCLAVE_ENV").ok();
        let old_account = env::var("STAGING_CLOUDFLARE_ACCOUNT_ID").ok();
        let old_zone = env::var("STAGING_CLOUDFLARE_ZONE_ID").ok();
        let old_token = env::var("STAGING_CLOUDFLARE_API_TOKEN").ok();
        let old_domain = env::var("STAGING_CLOUDFLARE_DOMAIN").ok();
        let old_generic_domain = env::var("CLOUDFLARE_DOMAIN").ok();

        env::set_var("EASYENCLAVE_ENV", "staging");
        env::set_var("STAGING_CLOUDFLARE_ACCOUNT_ID", "acct-staging");
        env::set_var("STAGING_CLOUDFLARE_ZONE_ID", "zone-staging");
        env::set_var("STAGING_CLOUDFLARE_API_TOKEN", "token-staging");
        env::remove_var("STAGING_CLOUDFLARE_DOMAIN");
        env::remove_var("CLOUDFLARE_DOMAIN");

        let svc = TunnelService::from_env();
        assert!(svc.is_configured());
        svc.validate_runtime_requirements()
            .expect("default staging domain should satisfy requirements");

        restore("EASYENCLAVE_ENV", old_env);
        restore("STAGING_CLOUDFLARE_ACCOUNT_ID", old_account);
        restore("STAGING_CLOUDFLARE_ZONE_ID", old_zone);
        restore("STAGING_CLOUDFLARE_API_TOKEN", old_token);
        restore("STAGING_CLOUDFLARE_DOMAIN", old_domain);
        restore("CLOUDFLARE_DOMAIN", old_generic_domain);
    }

    fn restore(key: &str, value: Option<String>) {
        if let Some(value) = value {
            env::set_var(key, value);
        } else {
            env::remove_var(key);
        }
    }
}
