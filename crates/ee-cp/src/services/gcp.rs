use std::env;

use ee_common::error::{AppError, AppResult};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Staging,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpConfig {
    pub staging_project_id: String,
    pub production_project_id: String,
    pub staging_zone: String,
    pub production_zone: String,
    pub staging_machine_type: String,
    pub production_machine_type: String,
    pub network: String,
    pub subnetwork: String,
    pub staging_service_account_email: String,
    pub production_service_account_email: String,
}

impl GcpConfig {
    pub fn from_env() -> AppResult<Self> {
        Ok(Self {
            staging_project_id: required_from(
                &[
                    "STAGING_GCP_PROJECT_ID",
                    "GCP_STAGING_PROJECT_ID",
                    "GCP_PROJECT_ID",
                ],
                "staging project id",
            )?,
            production_project_id: required_from(
                &[
                    "PRODUCTION_GCP_PROJECT_ID",
                    "GCP_PRODUCTION_PROJECT_ID",
                    "GCP_PROJECT_ID",
                ],
                "production project id",
            )?,
            staging_zone: zone_from_env(Environment::Staging)
                .unwrap_or_else(|| "us-central1-a".to_string()),
            production_zone: zone_from_env(Environment::Production)
                .unwrap_or_else(|| "us-central1-f".to_string()),
            staging_machine_type: machine_type_from_env(Environment::Staging)
                .unwrap_or_else(|| "c3-standard-4".to_string()),
            production_machine_type: machine_type_from_env(Environment::Production)
                .unwrap_or_else(|| "c3-standard-4".to_string()),
            network: first_env(&["GCP_NETWORK"]).unwrap_or_else(|| "default".to_string()),
            subnetwork: first_env(&["GCP_SUBNETWORK"]).unwrap_or_else(|| "default".to_string()),
            staging_service_account_email: required_service_account_email(Environment::Staging)?,
            production_service_account_email: required_service_account_email(
                Environment::Production,
            )?,
        })
    }

    pub fn project_for(&self, env: Environment) -> &str {
        match env {
            Environment::Staging => &self.staging_project_id,
            Environment::Production => &self.production_project_id,
        }
    }

    pub fn zone_for(&self, env: Environment) -> &str {
        match env {
            Environment::Staging => &self.staging_zone,
            Environment::Production => &self.production_zone,
        }
    }

    pub fn machine_type_for(&self, env: Environment) -> &str {
        match env {
            Environment::Staging => &self.staging_machine_type,
            Environment::Production => &self.production_machine_type,
        }
    }

    pub fn service_account_email_for(&self, env: Environment) -> &str {
        match env {
            Environment::Staging => &self.staging_service_account_email,
            Environment::Production => &self.production_service_account_email,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GcpService {
    config: GcpConfig,
}

impl GcpService {
    pub fn new(config: GcpConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &GcpConfig {
        &self.config
    }

    pub fn build_tdx_instance_insert_payload(
        &self,
        env: Environment,
        instance_name: &str,
        machine_type: &str,
        source_image: &str,
        startup_script: &str,
    ) -> Value {
        json!({
            "name": instance_name,
            "machineType": format!("zones/{}/machineTypes/{}", self.config.zone_for(env), machine_type),
            "networkInterfaces": [{
                "network": format!("global/networks/{}", self.config.network),
                "subnetwork": format!("regions/{}/subnetworks/{}", region_from_zone(self.config.zone_for(env)), self.config.subnetwork)
            }],
            "disks": [{
                "boot": true,
                "autoDelete": true,
                "initializeParams": {
                    "sourceImage": source_image
                }
            }],
            "metadata": {
                "items": [{"key": "startup-script", "value": startup_script}]
            },
            "serviceAccounts": [{
                "email": self.config.service_account_email_for(env),
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
            }],
            "confidentialInstanceConfig": {
                "enableConfidentialCompute": true,
                "confidentialInstanceType": "TDX"
            },
            "labels": {
                "easyenclave": "managed",
                "environment": match env {
                    Environment::Staging => "staging",
                    Environment::Production => "production"
                }
            }
        })
    }
}

fn required_from(keys: &[&str], label: &str) -> AppResult<String> {
    first_env(keys).ok_or_else(|| {
        AppError::Config(format!(
            "missing required {label}; checked env vars: {}",
            keys.join(", ")
        ))
    })
}

fn required_service_account_email(env_name: Environment) -> AppResult<String> {
    let (email_keys, key_keys, label) = match env_name {
        Environment::Staging => (
            &[
                "STAGING_GCP_SERVICE_ACCOUNT_EMAIL",
                "GCP_SERVICE_ACCOUNT_EMAIL",
            ][..],
            &["STAGING_GCP_SERVICE_ACCOUNT_KEY", "GCP_SERVICE_ACCOUNT_KEY"][..],
            "staging service account email",
        ),
        Environment::Production => (
            &[
                "PRODUCTION_GCP_SERVICE_ACCOUNT_EMAIL",
                "GCP_SERVICE_ACCOUNT_EMAIL",
            ][..],
            &[
                "PRODUCTION_GCP_SERVICE_ACCOUNT_KEY",
                "GCP_SERVICE_ACCOUNT_KEY",
            ][..],
            "production service account email",
        ),
    };

    if let Some(email) = first_env(email_keys) {
        return Ok(email);
    }

    for key_var in key_keys {
        if let Ok(key_json) = env::var(key_var) {
            if let Some(email) = service_account_email_from_key_json(&key_json) {
                return Ok(email);
            }
        }
    }

    Err(AppError::Config(format!(
        "missing required {label}; set one of [{}] or provide parseable key JSON in [{}]",
        email_keys.join(", "),
        key_keys.join(", ")
    )))
}

fn zone_from_env(env_name: Environment) -> Option<String> {
    let direct = match env_name {
        Environment::Staging => first_env(&[
            "STAGING_GCP_ZONE",
            "GCP_STAGING_ZONE",
            "STAGING_GCP_IMAGE_BUILD_ZONE",
        ]),
        Environment::Production => first_env(&[
            "PRODUCTION_GCP_ZONE",
            "GCP_PRODUCTION_ZONE",
            "PRODUCTION_GCP_IMAGE_BUILD_ZONE",
        ]),
    };

    direct.or_else(|| first_zone_from_list(&first_env(&["GCP_ZONE"]).unwrap_or_default()))
}

fn machine_type_from_env(env_name: Environment) -> Option<String> {
    match env_name {
        Environment::Staging => first_env(&[
            "STAGING_GCP_MACHINE_TYPE",
            "GCP_STAGING_MACHINE_TYPE",
            "GCP_MACHINE_TYPE",
        ]),
        Environment::Production => first_env(&[
            "PRODUCTION_GCP_MACHINE_TYPE",
            "GCP_PRODUCTION_MACHINE_TYPE",
            "GCP_MACHINE_TYPE",
        ]),
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

fn first_zone_from_list(value: &str) -> Option<String> {
    value
        .split(',')
        .map(str::trim)
        .find(|v| !v.is_empty())
        .map(ToString::to_string)
}

fn service_account_email_from_key_json(key_json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(key_json).ok()?;
    value
        .get("client_email")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn region_from_zone(zone: &str) -> String {
    let mut parts: Vec<&str> = zone.split('-').collect();
    if parts.len() >= 3 {
        let _ = parts.pop();
    }
    parts.join("-")
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{service_account_email_from_key_json, Environment, GcpConfig, GcpService};

    fn test_config() -> GcpConfig {
        GcpConfig {
            staging_project_id: "proj-staging".to_string(),
            production_project_id: "proj-prod".to_string(),
            staging_zone: "us-central1-a".to_string(),
            production_zone: "us-east1-b".to_string(),
            staging_machine_type: "c3-standard-4".to_string(),
            production_machine_type: "c3-standard-8".to_string(),
            network: "vpc-main".to_string(),
            subnetwork: "subnet-main".to_string(),
            staging_service_account_email: "staging-sa@proj.iam.gserviceaccount.com".to_string(),
            production_service_account_email: "prod-sa@proj.iam.gserviceaccount.com".to_string(),
        }
    }

    #[test]
    fn resolves_project_and_zone_by_environment() {
        let cfg = test_config();
        assert_eq!(cfg.project_for(Environment::Staging), "proj-staging");
        assert_eq!(cfg.project_for(Environment::Production), "proj-prod");
        assert_eq!(cfg.zone_for(Environment::Staging), "us-central1-a");
        assert_eq!(cfg.zone_for(Environment::Production), "us-east1-b");
        assert_eq!(cfg.machine_type_for(Environment::Staging), "c3-standard-4");
        assert_eq!(
            cfg.machine_type_for(Environment::Production),
            "c3-standard-8"
        );
    }

    #[test]
    fn builds_tdx_payload() {
        let svc = GcpService::new(test_config());
        let payload = svc.build_tdx_instance_insert_payload(
            Environment::Staging,
            "ee-staging-001",
            "c3-standard-4",
            "projects/example/global/images/family/ee-tdx",
            "echo hello",
        );

        let ci_cfg = payload["confidentialInstanceConfig"].clone();
        assert_eq!(ci_cfg["enableConfidentialCompute"], Value::Bool(true));
        assert_eq!(
            ci_cfg["confidentialInstanceType"],
            Value::String("TDX".to_string())
        );
        assert_eq!(
            payload["labels"]["environment"],
            Value::String("staging".to_string())
        );
        assert_eq!(
            payload["serviceAccounts"][0]["email"],
            Value::String("staging-sa@proj.iam.gserviceaccount.com".to_string())
        );
    }

    #[test]
    fn parses_service_account_email_from_key_json() {
        let raw =
            r#"{"type":"service_account","client_email":"cp@example.iam.gserviceaccount.com"}"#;
        let email = service_account_email_from_key_json(raw).expect("email");
        assert_eq!(email, "cp@example.iam.gserviceaccount.com");
    }
}
