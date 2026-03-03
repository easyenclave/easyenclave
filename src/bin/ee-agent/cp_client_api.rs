use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AgentChallengeResponse {
    pub nonce: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AgentRegisterResponse {
    pub agent_id: Uuid,
    pub tunnel_token: String,
    pub hostname: String,
}
