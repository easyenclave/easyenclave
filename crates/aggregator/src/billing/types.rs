use chrono::{DateTime, Utc};
use ee_common::types::VmSize;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listing {
    pub id: String,
    pub owner: String,
    pub size: VmSize,
    pub price_sats_per_hour: u64,
    pub tags: Vec<String>,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseRequest {
    pub listing_id: String,
    pub buyer: String,
    pub hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub listing_id: String,
    pub buyer: String,
    pub amount_sats: u64,
    pub status: InvoiceStatus,
    pub payment_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Expired,
    Refunded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub invoice_id: String,
    pub agent_id: String,
    pub buyer: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowStatus {
    pub invoice_id: String,
    pub amount_sats: u64,
    pub released: bool,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payout {
    pub id: String,
    pub operator: String,
    pub amount_sats: u64,
    pub period: String,
    pub status: PayoutStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Pending,
    Paid,
    Withheld,
}

/// Revenue split configuration.
#[derive(Debug, Clone)]
pub struct RevenueSplit {
    /// Platform fee as basis points (e.g. 1000 = 10%).
    pub platform_fee_bps: u32,
}

impl Default for RevenueSplit {
    fn default() -> Self {
        Self {
            platform_fee_bps: 1000,
        }
    }
}

impl RevenueSplit {
    /// Calculate operator and platform shares from a total amount.
    pub fn split(&self, total_sats: u64) -> (u64, u64) {
        let platform = total_sats * self.platform_fee_bps as u64 / 10_000;
        let operator = total_sats - platform;
        (operator, platform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revenue_split_default() {
        let split = RevenueSplit::default();
        let (operator, platform) = split.split(10_000);
        assert_eq!(operator, 9_000);
        assert_eq!(platform, 1_000);
    }

    #[test]
    fn test_revenue_split_custom() {
        let split = RevenueSplit {
            platform_fee_bps: 500,
        };
        let (operator, platform) = split.split(10_000);
        assert_eq!(operator, 9_500);
        assert_eq!(platform, 500);
    }
}
