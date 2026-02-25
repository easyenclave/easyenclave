//! Month-end SLA settlement: check uptime, payout or withhold.

use super::types::{Payout, PayoutStatus, RevenueSplit};
use chrono::{DateTime, Utc};
use tracing::info;

/// SLA threshold for payout (e.g. 99.5% uptime).
const SLA_THRESHOLD: f64 = 0.995;

/// Check SLA and determine payout.
pub fn settle(
    operator: &str,
    total_sats: u64,
    uptime_fraction: f64,
    period: &str,
    split: &RevenueSplit,
) -> Payout {
    let (operator_share, platform_share) = split.split(total_sats);

    let status = if uptime_fraction >= SLA_THRESHOLD {
        PayoutStatus::Paid
    } else {
        info!(
            operator,
            uptime_fraction, SLA_THRESHOLD, "SLA not met, withholding payout"
        );
        PayoutStatus::Withheld
    };

    Payout {
        id: uuid::Uuid::new_v4().to_string(),
        operator: operator.to_string(),
        amount_sats: operator_share,
        period: period.to_string(),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settle_above_sla() {
        let split = RevenueSplit::default();
        let payout = settle("operator1", 100_000, 0.999, "2026-01", &split);
        assert_eq!(payout.status, PayoutStatus::Paid);
        assert_eq!(payout.amount_sats, 90_000);
    }

    #[test]
    fn test_settle_below_sla() {
        let split = RevenueSplit::default();
        let payout = settle("operator1", 100_000, 0.99, "2026-01", &split);
        assert_eq!(payout.status, PayoutStatus::Withheld);
    }
}
