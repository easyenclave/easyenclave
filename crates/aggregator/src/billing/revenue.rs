//! Revenue tracking and operator/platform split.

use super::types::RevenueSplit;

/// Calculate the monthly revenue breakdown for an operator.
pub fn monthly_breakdown(total_revenue_sats: u64, split: &RevenueSplit) -> MonthlyBreakdown {
    let (operator_share, platform_share) = split.split(total_revenue_sats);
    MonthlyBreakdown {
        total_revenue_sats,
        operator_share_sats: operator_share,
        platform_share_sats: platform_share,
        platform_fee_bps: split.platform_fee_bps,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MonthlyBreakdown {
    pub total_revenue_sats: u64,
    pub operator_share_sats: u64,
    pub platform_share_sats: u64,
    pub platform_fee_bps: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monthly_breakdown() {
        let split = RevenueSplit {
            platform_fee_bps: 1500,
        };
        let breakdown = monthly_breakdown(1_000_000, &split);
        assert_eq!(breakdown.operator_share_sats, 850_000);
        assert_eq!(breakdown.platform_share_sats, 150_000);
    }
}
