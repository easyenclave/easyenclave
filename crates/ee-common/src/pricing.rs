use crate::error::{AppError, AppResult};

pub const CPU_RATE_USD_PER_HOUR: f64 = 0.04;
pub const MEMORY_RATE_USD_PER_HOUR: f64 = 0.005;
pub const GPU_RATE_USD_PER_HOUR: f64 = 0.50;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HourlyRates {
    pub cpu_usd_per_vcpu_hour: f64,
    pub memory_usd_per_gb_hour: f64,
    pub gpu_usd_per_hour: f64,
}

impl Default for HourlyRates {
    fn default() -> Self {
        Self {
            cpu_usd_per_vcpu_hour: CPU_RATE_USD_PER_HOUR,
            memory_usd_per_gb_hour: MEMORY_RATE_USD_PER_HOUR,
            gpu_usd_per_hour: GPU_RATE_USD_PER_HOUR,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UsageShape {
    pub cpu_vcpus: i32,
    pub memory_gb: f64,
    pub gpu_count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RevenueSplit {
    pub operator_cents: i64,
    pub contributor_cents: i64,
    pub platform_cents: i64,
}

pub fn hourly_cost_cents(shape: UsageShape, rates: HourlyRates) -> AppResult<i64> {
    if shape.cpu_vcpus < 0 || shape.memory_gb < 0.0 || shape.gpu_count < 0 {
        return Err(AppError::InvalidInput(
            "usage shape values must be non-negative".to_string(),
        ));
    }

    let usd = (shape.cpu_vcpus as f64 * rates.cpu_usd_per_vcpu_hour)
        + (shape.memory_gb * rates.memory_usd_per_gb_hour)
        + (shape.gpu_count as f64 * rates.gpu_usd_per_hour);

    Ok((usd * 100.0).round() as i64)
}

pub fn split_revenue_cents(total_cents: i64, contributor_pool_bps: i32) -> AppResult<RevenueSplit> {
    if total_cents < 0 {
        return Err(AppError::InvalidInput(
            "total_cents must be non-negative".to_string(),
        ));
    }
    if !(0..=10_000).contains(&contributor_pool_bps) {
        return Err(AppError::InvalidInput(
            "contributor_pool_bps must be between 0 and 10000".to_string(),
        ));
    }

    let operator_cents = (total_cents * 70) / 100;
    let platform_pool_cents = total_cents - operator_cents;
    let contributor_cents = (platform_pool_cents * contributor_pool_bps as i64) / 10_000;
    let platform_cents = platform_pool_cents - contributor_cents;

    Ok(RevenueSplit {
        operator_cents,
        contributor_cents,
        platform_cents,
    })
}

#[cfg(test)]
mod tests {
    use super::{hourly_cost_cents, split_revenue_cents, HourlyRates, UsageShape};

    #[test]
    fn hourly_cost_matches_rate_card() {
        let shape = UsageShape {
            cpu_vcpus: 4,
            memory_gb: 8.0,
            gpu_count: 1,
        };

        let cents = hourly_cost_cents(shape, HourlyRates::default()).expect("cost");
        assert_eq!(cents, 70);
    }

    #[test]
    fn split_revenue_respects_contributor_pool() {
        let split = split_revenue_cents(10_000, 5_000).expect("split");

        assert_eq!(split.operator_cents, 7_000);
        assert_eq!(split.contributor_cents, 1_500);
        assert_eq!(split.platform_cents, 1_500);
    }

    #[test]
    fn split_revenue_validates_inputs() {
        let err = split_revenue_cents(1000, 11_000).expect_err("invalid bps");
        assert!(err.to_string().contains("between 0 and 10000"));
    }
}
