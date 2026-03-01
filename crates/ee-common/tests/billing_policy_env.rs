use ee_common::billing_policy::{
    parse_unlimited_owners, unlimited_credit_owners_from_env, BILLING_UNLIMITED_OWNERS_ENV,
    DEFAULT_BILLING_UNLIMITED_OWNERS,
};

#[test]
fn billing_policy_env_reflects_runtime_allowlist() {
    let actual = unlimited_credit_owners_from_env();
    let expected = match std::env::var(BILLING_UNLIMITED_OWNERS_ENV) {
        Ok(value) => parse_unlimited_owners(&value),
        Err(_) => parse_unlimited_owners(DEFAULT_BILLING_UNLIMITED_OWNERS),
    };

    assert_eq!(actual, expected);
}
