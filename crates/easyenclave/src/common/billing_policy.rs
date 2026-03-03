use std::collections::HashMap;
use std::env;

pub const BILLING_UNLIMITED_OWNERS_ENV: &str = "BILLING_UNLIMITED_OWNERS";
pub const DEFAULT_BILLING_UNLIMITED_OWNERS: &str = "posix4e,easyenclave";

pub fn parse_unlimited_owners(raw: &str) -> Vec<String> {
    let mut owners = Vec::new();
    for candidate in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
    {
        if !owners.contains(&candidate) {
            owners.push(candidate);
        }
    }
    owners
}

pub fn unlimited_credit_owners_from_env() -> Vec<String> {
    unlimited_credit_owners_from_map(&env::vars().collect())
}

pub fn unlimited_credit_owners_from_map(vars: &HashMap<String, String>) -> Vec<String> {
    let raw = vars
        .get(BILLING_UNLIMITED_OWNERS_ENV)
        .map(String::as_str)
        .unwrap_or(DEFAULT_BILLING_UNLIMITED_OWNERS);
    parse_unlimited_owners(raw)
}

pub fn owner_has_unlimited_credit(owner: &str, allowlist: &[String]) -> bool {
    let normalized = owner.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    allowlist.iter().any(|entry| entry == &normalized)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        owner_has_unlimited_credit, parse_unlimited_owners, unlimited_credit_owners_from_map,
        BILLING_UNLIMITED_OWNERS_ENV,
    };

    #[test]
    fn default_unlimited_owners_include_posix4e_and_easyenclave() {
        let vars = HashMap::new();
        let owners = unlimited_credit_owners_from_map(&vars);

        assert!(owners.contains(&"posix4e".to_string()));
        assert!(owners.contains(&"easyenclave".to_string()));
    }

    #[test]
    fn env_override_replaces_default_allowlist() {
        let mut vars = HashMap::new();
        vars.insert(
            BILLING_UNLIMITED_OWNERS_ENV.to_string(),
            "FoundersOrg, another-org".to_string(),
        );

        let owners = unlimited_credit_owners_from_map(&vars);
        assert_eq!(
            owners,
            vec!["foundersorg".to_string(), "another-org".to_string()]
        );
    }

    #[test]
    fn parser_trims_lowercases_and_deduplicates() {
        let owners = parse_unlimited_owners(" Posix4E, easyenclave, posix4e ,  ");
        assert_eq!(
            owners,
            vec!["posix4e".to_string(), "easyenclave".to_string()]
        );
    }

    #[test]
    fn owner_lookup_is_case_insensitive() {
        let owners = vec!["posix4e".to_string(), "easyenclave".to_string()];
        assert!(owner_has_unlimited_credit("Posix4E", &owners));
        assert!(owner_has_unlimited_credit(" EASYENCLAVE ", &owners));
        assert!(!owner_has_unlimited_credit("not-in-list", &owners));
    }
}
