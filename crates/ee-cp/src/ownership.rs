pub fn owner_matches(agent_owner: &str, repository_owner: &str) -> bool {
    let normalized_agent_owner = agent_owner
        .strip_prefix("github:org/")
        .or_else(|| agent_owner.strip_prefix("github:user/"))
        .unwrap_or(agent_owner)
        .to_ascii_lowercase();

    normalized_agent_owner == repository_owner.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::owner_matches;

    #[test]
    fn owner_match_normalizes_prefix() {
        assert!(owner_matches("github:org/EasyEnclave", "easyenclave"));
        assert!(owner_matches("github:user/alice", "alice"));
        assert!(!owner_matches("github:org/a", "b"));
    }
}
