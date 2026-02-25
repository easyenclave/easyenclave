//! GitHub releases integration for tracking release tags.

use tracing::debug;

/// Fetch the latest release tag from GitHub.
pub async fn fetch_latest_release(
    client: &reqwest::Client,
    repo: &str,
) -> anyhow::Result<Option<String>> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    debug!(%url, "fetching latest release");

    let resp = client
        .get(&url)
        .header("User-Agent", "easyenclave-cp")
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !resp.status().is_success() {
        anyhow::bail!("GitHub returned {}", resp.status());
    }

    let data: serde_json::Value = resp.json().await?;
    Ok(data["tag_name"].as_str().map(|s| s.to_string()))
}
