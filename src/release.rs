//! GitHub Releases API client.
//!
//! Downloads static binaries from GitHub releases, puts them in a local
//! bin dir, and makes them executable. Replaces the OCI image pull path.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GithubRelease {
    /// owner/repo (e.g. "cloudflare/cloudflared")
    pub repo: String,
    /// Asset filename to match in the release (e.g. "cloudflared-linux-amd64")
    pub asset: String,
    /// Tag to fetch. None = latest release.
    #[serde(default)]
    pub tag: Option<String>,
    /// If set, create a symlink from this name to the downloaded asset.
    /// Lets you fetch `cloudflared-linux-amd64` and expose it as `cloudflared`.
    #[serde(default)]
    pub rename: Option<String>,
}

/// Download a GitHub release asset into `bin_dir`.
///
/// - Returns the path to the primary executable (the asset itself, or
///   for a tarball, whatever the rename field points at).
/// - If the asset ends in .tar.gz or .tgz, extract it into `bin_dir`.
/// - Sets chmod +x on the resulting binary.
/// - If `rename` is set, create a symlink pointing at the asset.
///
/// Called from `tokio::task::spawn_blocking` in workload.rs / main.rs.
pub fn download(release: &GithubRelease, bin_dir: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(bin_dir).map_err(|e| format!("create bin_dir: {e}"))?;

    let token = std::env::var("EE_GITHUB_TOKEN").ok();

    // 1. Fetch release metadata to find the asset's download URL.
    let api_url = match &release.tag {
        Some(t) => format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            release.repo, t
        ),
        None => format!(
            "https://api.github.com/repos/{}/releases/latest",
            release.repo
        ),
    };

    let meta = http_get_json(&api_url, token.as_deref())?;
    let assets = meta
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| format!("{}: no assets in release", release.repo))?;

    let asset_url = assets
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(&release.asset))
        .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
        .ok_or_else(|| format!("{}: asset {} not found", release.repo, release.asset))?
        .to_string();

    // 2. Download the asset bytes.
    let dest = format!("{bin_dir}/{}", release.asset);
    let bytes = http_get_bytes(&asset_url, token.as_deref())?;

    // 3. Extract if tarball, otherwise write directly.
    let primary: PathBuf = if is_tarball(&release.asset) {
        extract_tarball(&bytes, Path::new(bin_dir))?;
        // For tarballs the `rename` target (or else asset-without-extension)
        // is treated as the primary binary. Best-effort chmod.
        let stem = release
            .rename
            .clone()
            .unwrap_or_else(|| strip_tarball_ext(&release.asset).to_string());
        let p = PathBuf::from(format!("{bin_dir}/{stem}"));
        if p.exists() {
            set_executable(&p)?;
        }
        p
    } else {
        std::fs::write(&dest, &bytes).map_err(|e| format!("write {dest}: {e}"))?;
        let p = PathBuf::from(&dest);
        set_executable(&p)?;
        p
    };

    // 4. Symlink (bin_dir/<rename> -> bin_dir/<asset>).
    if let Some(name) = &release.rename {
        if !is_tarball(&release.asset) {
            let link_path = format!("{bin_dir}/{name}");
            let _ = std::fs::remove_file(&link_path);
            symlink(&release.asset, &link_path).map_err(|e| format!("symlink {link_path}: {e}"))?;
        }
    }

    Ok(primary)
}

fn http_get_json(url: &str, token: Option<&str>) -> Result<serde_json::Value, String> {
    let body = http_get_string(url, token, Some("application/vnd.github+json"))?;
    serde_json::from_str(&body).map_err(|e| format!("parse json from {url}: {e}"))
}

fn http_get_string(url: &str, token: Option<&str>, accept: Option<&str>) -> Result<String, String> {
    let mut req = ureq::get(url).set("User-Agent", "easyenclave");
    if let Some(a) = accept {
        req = req.set("Accept", a);
    }
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    req.call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .into_string()
        .map_err(|e| format!("read {url}: {e}"))
}

fn http_get_bytes(url: &str, token: Option<&str>) -> Result<Vec<u8>, String> {
    let mut req = ureq::get(url)
        .set("User-Agent", "easyenclave")
        .set("Accept", "application/octet-stream");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {url}: {e}"))?;
    Ok(buf)
}

fn is_tarball(name: &str) -> bool {
    name.ends_with(".tar.gz") || name.ends_with(".tgz")
}

fn strip_tarball_ext(name: &str) -> &str {
    name.strip_suffix(".tar.gz")
        .or_else(|| name.strip_suffix(".tgz"))
        .unwrap_or(name)
}

fn extract_tarball(bytes: &[u8], dest: &Path) -> Result<(), String> {
    use flate2::read::GzDecoder;
    use tar::Archive;
    let mut archive = Archive::new(GzDecoder::new(bytes));
    archive.set_overwrite(true);
    archive.unpack(dest).map_err(|e| format!("untar: {e}"))
}

fn set_executable(path: &Path) -> Result<(), String> {
    let mut perms = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).map_err(|e| format!("chmod {}: {e}", path.display()))
}
