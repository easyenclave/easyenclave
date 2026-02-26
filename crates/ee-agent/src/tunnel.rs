use std::process::Stdio;

use ee_common::error::AppResult;

pub async fn start_cloudflared(tunnel_token: &str) -> AppResult<()> {
    if tunnel_token.starts_with("local-token-") {
        tracing::info!("skipping cloudflared launch for local token");
        return Ok(());
    }

    let mut cmd = tokio::process::Command::new("cloudflared");
    cmd.arg("tunnel")
        .arg("run")
        .arg("--token")
        .arg(tunnel_token)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let _child = cmd.spawn().map_err(|e| {
        ee_common::error::AppError::Internal(format!("cloudflared spawn failed: {e}"))
    })?;

    Ok(())
}
