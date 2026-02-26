use ee_common::{
    config::LauncherConfig,
    error::{AppError, AppResult},
};

pub async fn run(config: &LauncherConfig) -> AppResult<()> {
    if config.qemu_bin.trim().is_empty() {
        return Err(AppError::BadRequest(
            "LAUNCHER_QEMU_BIN is empty".to_owned(),
        ));
    }
    Ok(())
}
