use ee_common::{config::LauncherConfig, error::AppResult};

use crate::config::kernel_cmdline;

pub async fn launch_vm(
    _config: &LauncherConfig,
    extracted_rootfs: &str,
    cp: bool,
    owner: Option<String>,
) -> AppResult<()> {
    let mut extra = std::collections::HashMap::new();
    if let Some(owner) = owner.clone() {
        extra.insert("owner".to_owned(), owner);
    }
    if cp {
        extra.insert("mode".to_owned(), "cp-bootstrap".to_owned());
    }
    let cmdline = kernel_cmdline(extra);
    println!(
        "launch requested: rootfs={} cp={} owner={} cmdline={}",
        extracted_rootfs,
        cp,
        owner.unwrap_or_else(|| "<none>".to_owned()),
        cmdline
    );
    Ok(())
}

pub async fn stop_vm(_config: &LauncherConfig, vm_id: &str) -> AppResult<()> {
    println!("stop requested for vm_id={vm_id}");
    Ok(())
}

pub async fn list_vms(_config: &LauncherConfig) -> AppResult<()> {
    println!("list requested");
    Ok(())
}

pub async fn logs(_config: &LauncherConfig, vm_id: &str) -> AppResult<()> {
    println!("logs requested for vm_id={vm_id}");
    Ok(())
}
