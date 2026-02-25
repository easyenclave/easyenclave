use ee_common::config::{env_or, listen_addr};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct HostdConfig {
    pub listen_addr: SocketAddr,
    pub image_dir: PathBuf,
    pub vm_memory_mb: u64,
    pub max_vms: usize,
}

impl HostdConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: listen_addr("LISTEN_ADDR", "0.0.0.0:8082"),
            image_dir: PathBuf::from(env_or("IMAGE_DIR", "/var/lib/easyenclave/images")),
            vm_memory_mb: env_or("VM_MEMORY_MB", "4096").parse().unwrap_or(4096),
            max_vms: env_or("MAX_VMS", "8").parse().unwrap_or(8),
        }
    }
}
