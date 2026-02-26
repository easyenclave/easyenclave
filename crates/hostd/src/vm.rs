//! VM lifecycle management using QEMU/KVM with TDX support.

use crate::config::HostdConfig;
use crate::error::HostdError;
use ee_common::types::VmSize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInfo {
    pub id: String,
    pub size: VmSize,
    pub memory_mb: u64,
    pub cpus: u32,
    pub image: String,
    pub status: VmStatus,
    pub agent_port: u16,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// Manages VMs on this host.
pub struct VmManager {
    config: HostdConfig,
    vms: HashMap<String, VmInfo>,
    next_port: u16,
}

impl VmManager {
    pub fn new(config: HostdConfig) -> Self {
        Self {
            config,
            vms: HashMap::new(),
            next_port: 9000,
        }
    }

    /// Launch a new TDX VM.
    pub async fn launch(&mut self, size: VmSize, image: &str) -> Result<VmInfo, HostdError> {
        if self.vms.len() >= self.config.max_vms {
            return Err(HostdError::ResourceExhausted(format!(
                "max VMs ({}) reached",
                self.config.max_vms
            )));
        }

        let (memory_mb, cpus) = size_resources(size);
        let vm_id = Uuid::new_v4().to_string();
        let agent_port = self.next_port;
        self.next_port += 1;

        let image_path = self.config.image_dir.join(format!("{image}.qcow2"));
        if !image_path.exists() {
            return Err(HostdError::ImageNotFound(image.to_string()));
        }

        // Build QEMU command with TDX support
        let args = build_qemu_args(&vm_id, &image_path, memory_mb, cpus, agent_port);

        tracing::info!(vm_id = %vm_id, %size, %memory_mb, %cpus, "launching VM");

        let child = tokio::process::Command::new("qemu-system-x86_64")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| HostdError::VmLaunch(format!("qemu spawn: {e}")))?;

        let pid = child.id();

        let info = VmInfo {
            id: vm_id.clone(),
            size,
            memory_mb,
            cpus,
            image: image.to_string(),
            status: VmStatus::Running,
            agent_port,
            pid,
        };

        self.vms.insert(vm_id, info.clone());
        Ok(info)
    }

    /// Stop a VM.
    pub async fn stop(&mut self, vm_id: &str) -> Result<(), HostdError> {
        let vm = self
            .vms
            .get_mut(vm_id)
            .ok_or_else(|| HostdError::VmStop(format!("VM {vm_id} not found")))?;

        if let Some(pid) = vm.pid {
            tracing::info!(vm_id = %vm_id, pid, "stopping VM");
            // Send SIGTERM
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }

        vm.status = VmStatus::Stopped;
        Ok(())
    }

    /// List all VMs.
    pub fn list(&self) -> Vec<VmInfo> {
        self.vms.values().cloned().collect()
    }

    /// Get a VM by ID.
    pub fn get(&self, vm_id: &str) -> Option<&VmInfo> {
        self.vms.get(vm_id)
    }
}

fn size_resources(size: VmSize) -> (u64, u32) {
    match size {
        VmSize::Small => (2048, 2),
        VmSize::Medium => (4096, 4),
        VmSize::Large => (8192, 8),
        VmSize::XLarge => (16384, 16),
    }
}

fn build_qemu_args(
    vm_id: &str,
    image_path: &std::path::Path,
    memory_mb: u64,
    cpus: u32,
    agent_port: u16,
) -> Vec<String> {
    vec![
        "-name".into(),
        format!("ee-{vm_id}"),
        "-machine".into(),
        "q35,accel=kvm,kernel-irqchip=split,confidential-guest-support=tdx".into(),
        "-object".into(),
        "tdx-guest,id=tdx".into(),
        "-cpu".into(),
        "host".into(),
        "-smp".into(),
        cpus.to_string(),
        "-m".into(),
        format!("{memory_mb}M"),
        "-drive".into(),
        format!("file={},format=qcow2,if=virtio", image_path.display()),
        "-netdev".into(),
        format!("user,id=net0,hostfwd=tcp::{agent_port}-:8081"),
        "-device".into(),
        "virtio-net-pci,netdev=net0".into(),
        "-nographic".into(),
        "-daemonize".into(),
    ]
}
