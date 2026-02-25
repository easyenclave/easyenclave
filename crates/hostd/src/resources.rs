//! Host resource discovery and tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResources {
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub total_cpus: u32,
    pub available_cpus: u32,
    pub tdx_supported: bool,
}

impl HostResources {
    /// Discover resources on this host.
    pub fn discover() -> Self {
        let total_memory_mb = sys_total_memory_mb();
        let total_cpus = num_cpus();

        Self {
            total_memory_mb,
            available_memory_mb: total_memory_mb,
            total_cpus,
            available_cpus: total_cpus,
            tdx_supported: is_tdx_supported(),
        }
    }

    /// Reserve resources for a VM.
    pub fn reserve(&mut self, memory_mb: u64, cpus: u32) -> bool {
        if self.available_memory_mb >= memory_mb && self.available_cpus >= cpus {
            self.available_memory_mb -= memory_mb;
            self.available_cpus -= cpus;
            true
        } else {
            false
        }
    }

    /// Release resources when a VM is destroyed.
    pub fn release(&mut self, memory_mb: u64, cpus: u32) {
        self.available_memory_mb = (self.available_memory_mb + memory_mb).min(self.total_memory_mb);
        self.available_cpus = (self.available_cpus + cpus).min(self.total_cpus);
    }
}

fn sys_total_memory_mb() -> u64 {
    // Read from /proc/meminfo
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

fn is_tdx_supported() -> bool {
    std::path::Path::new("/sys/firmware/tdx").exists()
        || std::path::Path::new("/dev/tdx_guest").exists()
}
