//! GPU evidence backend that shells out to a configurable helper binary.
//!
//! Wire protocol (helper stdout):
//!   `gpu_report_len:u32_be || gpu_report || switch_report_len:u32_be || switch_report`
//!
//! `switch_report_len = 0` means no NVSwitch / single-GPU host (the
//! switch_report bytes are then absent — the parser treats len=0 as
//! optional and omits the field from the response).
//!
//! Helper stdin: reserved. Today the runtime writes nothing. When the
//! binding protocol pins down nonce-based combined evidence (see
//! `docs/gpu-attestation.md`), the runtime will write the verifier nonce
//! as the first line on stdin so the helper can fold it into the GPU
//! report's caller-nonce field.
//!
//! Exit code: 0 = success, anything else = failure (stderr captured into
//! the response's `evidence.nvgpu_error`). Failure never escalates: the
//! TDX path stays whole. This is consistent with EasyEnclave's
//! "evidence producer, not verifier" invariant.

use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::GpuAttestationConfig;

use super::{GpuEvidence, GpuEvidenceBackend};

/// Hard cap on a single report's length to avoid OOM if a buggy helper
/// emits a giant length prefix. 64 MiB is well above any plausible GPU
/// attestation report.
const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

pub struct HelperBackend {
    cfg: GpuAttestationConfig,
    cache: Mutex<Option<CacheEntry>>,
}

struct CacheEntry {
    evidence: GpuEvidence,
    fetched_at: Instant,
}

impl HelperBackend {
    pub fn new(cfg: GpuAttestationConfig) -> Self {
        Self {
            cfg,
            cache: Mutex::new(None),
        }
    }

    fn try_cached(&self) -> Option<GpuEvidence> {
        if self.cfg.cache_ttl_secs == 0 {
            return None;
        }
        let guard = self.cache.lock().unwrap();
        let entry = guard.as_ref()?;
        if entry.fetched_at.elapsed() < Duration::from_secs(self.cfg.cache_ttl_secs) {
            Some(entry.evidence.clone())
        } else {
            None
        }
    }

    fn store_cached(&self, ev: &GpuEvidence) {
        if self.cfg.cache_ttl_secs == 0 {
            return;
        }
        let mut guard = self.cache.lock().unwrap();
        *guard = Some(CacheEntry {
            evidence: ev.clone(),
            fetched_at: Instant::now(),
        });
    }

    fn run_helper(&self) -> Result<GpuEvidence, String> {
        let timeout = Duration::from_secs(self.cfg.timeout_secs);
        let mut child = Command::new(&self.cfg.helper_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", self.cfg.helper_path))?;

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = Vec::new();
                    let mut stderr_buf = String::new();
                    if let Some(mut s) = child.stdout.take() {
                        use std::io::Read;
                        let _ = s.read_to_end(&mut stdout);
                    }
                    if let Some(mut s) = child.stderr.take() {
                        use std::io::Read;
                        let _ = s.read_to_string(&mut stderr_buf);
                    }
                    if !status.success() {
                        let trimmed = stderr_buf.trim();
                        let detail = if trimmed.is_empty() {
                            String::new()
                        } else {
                            format!(": {trimmed}")
                        };
                        return Err(format!("helper exited {status}{detail}"));
                    }
                    return parse_evidence(&stdout);
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("helper timed out after {timeout:?}"));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(format!("wait helper: {e}")),
            }
        }
    }
}

impl GpuEvidenceBackend for HelperBackend {
    fn evidence_type(&self) -> &str {
        "nvidia-cc"
    }

    fn collect(&self) -> Result<GpuEvidence, String> {
        if let Some(ev) = self.try_cached() {
            return Ok(ev);
        }
        let ev = self.run_helper()?;
        self.store_cached(&ev);
        Ok(ev)
    }
}

fn parse_evidence(buf: &[u8]) -> Result<GpuEvidence, String> {
    let (gpu_report, rest) = take_length_prefixed(buf, "gpu_report")?;
    if gpu_report.is_empty() {
        return Err("helper produced empty gpu_report (length-prefix 0)".into());
    }
    let (switch_bytes, _trailing) = take_length_prefixed(rest, "switch_report")?;
    let switch_report = if switch_bytes.is_empty() {
        None
    } else {
        Some(switch_bytes)
    };
    Ok(GpuEvidence {
        gpu_report,
        switch_report,
        collected_at: now_unix(),
    })
}

fn take_length_prefixed<'a>(buf: &'a [u8], field: &str) -> Result<(Vec<u8>, &'a [u8]), String> {
    if buf.len() < 4 {
        return Err(format!("truncated {field} length prefix"));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_REPORT_BYTES {
        return Err(format!("{field} length {len} exceeds {MAX_REPORT_BYTES}"));
    }
    let payload = &buf[4..];
    if payload.len() < len {
        return Err(format!(
            "{field} truncated: header says {len}, only {} bytes available",
            payload.len()
        ));
    }
    Ok((payload[..len].to_vec(), &payload[len..]))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::{NamedTempFile, TempPath};

    /// Cargo runs tests as threads in one process. When thread A creates a
    /// NamedTempFile, the writable fd is briefly visible to the whole
    /// process. If thread B forks (via Command::spawn) during that window,
    /// the child inherits A's writable fd. When thread A then tries to
    /// exec its helper file, the kernel sees a writable fd to that inode
    /// in another task and returns ETXTBSY.
    ///
    /// O_CLOEXEC closes the fd in the grandchild AFTER its own exec, but
    /// the race window between fork and exec is enough to flake CI under
    /// load. Local runs almost never hit it; GitHub-hosted runners do.
    ///
    /// Serialize every helper-spawning test through this mutex so only
    /// one NamedTempFile-then-spawn sequence is in flight at a time.
    static SPAWN_LOCK: Mutex<()> = Mutex::new(());

    fn spawn_guard() -> MutexGuard<'static, ()> {
        SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Writes a shell script to a temp path and returns the path. Caller
    /// must hold `spawn_guard()` for the lifetime of the spawn that
    /// follows.
    fn write_helper(script: &str) -> TempPath {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(script.as_bytes()).unwrap();
        f.flush().unwrap();
        // Explicitly drop the File before returning the path so the
        // writable fd is closed; into_temp_path()'s Drop does this too,
        // but being explicit makes the lifetime obvious.
        let (file, path) = f.into_parts();
        drop(file);
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn cfg_for(path: &TempPath) -> GpuAttestationConfig {
        GpuAttestationConfig {
            enabled: true,
            helper_path: path.to_string_lossy().into_owned(),
            timeout_secs: 5,
            cache_ttl_secs: 0, // disable cache for tests by default
        }
    }

    #[test]
    fn parses_gpu_only_payload() {
        // 0x00000004 || "ABCD" || 0x00000000
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(b"ABCD");
        buf.extend_from_slice(&0u32.to_be_bytes());

        let ev = parse_evidence(&buf).unwrap();
        assert_eq!(ev.gpu_report, b"ABCD");
        assert!(ev.switch_report.is_none());
    }

    #[test]
    fn parses_gpu_and_switch_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"GPU");
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"SWI");
        let ev = parse_evidence(&buf).unwrap();
        assert_eq!(ev.gpu_report, b"GPU");
        assert_eq!(ev.switch_report.as_deref(), Some(b"SWI" as &[u8]));
    }

    #[test]
    fn rejects_truncated_length_prefix() {
        let buf = vec![0u8, 0u8, 0u8]; // 3 bytes — need 4 for u32 prefix
        let err = parse_evidence(&buf).unwrap_err();
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes()); // claim 100 bytes
        buf.extend_from_slice(b"only-a-few"); // but provide ~10
        let err = parse_evidence(&buf).unwrap_err();
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn rejects_oversize_length() {
        let mut buf = Vec::new();
        let oversize = (MAX_REPORT_BYTES as u32) + 1;
        buf.extend_from_slice(&oversize.to_be_bytes());
        let err = parse_evidence(&buf).unwrap_err();
        assert!(err.contains("exceeds"), "got: {err}");
    }

    #[test]
    fn rejects_empty_gpu_report() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let err = parse_evidence(&buf).unwrap_err();
        assert!(err.contains("empty gpu_report"), "got: {err}");
    }

    #[test]
    fn helper_success_round_trip() {
        let _g = spawn_guard();
        // /bin/sh helper that prints len=4|"ABCD"|len=0 to stdout.
        let helper = write_helper(
            r#"#!/bin/bash
printf '\x00\x00\x00\x04ABCD\x00\x00\x00\x00'
"#,
        );
        let backend = HelperBackend::new(cfg_for(&helper));
        let ev = backend.collect().unwrap();
        assert_eq!(ev.gpu_report, b"ABCD");
        assert!(ev.switch_report.is_none());
    }

    #[test]
    fn helper_nonzero_exit_surfaces_stderr() {
        let _g = spawn_guard();
        let helper = write_helper(
            r#"#!/bin/sh
echo "GPU not in CC mode" >&2
exit 7
"#,
        );
        let backend = HelperBackend::new(cfg_for(&helper));
        let err = backend.collect().unwrap_err();
        assert!(err.contains("GPU not in CC mode"), "got: {err}");
        assert!(err.contains("exited"), "got: {err}");
    }

    #[test]
    fn helper_timeout_kills_child() {
        let _g = spawn_guard();
        let helper = write_helper(
            r#"#!/bin/sh
sleep 30
"#,
        );
        let mut cfg = cfg_for(&helper);
        cfg.timeout_secs = 1;
        let backend = HelperBackend::new(cfg);
        let start = Instant::now();
        let err = backend.collect().unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(5), "took too long");
    }

    #[test]
    fn cache_avoids_second_helper_invocation() {
        let _g = spawn_guard();
        // Helper that increments a counter file; second collect() should
        // hit cache and not bump it.
        let counter = NamedTempFile::new().unwrap();
        let counter_path = counter.into_temp_path();
        std::fs::write(&counter_path, b"0").unwrap();

        let script = format!(
            r#"#!/bin/bash
n=$(cat {p})
n=$((n+1))
echo -n "$n" > {p}
printf '\x00\x00\x00\x04ABCD\x00\x00\x00\x00'
"#,
            p = counter_path.display()
        );
        let helper = write_helper(&script);

        let mut cfg = cfg_for(&helper);
        cfg.cache_ttl_secs = 30;
        let backend = HelperBackend::new(cfg);

        let _ = backend.collect().unwrap();
        let _ = backend.collect().unwrap();

        let count = std::fs::read_to_string(&counter_path).unwrap();
        assert_eq!(count.trim(), "1", "helper should only have run once");
    }
}
