//! PID 1 init: mount filesystems, parse kernel cmdline, reap zombies.

/// If we are PID 1, mount virtual filesystems, parse kernel params, and start
/// the zombie reaper. Otherwise this is a no-op.
pub fn maybe_init() {
    if std::process::id() != 1 {
        return;
    }

    eprintln!("easyenclave: running as PID 1 -- sealed VM init");

    // Set PATH so we can find busybox tools
    std::env::set_var(
        "PATH",
        "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
    );

    // Mount virtual filesystems
    for (src, target, fstype) in [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("tmpfs", "/tmp", "tmpfs"),
        ("tmpfs", "/run", "tmpfs"),
    ] {
        match nix_mount(src, target, fstype) {
            Ok(()) => eprintln!("easyenclave: init: mounted {target}"),
            Err(e) => eprintln!("easyenclave: init: mount {target} ({fstype}): {e}"),
        }
    }

    // Mount configfs for TDX attestation (tsm report interface)
    let _ = std::fs::create_dir_all("/sys/kernel/config");
    if let Err(e) = nix_mount("configfs", "/sys/kernel/config", "configfs") {
        eprintln!("easyenclave: init: mount configfs: {e}");
    }

    // Create /dev/pts for PTY support (needed for TTY workloads)
    let _ = std::fs::create_dir_all("/dev/pts");
    if let Err(e) = nix_mount("devpts", "/dev/pts", "devpts") {
        eprintln!("easyenclave: init: mount devpts: {e}");
    }

    // Writable tmpfs for workload data (rootfs may be read-only dm-verity)
    if let Err(e) = nix_mount("tmpfs", "/var/lib/easyenclave", "tmpfs") {
        eprintln!("easyenclave: init: mount /var/lib/easyenclave tmpfs: {e}");
    } else {
        let _ = std::fs::create_dir_all("/var/lib/easyenclave/workloads");
        let _ = std::fs::create_dir_all("/var/lib/easyenclave/shared");
        eprintln!("easyenclave: init: mounted /var/lib/easyenclave (tmpfs, writable)");
    }

    // Parse kernel cmdline for ee.* params -> set as env vars
    // e.g. ee.EE_OWNER=alice -> env EE_OWNER=alice
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        for param in cmdline.split_whitespace() {
            if let Some(kv) = param.strip_prefix("ee.") {
                if let Some((key, val)) = kv.split_once('=') {
                    std::env::set_var(key, val);
                    eprintln!("easyenclave: init: cmdline env {key}={val}");
                }
            }
            if let Some(hostname) = param.strip_prefix("hostname=") {
                let _ = std::fs::write("/etc/hostname", hostname);
                eprintln!("easyenclave: init: hostname={hostname}");
            }
        }
    }

    // Load config from config disk (second virtio disk)
    let config_dir = "/tmp/config";
    let _ = std::fs::create_dir_all(config_dir);
    let config_mounted = {
        let mut mounted = false;
        std::thread::sleep(std::time::Duration::from_secs(1));
        for dev in ["/dev/vdb", "/dev/sdb"] {
            for fstype in ["ext4", "vfat", "ext2"] {
                if nix_mount_ro(dev, config_dir, fstype).is_ok() {
                    eprintln!("easyenclave: init: mounted config disk ({dev}, {fstype})");
                    mounted = true;
                    break;
                }
            }
            if mounted {
                break;
            }
        }
        mounted
    };
    if config_mounted {
        let env_path = format!("{config_dir}/agent.env");
        if let Ok(env_file) = std::fs::read_to_string(&env_path) {
            for line in env_file.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, val)) = line.split_once('=') {
                    std::env::set_var(key.trim(), val.trim());
                    eprintln!("easyenclave: init: config env {key}={val}");
                }
            }
        }
        let _ = std::process::Command::new("umount")
            .arg(config_dir)
            .status();
    }

    // GCE instance metadata: fetch the `ee-config` attribute and apply
    // each key as an env var. This is the per-VM boot-config path for
    // easyenclave VMs on GCP — gcloud passes it via
    //   --metadata-from-file=ee-config=<path to JSON>
    // Non-GCE hosts fail silently (no metadata server reachable).
    fetch_gce_metadata_config();

    // Set up networking
    let ip_bin = "/sbin/ip";
    let _ = std::process::Command::new(ip_bin)
        .args(["link", "set", "lo", "up"])
        .status();

    // Find first non-lo interface
    let iface = std::fs::read_dir("/sys/class/net")
        .ok()
        .and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .find(|n| n != "lo")
        });

    if let Some(ref iface) = iface {
        let _ = std::process::Command::new(ip_bin)
            .args(["link", "set", iface, "up"])
            .status();

        if let Ok(ee_ip) = std::env::var("EE_IP") {
            eprintln!("easyenclave: init: setting {iface} ip={ee_ip}");
            let _ = std::process::Command::new(ip_bin)
                .args(["addr", "add", &ee_ip, "dev", iface])
                .status();
        }
        if let Ok(gw) = std::env::var("EE_GATEWAY") {
            eprintln!("easyenclave: init: default route via {gw}");
            let _ = std::process::Command::new(ip_bin)
                .args(["route", "add", "default", "via", &gw, "dev", iface])
                .status();
        }
    }
    if let Ok(dns) = std::env::var("EE_DNS") {
        eprintln!("easyenclave: init: dns={dns}");
        let _ = std::fs::write("/tmp/resolv.conf", format!("nameserver {dns}\n"));
        let _ = nix_mount_flags("/tmp/resolv.conf", "/etc/resolv.conf", "", libc::MS_BIND);
    }

    // Enable podman socket (systemd-less activation)
    let _ = std::process::Command::new("podman")
        .args(["system", "service", "--time=0"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    // Start zombie reaper thread (PID 1 must reap children)
    std::thread::spawn(|| loop {
        unsafe {
            libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    });

    eprintln!("easyenclave: init complete");
}

fn nix_mount(src: &str, target: &str, fstype: &str) -> Result<(), String> {
    nix_mount_flags(src, target, fstype, 0)
}

fn nix_mount_ro(src: &str, target: &str, fstype: &str) -> Result<(), String> {
    nix_mount_flags(src, target, fstype, libc::MS_RDONLY)
}

/// Fetch `ee-config` from GCE instance metadata and apply each entry
/// as an env var. Expected body is a JSON object of `{ "KEY": "VALUE", ... }`.
/// In particular, setting `"EE_BOOT_WORKLOADS"` here (as a stringified
/// JSON array) is how you get easyenclave to deploy workloads at boot
/// on a GCE VM — no secondary disk needed.
///
/// On non-GCE hosts, or if the attribute isn't set, fail silently.
fn fetch_gce_metadata_config() {
    const URL: &str = "http://169.254.169.254/computeMetadata/v1/instance/attributes/ee-config";
    let body = match ureq::get(URL)
        .set("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(2))
        .call()
    {
        Ok(resp) => match resp.into_string() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("easyenclave: init: gce-meta read body: {e}");
                return;
            }
        },
        Err(_) => {
            // Not on GCE (connection refused / timeout), or attribute
            // not set (404). Nothing to do.
            return;
        }
    };

    let map: std::collections::HashMap<String, String> = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("easyenclave: init: gce-meta ee-config parse error: {e}");
            return;
        }
    };

    for k in map.keys() {
        eprintln!("easyenclave: init: gce-meta env {k}=<redacted>");
    }
    for (k, v) in map {
        std::env::set_var(k, v);
    }
}

fn nix_mount_flags(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> Result<(), String> {
    use std::ffi::CString;
    let _ = std::fs::create_dir_all(target);
    let src = CString::new(src).unwrap();
    let target_c = CString::new(target).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            flags as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        Err(format!("errno {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
