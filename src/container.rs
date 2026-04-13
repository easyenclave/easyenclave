//! Container management via libcontainer (youki) + oci-distribution.
//!
//! No Docker/Podman daemon needed. Pulls OCI images directly from registries,
//! unpacks layers, and runs containers using Linux namespaces via libcontainer.

use oci_distribution::client::{ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use std::path::{Path, PathBuf};

const CONTAINER_ROOT: &str = "/var/lib/easyenclave/containers";

/// Pull an OCI image, unpack it, and run it as a container. Returns a container ID.
pub async fn pull_and_run(
    image: &str,
    name: &str,
    env: Option<Vec<String>>,
    _volumes: Option<Vec<String>>,
    _network_host: bool,
) -> Result<String, String> {
    let container_id = uuid::Uuid::new_v4().to_string();
    let container_dir = format!("{CONTAINER_ROOT}/{name}");
    let rootfs_dir = format!("{container_dir}/rootfs");
    let _ = tokio::fs::create_dir_all(&rootfs_dir).await;

    // Pull and unpack image, extract entrypoint/cmd from image config
    eprintln!("easyenclave: pulling {image}");
    let image_config = pull_image(image, &rootfs_dir).await?;
    eprintln!("easyenclave: image unpacked to {rootfs_dir}");

    // Ensure /etc/hosts exists in the container rootfs. Without it,
    // Go binaries (like cloudflared) resolve "localhost" via DNS
    // instead of the hosts file, failing with "no such host".
    let etc_dir = format!("{rootfs_dir}/etc");
    let _ = tokio::fs::create_dir_all(&etc_dir).await;
    let hosts_path = format!("{etc_dir}/hosts");
    if !tokio::fs::try_exists(&hosts_path).await.unwrap_or(false) {
        let _ = tokio::fs::write(&hosts_path, "127.0.0.1 localhost\n::1 localhost\n").await;
    }
    // Also ensure resolv.conf so DNS works inside the container
    let resolv_path = format!("{etc_dir}/resolv.conf");
    if !tokio::fs::try_exists(&resolv_path).await.unwrap_or(false) {
        if let Ok(host_resolv) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            let _ = tokio::fs::write(&resolv_path, host_resolv).await;
        }
    }

    // Generate OCI runtime spec using the image's entrypoint/cmd/env
    let spec = build_spec(&rootfs_dir, env, &image_config);
    let spec_path = format!("{container_dir}/config.json");
    let spec_json = serde_json::to_string_pretty(&spec).map_err(|e| format!("spec: {e}"))?;
    tokio::fs::write(&spec_path, spec_json)
        .await
        .map_err(|e| format!("write spec: {e}"))?;

    // Start container via libcontainer
    let container_dir_path = PathBuf::from(&container_dir);
    let name_clone = name.to_string();
    let cid = container_id.clone();
    tokio::task::spawn_blocking(move || start_container(&container_dir_path, &name_clone, &cid))
        .await
        .map_err(|e| format!("spawn: {e}"))?
        .map_err(|e| format!("start container: {e}"))?;

    eprintln!("easyenclave: container {name} started (id={container_id})");
    Ok(container_id)
}

/// Pull an OCI image and extract the entrypoint + env for native execution.
/// Returns (entrypoint_args, env_vars). The unpacked rootfs is at
/// {CONTAINER_ROOT}/{name}/rootfs — binaries can be run directly from there.
pub async fn pull_native(image: &str, name: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let container_dir = format!("{CONTAINER_ROOT}/{name}");
    let rootfs_dir = format!("{container_dir}/rootfs");
    let _ = tokio::fs::create_dir_all(&rootfs_dir).await;

    eprintln!("easyenclave: pulling {image} (native)");
    let config = pull_image(image, &rootfs_dir).await?;
    eprintln!("easyenclave: image unpacked to {rootfs_dir}");

    // Build the full command: entrypoint + cmd (per OCI spec)
    let args = if !config.entrypoint.is_empty() {
        let mut a = config.entrypoint;
        a.extend(config.cmd);
        a
    } else if !config.cmd.is_empty() {
        config.cmd
    } else {
        return Err("image has no entrypoint or cmd".into());
    };

    // Rewrite paths to point into the unpacked rootfs
    let mut resolved = args;
    if let Some(first) = resolved.first_mut() {
        let rootfs_path = format!("{rootfs_dir}{first}");
        if tokio::fs::try_exists(&rootfs_path).await.unwrap_or(false) {
            *first = rootfs_path;
        }
    }

    Ok((resolved, config.env))
}

/// OCI image config — extracted from the registry for building the runtime spec.
#[derive(Default)]
struct ImageConfig {
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<String>,
    working_dir: String,
}

/// Extract a JSON array of strings, or empty vec if null/missing.
fn json_string_array(val: Option<&serde_json::Value>) -> Vec<String> {
    val.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pull an OCI image, unpack its layers, and return the image config.
async fn pull_image(image: &str, rootfs: &str) -> Result<ImageConfig, String> {
    let reference: Reference = image
        .parse()
        .map_err(|e| format!("parse ref {image}: {e}"))?;

    let client_config = ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    };
    let client = oci_distribution::Client::new(client_config);

    // pull_manifest_and_config resolves multi-arch indexes and returns
    // both the manifest (for layers) and the config JSON (for
    // entrypoint/cmd/env/workdir).
    let (manifest, _digest, config_json) = client
        .pull_manifest_and_config(&reference, &RegistryAuth::Anonymous)
        .await
        .map_err(|e| format!("pull manifest: {e}"))?;

    let config_val: serde_json::Value =
        serde_json::from_str(&config_json).map_err(|e| format!("parse image config: {e}"))?;
    let c = &config_val["config"];
    let image_config = ImageConfig {
        entrypoint: json_string_array(c.get("Entrypoint")),
        cmd: json_string_array(c.get("Cmd")),
        env: json_string_array(c.get("Env")),
        working_dir: c
            .get("WorkingDir")
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .to_string(),
    };

    let layers = manifest.layers.clone();

    for layer in &layers {
        let mut layer_data = Vec::new();
        client
            .pull_blob(&reference, layer, &mut layer_data)
            .await
            .map_err(|e| format!("pull layer {}: {e}", layer.digest))?;

        // Unpack the gzipped tar layer
        let rootfs_path = PathBuf::from(rootfs);
        let data = layer_data;
        tokio::task::spawn_blocking(move || unpack_layer(&data, &rootfs_path))
            .await
            .map_err(|e| format!("spawn unpack: {e}"))?
            .map_err(|e| format!("unpack layer: {e}"))?;
    }

    Ok(image_config)
}

/// Unpack a gzipped tar layer into the rootfs.
fn unpack_layer(data: &[u8], rootfs: &Path) -> Result<(), String> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    archive.set_overwrite(true);
    archive.unpack(rootfs).map_err(|e| format!("untar: {e}"))?;
    Ok(())
}

/// Build an OCI runtime spec using the image's config.
fn build_spec(
    rootfs: &str,
    env: Option<Vec<String>>,
    image_config: &ImageConfig,
) -> oci_spec::runtime::Spec {
    use oci_spec::runtime::*;

    // Env: image defaults → workload overrides (later entries win)
    let mut env_vars = image_config.env.clone();
    if env_vars.iter().all(|e| !e.starts_with("PATH=")) {
        env_vars.insert(
            0,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        );
    }
    env_vars.push("TERM=xterm".to_string());
    if let Some(extra) = env {
        env_vars.extend(extra);
    }

    // Args: entrypoint + cmd (per OCI spec). Fallback to /bin/sh.
    let args = if !image_config.entrypoint.is_empty() {
        let mut a = image_config.entrypoint.clone();
        a.extend(image_config.cmd.clone());
        a
    } else if !image_config.cmd.is_empty() {
        image_config.cmd.clone()
    } else {
        vec!["/bin/sh".to_string()]
    };

    let cwd = if image_config.working_dir.is_empty() {
        "/".to_string()
    } else {
        image_config.working_dir.clone()
    };

    let process = ProcessBuilder::default()
        .terminal(false)
        .user(UserBuilder::default().uid(0u32).gid(0u32).build().unwrap())
        .args(args)
        .env(env_vars)
        .cwd(cwd)
        .build()
        .unwrap();

    let root = RootBuilder::default()
        .path(rootfs.to_string())
        .readonly(false)
        .build()
        .unwrap();

    // Minimal Linux namespaces
    let namespaces = vec![
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Pid)
            .build()
            .unwrap(),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Mount)
            .build()
            .unwrap(),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Ipc)
            .build()
            .unwrap(),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Uts)
            .build()
            .unwrap(),
    ];

    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .build()
        .unwrap();

    SpecBuilder::default()
        .version("1.0.2".to_string())
        .process(process)
        .root(root)
        .linux(linux)
        .build()
        .unwrap()
}

/// Start a container using libcontainer.
fn start_container(container_dir: &Path, name: &str, _container_id: &str) -> Result<(), String> {
    use libcontainer::container::builder::ContainerBuilder;
    use libcontainer::syscall::syscall::SyscallType;

    let mut container = ContainerBuilder::new(name.to_string(), SyscallType::default())
        .with_root_path(container_dir.to_path_buf())
        .map_err(|e| format!("root path: {e}"))?
        .as_init(container_dir)
        .with_systemd(false)
        .build()
        .map_err(|e| format!("build container: {e}"))?;

    container.start().map_err(|e| format!("start: {e}"))?;

    Ok(())
}

/// Execute a command inside a running container. Returns (exit_code, stdout, stderr).
pub async fn exec(container_name: &str, cmd: &[String]) -> Result<(i64, String, String), String> {
    // For now, use nsenter via the container's PID namespace
    let container_dir = format!("{CONTAINER_ROOT}/{container_name}");
    let pid_file = format!("{container_dir}/state.json");

    let pid = read_container_pid(&pid_file).await?;

    let mut args = vec![
        "-t".to_string(),
        pid.to_string(),
        "-m".to_string(),
        "-u".to_string(),
        "-i".to_string(),
        "-p".to_string(),
        "--".to_string(),
    ];
    args.extend(cmd.iter().cloned());

    let output = tokio::process::Command::new("nsenter")
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("nsenter: {e}"))?;

    Ok((
        output.status.code().unwrap_or(-1) as i64,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// Read the init PID from the container state.
async fn read_container_pid(state_path: &str) -> Result<u32, String> {
    let data = tokio::fs::read_to_string(state_path)
        .await
        .map_err(|e| format!("read state: {e}"))?;
    let state: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("parse state: {e}"))?;
    state["init_process_start"]
        .as_u64()
        .or_else(|| state["pid"].as_u64())
        .map(|p| p as u32)
        .ok_or_else(|| "no pid in container state".into())
}

/// Stop a container by killing its init process.
pub async fn stop(container_id: &str) -> Result<(), String> {
    // Find by ID or name in CONTAINER_ROOT
    let container_dir = format!("{CONTAINER_ROOT}/{container_id}");
    if let Ok(pid) = read_container_pid(&format!("{container_dir}/state.json")).await {
        crate::process::kill_process(pid).await?;
    }
    let _ = tokio::fs::remove_dir_all(&container_dir).await;
    Ok(())
}

/// Check if a container is running.
pub async fn is_running(container_id: &str) -> bool {
    let state_path = format!("{CONTAINER_ROOT}/{container_id}/state.json");
    if let Ok(pid) = read_container_pid(&state_path).await {
        Path::new(&format!("/proc/{pid}")).exists()
    } else {
        false
    }
}

/// Get the last N lines of container logs (from stdout capture file).
pub async fn logs(container_id: &str, _tail: usize) -> Result<Vec<String>, String> {
    let log_path = format!("{CONTAINER_ROOT}/{container_id}/output.log");
    match tokio::fs::read_to_string(&log_path).await {
        Ok(content) => Ok(content.lines().map(String::from).collect()),
        Err(_) => Ok(Vec::new()),
    }
}
