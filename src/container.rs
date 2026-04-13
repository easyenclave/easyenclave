//! Container management via libcontainer (youki) + oci-distribution.
//!
//! No Docker/Podman daemon needed. Pulls OCI images directly from registries,
//! unpacks layers, and runs containers using Linux namespaces via libcontainer.

use oci_distribution::client::{ClientConfig, ClientProtocol};
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Component;
use std::path::{Path, PathBuf};

const DEFAULT_DATA_DIR: &str = "/var/lib/easyenclave";

fn container_root() -> PathBuf {
    let data_dir = std::env::var("EE_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string());
    PathBuf::from(data_dir).join("containers")
}

fn container_dir(container_id: &str) -> PathBuf {
    container_root().join(container_id)
}

fn native_dir(name: &str) -> PathBuf {
    container_root().join("native").join(name)
}

/// Pull an OCI image, unpack it, and run it as a container. Returns a container ID.
pub async fn pull_and_run(
    image: &str,
    name: &str,
    env: Option<Vec<String>>,
    _volumes: Option<Vec<String>>,
    _network_host: bool,
) -> Result<String, String> {
    let container_id = uuid::Uuid::new_v4().to_string();
    let root_path = container_root();
    let container_dir = container_dir(&container_id);
    let rootfs_dir = container_dir.join("rootfs");
    tokio::fs::create_dir_all(&rootfs_dir)
        .await
        .map_err(|e| format!("create rootfs dir: {e}"))?;
    let rootfs_dir_str = rootfs_dir.to_string_lossy().into_owned();

    // Pull and unpack image, extract entrypoint/cmd from image config
    eprintln!("easyenclave: pulling {image}");
    let image_config = pull_image(image, &rootfs_dir_str).await?;
    eprintln!("easyenclave: image unpacked to {}", rootfs_dir.display());

    // Ensure /etc/hosts exists in the container rootfs. Without it,
    // Go binaries (like cloudflared) resolve "localhost" via DNS
    // instead of the hosts file, failing with "no such host".
    let etc_dir = rootfs_dir.join("etc");
    let _ = tokio::fs::create_dir_all(&etc_dir).await;
    let hosts_path = etc_dir.join("hosts");
    if !tokio::fs::try_exists(&hosts_path).await.unwrap_or(false) {
        let _ = tokio::fs::write(&hosts_path, "127.0.0.1 localhost\n::1 localhost\n").await;
    }
    // Also ensure resolv.conf so DNS works inside the container
    let resolv_path = etc_dir.join("resolv.conf");
    if !tokio::fs::try_exists(&resolv_path).await.unwrap_or(false) {
        if let Ok(host_resolv) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            let _ = tokio::fs::write(&resolv_path, host_resolv).await;
        }
    }

    // Generate OCI runtime spec using the image's entrypoint/cmd/env
    let spec = build_spec(&rootfs_dir_str, env, &image_config);
    let spec_path = container_dir.join("config.json");
    let spec_json = serde_json::to_string_pretty(&spec).map_err(|e| format!("spec: {e}"))?;
    tokio::fs::write(&spec_path, spec_json)
        .await
        .map_err(|e| format!("write spec: {e}"))?;

    // Start container via libcontainer
    let root_path_clone = root_path.clone();
    let bundle_path = container_dir.clone();
    let cid = container_id.clone();
    tokio::task::spawn_blocking(move || start_container(&root_path_clone, &bundle_path, &cid))
        .await
        .map_err(|e| format!("spawn: {e}"))?
        .map_err(|e| format!("start container: {e}"))?;

    eprintln!("easyenclave: container {name} started (id={container_id})");
    Ok(container_id)
}

/// Pull an OCI image and extract a single static executable for native
/// execution. Returns (entrypoint_args, env_vars).
pub async fn pull_native(image: &str, name: &str) -> Result<(Vec<String>, Vec<String>), String> {
    eprintln!("easyenclave: pulling {image} (native static)");
    let (reference, client, manifest, config) = fetch_manifest_and_image_config(image).await?;
    let mut args = build_image_args(&config)?;
    let candidate_paths = resolve_native_executable_candidates(&args[0], &config)?;
    let extracted =
        extract_native_binary(&client, &reference, &manifest.layers, &candidate_paths).await?;
    validate_static_elf(&extracted.bytes)?;

    let target_dir = native_dir(name);
    let _ = tokio::fs::remove_dir_all(&target_dir).await;
    tokio::fs::create_dir_all(&target_dir)
        .await
        .map_err(|e| format!("create native dir: {e}"))?;

    let file_name = Path::new(&extracted.source_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("app");
    let binary_path = target_dir.join(file_name);
    tokio::fs::write(&binary_path, &extracted.bytes)
        .await
        .map_err(|e| format!("write native binary: {e}"))?;
    std::fs::set_permissions(
        &binary_path,
        std::fs::Permissions::from_mode(extracted.mode),
    )
    .map_err(|e| format!("chmod native binary: {e}"))?;

    args[0] = binary_path.to_string_lossy().into_owned();
    Ok((args, config.env))
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
    let (reference, client, manifest, image_config) =
        fetch_manifest_and_image_config(image).await?;
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

async fn fetch_manifest_and_image_config(
    image: &str,
) -> Result<
    (
        Reference,
        oci_distribution::Client,
        OciImageManifest,
        ImageConfig,
    ),
    String,
> {
    let reference: Reference = image
        .parse()
        .map_err(|e| format!("parse ref {image}: {e}"))?;

    let client_config = ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    };
    let client = oci_distribution::Client::new(client_config);
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

    Ok((reference, client, manifest, image_config))
}

fn build_image_args(image_config: &ImageConfig) -> Result<Vec<String>, String> {
    if !image_config.entrypoint.is_empty() {
        let mut args = image_config.entrypoint.clone();
        args.extend(image_config.cmd.clone());
        Ok(args)
    } else if !image_config.cmd.is_empty() {
        Ok(image_config.cmd.clone())
    } else {
        Err("image has no entrypoint or cmd".into())
    }
}

fn resolve_native_executable_candidates(
    program: &str,
    image_config: &ImageConfig,
) -> Result<Vec<String>, String> {
    if program.contains('/') {
        return Ok(vec![resolve_image_program_path(
            program,
            &image_config.working_dir,
        )?]);
    }

    let path_env = image_config
        .env
        .iter()
        .find_map(|entry| entry.strip_prefix("PATH=").map(str::to_string))
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());

    let mut candidates = Vec::new();
    for dir in path_env.split(':').filter(|dir| !dir.is_empty()) {
        candidates.push(resolve_image_program_path(
            &format!("{dir}/{program}"),
            &image_config.working_dir,
        )?);
    }

    if candidates.is_empty() {
        Err(format!("could not resolve executable path for {program}"))
    } else {
        Ok(candidates)
    }
}

fn resolve_image_program_path(program: &str, working_dir: &str) -> Result<String, String> {
    let base = if program.starts_with('/') {
        PathBuf::from(program)
    } else {
        PathBuf::from(if working_dir.is_empty() {
            "/"
        } else {
            working_dir
        })
        .join(program)
    };
    normalize_image_path(&base)
}

fn normalize_image_path(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!("path escapes image root: {}", path.display()));
                }
            }
            Component::Prefix(_) => {
                return Err(format!("unsupported image path: {}", path.display()));
            }
        }
    }

    Ok(format!("/{}", parts.join("/")))
}

#[derive(Clone, Debug)]
struct NativeBinary {
    source_path: String,
    bytes: Vec<u8>,
    mode: u32,
}

async fn extract_native_binary(
    client: &oci_distribution::Client,
    reference: &Reference,
    layers: &[OciDescriptor],
    candidate_paths: &[String],
) -> Result<NativeBinary, String> {
    let mut states: HashMap<String, Option<NativeBinary>> = candidate_paths
        .iter()
        .cloned()
        .map(|path| (path, None))
        .collect();

    for layer in layers {
        let mut layer_data = Vec::new();
        client
            .pull_blob(reference, layer, &mut layer_data)
            .await
            .map_err(|e| format!("pull layer {}: {e}", layer.digest))?;
        scan_native_layer(&layer_data, &mut states)?;
    }

    candidate_paths
        .iter()
        .find_map(|path| states.get(path).and_then(|state| state.clone()))
        .ok_or_else(|| {
            format!(
                "native mode could not find executable in image: {}",
                candidate_paths.join(", ")
            )
        })
}

fn scan_native_layer(
    data: &[u8],
    states: &mut HashMap<String, Option<NativeBinary>>,
) -> Result<(), String> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);
    let candidate_paths: Vec<String> = states.keys().cloned().collect();

    for entry_result in archive
        .entries()
        .map_err(|e| format!("read tar entries: {e}"))?
    {
        let mut entry = entry_result.map_err(|e| format!("read tar entry: {e}"))?;
        let path = normalize_image_path(
            &entry
                .path()
                .map_err(|e| format!("read tar path: {e}"))?
                .into_owned(),
        )?;

        if let Some(opaque_dir) = opaque_whiteout_dir(&path) {
            for candidate in &candidate_paths {
                if candidate.starts_with(&(opaque_dir.clone() + "/")) {
                    states.insert(candidate.clone(), None);
                }
            }
            continue;
        }

        if let Some(whiteout_target) = whiteout_target_path(&path) {
            for candidate in &candidate_paths {
                if candidate == &whiteout_target
                    || candidate.starts_with(&(whiteout_target.clone() + "/"))
                {
                    states.insert(candidate.clone(), None);
                }
            }
            continue;
        }

        if !states.contains_key(&path) {
            continue;
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(format!(
                "native mode does not support symlinked executables: {path}"
            ));
        }
        if !entry_type.is_file() {
            continue;
        }

        let mode = entry.header().mode().unwrap_or(0o755);
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read executable bytes: {e}"))?;
        states.insert(
            path.clone(),
            Some(NativeBinary {
                source_path: path,
                bytes,
                mode,
            }),
        );
    }

    Ok(())
}

fn opaque_whiteout_dir(path: &str) -> Option<String> {
    if !path.ends_with("/.wh..wh..opq") && path != "/.wh..wh..opq" {
        return None;
    }

    let parent = Path::new(path).parent()?;
    normalize_image_path(parent).ok()
}

fn whiteout_target_path(path: &str) -> Option<String> {
    let file_name = Path::new(path).file_name()?.to_str()?;
    let target_name = file_name.strip_prefix(".wh.")?;
    if target_name == ".wh..opq" {
        return None;
    }

    let parent = Path::new(path).parent()?;
    normalize_image_path(&parent.join(target_name)).ok()
}

#[derive(Clone, Copy)]
enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy)]
enum ElfEndian {
    Little,
    Big,
}

fn validate_static_elf(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 0x34 || &bytes[..4] != b"\x7FELF" {
        return Err("native mode requires a static ELF executable".into());
    }

    let class = match bytes[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return Err("native mode requires a supported ELF executable".into()),
    };
    let endian = match bytes[5] {
        1 => ElfEndian::Little,
        2 => ElfEndian::Big,
        _ => return Err("native mode requires a supported ELF executable".into()),
    };

    let (phoff, phentsize, phnum) = match class {
        ElfClass::Elf32 => (
            read_u32(bytes, 28, endian)? as u64,
            read_u16(bytes, 42, endian)? as u64,
            read_u16(bytes, 44, endian)? as u64,
        ),
        ElfClass::Elf64 => (
            read_u64(bytes, 32, endian)?,
            read_u16(bytes, 54, endian)? as u64,
            read_u16(bytes, 56, endian)? as u64,
        ),
    };

    if phoff == 0 || phentsize == 0 || phnum == 0 {
        return Err("native mode requires an executable ELF with program headers".into());
    }

    let ph_table_len = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| "invalid ELF program header table".to_string())?;
    let ph_table_end = phoff
        .checked_add(ph_table_len)
        .ok_or_else(|| "invalid ELF program header table".to_string())?;
    if ph_table_end as usize > bytes.len() {
        return Err("invalid ELF program header table".into());
    }

    let mut dynamic_segment = None;
    for index in 0..phnum {
        let entry_offset = (phoff + index * phentsize) as usize;
        let p_type = read_u32(bytes, entry_offset, endian)?;
        if p_type == 3 {
            return Err("native mode requires a static ELF executable".into());
        }
        if p_type == 2 {
            dynamic_segment = Some(match class {
                ElfClass::Elf32 => (
                    read_u32(bytes, entry_offset + 4, endian)? as u64,
                    read_u32(bytes, entry_offset + 16, endian)? as u64,
                ),
                ElfClass::Elf64 => (
                    read_u64(bytes, entry_offset + 8, endian)?,
                    read_u64(bytes, entry_offset + 32, endian)?,
                ),
            });
        }
    }

    if let Some((offset, size)) = dynamic_segment {
        let entry_size = match class {
            ElfClass::Elf32 => 8usize,
            ElfClass::Elf64 => 16usize,
        };
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "invalid ELF dynamic section".to_string())?;
        if end as usize > bytes.len() {
            return Err("invalid ELF dynamic section".into());
        }

        let mut cursor = offset as usize;
        while cursor + entry_size <= end as usize {
            let tag = match class {
                ElfClass::Elf32 => read_i32(bytes, cursor, endian)? as i64,
                ElfClass::Elf64 => read_i64(bytes, cursor, endian)?,
            };
            if tag == 0 {
                break;
            }
            if tag == 1 {
                return Err("native mode requires a static ELF executable".into());
            }
            cursor += entry_size;
        }
    }

    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u16, String> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated ELF".to_string())?;
    Ok(match endian {
        ElfEndian::Little => u16::from_le_bytes([slice[0], slice[1]]),
        ElfEndian::Big => u16::from_be_bytes([slice[0], slice[1]]),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u32, String> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated ELF".to_string())?;
    Ok(match endian {
        ElfEndian::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
        ElfEndian::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u64, String> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated ELF".to_string())?;
    Ok(match endian {
        ElfEndian::Little => u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
        ElfEndian::Big => u64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
    })
}

fn read_i32(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<i32, String> {
    Ok(read_u32(bytes, offset, endian)? as i32)
}

fn read_i64(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<i64, String> {
    Ok(read_u64(bytes, offset, endian)? as i64)
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
fn start_container(root_path: &Path, bundle: &Path, container_id: &str) -> Result<(), String> {
    use libcontainer::container::builder::ContainerBuilder;
    use libcontainer::syscall::syscall::SyscallType;

    let stdout_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(bundle.join("output.log"))
        .map_err(|e| format!("open output.log: {e}"))?;
    let stderr_log = stdout_log
        .try_clone()
        .map_err(|e| format!("clone output.log: {e}"))?;

    let mut container = ContainerBuilder::new(container_id.to_string(), SyscallType::default())
        .with_root_path(root_path.to_path_buf())
        .map_err(|e| format!("root path: {e}"))?
        .with_stdout(stdout_log)
        .with_stderr(stderr_log)
        .as_init(bundle)
        .with_systemd(false)
        .build()
        .map_err(|e| format!("build container: {e}"))?;

    container.start().map_err(|e| format!("start: {e}"))?;

    Ok(())
}

/// Execute a command inside a running container. Returns (exit_code, stdout, stderr).
pub async fn exec(container_id: &str, cmd: &[String]) -> Result<(i64, String, String), String> {
    // For now, use nsenter via the container's PID namespace
    let pid = read_container_pid(&container_dir(container_id).join("state.json")).await?;

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
async fn read_container_pid(state_path: &Path) -> Result<u32, String> {
    let data = tokio::fs::read_to_string(state_path)
        .await
        .map_err(|e| format!("read state: {e}"))?;
    let state: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("parse state: {e}"))?;
    state["pid"]
        .as_i64()
        .filter(|pid| *pid > 0)
        .map(|p| p as u32)
        .ok_or_else(|| "no pid in container state".into())
}

/// Stop a container by killing its init process.
pub async fn stop(container_id: &str) -> Result<(), String> {
    let container_dir = container_dir(container_id);
    if let Ok(pid) = read_container_pid(&container_dir.join("state.json")).await {
        crate::process::kill_process(pid).await?;
    }
    let _ = tokio::fs::remove_dir_all(&container_dir).await;
    Ok(())
}

/// Check if a container is running.
pub async fn is_running(container_id: &str) -> bool {
    if let Ok(pid) = read_container_pid(&container_dir(container_id).join("state.json")).await {
        Path::new(&format!("/proc/{pid}")).exists()
    } else {
        false
    }
}

/// Get the last N lines of container logs (from stdout capture file).
pub async fn logs(container_id: &str, tail: usize) -> Result<Vec<String>, String> {
    let log_path = container_dir(container_id).join("output.log");
    match tokio::fs::read_to_string(&log_path).await {
        Ok(content) => {
            if tail == 0 {
                return Ok(Vec::new());
            }
            let mut lines: Vec<String> = content.lines().map(String::from).collect();
            if lines.len() > tail {
                lines = lines.split_off(lines.len() - tail);
            }
            Ok(lines)
        }
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_image_path, opaque_whiteout_dir, resolve_native_executable_candidates,
        validate_static_elf, whiteout_target_path, ImageConfig,
    };
    use std::path::Path;

    fn image_config(
        entrypoint: &[&str],
        cmd: &[&str],
        env: &[&str],
        working_dir: &str,
    ) -> ImageConfig {
        ImageConfig {
            entrypoint: entrypoint.iter().map(|s| s.to_string()).collect(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            env: env.iter().map(|s| s.to_string()).collect(),
            working_dir: working_dir.to_string(),
        }
    }

    fn minimal_elf64(ph_type: u32, dynamic_tag: Option<i64>) -> Vec<u8> {
        let phoff = 64u64;
        let phentsize = 56u16;
        let phnum = 1u16;
        let mut bytes = vec![0u8; 64 + 56 + 16];
        bytes[..4].copy_from_slice(b"\x7FELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&phoff.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&phentsize.to_le_bytes());
        bytes[56..58].copy_from_slice(&phnum.to_le_bytes());

        let ph = &mut bytes[64..120];
        ph[..4].copy_from_slice(&ph_type.to_le_bytes());
        ph[8..16].copy_from_slice(&120u64.to_le_bytes());
        ph[32..40].copy_from_slice(&16u64.to_le_bytes());

        if let Some(tag) = dynamic_tag {
            bytes[120..128].copy_from_slice(&tag.to_le_bytes());
        }

        bytes
    }

    #[test]
    fn resolve_native_candidates_uses_image_path() {
        let config = image_config(&["demo"], &[], &["PATH=/usr/local/bin:/usr/bin"], "/");
        let candidates = resolve_native_executable_candidates("demo", &config).unwrap();
        assert_eq!(candidates, vec!["/usr/local/bin/demo", "/usr/bin/demo"]);
    }

    #[test]
    fn resolve_native_candidates_resolves_relative_workdir() {
        let config = image_config(&["./demo"], &[], &[], "/work");
        let candidates = resolve_native_executable_candidates("./demo", &config).unwrap();
        assert_eq!(candidates, vec!["/work/demo"]);
    }

    #[test]
    fn normalize_image_path_collapses_dot_segments() {
        assert_eq!(
            normalize_image_path(Path::new("/opt/./app/../demo")).unwrap(),
            "/opt/demo"
        );
    }

    #[test]
    fn whiteout_helpers_map_targets() {
        assert_eq!(
            whiteout_target_path("/usr/bin/.wh.demo").unwrap(),
            "/usr/bin/demo"
        );
        assert_eq!(
            opaque_whiteout_dir("/usr/bin/.wh..wh..opq").unwrap(),
            "/usr/bin"
        );
    }

    #[test]
    fn validate_static_elf_accepts_plain_executable() {
        let elf = minimal_elf64(1, None);
        validate_static_elf(&elf).unwrap();
    }

    #[test]
    fn validate_static_elf_rejects_interp() {
        let elf = minimal_elf64(3, None);
        assert!(validate_static_elf(&elf).is_err());
    }

    #[test]
    fn validate_static_elf_rejects_needed_dynamic_entry() {
        let elf = minimal_elf64(2, Some(1));
        assert!(validate_static_elf(&elf).is_err());
    }
}
