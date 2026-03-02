use regex::Regex;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use uuid::Uuid;

const LOCAL_TDX_MANAGED_PREFIX: &str = "ee-local-tdx-";
const LOCAL_TDX_TEMPLATE_PREFIX: &str = "tdvirsh-trust_domain_verity-";

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("ee-ops ops: {err}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<(), String> {
    let (provider_kind, tail) = parse_provider(args)?;
    if tail.is_empty() {
        return Err(ops_usage());
    }
    let provider: Box<dyn ProviderOps> = match provider_kind {
        ProviderKind::Gcp => Box::new(GcpProvider),
        ProviderKind::LocalTdx => Box::new(LocalTdxProvider),
    };

    match tail[0].as_str() {
        "node" | "nodes" => provider.node(&tail[1..]),
        "image" | "images" => provider.image(&tail[1..]),
        other => Err(format!("unknown ops domain '{other}'\n{}", ops_usage())),
    }
}

fn ops_usage() -> String {
    "Usage:
  cargo run -p ee-ops -- ops [--provider gcp|local-tdx] node <new|list|delete|measure> [args...]
  cargo run -p ee-ops -- ops [--provider gcp|local-tdx] image bake [args...]"
        .to_string()
}

#[derive(Clone, Copy)]
enum ProviderKind {
    Gcp,
    LocalTdx,
}

fn parse_provider(args: &[String]) -> Result<(ProviderKind, Vec<String>), String> {
    let mut provider = ProviderKind::Gcp;
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--provider" {
            let Some(value) = args.get(i + 1) else {
                return Err("missing value for --provider".to_string());
            };
            provider = parse_provider_value(value)?;
            i += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--provider=") {
            provider = parse_provider_value(value)?;
            i += 1;
            continue;
        }
        out.push(arg.clone());
        i += 1;
    }
    Ok((provider, out))
}

fn parse_provider_value(raw: &str) -> Result<ProviderKind, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gcp" => Ok(ProviderKind::Gcp),
        "local-tdx" | "local_tdx" | "local" => Ok(ProviderKind::LocalTdx),
        other => Err(format!(
            "unsupported provider '{other}' (expected gcp or local-tdx)"
        )),
    }
}

trait ProviderOps {
    fn node(&self, args: &[String]) -> Result<(), String>;
    fn image(&self, args: &[String]) -> Result<(), String>;
}

struct GcpProvider;

impl GcpProvider {
    fn run_script(&self, script_rel: &str, args: &[String]) -> Result<(), String> {
        let root = repo_root()?;
        let script = root.join(script_rel);
        if !script.exists() {
            return Err(format!("script not found: {}", script.display()));
        }
        run_status(
            "bash",
            std::iter::once(script.to_string_lossy().to_string())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        )
    }
}

impl ProviderOps for GcpProvider {
    fn node(&self, args: &[String]) -> Result<(), String> {
        let Some(subcmd) = args.first() else {
            return Err("missing node subcommand (expected new|list|delete|measure)".to_string());
        };
        match subcmd.as_str() {
            "new" | "list" | "delete" | "measure" => self.run_script(
                "crates/ee-ops/assets/gcp-nodectl.sh",
                &std::iter::once("vm".to_string())
                    .chain(std::iter::once(subcmd.clone()))
                    .chain(args.iter().skip(1).cloned())
                    .collect::<Vec<_>>(),
            ),
            other => Err(format!(
                "unsupported gcp node subcommand '{other}' (expected new|list|delete|measure)"
            )),
        }
    }

    fn image(&self, args: &[String]) -> Result<(), String> {
        let Some(subcmd) = args.first() else {
            return Err("missing image subcommand (expected bake)".to_string());
        };
        match subcmd.as_str() {
            "bake" => self.run_script("crates/ee-ops/assets/gcp-bake-image.sh", &args[1..]),
            other => Err(format!(
                "unsupported gcp image subcommand '{other}' (expected bake)"
            )),
        }
    }
}

struct LocalTdxProvider;

impl ProviderOps for LocalTdxProvider {
    fn node(&self, args: &[String]) -> Result<(), String> {
        let Some(subcmd) = args.first() else {
            return Err("missing node subcommand (expected new|list|delete)".to_string());
        };
        match subcmd.as_str() {
            "list" => run_status("virsh", vec!["list".to_string(), "--all".to_string()]),
            "new" => local_new(&args[1..]),
            "delete" => local_delete(&args[1..]),
            other => Err(format!(
                "unsupported local-tdx node subcommand '{other}' (expected new|list|delete)"
            )),
        }
    }

    fn image(&self, args: &[String]) -> Result<(), String> {
        let Some(subcmd) = args.first() else {
            return Err("missing image subcommand (expected bake)".to_string());
        };
        match subcmd.as_str() {
            "bake" => local_bake(&args[1..]),
            other => Err(format!(
                "unsupported local-tdx image subcommand '{other}' (expected bake)"
            )),
        }
    }
}

fn local_new(args: &[String]) -> Result<(), String> {
    let mut count = 1usize;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                let Some(raw) = args.get(i + 1) else {
                    return Err("missing value for --count".to_string());
                };
                count = raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --count value '{raw}'"))?;
                if count == 0 {
                    return Err("--count must be greater than zero".to_string());
                }
                i += 2;
            }
            other => {
                return Err(format!("unknown local-tdx node new arg: {other}"));
            }
        }
    }

    let template = discover_template_vm()?;
    for _ in 0..count {
        let vm = clone_local_vm(&template)?;
        println!("{vm}");
    }
    Ok(())
}

fn local_delete(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: ops --provider local-tdx node delete <name|all|all-with-template> [name...]"
                .to_string(),
        );
    }

    let mut names: Vec<String> = Vec::new();
    for arg in args {
        if arg == "all" {
            let out = run_capture(
                "virsh",
                vec![
                    "list".to_string(),
                    "--all".to_string(),
                    "--name".to_string(),
                ],
            )?;
            for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if line.starts_with(LOCAL_TDX_MANAGED_PREFIX) {
                    names.push(line.to_string());
                }
            }
        } else if arg == "all-with-template" {
            let out = run_capture(
                "virsh",
                vec![
                    "list".to_string(),
                    "--all".to_string(),
                    "--name".to_string(),
                ],
            )?;
            for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if line.starts_with(LOCAL_TDX_MANAGED_PREFIX)
                    || line.starts_with(LOCAL_TDX_TEMPLATE_PREFIX)
                {
                    names.push(line.to_string());
                }
            }
        } else {
            names.push(arg.clone());
        }
    }
    names.sort();
    names.dedup();

    if names.is_empty() {
        return Err("no local TDX VMs matched delete selection".to_string());
    }

    for name in names {
        let _ = run_status("virsh", vec!["destroy".to_string(), name.clone()]);
        run_status("virsh", vec!["undefine".to_string(), name.clone()])?;
        println!("deleted {name}");
    }
    Ok(())
}

fn local_bake(args: &[String]) -> Result<(), String> {
    let mut output_path: Option<PathBuf> = None;
    let mut source_vm: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                let Some(raw) = args.get(i + 1) else {
                    return Err("missing value for --output".to_string());
                };
                output_path = Some(PathBuf::from(raw));
                i += 2;
            }
            "--source-vm" => {
                let Some(raw) = args.get(i + 1) else {
                    return Err("missing value for --source-vm".to_string());
                };
                source_vm = Some(raw.clone());
                i += 2;
            }
            other => {
                return Err(format!("unknown local-tdx image bake arg: {other}"));
            }
        }
    }

    let out = output_path.ok_or_else(|| {
        "usage: ops --provider local-tdx image bake --output <path> [--source-vm <name>]"
            .to_string()
    })?;
    if out.exists() {
        return Err(format!("output already exists: {}", out.display()));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed creating output directory '{}': {e}",
                    parent.display()
                )
            })?;
        }
    }

    let source = source_vm.unwrap_or(discover_template_vm()?);
    let disk_path = source_disk_for_vm(&source)?;
    fs::copy(&disk_path, &out).map_err(|e| {
        format!(
            "failed copying source disk '{}' to '{}': {e}",
            disk_path,
            out.display()
        )
    })?;
    println!("baked local TDX image from {source} -> {}", out.display());
    Ok(())
}

fn discover_template_vm() -> Result<String, String> {
    if let Ok(raw) = env::var("EE_LOCAL_TDX_TEMPLATE_VM") {
        let value = raw.trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
    }

    let out = run_capture(
        "virsh",
        vec![
            "list".to_string(),
            "--all".to_string(),
            "--name".to_string(),
        ],
    )?;
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with(LOCAL_TDX_TEMPLATE_PREFIX) {
            return Ok(line.to_string());
        }
    }
    Err(format!(
        "no local template VM found (expected prefix '{}'); set EE_LOCAL_TDX_TEMPLATE_VM",
        LOCAL_TDX_TEMPLATE_PREFIX
    ))
}

fn clone_local_vm(template: &str) -> Result<String, String> {
    let vm_uuid = Uuid::new_v4().to_string();
    let vm_name = format!("{LOCAL_TDX_MANAGED_PREFIX}{vm_uuid}");
    let vm_mac = random_mac();
    let console_id = vm_uuid.replace('-', "");
    let console_path = format!("/var/tmp/tdvirsh/console.{}.log", &console_id[..16]);

    let xml = run_capture("virsh", vec!["dumpxml".to_string(), template.to_string()])?;
    let mut new_xml = xml;
    new_xml = Regex::new(r"<name>[^<]+</name>")
        .map_err(|e| format!("regex error: {e}"))?
        .replace(&new_xml, format!("<name>{vm_name}</name>"))
        .into_owned();
    new_xml = Regex::new(r"<uuid>[^<]+</uuid>")
        .map_err(|e| format!("regex error: {e}"))?
        .replace(&new_xml, format!("<uuid>{vm_uuid}</uuid>"))
        .into_owned();
    new_xml = Regex::new(r"<mac address='[^']+'/>")
        .map_err(|e| format!("regex error: {e}"))?
        .replace(&new_xml, format!("<mac address='{vm_mac}'/>"))
        .into_owned();
    new_xml = Regex::new(r"/var/tmp/tdvirsh/console\.[^']+\.log")
        .map_err(|e| format!("regex error: {e}"))?
        .replace_all(&new_xml, console_path.as_str())
        .into_owned();

    let xml_path = format!("/tmp/ee-local-tdx-{vm_uuid}.xml");
    fs::write(&xml_path, new_xml)
        .map_err(|e| format!("failed writing domain XML '{}': {e}", xml_path))?;

    let define_result = run_status("virsh", vec!["define".to_string(), xml_path.clone()]);
    let _ = fs::remove_file(&xml_path);
    define_result?;

    if let Err(err) = run_status("virsh", vec!["start".to_string(), vm_name.clone()]) {
        let _ = run_status("virsh", vec!["undefine".to_string(), vm_name.clone()]);
        return Err(err);
    }

    Ok(vm_name)
}

fn source_disk_for_vm(vm_name: &str) -> Result<String, String> {
    let out = run_capture("virsh", vec!["domblklist".to_string(), vm_name.to_string()])?;
    for line in out.lines().map(str::trim) {
        if line.is_empty() || line.starts_with("Target") || line.starts_with('-') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let target = parts.next().unwrap_or_default();
        let source = parts.next().unwrap_or_default();
        if target == "vda" && !source.is_empty() {
            return Ok(source.to_string());
        }
    }
    Err(format!(
        "failed to resolve boot disk path from 'virsh domblklist {vm_name}'"
    ))
}

fn random_mac() -> String {
    let bytes = *Uuid::new_v4().as_bytes();
    format!(
        "52:54:00:{:02x}:{:02x}:{:02x}",
        bytes[13], bytes[14], bytes[15]
    )
}

fn run_status(program: &str, args: Vec<String>) -> Result<(), String> {
    let status = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "command failed: {} {} (exit={})",
            program,
            args.join(" "),
            status.code().unwrap_or(1)
        ))
    }
}

fn run_capture(program: &str, args: Vec<String>) -> Result<String, String> {
    let output = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map_err(|e| format!("invalid UTF-8 output from {program}: {e}"))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "command failed: {} {} (exit={})\n{}",
            program,
            args.join(" "),
            output.status.code().unwrap_or(1),
            stderr.trim()
        ))
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("failed to resolve repo root: {e}"))
}
