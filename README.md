# EasyEnclave

Generic enclave runtime for Intel TDX confidential VMs. Runs as PID 1 inside a sealed VM and exposes a unix socket API for workload management.

No HTTP server. No networking. No database. Minimal attack surface.

## Quick start

```bash
cargo build --release
# Run inside a TDX VM as PID 1
./target/release/easyenclave
```

Requires Intel TDX hardware — refuses to start without it.

## Architecture

```
TDX VM (hardware-sealed memory)
  └── easyenclave (PID 1)
        ├── unix socket: /var/lib/easyenclave/agent.sock
        ├── workloads (OCI containers via libcontainer, or bare processes)
        └── TDX attestation (configfs-tsm)
```

## Socket API

Newline-delimited JSON over `/var/lib/easyenclave/agent.sock`:

| Method | Request | Response |
|--------|---------|----------|
| health | `{"method":"health"}` | `{"ok":true,"attestation_type":"tdx","workloads":2}` |
| deploy | `{"method":"deploy","image":"...","app_name":"myapp"}` | `{"ok":true,"id":"...","status":"deploying"}` |
| attest | `{"method":"attest","nonce":"..."}` | `{"ok":true,"quote_b64":"..."}` |
| list | `{"method":"list"}` | `{"ok":true,"deployments":[...]}` |
| stop | `{"method":"stop","id":"..."}` | `{"ok":true}` |
| exec | `{"method":"exec","cmd":["uname","-a"]}` | `{"ok":true,"exit_code":0,"stdout":"..."}` |
| logs | `{"method":"logs","id":"..."}` | `{"ok":true,"logs":["..."]}` |

## Configuration

`/etc/easyenclave/config.json` (optional, env vars override):

```json
{
  "socket_path": "/var/lib/easyenclave/agent.sock",
  "data_dir": "/var/lib/easyenclave",
  "boot_workloads": [
    {"app_name": "my-client", "cmd": ["/usr/local/bin/my-client"]}
  ]
}
```

| Env var | Default | Description |
|---------|---------|-------------|
| `EE_SOCKET_PATH` | `/var/lib/easyenclave/agent.sock` | Unix socket path |
| `EE_DATA_DIR` | `/var/lib/easyenclave` | Data directory |
| `EE_BOOT_WORKLOADS` | (none) | JSON array of boot workloads |

## Run locally in TDX (libvirt)

On a TDX-capable host (check `cat /sys/module/kvm_intel/parameters/tdx` → `Y`), boot the sealed image locally with real attestation:

```bash
# Fetch the latest qcow2 (or use a local `make build` output)
gh release download -R easyenclave/easyenclave image-<sha> \
    --pattern '*.qcow2'

# Write a per-VM agent.env (KEY=VALUE per line)
cat > /tmp/agent.env <<'EOF'
EE_OWNER=devopsdefender
EE_BOOT_WORKLOADS=[{"image":"docker.io/library/busybox","app_name":"smoke","cmd":["sh","-c","echo hello; sleep 3600"]}]
EOF

# Boot: builds an iso9660 config disk with /agent.env, copies the qcow2
# and iso into /var/lib/libvirt/images/, launches via virt-install with
# --launchSecurity type=tdx, and attaches the serial console.
bash image/run-local.sh easyenclave-<sha>.qcow2 /tmp/agent.env

# Tear down when done (Ctrl-] detaches from the serial first)
bash image/run-local.sh --destroy
```

Host dependencies: `libvirt-clients`, `virtinst`, `qemu-system-x86`, `ovmf`, `genisoimage`. The user running this must be in the `libvirt` group.

Networking is libvirt's default `virbr0` NAT bridge — the sealed VM's `dhclient` acquires a 192.168.122.x lease automatically. GCE metadata fetch silently skips (no metadata server locally), so per-VM config comes from `/agent.env` on the iso9660 secondary disk.

## Source

```
src/
├── main.rs           Entry: init, config, boot workloads, socket server
├── init.rs           PID 1: mount, configfs, kernel cmdline, zombie reaper
├── config.rs         Config from file + env overlays
├── socket.rs         Unix socket server (7 methods)
├── workload.rs       Deploy/stop/list, container + process lifecycle
├── container.rs      Rust-native OCI runtime (libcontainer + oci-distribution)
├── process.rs        Spawn, kill, liveness
└── attestation/
    ├── mod.rs         Backend trait + TDX detection (no insecure fallback)
    └── tsm.rs         TDX configfs-tsm implementation
```

## License

MIT
