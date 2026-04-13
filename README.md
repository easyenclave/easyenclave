# EasyEnclave

Generic enclave runtime for Intel TDX confidential VMs. Runs as PID 1 inside a sealed VM and exposes a unix socket API for workload management.

No HTTP server. Unix socket control plane only. No database. Minimal attack surface.

`native` deployments are intentionally narrow: easyenclave extracts and runs a single static ELF from the OCI image rather than unpacking a full root filesystem.

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

The control API is local-only over a Unix socket, but the runtime does configure guest networking at boot and can use outbound HTTP(S) for DHCP-dependent metadata fetches and OCI image pulls.

## Socket API

Newline-delimited JSON over `/var/lib/easyenclave/agent.sock`:

| Method | Request | Response |
|--------|---------|----------|
| health | `{"method":"health"}` | `{"ok":true,"attestation_type":"tdx","workloads":2}` |
| deploy | `{"method":"deploy","image":"...","app_name":"myapp"}` | `{"ok":true,"id":"...","status":"deploying"}` |
| attest | `{"method":"attest","nonce":"<base64>"}` | `{"ok":true,"quote_b64":"..."}` |
| list | `{"method":"list"}` | `{"ok":true,"deployments":[...]}` |
| stop | `{"method":"stop","id":"..."}` | `{"ok":true}` |
| exec | `{"method":"exec","cmd":["uname","-a"]}` | `{"ok":true,"exit_code":0,"stdout":"..."}` |
| logs | `{"method":"logs","id":"..."}` | `{"ok":true,"lines":["..."]}` |

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
