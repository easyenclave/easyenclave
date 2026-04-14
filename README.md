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
        ├── workloads (static binaries from GitHub releases, or bare commands)
        └── TDX attestation (configfs-tsm)
```

## Socket API

Newline-delimited JSON over `/var/lib/easyenclave/agent.sock`:

| Method | Request | Response |
|--------|---------|----------|
| health | `{"method":"health"}` | `{"ok":true,"attestation_type":"tdx","workloads":2}` |
| deploy | `{"method":"deploy","github_release":{"repo":"owner/repo","asset":"app"},"cmd":["app"],"app_name":"myapp"}` | `{"ok":true,"id":"...","status":"deploying"}` |
| attest | `{"method":"attest","nonce":"..."}` | `{"ok":true,"quote_b64":"..."}` |
| list | `{"method":"list"}` | `{"ok":true,"deployments":[...]}` |
| stop | `{"method":"stop","id":"..."}` | `{"ok":true}` |
| exec | `{"method":"exec","cmd":["uname","-a"]}` | `{"ok":true,"exit_code":0,"stdout":"..."}` |
| logs | `{"method":"logs","id":"..."}` | `{"ok":true,"lines":["..."]}` |
| attach | `{"method":"attach","cmd":["/bin/sh"]}` | `{"ok":true,"attached":true}` then raw byte stream (PTY-backed shell) |

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
├── socket.rs         Unix socket server (8 methods, attach switches to raw bytes)
├── workload.rs       Deploy/stop/list, process lifecycle
├── release.rs        GitHub Releases API: fetch static binaries
├── process.rs        Spawn (with log capture), kill, logs
└── attestation/
    ├── mod.rs         Backend trait + TDX detection (no insecure fallback)
    └── tsm.rs         TDX configfs-tsm implementation
```

## License

MIT
