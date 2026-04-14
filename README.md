# EasyEnclave

Generic enclave runtime for Intel TDX confidential VMs. Runs as PID 1 inside a sealed VM and exposes a unix socket API for workload management.

No HTTP server. No networking. No database. No container runtime. Minimal attack surface.

## Quick start

```bash
cargo build --release
# Run inside a TDX VM as PID 1
./target/release/easyenclave
```

Requires Intel TDX hardware (configfs-tsm) — refuses to start without it.

Config: `/etc/easyenclave/config.json` or env vars (`EE_SOCKET_PATH`, `EE_DATA_DIR`, `EE_BOOT_WORKLOADS`).

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

`attach` is the only method that changes the connection's protocol — after the JSON ack, the connection is a raw byte stream bridging a `script -qfc <cmd> /dev/null` PTY. Used by clients that want an interactive shell (dd-client, dd-web).

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
| `EE_GITHUB_TOKEN` | (none) | Optional GitHub token for private repos / higher rate limits |

## Source

```
src/
├── main.rs           Entry: init, config, pre-fetch, boot workloads, socket server
├── init.rs           PID 1: mount, configfs, kernel cmdline, zombie reaper
├── config.rs         Config from file + env overlays
├── socket.rs         Unix socket server (8 methods; attach switches to raw bytes)
├── workload.rs       Deploy/stop/list, process lifecycle
├── release.rs        GitHub Releases API: fetch static binaries
├── process.rs        Spawn (with log capture), kill, logs
└── attestation/
    ├── mod.rs         Backend trait + TDX detection (no insecure fallback)
    └── tsm.rs         TDX configfs-tsm implementation
```

## Key decisions

- **No insecure attestation fallback** — `detect()` returns error without TDX.
- **Unix socket only** — clients (like dd-client) handle networking.
- **Workloads are static binaries from GitHub releases, or bare commands** — no container runtime.
- **Fetch-only workloads** (`github_release` with no `cmd`) prime the bin dir for other workloads to shell out to (e.g. cloudflared).
- **Config from JSON + env, not database** — stateless runtime.

## Contributing

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## License

MIT
