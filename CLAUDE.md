# CLAUDE.md

## Project

EasyEnclave — generic enclave runtime for Intel TDX VMs. Single Rust binary, runs as PID 1, unix socket API. No HTTP, no networking, no database.

## Build & Test

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Run

Requires Intel TDX hardware (configfs-tsm). Refuses to start without it.

```bash
./target/release/easyenclave
```

Config: `/etc/easyenclave/config.json` or env vars (`EE_SOCKET_PATH`, `EE_DATA_DIR`, `EE_BOOT_WORKLOADS`).

## Source layout

```
src/
├── main.rs           Entry: init, config, pre-fetch, boot workloads, socket server
├── init.rs           PID 1: mount /proc /sys /dev, configfs, zombie reaper
├── config.rs         Config from JSON file + env overlays
├── socket.rs         Unix socket server, newline-delimited JSON (7 methods)
├── workload.rs       Deploy/stop/list — process lifecycle
├── release.rs        GitHub Releases API: fetch static binaries into /var/lib/easyenclave/bin
├── process.rs        Spawn (with log capture), kill, logs
└── attestation/
    ├── mod.rs         AttestationBackend trait + detect() — errors if no TDX
    └── tsm.rs         TDX via configfs-tsm (/sys/kernel/config/tsm/report)
```

## Key decisions

- No insecure attestation fallback — detect() returns error without TDX
- Unix socket only — clients (like dd-client) handle networking
- Workloads are static binaries from GitHub releases, or bare commands — no container runtime
- Fetch-only workloads (github_release with no cmd) prime the bin dir for other workloads to shell out to
- Config from JSON + env, not database — stateless runtime
