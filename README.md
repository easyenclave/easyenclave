# EasyEnclave

Generic enclave runtime for Intel TDX confidential VMs. Runs as PID 1 inside a sealed VM and exposes a unix socket API for workload management.

No HTTP server. No database. No container runtime. The control plane is a local unix socket; PID 1 still brings up networking for boot configuration, release downloads, and workloads.

## Quick start

```bash
cargo build --release
# Run inside a TDX VM as PID 1
./target/release/easyenclave
```

Requires Intel TDX hardware (configfs-tsm) — refuses to start without it.

Config: `/etc/easyenclave/config.json`, env vars (`EE_SOCKET_PATH`, `EE_DATA_DIR`, `EE_BOOT_WORKLOADS`), a config disk, or GCE metadata.

## Deployment targets

Image builds are profile-driven. Each deployment target is a directory under `image/targets/<name>/` with a `profile.env` that supplies its module set, root strategy, kernel cmdline, output format, and default machine topology.

Artifacts land in `image/output/<target>/`.

| Target | Format | Root strategy | Primary artifacts | Use case |
|--------|--------|---------------|-------------------|----------|
| `gcp` | GPT disk | ext4 label + optional dm-verity | `easyenclave.root.raw`, `easyenclave.qcow2`, `easyenclave-gcp.tar.gz` | GCP TDX compute images (default) |
| `local-tdx` | hybrid ISO with embedded ESP | iso9660 + squashfs + tmpfs overlay | `easyenclave.iso`, `rootfs.squashfs` | Local QEMU/OVMF TDX boot for dev iteration |

Build:

```bash
cd image
make build                   # defaults to TARGET=gcp
make build TARGET=local-tdx  # hybrid ISO for local TDX
```

For local launch, boot `image/output/local-tdx/easyenclave.iso` with a TDX-capable QEMU/TDVF or libvirt setup. If you need boot-time config, attach a second read-only disk or CD-ROM with `/agent.env`; PID 1 probes `/dev/vdb` and `/dev/sdb` for `iso9660`, `ext4`, `vfat`, or `ext2` config media.

### Adding a new target

1. `mkdir image/targets/<name> && $EDITOR image/targets/<name>/profile.env` (copy from an existing profile, tweak `TARGET_INITRD_MODULES`, `TARGET_CMDLINE`, `TARGET_FORMAT`, and `TARGET_OUTPUTS`).
2. If you need a new root acquisition strategy, add `image/init-templates/<name>.sh` — it becomes the `/init` inside the initrd.
3. `make build TARGET=<name>`.

### Attestation across targets

TDX MRTD and RTMR values **differ per target**, and differ again per launch site:

- **MRTD** is derived from TDVF binary + memory size + vCPU topology. Local TDVF ≠ GCP's TDVF; `-m 4G -smp 2` locally ≠ `c3-standard-4` on GCP.
- **RTMRs** depend on UKI bytes (each target's UKI embeds a different initrd and cmdline).

Don't cross-verify a local quote against a GCP measurement. Treat local-tdx as a dev convenience, not a production-attestation-equivalent artifact.

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
| health | `{"method":"health"}` | `{"ok":true,"attestation_type":"tdx","workloads":2,"uptime_secs":60}` |
| deploy | `{"method":"deploy","github_release":{"repo":"owner/repo","asset":"app"},"cmd":["app"],"app_name":"myapp"}` | `{"ok":true,"id":"...","status":"deploying"}` |
| attest | `{"method":"attest","nonce":"..."}` | `{"ok":true,"quote_b64":"..."}` |
| list | `{"method":"list"}` | `{"ok":true,"deployments":[...]}` |
| stop | `{"method":"stop","id":"..."}` | `{"ok":true}` |
| exec | `{"method":"exec","cmd":["uname","-a"],"timeout_secs":30}` | `{"ok":true,"exit_code":0,"stdout":"...","stderr":"..."}` |
| logs | `{"method":"logs","id":"...","tail":100}` | `{"ok":true,"lines":["..."]}` |
| attach | `{"method":"attach","cmd":["/bin/sh"]}` | `{"ok":true,"attached":true}` then raw byte stream (PTY-backed shell) |

`attest.nonce` is optional base64-encoded caller data. `attach` is the only method that changes the connection's protocol — after the JSON ack, the connection is a raw byte stream bridging a `script -qfc <cmd> /dev/null` PTY. Used by clients that want an interactive shell (dd-client, dd-web).

For a Java workload example, see
[`docs/confer-proxy-on-easyenclave.md`](docs/confer-proxy-on-easyenclave.md).

### ITA v2 and verifier integration

EasyEnclave is an evidence producer, not a verifier. The runtime intentionally
does not carry Intel Trust Authority API keys, call ITA over the network, or
make policy decisions inside PID 1. A relying party, dd-web/dd-register, or a
small verifier sidecar should:

1. Get freshness material from the verifier. For ITA v2 this can be
   `GET https://api.trustauthority.intel.com/appraisal/v2/nonce`.
2. Compute the 64-byte TDX `report_data` binding required by the verifier.
   For ITA, use Intel's client adapter logic for the verifier nonce,
   `runtime_data`, and any held data you include.
3. Ask EasyEnclave for a quote:

   ```json
   {"method":"attest","report_data_b64":"<64-byte-report-data-base64>"}
   ```

4. Submit the returned `quote_b64` to ITA v2:

   ```json
   {
     "tdx": {
       "quote": "<quote_b64>",
       "verifier_nonce": {"val":"...","iat":"...","signature":"..."}
     },
     "policy_ids": ["<policy-id>"],
     "policy_must_match": true
   }
   ```

The legacy `nonce` request field is still accepted. Hex-looking values are
decoded as hex for existing tooling; other values are decoded as base64. New
verifier integrations should use `report_data_b64` so the caller controls the
exact TDX report-data bytes.

### QGS boundary

EasyEnclave does not talk to the Intel TDX Quote Generation Service directly.
It uses the Linux `configfs-tsm` interface:

```
/sys/kernel/config/tsm/report/<report>/inblob
/sys/kernel/config/tsm/report/<report>/outblob
```

If QGS is needed on a platform, it sits below that interface in the guest
kernel, VMM, host, or cloud provider quote path. EasyEnclave only requires that
`configfs-tsm` can produce a real TDX quote.

## Configuration

Config is loaded from `/etc/easyenclave/config.json`, then environment variables override it. PID 1 can populate env vars from:

- kernel command line params prefixed with `ee.`, for example `ee.EE_DATA_DIR=/var/lib/easyenclave`
- a secondary config disk containing `/agent.env`
- GCE instance metadata attribute `ee-config`, encoded as a JSON object of environment variable names to values
- the inherited process environment

Example `/etc/easyenclave/config.json`:

```json
{
  "socket_path": "/var/lib/easyenclave/agent.sock",
  "data_dir": "/var/lib/easyenclave",
  "boot_workloads": [
    {
      "app_name": "cloudflared",
      "github_release": {
        "repo": "cloudflare/cloudflared",
        "asset": "cloudflared-linux-amd64",
        "rename": "cloudflared"
      }
    },
    {
      "app_name": "my-client",
      "cmd": ["/usr/local/bin/my-client"],
      "env": ["RUST_LOG=info"],
      "tty": false
    }
  ]
}
```

| Env var | Default | Description |
|---------|---------|-------------|
| `EE_SOCKET_PATH` | `/var/lib/easyenclave/agent.sock` | Unix socket path |
| `EE_DATA_DIR` | `/var/lib/easyenclave` | Data directory |
| `EE_BOOT_WORKLOADS` | (none) | JSON array of boot workloads |
| `EE_GITHUB_TOKEN` | (none) | Optional GitHub token for private repos / higher rate limits |
| `EE_IP` | DHCP | Static address/CIDR for the first non-loopback interface |
| `EE_GATEWAY` | (none) | Default gateway when `EE_IP` is set |
| `EE_DNS` | DHCP DNS | DNS server override written to `/run/resolv.conf` |

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
- **Unix socket control plane** — clients (like dd-client) handle external control-plane networking.
- **Runtime-managed networking** — PID 1 brings up networking for metadata/config fetches, GitHub release downloads, and workload connectivity.
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
