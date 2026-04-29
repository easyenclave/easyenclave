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

Config: `/etc/easyenclave/config.json`, env vars (`EE_SOCKET_PATH`, `EE_DATA_DIR`, `EE_BOOT_WORKLOADS`). The per-vendor boot-time env file at `/run/easyenclave/env` — written by the initrd vendor stage from kernel cmdline `ee.*` params, a secondary config disk (`/agent.env`), GCE instance attribute `ee-config`, or Azure IMDS customData — is merged into the process env before config loads.

## Deployment targets

Image builds are profile-driven. Each deployment target is a directory under `image/targets/<name>/` with a `profile.env` that supplies its module set, root strategy, kernel cmdline, output format, and default machine topology.

Artifacts land in `image/output/<target>/`.

| Target | Vendor stage | Format | Root strategy | Primary artifacts | Use case |
|--------|--------------|--------|---------------|-------------------|----------|
| `gcp` | `gcp` (IMDS `ee-config`) | GPT disk | ext4 label + optional dm-verity | `easyenclave.root.raw`, `easyenclave.qcow2`, `easyenclave-gcp.tar.gz` | GCP TDX compute images (default) |
| `azure` | `azure` (IMDS `customData`) | GPT disk | ext4 label + optional dm-verity | `easyenclave.root.raw`, `easyenclave.vhd` | Azure TDX CVMs — import the VHD into a Shared Image Gallery or Managed Disk |
| `local-tdx-qcow2` | `qemu` (secondary config disk) | GPT disk | ext4 label + optional dm-verity | `easyenclave.root.raw`, `easyenclave.qcow2` | libvirt backing-file shape (`devopsdefender/dd` et al) — persistent base qcow2, COW overlay per VM |
| `llm-cuda` | `qemu` (secondary config disk) | GPT disk | ext4 label + optional dm-verity | `easyenclave.root.raw`, `easyenclave.qcow2` | TDX confidential VM with NVIDIA GPU passthrough, vLLM as a boot workload (scaffolding — see "LLM target" below) |

Build:

```bash
cd image
make build                         # defaults to TARGET=gcp
make build TARGET=azure            # Azure fixed-size VHD
make build TARGET=local-tdx-qcow2  # qcow2 backing file for libvirt
make build TARGET=llm-cuda         # vLLM + GPU passthrough scaffolding (see "LLM target" below)
```

For local launch, boot `image/output/local-tdx-qcow2/easyenclave.qcow2` under libvirt+TDVF. If you need boot-time config, attach a second read-only disk or CD-ROM with `/agent.env`; the qemu vendor stage probes `/dev/vdb` and `/dev/sdb` for `iso9660`, `ext4`, `vfat`, or `ext2` config media.

### Adding a new target

1. `mkdir image/targets/<name> && $EDITOR image/targets/<name>/profile.env` (copy from an existing profile, tweak `TARGET_INITRD_MODULES`, `TARGET_CMDLINE`, `TARGET_FORMAT`, `TARGET_OUTPUTS`, and `TARGET_VENDOR`).
2. If you need a new root acquisition strategy, add `image/init-templates/<name>.sh` — it becomes the `/init` inside the initrd.
3. If the host is a new cloud (or a variant that needs its own metadata/network plumbing), add `image/init-templates/vendors/<vendor>.sh` and set `TARGET_VENDOR=<vendor>` in the profile. The vendor stage gets `$1 = <newroot>`, is expected to load its network driver, bring up DHCP, fetch metadata, and append KEY=VALUE lines to `<newroot>/run/easyenclave/env`.
4. If the target needs extra packages or files in the rootfs (e.g. a CUDA stack or a custom binary), drop them under `image/mkosi.profiles/<name>/mkosi.conf` and `image/mkosi.profiles/<name>/mkosi.extra/` and set `TARGET_MKOSI_PROFILE=<name>` in `profile.env` — the Makefile then passes `--profile=<name>` to mkosi so the overlay applies only for that target.
5. `make build TARGET=<name>`.

### LLM target (`llm-cuda`)

Pattern adapted from [`ConferLabs/confer-image`](https://github.com/ConferLabs/confer-image) — the same mkosi + Ubuntu Noble + dm-verity shape, retargeted at EasyEnclave's "no systemd, PID 1 is the runtime" invariant. confer-image's `confer-vllm.service`, `nvidia-persistenced.service`, `nvidia-fabricmanager.service`, and `nvidia-cc-attestation.service` collapse into entries in `boot_workloads` in `/etc/easyenclave/config.json`, sequenced by easyenclave directly. The sample config baked into the image lives at [`image/mkosi.profiles/llm-cuda/mkosi.extra/etc/easyenclave/config.json`](image/mkosi.profiles/llm-cuda/mkosi.extra/etc/easyenclave/config.json), and the launcher modeled on `confer-vllm` is at [`image/mkosi.profiles/llm-cuda/mkosi.extra/usr/local/bin/vllm-serve`](image/mkosi.profiles/llm-cuda/mkosi.extra/usr/local/bin/vllm-serve).

Target-specific package overlays use mkosi's `--profile` mechanism: anything under `image/mkosi.profiles/<target>/` (a `mkosi.conf` and an `mkosi.extra/` overlay) applies only when the profile is active. The Makefile passes `--profile=$TARGET_MKOSI_PROFILE` automatically when a target's `profile.env` declares it.

**Status: scaffolding.** The current `make build TARGET=llm-cuda` produces a bootable image with the launcher script, sample config, and IOMMU/passthrough cmdline in place — but **not** the NVIDIA driver, CUDA runtime, or vLLM Python install. Booting it on a GPU host today will surface `nvidia-persistenced`, `nv-fabricmanager`, and the vLLM entrypoint as missing binaries. The driver + CUDA + vLLM bake (Ubuntu `nvidia-driver-580-open` + `cuda-12-8-*` + `pip install vllm`, mirroring confer-image's `mkosi.conf` + `mkosi.postinst` stages 1–2) is intentionally deferred to a follow-up concept; see the comment block in [`image/mkosi.profiles/llm-cuda/mkosi.conf`](image/mkosi.profiles/llm-cuda/mkosi.conf) for the exact additions and `TODO.md` "GPU passthrough image packaging".

### Attestation across targets

TDX MRTD and RTMR values **differ per target**, and differ again per launch site:

- **MRTD** is derived from TDVF binary + memory size + vCPU topology. Local TDVF ≠ GCP's TDVF; `-m 4G -smp 2` locally ≠ `c3-standard-4` on GCP.
- **RTMRs** depend on UKI bytes (each target's UKI embeds a different initrd and cmdline).

Don't cross-verify a local quote against a GCP measurement. Treat the local-tdx-qcow2 build as a dev / dd-runtime convenience, not a production-attestation-equivalent artifact.

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

For a Rust workload example — a TDX-attested LLM proxy with
ITA-v2 attestation and OpenRouter ZDR routing — see
[`docs/private-claude.md`](docs/private-claude.md).

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

Config is loaded from `/etc/easyenclave/config.json`, then environment variables override it. The initrd's per-vendor stage populates `/run/easyenclave/env` (a KEY=VALUE file, one per line) from the sources below, and PID 1 merges those entries into the process env before config loads:

- kernel command line params prefixed with `ee.`, for example `ee.EE_DATA_DIR=/var/lib/easyenclave` (parsed by the root-strategy init template)
- a secondary config disk containing `/agent.env` (local-tdx-qcow2 / qemu vendor stage only)
- GCE instance metadata attribute `ee-config` — KEY=VALUE per line, or the legacy flat-JSON `{"KEY":"VALUE",...}` (auto-flattened by the gcp vendor stage)
- Azure IMDS `customData` — base64-encoded. The decoded bytes may be KEY=VALUE per line or legacy flat-JSON (azure vendor stage)
- the inherited process environment

The Rust binary itself never talks to a metadata service or probes a config disk — all of that is shell code baked into the target's initrd, so the runtime stays vendor-agnostic.

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
| `EE_IP` | DHCP | Static address/CIDR for the first non-loopback interface (consumed by vendor stage, not by Rust) |
| `EE_GATEWAY` | (none) | Default gateway when `EE_IP` is set (consumed by vendor stage) |
| `EE_DNS` | DHCP DNS | DNS server written to `/run/resolv.conf` by the vendor stage |

Networking (interface up, DHCP, DNS) is handled entirely by the vendor stage at `image/init-templates/vendors/<vendor>.sh` in the initrd. `EE_IP`/`EE_GATEWAY`/`EE_DNS` are read by the shared `ee_ifup` helper in `vendors/_lib.sh`, so they continue to work even though the PID 1 binary no longer reads them directly.

## Source

```
src/
├── main.rs           Entry: init, config, pre-fetch, boot workloads, socket server
├── init.rs           PID 1: load /run/easyenclave/env, mount configfs/devpts, zombie reaper
├── config.rs         Config from file + env overlays
├── socket.rs         Unix socket server (8 methods; attach switches to raw bytes)
├── workload.rs       Deploy/stop/list, process lifecycle
├── release.rs        GitHub Releases API: fetch static binaries
├── process.rs        Spawn (with log capture), kill, logs
└── attestation/
    ├── mod.rs         Backend trait + TDX detection (no insecure fallback)
    └── tsm.rs         TDX configfs-tsm implementation

image/
├── init-templates/
│   ├── ext4-label.sh       Root strategy: mount ext4 LABEL=root (all targets)
│   └── vendors/
│       ├── gcp.sh           Network + GCE IMDS `ee-config` → /run/easyenclave/env
│       ├── azure.sh         Network + Azure IMDS `customData` → /run/easyenclave/env
│       └── qemu.sh          Secondary config disk /agent.env → /run/easyenclave/env
└── targets/<name>/profile.env    Declares TARGET_ROOT_STRATEGY, TARGET_VENDOR, modules, outputs
```

## Key decisions

- **No insecure attestation fallback** — `detect()` returns error without TDX.
- **Unix socket control plane** — clients (like dd-client) handle external control-plane networking.
- **Vendor plumbing is image-time, not Rust-time** — networking, cloud metadata, and config-disk probing live in per-vendor shell scripts baked into the initrd. The PID 1 binary only reads `/run/easyenclave/env` and runs; it never talks to a metadata service or probes `/dev/vdb`. Adding a cloud = adding a `vendors/<name>.sh` plus a target profile, with no Rust changes.
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
