# EasyEnclave Infra Assets

This directory is the runtime infra surface for EasyEnclave.

## Scope

- GCP orchestration for control plane and agent VMs.
- Bare-metal-ready image baking via Packer QEMU.
- Real Intel TDX VMs via Google Confidential VM (`--confidential-compute-type=TDX`) and local TDX-capable workers.

## Files

- `crates/ee-ops/assets/gcp-nodectl.sh`: CLI used by CI/workflows to create, list, delete, and measure GCP TDX VMs.
- `crates/ee-ops/assets/gcp-bake-image.sh`: Image build entrypoint used by staging/production workflows.
- `crates/ee-ops/assets/baremetal-bake-image.sh`: Packer QEMU image build entrypoint for bare-metal/worker-hosted image outputs.
- `crates/ee-ops/assets/packer/baremetal-agent-image.pkr.hcl`: Bare-metal Packer template.
- `crates/ee-agent`: Rust in-VM runtime used for agent/control-plane/measure modes.

## Required environment

- `GCP_PROJECT_ID`
- `GCP_SERVICE_ACCOUNT_KEY`
- One of:
  - `EE_GCP_IMAGE_NAME`
  - `EE_GCP_IMAGE_FAMILY` (defaults to `easyenclave-agent-main`)

Optional:

- `EE_GCP_IMAGE_PROJECT` (defaults to `GCP_PROJECT_ID`)
- `GCP_ZONE` or `AGENT_DATACENTER_AZ` (defaults to `us-central1-a`)

## Common commands

```bash
bash crates/ee-ops/assets/gcp-nodectl.sh control-plane new --wait --port 8080
bash crates/ee-ops/assets/gcp-nodectl.sh vm new --size tiny --cp-url https://app-staging.easyenclave.com --ita-api-key "$ITA_API_KEY" --wait
bash crates/ee-ops/assets/gcp-nodectl.sh vm measure --size tiny --json
bash crates/ee-ops/assets/gcp-nodectl.sh vm list
bash crates/ee-ops/assets/gcp-nodectl.sh vm delete <vm-name>
cargo run -p ee-ops -- baremetal-bake-image
```
