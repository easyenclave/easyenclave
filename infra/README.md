# EasyEnclave Infra (GCP-only)

This directory is the runtime infra surface for EasyEnclave.

## Scope

- GCP-only orchestration for control plane and agent VMs.
- Real Intel TDX VMs via Google Confidential VM (`--confidential-compute-type=TDX`).
- No local/libvirt, no mkosi image pipeline, no provider compatibility layer.

## Files

- `infra/tdx_cli.py`: CLI used by CI/workflows to create, list, delete, and measure GCP TDX VMs.
- `infra/launcher/launcher.py`: in-VM launcher service entrypoint baked into agent image.
- `infra/launcher/admin.html`: admin UI served by launcher.

## Required environment

- `GCP_PROJECT_ID`
- `GCP_SERVICE_ACCOUNT_KEY`
- One of:
  - `EE_GCP_IMAGE_NAME`
  - `EE_GCP_IMAGE_FAMILY` (defaults to `easyenclave-agent-main`)

Optional:

- `EE_GCP_IMAGE_PROJECT` (defaults to `GCP_PROJECT_ID`)
- `GCP_ZONE` or `AGENT_DATACENTER_AZ` (defaults to `us-central1-f`)

## Common commands

```bash
python3 infra/tdx_cli.py control-plane new --wait --port 8080
python3 infra/tdx_cli.py vm new --size tiny --easyenclave-url https://app-staging.easyenclave.com --wait
python3 infra/tdx_cli.py vm measure --size tiny --json
python3 infra/tdx_cli.py vm list
python3 infra/tdx_cli.py vm delete <vm-name>
```
