# EasyEnclave Infra Assets

This directory is the runtime infra surface for EasyEnclave.

## Scope

- GCP orchestration for control plane, agent VMs, and image baking via Ansible + Packer.
- Ansible playbooks for GCP image/node orchestration and baremetal node orchestration via `tdx-runner`.
- Bare-metal-ready image baking via Packer QEMU.
- Real Intel TDX VMs via Google Confidential VM (`--confidential-compute-type=TDX`) and local TDX-capable workers.

## Files

- `crates/ee-ops/assets/baremetal-bake-image.sh`: Packer QEMU image build entrypoint for bare-metal/worker-hosted image outputs.
- `crates/ee-ops/ansible/playbooks/*.yml`: Ansible orchestration layer for GCP control-plane/VM/image operations and baremetal VM launches.
- `crates/ee-ops/assets/packer/baremetal-agent-image.pkr.hcl`: Bare-metal Packer template.
- `crates/ee-ops/assets/packer/templates/*`: Cloud-init templates used by bare-metal image baking.
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
ANSIBLE_CONFIG=crates/ee-ops/ansible/ansible.cfg ansible-playbook crates/ee-ops/ansible/playbooks/gcp-control-plane-new.yml -e cp_wait=true
ANSIBLE_CONFIG=crates/ee-ops/ansible/ansible.cfg ansible-playbook crates/ee-ops/ansible/playbooks/gcp-vm-fleet-new.yml -e cp_url=https://app-staging.easyenclave.com -e ita_api_key="$ITA_API_KEY" -e num_tiny=1
ANSIBLE_CONFIG=crates/ee-ops/ansible/ansible.cfg ansible-playbook crates/ee-ops/ansible/playbooks/gcp-vm-measure.yml -e node_size=tiny
cargo run -p ee-ops -- baremetal-bake-image
```
