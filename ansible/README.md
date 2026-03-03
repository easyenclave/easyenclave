# EasyEnclave Infra Assets

This directory is the runtime infra surface for EasyEnclave.

## Scope

- GCP orchestration for control plane, agent VMs, and image baking via Ansible + Packer.
- Ansible playbooks for GCP image/node orchestration and baremetal node orchestration via `tdx-runner`.
- Bare-metal-ready image baking via Packer QEMU.
- Real Intel TDX VMs via Google Confidential VM (`--confidential-compute-type=TDX`) and local TDX-capable workers.

## Files

- `ansible/playbooks/*.yml`: Ansible orchestration layer for GCP control-plane/VM/image operations, CI deploy orchestration, baremetal image baking, and baremetal VM launches.
- `packer/baremetal-agent-image.pkr.hcl`: Bare-metal Packer template.
- `packer/templates/*`: Cloud-init templates used by bare-metal image baking.
- repo-root Rust package providing `ee-agent`, `ee-cp`, and `ee-admin` binaries.

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
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/gcp-control-plane-new.yml -e cp_wait=true
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/gcp-vm-fleet-new.yml -e cp_url=https://app-staging.easyenclave.com -e ita_api_key="$ITA_API_KEY" -e num_tiny=1
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/gcp-vm-measure.yml -e node_size=tiny
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/gcp-deploy.yml -e cp_bootstrap_timeout=600 -e num_tiny_agents=1
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/baremetal-image-bake.yml -e target_image_name=easyenclave-baremetal-local
```
