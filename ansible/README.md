# EasyEnclave Ansible Overview

Ansible is the orchestration layer for EasyEnclave infrastructure. It coordinates control plane rollout, agent image baking, and VM fleet lifecycle across GCP and bare-metal/TDX environments.

## Scope

- GCP orchestration for control plane, agent VMs, and image baking (Ansible + Packer).
- Baremetal orchestration via `tdx-runner`, including local image baking/launch flows.
- Runtime deploy orchestration consumed by CI/CD workflows.

## Files

- `ansible/playbooks/*.yml`: orchestration entry points for deploy, image bake, and fleet lifecycle.
- `ansible/inventory/hosts.yml`: inventory definitions.
- `packer/*.pkr.hcl` and `packer/templates/*`: image build definitions consumed by Ansible workflows.

## Usage In GitHub Actions

Workflow runs are the canonical examples of how Ansible is invoked in this repo:

- [Staging Deploy](../.github/workflows/staging-deploy.yml)
- [Production Deploy](../.github/workflows/production-deploy.yml)
- [Baremetal Image](../.github/workflows/baremetal-image.yml)
