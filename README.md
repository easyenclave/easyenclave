# EasyEnclave

EasyEnclave is a control plane for confidential workloads running in TDX-attested agents.
Use this top-level README as a router: pick what you want to do, then jump into the runbook.

## Choose Your Path

| What you want to do | Start here | Work mostly in |
|---|---|---|
| Run a new agent from a blank TDX host | [`docs/runbooks/run-agent.md`](docs/runbooks/run-agent.md) | `infra/`, `app/` |
| Build and deploy an app to an existing agent | [`docs/runbooks/deploy-app.md`](docs/runbooks/deploy-app.md) | `examples/`, `sdk/`, `.github/actions/` |
| Add a new cloud/provider | [`docs/guides/add-cloud.md`](docs/guides/add-cloud.md) | `app/`, `infra/`, `.github/workflows/` |
| Ship a release to production | [`docs/runbooks/release-production.md`](docs/runbooks/release-production.md) | `.github/workflows/`, `infra/` |
| Understand system design and trust model | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/FAQ.md`](docs/FAQ.md) | `docs/` |

## Repository Map

- `app/`: control plane API, attestation verification, scheduling, capacity orchestration.
- `infra/`: launcher, TDX VM tooling (`tdx_cli.py`), image build assets.
- `examples/`: deployable reference apps (`hello-tdx`, `private-llm`).
- `sdk/`: Python client SDK used by examples and user apps.
- `.github/workflows/`: CI/CD orchestration (staging, release artifacts, production).
- `docs/`: runbooks, guides, architecture, security background.

## Fast Sanity Checks

Run locally:

```bash
docker compose up --build
curl -f http://localhost:8080/health
```

List current agents from a control plane:

```bash
curl -s https://app.easyenclave.com/api/v1/agents | jq '.agents[] | {agent_id,vm_name,node_size,datacenter,status,verified,health_status}'
```

## CI/CD at a Glance

- `CI` (`.github/workflows/test.yml`): lint/test/build/sign image (non-mutating).
- `Staging Rollout` (`.github/workflows/staging-rollout.yml`): automatic from `main`, low-cost/untrusted.
- `Release Trust Bundle` (`.github/workflows/release-trust-bundle.yml`): pinned trusted measurements per release tag.
- `Release GCP Image` (`.github/workflows/release-gcp-image.yml`): pinned GCP image descriptor per release tag.
- `Production Rollout` (`.github/workflows/production-rollout.yml`): manual, `release_tag` required, strict policy.

Note:
- README-only changes should not trigger PR deploy-example workflows.

## Required Secrets and Vars

Core secrets:

- `INTEL_API_KEY`
- `CP_ADMIN_PASSWORD`
- `AGENT_ADMIN_PASSWORD`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_ID`
- `GCP_PROJECT_ID`
- `GCP_SERVICE_ACCOUNT_KEY`

Common vars:

- `STAGING_CP_URL`
- `PRODUCTION_CP_URL`
- `STAGING_EASYENCLAVE_DOMAIN`
- `PRODUCTION_EASYENCLAVE_DOMAIN`
- `GCP_DATACENTER`
- `GCP_ZONE`
- `EE_GCP_BASE_IMAGE_PROJECT`
- `EE_GCP_BASE_IMAGE_FAMILY`

## Docs Index

- Agent onboarding: [`docs/runbooks/run-agent.md`](docs/runbooks/run-agent.md)
- Build + deploy apps: [`docs/runbooks/deploy-app.md`](docs/runbooks/deploy-app.md)
- Adding clouds/providers: [`docs/guides/add-cloud.md`](docs/guides/add-cloud.md)
- Release/prod operations: [`docs/runbooks/release-production.md`](docs/runbooks/release-production.md)
- CI/CD split: [`docs/CI_CD_NETWORKS.md`](docs/CI_CD_NETWORKS.md)
- Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Security FAQ: [`docs/FAQ.md`](docs/FAQ.md)
