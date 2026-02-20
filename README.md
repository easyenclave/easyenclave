# EasyEnclave

A confidential discovery service for TDX-attested applications. EasyEnclave enables registration and discovery of TDX-attested services with their metadata, including source code location, endpoints, and attestation information.

## Features

- **Service Registration**: Register TDX-attested services with metadata
- **Service Discovery**: Find services by name, tags, environment, or MRTD
- **Attestation Verification**: Verify service attestations via Intel Trust Authority
- **Web GUI**: Browser-based dashboard for viewing and managing services
- **Python SDK**: Client library for programmatic access
- **TDX Deployment**: Deploy as an attested TDX application

## What is Remote Attestation?

**Remote attestation** provides cryptographic proof that your code is running in a genuine Trusted Execution Environment (TEE) with the exact code you expect.

**How it works:**
1. **TEE measures your application** - Hardware computes MRTD (hash of VM image)
2. **TEE signs the measurement** - CPU creates a cryptographic quote
3. **Client verifies the quote** - Intel Trust Authority validates the signature
4. **Client checks MRTD** - Ensures running code matches expected version

**Benefits:**
- ✅ Verify code before sending sensitive data
- ✅ Protection from cloud provider access
- ✅ Defense against OS/hypervisor attacks
- ✅ Build zero-trust applications

**Supported TEE vendors:**
- Intel TDX (Trust Domain Extensions) - ✅ Production
- AMD SEV-SNP - 🔜 Coming soon
- ARM CCA - 🔜 Planned

**Learn more:** See [docs/FAQ.md](docs/FAQ.md) for security and deployment Q&A, [docs/REPRODUCIBLE_BUILDS.md](docs/REPRODUCIBLE_BUILDS.md) for reproducibility verification (two clean builds per check; any artifact or measurement drift fails), [docs/CAPACITY_LAUNCHER.md](docs/CAPACITY_LAUNCHER.md) for CP launch-order workers, and [docs/CI_CD_NETWORKS.md](docs/CI_CD_NETWORKS.md) for staging/production rollout policy.

### What is Intel TDX?

**Intel Trust Domain Extensions (TDX)** is a hardware-based TEE technology.

**How it works:**
- **Hardware isolation** - CPU enforces memory encryption
- **Encrypted memory** - All RAM encrypted with per-VM keys
- **Integrity protection** - Detects memory tampering
- **Attestation** - Cryptographic proof of running code

**Protection boundaries:**
```
┌─────────────────────────────────────────┐
│  Untrusted: Cloud Provider              │
│  ┌───────────────────────────────────┐  │
│  │ Hypervisor (VMware, KVM, Hyper-V) │  │
│  │ ❌ Cannot read TDX memory          │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │ Operating System (Linux, etc.)    │  │
│  │ ❌ Cannot read TDX memory          │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
           ↓ Encrypted boundary
┌─────────────────────────────────────────┐
│  Trusted: TDX Virtual Machine           │
│  ┌───────────────────────────────────┐  │
│  │ Your Application + Data           │  │
│  │ ✅ Protected by hardware          │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Requirements:**
- 4th Gen Intel Xeon Scalable or newer (Sapphire Rapids+)
- TDX-enabled BIOS
- TDX-aware hypervisor (KVM, VMware ESXi)

### TDX vs SGX

| Feature | Intel TDX | Intel SGX |
|---------|-----------|-----------|
| **Isolation** | Full VM | Enclave (process) |
| **Memory** | Gigabytes | Megabytes |
| **Performance** | Near-native | 10-50% overhead |
| **OS Support** | Any OS | Modified app |
| **Use Case** | Large apps | Small modules |
| **Status** | ✅ Production | ⚠️ Deprecated on client CPUs |

**TDX advantages:**
- Run entire VMs (no app changes)
- More memory (scale to hundreds of GBs)
- Better performance
- Easier to use

**SGX advantages:**
- Smaller TCB (fewer trusted components)
- Works on older hardware
- More mature ecosystem

**EasyEnclave focuses on TDX** because it's easier for developers and supports larger applications (like LLMs).

### TDX vs AMD SEV-SNP

| Feature | Intel TDX | AMD SEV-SNP |
|---------|-----------|-------------|
| **Encryption** | AES-GCM per-VM | AES per-VM |
| **Integrity** | Hardware checks | Hardware checks |
| **Attestation** | Intel Trust Authority | AMD ASP |
| **Availability** | 4th Gen Xeon+ | EPYC Milan+ |
| **Maturity** | Production (2023+) | Production (2021+) |

**Both provide:**
- ✅ Memory encryption
- ✅ Remote attestation
- ✅ VM-level isolation
- ✅ Protection from cloud provider

## Quick Start

### Run Locally

```bash
# Build and run with Docker
docker compose up --build

# Or run directly with Python
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Access the service at:
- Web GUI: http://localhost:8080/
- API Docs: http://localhost:8080/docs
- Health Check: http://localhost:8080/health

### Deploy to TDX

> **GPU passthrough** has only been tested on Ubuntu 25.04+.

Use the GitHub Actions workflows to deploy to TDX VMs:

```bash
# Roll out staging network (latest main, no-cost profile)
gh workflow run staging-rollout.yml

# Build/re-publish release trust bundle (for a release tag)
gh workflow run release-trust-bundle.yml -f release_tag=v0.1.0

# Build/re-publish release GCP image descriptor (for the same tag)
gh workflow run release-gcp-image.yml -f release_tag=v0.1.0

# Roll out production network for a release tag (strict + pinned trust bundle)
gh workflow run production-rollout.yml -f release_tag=v0.1.0
```

See [examples/private-llm](examples/private-llm) for a complete E2E encrypted LLM example.

#### Available Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `CI` (`test.yml`) | Push/PR/manual | Lint, test, and build/sign container image (non-mutating) |
| `PR Staging Checks` | Pull request | Workflow policy checks + staging deploy examples (baremetal + gcp) for same-repo PRs |
| `Staging Rollout` | CI success on `main`/manual | Bootstrap staging CP and run builtin deploy examples (baremetal + gcp in parallel) |
| `Release Trust Bundle` | Release published/manual | Compute deterministic trusted measurements and publish pinned release trust bundle asset |
| `Release GCP Image` | Release published/manual | Publish release-pinned GCP image descriptor asset used by production provisioning |
| `Production Rollout` | Manual | Strict production rollout for a `release_tag` using pinned release trust bundle + pinned release GCP image descriptor |
| `Bootstrap Control Plane` | Manual/reusable | Reusable control-plane bootstrap component used by rollout workflows |
| `Builtin Deploy Examples (Baremetal)` | Manual/reusable | Deploy `hello-tdx` + `private-llm` (OpenAI-compatible smoke) on baremetal |
| `Builtin Deploy Examples (GCP)` | Manual/reusable | Deploy `hello-tdx` + `private-llm` (OpenAI-compatible smoke) on gcp |

#### Release Components (Complete)

Production rollout is release-gated and depends on two generated release assets:

1. `trusted_values.<tag>.json` (plus canonical `trusted_values.json`)
2. `gcp-image.<tag>.json` (plus canonical `gcp-image.json`)

These are generated by `Release Trust Bundle` and `Release GCP Image`.

Prerequisites:

- A published GitHub Release tag (for example `v0.1.0`)
- Self-hosted `[self-hosted, tdx]` runner available (required by `Release Trust Bundle`)
- GitHub secret `GCP_PROJECT_ID` (target project for release-pinned image creation)
- GitHub secret `GCP_SERVICE_ACCOUNT_KEY` (service account JSON with image create/describe permissions)
- Optional GitHub vars for base image selection:
  - `EE_GCP_BASE_IMAGE_PROJECT` (default `ubuntu-os-cloud`)
  - `EE_GCP_BASE_IMAGE_FAMILY` (default `ubuntu-2404-lts-amd64`)

End-to-end generation and rollout sequence:

```bash
# 1) Create/publish release tag
gh release create v0.1.0 --target main --title v0.1.0 --notes "Release v0.1.0"

# 2) Generate deterministic trusted measurements for this release
gh workflow run release-trust-bundle.yml -f release_tag=v0.1.0

# 3) Generate release-pinned GCP image descriptor for this release
gh workflow run release-gcp-image.yml -f release_tag=v0.1.0

# 4) Verify release assets exist
gh release view v0.1.0 --json assets --jq '.assets[].name'

# 5) Roll out production using this exact release tag
gh workflow run production-rollout.yml -f release_tag=v0.1.0
```

Expected release assets:

- `trusted_values.v0.1.0.json`
- `trusted_values.json`
- `gcp-image.v0.1.0.json`
- `gcp-image.json`

What each generated component contains:

- Trust bundle (`trusted_values*.json`):
  - `digest`
  - `mrtds`
  - `mrtds_by_size`
  - `rtmrs`
  - `rtmrs_by_size`
  - `release_tag`, `git_sha`, `generated_at`
- GCP image descriptor (`gcp-image*.json`):
  - `image_project`
  - `image_name`
  - `image_family`
  - `source_image_project`
  - `source_image_family`
  - `release_tag`, `git_sha`, `generated_at`

How production consumes these:

- `production-rollout.yml` fails fast if either asset is missing.
- Control plane bootstraps with precomputed trusted values from `trusted_values*.json`.
- CP-native GCP provisioning uses exact `image_project + image_name` from `gcp-image*.json`.
- Signature verification is strict and pinned to release-tag GitHub Actions identities.

#### Repo Creation Blueprint (Prompt + Build)

If you want to recreate a repo with the same architecture and CI/CD behavior, use this checklist.

Minimum local/bootstrap prerequisites:

- Ubuntu host with Docker, Python 3.11+, `jq`, `gh`, `git`
- Self-hosted runner labeled `[self-hosted, tdx]` for TDX build/measurement jobs
- Cloudflare account + token for public CP URL
- Intel Trust Authority API key
- GCP project + service-account key (for CP-native GCP provisioning and release GCP image workflow)

Initial repo bootstrap commands:

```bash
mkdir easyenclave && cd easyenclave
git init
gh repo create easyenclave/easyenclave --public --source=. --remote=origin --push
```

Prompt template to generate the repo (for an AI coding agent):

```text
Create a production-ready confidential computing control plane called EasyEnclave.
Requirements:
1) FastAPI control plane with app/version registry, deployment API, agent registration, and admin auth.
2) Intel TDX remote attestation verification for agents (Intel Trust Authority tokens + trusted MRTD/RTMR policy).
3) CP-native capacity orchestration including GCP VM provisioning and launch orders.
4) SDK + examples: hello-tdx and private-llm with OpenAI-compatible smoke test.
5) CI/CD split:
   - CI: lint/test/build/sign image
   - staging-rollout: automatic from main, relaxed/non-billing
   - production-rollout: manual release_tag only, strict policy
   - release-trust-bundle: deterministic trusted values asset per release
   - release-gcp-image: release-pinned GCP image descriptor asset per release
6) Production rollout must fail if trust/image release assets are missing.
7) Include docs, diagrams, and GitHub Pages website copy describing staging as untrusted and production as trusted.
8) Add policy checks in PR workflow so rollout trigger rules cannot drift.
9) Keep deploy examples for baremetal and GCP reusable/manual and run in parallel from rollout orchestrators.
Deliver complete code, tests, workflows, and docs.
```

Required repository components:

- Control plane API and storage (`app/`)
- Launcher and TDX tooling (`infra/`)
- SDK (`sdk/`)
- Examples (`examples/hello-tdx`, `examples/private-llm`)
- Workflows:
  - `.github/workflows/test.yml`
  - `.github/workflows/pr-staging-checks.yml`
  - `.github/workflows/staging-rollout.yml`
  - `.github/workflows/release-trust-bundle.yml`
  - `.github/workflows/release-gcp-image.yml`
  - `.github/workflows/production-rollout.yml`
  - Reusable: `.github/workflows/bootstrap-control-plane.yml`, `deploy-examples*.yml`

Required GitHub secrets:

- `INTEL_API_KEY`
- `CP_ADMIN_PASSWORD`
- `AGENT_ADMIN_PASSWORD`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_ID`
- `GCP_PROJECT_ID`
- `GCP_SERVICE_ACCOUNT_KEY`
- Optional deploy billing creds used by example workflows:
  - `CP_DEPLOYER_ACCOUNT_ID`
  - `CP_DEPLOYER_API_KEY`

Recommended GitHub vars:

- `STAGING_CP_URL`
- `STAGING_EASYENCLAVE_DOMAIN`
- `PRODUCTION_CP_URL`
- `PRODUCTION_EASYENCLAVE_DOMAIN`
- `GCP_DATACENTER`
- `GCP_ZONE`
- `EE_GCP_BASE_IMAGE_PROJECT`
- `EE_GCP_BASE_IMAGE_FAMILY`

Validation criteria for a successful recreation:

- `CI` green on push/PR
- `Staging Rollout` can bootstrap and run both deploy example workflows in parallel
- Release assets (`trusted_values.*.json`, `gcp-image.*.json`) are generated for a tag
- `Production Rollout` succeeds for `release_tag` and refuses to run when required release assets are absent

#### Placement and Measurement Model

- Deploy requests should normally set `node_size` and optional datacenter filters; the control plane picks a verified healthy agent.
- Direct `agent_id` targeting is reserved for controlled upgrade/recovery flows.
- App versions are attested per `node_size` before deployment is allowed.
- Version measurement is performed directly in the control plane (no dedicated measurer deployment).
- Capacity shortfall creates CP launch orders; launcher workers fulfill orders with launcher-scoped API keys.

#### Manual Bootstrap Component

```bash
# Bring up control plane + agents with explicit profile inputs
gh workflow run bootstrap-control-plane.yml
```

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/apps` | Register an app |
| `GET` | `/api/v1/apps` | List apps |
| `POST` | `/api/v1/apps/{name}/versions` | Publish app version |
| `POST` | `/api/v1/apps/{name}/versions/{version}/deploy/preflight` | Validate deploy request |
| `POST` | `/api/v1/apps/{name}/versions/{version}/deploy` | Deploy app version |
| `GET` | `/health` | Health check |
| `GET` | `/` | Web GUI |
| `GET` | `/admin` | Admin panel |

### Admin Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/admin/login` | Login with password (legacy/non-prod fallback) |
| `GET` | `/auth/github` | Start GitHub OAuth flow |
| `GET` | `/auth/github/callback` | GitHub OAuth callback |
| `GET` | `/auth/me` | Get current user info |

### Capacity Launcher API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/admin/agents/capacity/orders` | List queued launch orders (admin) |
| `POST` | `/api/v1/launchers/capacity/orders/claim` | Claim next order (launcher API key) |
| `POST` | `/api/v1/launchers/capacity/orders/{order_id}` | Update order status (launcher API key) |

### Register App + Publish Version

```bash
curl -X POST http://localhost:8080/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "description": "My confidential app",
    "source_repo": "org/my-app",
    "tags": ["api", "production"]
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/apps/my-app/versions \
  -H "Content-Type: application/json" \
  -d '{
    "version": "20260219-001",
    "compose": "<base64-docker-compose-yml>",
    "node_size": "tiny"
  }'
```

### Deploy Published Version

```bash
curl -X POST http://localhost:8080/api/v1/apps/my-app/versions/20260219-001/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "node_size": "tiny",
    "allowed_clouds": ["baremetal"]
  }'
```

## Python SDK

Install the SDK:

```bash
pip install ./sdk/
```

Connect to the control plane and query a service through the proxy:

```python
from easyenclave import EasyEnclaveClient

client = EasyEnclaveClient("https://app.easyenclave.com")
llm = client.service("private-llm")
resp = llm.post("/v1/chat/completions", json={
    "model": "smollm2:135m",
    "messages": [{"role": "user", "content": "Say hello"}],
})
print(resp.json()["choices"][0]["message"]["content"])
```

For a complete working example (tested in CI on every push), see [`examples/private-llm/test.py`](examples/private-llm/test.py). Full SDK docs in [`sdk/README.md`](sdk/README.md).

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ITA_API_URL` | Intel Trust Authority API URL | `https://api.trustauthority.intel.com/appraisal/v2` |
| `ITA_API_KEY` | Intel Trust Authority API key | (none) |
| `TCB_ENFORCEMENT_MODE` | TCB status checking mode: `strict`, `warn`, `disabled` | `strict` |
| `ALLOWED_TCB_STATUSES` | Comma-separated allowed TCB statuses | `UpToDate` |
| `NONCE_ENFORCEMENT_MODE` | Nonce challenge mode: `required`, `optional`, `disabled` | `required` |
| `NONCE_TTL_SECONDS` | Nonce expiration time in seconds | `300` |
| `SIGNATURE_VERIFICATION_MODE` | Measurement signature mode: `strict`, `warn`, `disabled` | `warn` |
| `ADMIN_PASSWORD_HASH` | Bcrypt hash for admin password authentication | (none) |
| `GITHUB_OAUTH_CLIENT_ID` | GitHub OAuth app client ID (optional) | (none) |
| `GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth app client secret (optional) | (none) |
| `GITHUB_OAUTH_REDIRECT_URI` | OAuth callback URL | `https://app.easyenclave.com/auth/github/callback` |

## Admin Authentication

The admin panel at `/admin` supports two authentication methods:

### Password Authentication

Generate a bcrypt hash for your password:

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt()).decode())"
```

Set the hash as an environment variable or GitHub secret:

```bash
export ADMIN_PASSWORD_HASH='$2b$12$...'
```

For GitHub Actions deployments, add the secret:
```bash
echo '$2b$12$...' | gh secret set ADMIN_PASSWORD_HASH
```

### GitHub OAuth (Recommended)

GitHub OAuth provides better security with per-user accounts, audit trails, and built-in MFA.

**Setup:**

1. Create a GitHub OAuth App at https://github.com/settings/developers
   - **Application name**: EasyEnclave Control Plane
   - **Homepage URL**: https://easyenclave.com
   - **Callback URL**: https://app.easyenclave.com/auth/github/callback

2. Set the OAuth credentials:
   ```bash
   echo 'your_client_id' | gh secret set GITHUB_OAUTH_CLIENT_ID
   echo 'your_client_secret' | gh secret set GITHUB_OAUTH_CLIENT_SECRET
   ```

3. Admins can now sign in with their GitHub accounts at `/admin`

**Benefits:**
- ✅ Per-user GitHub identity (no shared passwords)
- ✅ Leverage GitHub 2FA/SSO
- ✅ Complete audit trail of admin access
- ✅ Auto-rotating OAuth tokens
- ✅ Ready for org-based auto-provisioning

See [docs/GITHUB_OAUTH.md](docs/GITHUB_OAUTH.md) for detailed setup instructions and architecture.

## Development

### Run Tests

```bash
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```

Critical registration/deploy readiness flow (fast-fail):

```bash
pytest tests/test_agent_registration_e2e.py -v
```

### Project Structure

```
easyenclave/
├── app/
│   ├── main.py          # FastAPI application
│   ├── attestation.py   # Attestation business logic
│   ├── oauth.py         # GitHub OAuth integration
│   ├── auth.py          # Authentication helpers
│   ├── models.py        # Request/response DTOs
│   ├── db_models.py     # SQLModel ORM models
│   ├── storage.py       # Storage layer (Store classes)
│   ├── crud.py          # CRUD helpers
│   ├── ita.py           # Intel Trust Authority integration
│   └── static/          # Web GUI files
├── sdk/
│   └── easyenclave/     # Python SDK
├── examples/
│   ├── hello-tdx/       # Minimal HTTP server example
│   └── private-llm/     # LLM in TDX (with SDK smoke test)
├── docs/
│   └── GITHUB_OAUTH.md  # OAuth setup documentation
├── tests/               # Unit tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Security Considerations

### TEE Protection Boundaries

EasyEnclave uses Intel TDX, which provides hardware-based protection:

| Attack Type | TDX Protection | Notes |
|-------------|----------------|-------|
| **Remote attacker** | ✅ Full | Encrypted memory, network isolation |
| **Malicious hypervisor** | ✅ Full | Hardware-enforced memory encryption |
| **Malicious OS** | ✅ Full | TEE isolated from OS |
| **Physical memory dump** | ✅ Partial | Memory encrypted, but keys could be extracted |
| **Side channels (cache)** | ⚠️ Partial | Some mitigations, not perfect |
| **Voltage glitching** | ⚠️ Limited | Hardware defenses, but attackable |

### Defense-in-Depth: Beyond TEEs

For maximum security, combine TDX with additional techniques:

**1. Encrypted storage** - Data at rest protection
- Encrypt data with separate keys
- Keys never leave TEE
- Protects against physical storage attacks

**2. MPC (Multi-Party Computation)** - Distribute trust
- No single party has complete data
- Protects against insider threats
- Useful for collaborative analytics

### Attestation Security Features

EasyEnclave enforces two critical security policies during agent registration:

**1. TCB Status Enforcement** - Prevents vulnerable platforms
- Checks Intel Trust Authority `attester_tcb_status` field
- Rejects agents with outdated security patches (strict mode)
- Default: `strict` mode (only UpToDate platforms allowed)
- Configuration: `TCB_ENFORCEMENT_MODE=strict|warn|disabled`

**2. Nonce Challenge** - Prevents replay attacks
- Requires agents to request one-time nonce before registration
- Nonce included in TDX quote REPORTDATA field
- Prevents attackers from reusing captured attestation quotes
- Default: `required` mode (nonce mandatory)
- Configuration: `NONCE_ENFORCEMENT_MODE=required|optional|disabled`

These features are enabled by default in `docker-compose.yml`. See `.env.example` for configuration options.

### About tee.fail

**[tee.fail](https://tee.fail)** documents physical attacks on TEEs, showing that:

1. **TEE encryption can be broken** with physical access
   - Voltage glitching
   - Laser fault injection
   - Memory bus sniffing

2. **Side channels leak information**
   - Cache timing attacks
   - Page fault patterns
   - Memory access patterns

3. **Supply chain attacks** possible
   - Compromised firmware
   - Modified hardware

**Does this mean TEEs are useless?**

**No!** TEEs still provide strong protection:

✅ **Against remote attackers** - TDX is excellent
✅ **Against cloud providers** - Strong protection
✅ **Against malicious OS** - Full protection
⚠️ **Against nation-states with physical access** - Limited

**Defense-in-depth approach:**
- **Use TEEs** for cloud/OS protection
- **Add encrypted storage** for data-at-rest protection
- **Use MPC** for multi-party scenarios
- **Add protocol-level encryption** for data in transit

### When Should I Worry About Physical Attacks?

**It depends on your threat model:**

**Low risk scenarios:**
- Running on your own hardware
- Trusted cloud provider
- Non-critical data

**High risk scenarios:**
- Nation-state adversaries
- High-value data (medical, financial)
- Regulated industries (HIPAA, GDPR)

**Recommendations:**

| Threat Level | Protection Strategy |
|--------------|---------------------|
| **Basic** | TDX + attestation |
| **Moderate** | TDX + attestation + encrypted storage |
| **High** | TDX + encrypted storage + MPC + defense-in-depth |
| **Maximum** | Air-gapped + HSMs + formal verification |

**For most use cases:** TDX attestation is sufficient.

## Examples

### Hello TDX
Minimal HTTP server demonstrating TDX deployment and attestation.
- **Path:** `examples/hello-tdx/`
- **Features:** Basic FastAPI service, TDX attestation, Docker deployment

### Private LLM
Run language models with privacy protection in TDX.
- **Path:** `examples/private-llm/`
- **Features:** Ollama in TDX, end-to-end encryption, SDK integration
- **Live demo:** Runs in CI on every push

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - System design, deploy flow, and measurement flow diagrams
- **[CI/CD Networks](docs/CI_CD_NETWORKS.md)** - Staging vs production rollout plan and workflow graph
- **[FAQ](docs/FAQ.md)** - Security, deployment guides, and additional Q&A
- **[GitHub OAuth Setup](docs/GITHUB_OAUTH.md)** - Admin authentication configuration
- **[SDK Documentation](sdk/README.md)** - Python client library

## Future Enhancements

- [ ] AMD SEV-SNP support
- [ ] ARM CCA support
- [ ] S3 backup/restore for persistence
- [ ] Accounting (credit for work, debit to deploy)
- [ ] Private EVM example
- [ ] MPC framework integration
