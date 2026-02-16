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

**Learn more:** See [docs/FAQ.md](docs/FAQ.md) for security and deployment Q&A, and [docs/REPRODUCIBLE_BUILDS.md](docs/REPRODUCIBLE_BUILDS.md) for reproducibility verification (two clean builds per check; any artifact or measurement drift fails).

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
# Bootstrap the full infrastructure (control plane + agents)
gh workflow run bootstrap.yml -f action=bootstrap-all

# Or deploy just the private-llm demo (uses existing infrastructure)
gh workflow run deploy.yml
```

See [examples/private-llm](examples/private-llm) for a complete E2E encrypted LLM example.

#### Available Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `bootstrap.yml` | Manual | Bootstrap infrastructure: control plane, agents, trusted MRTDs |
| `deploy.yml` | Push to main | Auto-deploy private-llm demo to existing infrastructure |

#### Placement and Measurement Model

- Deploy requests should normally set `node_size` and optional datacenter filters; the control plane picks a verified healthy agent.
- Direct `agent_id` targeting is reserved for controlled upgrade/recovery flows.
- App versions are attested per `node_size` before deployment is allowed.
- Measurement jobs are routed to `measuring-enclave` (default) or `measuring-enclave-<node_size>` variants.
- Measurer capacity can run on verified tiny agents in either bare metal or GCP datacenters.

#### Bootstrap Actions

```bash
# Full bootstrap: control plane + agents
gh workflow run bootstrap.yml -f action=bootstrap-all -f agent_count=2

# Launch control plane only
gh workflow run bootstrap.yml -f action=control-plane-only

# Add more agents to existing control plane
gh workflow run bootstrap.yml -f action=add-agents -f agent_count=3

# Trust a new VM image MRTD
gh workflow run bootstrap.yml -f action=add-trusted-mrtd -f mrtd="91eb2b44..."

# Clean up all VMs
gh workflow run bootstrap.yml -f action=cleanup-vms
```

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/register` | Register a new service |
| `GET` | `/api/v1/services` | List/search services |
| `GET` | `/api/v1/services/{id}` | Get service details |
| `DELETE` | `/api/v1/services/{id}` | Deregister a service |
| `GET` | `/api/v1/services/{id}/verify` | Verify attestation |
| `GET` | `/health` | Health check |
| `GET` | `/` | Web GUI |
| `GET` | `/admin` | Admin panel |

### Admin Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/admin/login` | Login with password |
| `GET` | `/auth/github` | Start GitHub OAuth flow |
| `GET` | `/auth/github/callback` | GitHub OAuth callback |
| `GET` | `/auth/me` | Get current user info |

### Register a Service

```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-service",
    "description": "My TDX-attested service",
    "endpoints": {
      "prod": "https://my-service.example.com"
    },
    "source_repo": "https://github.com/org/my-service",
    "tags": ["api", "production"],
    "mrtd": "abc123..."
  }'
```

### Discover Services

```bash
# List all services
curl http://localhost:8080/api/v1/services

# Filter by name
curl "http://localhost:8080/api/v1/services?name=my-service"

# Filter by tags
curl "http://localhost:8080/api/v1/services?tags=api,production"

# Filter by environment
curl "http://localhost:8080/api/v1/services?environment=prod"

# Search
curl "http://localhost:8080/api/v1/services?q=my-service"
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
├── apps/
│   └── measuring-enclave/  # Image digest resolution service
├── docs/
│   └── GITHUB_OAUTH.md  # OAuth setup documentation
├── alembic/             # Database migrations
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
