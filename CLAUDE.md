# CLAUDE.md — EasyEnclave

## Project Overview

EasyEnclave is a confidential discovery service (control plane) for TDX-attested applications. It enables registration, discovery, and management of services running in Intel TDX (Trust Domain Extensions) Trusted Execution Environments. The system handles attestation verification, VM deployment, app catalogs, billing, and admin interfaces.

## Tech Stack

- **Language**: Python 3.10+ (target 3.11 for production)
- **Framework**: FastAPI with Uvicorn
- **ORM/Models**: SQLModel (SQLAlchemy + Pydantic hybrid)
- **Database**: SQLite (via SQLModel), migrations via Alembic
- **Linting**: ruff (format + check), shellcheck, actionlint
- **Testing**: pytest with pytest-asyncio and pytest-httpx
- **Container**: Docker (Python 3.11-slim base)
- **Infrastructure**: Intel TDX VMs, mkosi image builder, Cloudflare tunnels

## Repository Structure

```
app/                  # Main FastAPI application
  main.py             # All API routes (~60+ endpoints)
  db_models.py        # SQLModel ORM table definitions
  models.py           # Pydantic request/response DTOs
  storage.py          # In-memory + DB storage layer
  settings.py         # Config from env vars and DB settings
  attestation.py      # TDX attestation verification
  auth.py             # Password, session, API key auth
  billing.py          # Account management, charging
  cloudflare.py       # Cloudflare tunnel integration
  oauth.py            # GitHub OAuth for admin panel
  nonce.py            # Nonce challenge (replay prevention)
  ita.py              # Intel Trust Authority API client
  proxy.py            # Request proxying to deployed services
  pricing.py          # SLA-based pricing calculations
  crud.py             # Database CRUD helpers
  database.py         # DB engine initialization
  static/             # Admin UI (HTML/JS/CSS)
sdk/easyenclave/      # Python SDK for programmatic access
  client.py           # SDK client class
  verify.py           # TDX attestation verification
infra/                # Infrastructure tooling
  tdx_cli.py          # TDX VM lifecycle CLI (create/destroy/measure/deploy)
  launcher/           # Agent that runs inside TDX VMs
  image/              # VM image build system (mkosi + Nix)
examples/             # Example applications (hello-tdx, private-llm, oram-contacts)
apps/                 # Production services (measuring-enclave, oram-contacts)
alembic/              # Database migration scripts
tests/                # Test suite (16 files)
scripts/              # Utility scripts (lint.sh, hash_admin_password.py, cleanup)
.github/              # CI workflows and custom actions
```

## Common Commands

### Install dependencies
```bash
pip install -r requirements.txt
pip install -e sdk/
pip install pytest pytest-asyncio pytest-httpx httpx ruff  # dev deps
```

### Run the application
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Run tests
```bash
pytest tests/ -v
```

### Run linting
```bash
# Full lint suite (ruff + shellcheck + actionlint)
./scripts/lint.sh

# Individual linters
ruff check app/ sdk/ tests/ infra/
ruff format --check app/ sdk/ tests/ infra/
```

### Fix formatting
```bash
ruff format app/ sdk/ tests/ infra/
ruff check --fix app/ sdk/ tests/ infra/
```

### Database migrations
```bash
# Apply all migrations
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "description"
```

### Docker
```bash
docker build -t easyenclave:test .
docker run -d -p 8080:8080 easyenclave:test
```

## Code Conventions

### Python style
- **Line length**: 100 characters (enforced by ruff)
- **Target version**: Python 3.10 (`from __future__ import annotations` used)
- **Type hints**: Use modern syntax (`str | None` not `Optional[str]`, `dict[str, str]` not `Dict`)
- **Imports**: Sorted by isort rules with `app`, `sdk`, `infra` as known first-party
- **Lint rules**: E, W, F, I, B, C4, UP enabled; E501 and B008 ignored (B008 for FastAPI dependency injection)

### Database models
- All models in `app/db_models.py` use SQLModel (dual SQLAlchemy ORM + Pydantic)
- UUIDs generated as strings via `uuid.uuid4()`
- Timestamps use `datetime.now(timezone.utc)` (timezone-aware)
- JSON columns use `sa_column=Column(JSON)` for complex types

### Testing patterns
- Tests use `FastAPI TestClient` (sync) with `pytest`
- Async mode set to `"auto"` in pytest config
- Fixtures provide `client`, sample data, and mock objects
- Tests organized in classes by feature area (e.g., `TestHealthEndpoint`)
- Mock external services (Intel Trust Authority, Cloudflare) with `unittest.mock`

### API conventions
- All API routes under `/api/v1/` prefix
- Admin routes under `/admin/`
- Health check at `/health`
- JSON request/response bodies using Pydantic models from `app/models.py`
- Authentication via Bearer tokens (admin sessions) or API keys

### Environment configuration
- Config loaded from env vars with fallbacks (see `.env.example`)
- DB-stored settings can override env vars (managed via `app/settings.py`)
- Key settings: `ITA_API_KEY`, `CLOUDFLARE_*`, `TCB_ENFORCEMENT_MODE`, `NONCE_ENFORCEMENT_MODE`, `ADMIN_PASSWORD_HASH`

## CI Pipeline

The CI workflow (`.github/workflows/test.yml`) runs on push to main and PRs:
1. **test** job: Python 3.11 setup, install deps, `./scripts/lint.sh`, `pytest tests/ -v`
2. **docker** job: Build image, test health endpoint, push app images to GHCR
3. **deploy** job (push only, self-hosted TDX runner): Build verity VM image, measure MRTD/RTMRs, deploy control plane and agents

## Key Domain Concepts

- **Agent**: A TDX VM that registers with the control plane and runs deployed services
- **Service**: A registered application with attestation, endpoints, and health status
- **MRTD**: Measurement of the TDX Trust Domain (hardware attestation hash)
- **RTMRs**: Runtime Memory Registers (additional attestation registers)
- **TCB**: Trusted Computing Base — platform security posture status
- **Nonce challenge**: One-time tokens to prevent attestation replay attacks
- **App catalog**: Registry of published applications with versioned deployments
- **Measuring enclave**: Special service that resolves Docker image digests for attestation
