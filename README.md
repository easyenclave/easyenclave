# EasyEnclave

A confidential discovery service for TDX-attested applications. EasyEnclave enables registration and discovery of TDX-attested services with their metadata, including source code location, endpoints, and attestation information.

## Features

- **Service Registration**: Register TDX-attested services with metadata
- **Service Discovery**: Find services by name, tags, environment, or MRTD
- **Attestation Verification**: Verify service attestations via Intel Trust Authority
- **Web GUI**: Browser-based dashboard for viewing and managing services
- **Python SDK**: Client library for programmatic access
- **TDX Deployment**: Deploy as an attested TDX application

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

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/register` | Register a new service |
| `GET` | `/api/v1/services` | List/search services |
| `GET` | `/api/v1/services/{id}` | Get service details |
| `DELETE` | `/api/v1/services/{id}` | Deregister a service |
| `GET` | `/api/v1/services/{id}/verify` | Verify attestation |
| `GET` | `/health` | Health check |
| `GET` | `/` | Web GUI |

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
├── tests/               # Unit tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Future Enhancements

- [ ] S3 backup/restore for persistence
- [ ] Accounting (credit for work, debit to deploy)
- [ ] Private EVM example
