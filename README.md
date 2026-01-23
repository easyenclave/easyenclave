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

Use the GitHub Actions workflow to deploy to a TDX VM:

```bash
# Trigger the deploy workflow
gh workflow run deploy.yml -f vm_name=easyenclave -f memory_gb=8
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
cd sdk
pip install -e .
```

Use the SDK:

```python
from easyenclave import EasyEnclaveClient

# Connect to the discovery service
client = EasyEnclaveClient("http://localhost:8080")

# Register a service
service_id = client.register(
    name="my-service",
    endpoints={"prod": "https://my-service.example.com"},
    tags=["api"],
)

# Discover services
services = client.discover(tags=["api"])

# Get service details
service = client.get_service(service_id)

# Verify attestation
result = client.verify_service(service_id)

# Deregister
client.deregister(service_id)
```

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
│   ├── models.py        # Data models
│   ├── storage.py       # In-memory storage
│   ├── ita.py           # ITA integration
│   └── static/          # Web GUI files
├── sdk/
│   └── easyenclave/     # Python SDK
├── tests/               # Unit tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Future Enhancements

- [ ] S3 backup/restore for persistence
- [ ] Periodic health checks of registered services
- [ ] Webhook notifications on registration/deregistration
- [ ] Service groups/namespaces
- [ ] Rate limiting
- [ ] Authentication for registration
