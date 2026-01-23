# EasyEnclave SDK

Python client library for the EasyEnclave discovery service.

## Installation

```bash
pip install easyenclave
```

Or install from source:

```bash
cd sdk
pip install -e .
```

## Usage

### Basic Example

```python
from easyenclave import EasyEnclaveClient

# Connect to the discovery service
client = EasyEnclaveClient("https://easyenclave.example.com")

# Register a service
service_id = client.register(
    name="my-service",
    endpoints={"prod": "https://my-service.example.com"},
    description="My TDX-attested service",
    tags=["api", "production"],
    source_repo="https://github.com/org/my-service",
)
print(f"Registered with ID: {service_id}")

# Discover services
services = client.discover(tags=["api"])
for svc in services:
    print(f"Found: {svc['name']} at {svc['endpoints']}")

# Get specific service details
service = client.get_service(service_id)
print(f"Service details: {service}")

# Verify a service's attestation
result = client.verify_service(service_id)
if result["verified"]:
    print("Attestation verified!")
else:
    print(f"Verification failed: {result['error']}")

# Deregister when done
client.deregister(service_id)
```

### With Attestation

```python
import subprocess
import json

# Get attestation from measure-tdx
result = subprocess.run(
    ["measure-tdx", "--json"],
    capture_output=True,
    text=True,
)
attestation = json.loads(result.stdout)

# Register with attestation
service_id = client.register(
    name="attested-service",
    endpoints={"prod": "https://secure.example.com"},
    attestation_json=attestation,
    mrtd=attestation.get("mrtd"),
    intel_ta_token=attestation.get("token"),
)
```

### Context Manager

```python
with EasyEnclaveClient("https://easyenclave.example.com") as client:
    services = client.discover()
    # Client is automatically closed when exiting the context
```

## API Reference

### EasyEnclaveClient

#### `__init__(discovery_url, verify_attestation=True, timeout=30.0)`

Create a new client connected to the discovery service.

- `discovery_url`: Base URL of the EasyEnclave service
- `verify_attestation`: Whether to verify the service's attestation on connect
- `timeout`: Request timeout in seconds

#### `register(...) -> str`

Register a service. Returns the service ID.

#### `discover(...) -> list[dict]`

Find services matching the given criteria.

#### `get_service(service_id) -> dict`

Get details for a specific service.

#### `verify_service(service_id) -> dict`

Verify a service's attestation via Intel Trust Authority.

#### `deregister(service_id) -> bool`

Remove a service from the registry.

## Exceptions

- `EasyEnclaveError`: Base exception for all client errors
- `ServiceNotFoundError`: Raised when a service is not found
- `VerificationError`: Raised when attestation verification fails
