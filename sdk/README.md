# EasyEnclave SDK

Python client library for the EasyEnclave control plane.

## Installation

```bash
pip install easyenclave
```

Or install from source:

```bash
pip install ./sdk/
```

## Usage

### Query a service through the proxy

The most common pattern — connect to the control plane and call a service:

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

For a complete working example (tested in CI on every push), see [`examples/private-llm/test.py`](../examples/private-llm/test.py).

### Verify control plane attestation

Pass `verify=True` (the default) to verify the control plane's TDX quote on connect. This confirms you're talking to a genuine TDX enclave before routing any traffic:

```python
client = EasyEnclaveClient("https://app.easyenclave.com", verify=True)

# At this point, the control plane's TDX attestation has been verified.
# All requests through client.service() are routed via the attested proxy.
resp = client.service("my-app").get("/api/data")
```

Use `verify=False` when running outside TDX (e.g. local dev, CI runners):

```python
client = EasyEnclaveClient("https://app.easyenclave.com", verify=False)
```

### Browse the app catalog

```python
client = EasyEnclaveClient("https://app.easyenclave.com", verify=False)

# List all apps
apps = client.list_apps()

# Get a specific app and its versions
app = client.get_app("private-llm")
version = client.get_app_version("private-llm", "20260205-abc1234")
```

### Service discovery

```python
# Find services by name, tags, or MRTD
services = client.discover(tags=["api"])
for svc in services:
    print(f"{svc['name']} — {svc['endpoints']}")

# Get details for a specific service
service = client.get_service(service_id)
```

### Context manager

```python
with EasyEnclaveClient("https://app.easyenclave.com", verify=False) as client:
    resp = client.service("my-app").get("/health")
    # Client is automatically closed when exiting the context
```

## API Reference

### EasyEnclaveClient

#### `__init__(control_plane_url, verify=True, expected_mrtd=None, timeout=30.0)`

Connect to the control plane. If `verify=True`, the control plane's TDX attestation is checked immediately.

#### `service(service_name) -> ServiceClient`

Get a client for a named service. Requests are routed through the control plane proxy.

#### `list_apps(name=None, tags=None) -> list[dict]`

List apps in the catalog, optionally filtered by name or tags.

#### `get_app(app_name) -> dict`

Get details for an app.

#### `get_app_version(app_name, version) -> dict`

Get details for a specific version of an app.

#### `discover(...) -> list[dict]`

Find services matching criteria (name, tags, environment, mrtd, health_status, query).

#### `get_service(service_id) -> dict`

Get details for a specific service.

#### `register(...) -> str`

Register a service. Returns the service ID.

#### `deregister(service_id) -> bool`

Remove a service from the registry.

### ServiceClient

Returned by `client.service("name")`. Supports `get()`, `post()`, `put()`, `patch()`, `delete()`, and `request()` — all taking a path and optional httpx kwargs.

## Exceptions

- `EasyEnclaveError` — Base exception for all client errors
- `ServiceNotFoundError` — Service or app not found
- `ControlPlaneNotVerifiedError` — Control plane attestation failed
- `VerificationError` — Attestation verification failed
