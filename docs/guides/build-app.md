# Build a New App for EasyEnclave

Primary directories: `examples/`, `sdk/`

## Goal

Create a deployable containerized app and publish/deploy it through EasyEnclave.

## Recommended Flow

1. Start from an example skeleton:

```bash
cd examples
cp -r hello-tdx my-app
cd my-app
```

2. Update app image and compose (`docker-compose.yml`) for your service.

3. Build and test locally:

```bash
docker compose up --build
curl -f http://localhost:8080/
```

4. Publish via control plane:

- Register app (`POST /api/v1/apps`)
- Publish version (`POST /api/v1/apps/{name}/versions`)
- Deploy (`POST /api/v1/apps/{name}/versions/{version}/deploy`)

5. Add SDK integration tests if your app exposes API endpoints:

```bash
cd ../../sdk
pip install -e .
```

Use `examples/private-llm/test.py` as a reference for end-to-end SDK usage.
