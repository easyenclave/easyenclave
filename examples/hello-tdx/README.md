# Hello TDX

Minimal example — a single HTTP server that returns `Hello from TDX!`. This is the smallest possible EasyEnclave app, useful as a starting point or smoke test.

## What it does

Runs [hashicorp/http-echo](https://hub.docker.com/r/hashicorp/http-echo) on port 8080. Any HTTP request returns a plain text greeting.

## docker-compose.yml

```yaml
services:
  app:
    image: hashicorp/http-echo:latest
    command: ["-text=Hello from TDX!", "-listen=:8080"]
    ports:
      - "8080:8080"
```

## Deployment

Deployed automatically by the [Deploy Examples](../../.github/workflows/deploy-examples.yml) workflow. The deploy action registers the app, publishes the compose file, and waits for the health check on `/` to pass.

This compose file is also used by the **unregistered app test** — the workflow attempts to deploy it without registering first and verifies the control plane rejects it. This proves the app catalog is enforced, not optional.
