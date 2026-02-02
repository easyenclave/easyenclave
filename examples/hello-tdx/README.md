# Hello TDX

Minimal example showing a service running in a TDX enclave.

## Deploy

```yaml
- uses: easyenclave/easyenclave/.github/actions/deploy@main
  with:
    app_name: hello-tdx
    compose_file: examples/hello-tdx/docker-compose.yml
    service_name: hello-tdx
```
