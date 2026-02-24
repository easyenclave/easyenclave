# EasyEnclave v2 (Go)

`v2/` is the active rewrite workspace.

## Binaries
- `control-plane`: CP API/service
- `agent`: node runtime
- `installer`: installs/configures/runs the agent on a host

## Build and Test
```bash
cd v2
go test ./...
go build ./cmd/control-plane ./cmd/agent ./cmd/installer
```

## Local Run
```bash
cd v2
CONTROL_PLANE_ADDR=:8080 go run ./cmd/control-plane
AGENT_ADDR=:8000 go run ./cmd/agent
```

## Installer Usage
Installer defaults:
- install root: `/opt/easyenclave`
- service: `easyenclave-agent`
- env file: `/etc/easyenclave/agent.env`
- systemd unit: `/etc/systemd/system/easyenclave-agent.service`

Example safe local run (no systemd writes):
```bash
cd v2
EE_AGENT_SOURCE="$(pwd)/bin/agent" \
EE_INSTALL_ROOT=/tmp/easyenclave \
EE_SYSTEMD_DIR=/tmp/systemd \
EE_ENV_DIR=/tmp/easyenclave-env \
EE_SKIP_SYSTEMD=true \
EE_DRY_RUN=true \
go run ./cmd/installer
```

Useful env vars:
- `EE_AGENT_SOURCE`
- `EE_INSTALL_ROOT`
- `EE_SYSTEMD_DIR`
- `EE_ENV_DIR`
- `EE_AGENT_SERVICE_NAME`
- `EE_AGENT_USER`
- `EE_AGENT_GROUP`
- `EE_SKIP_SYSTEMD=true|false`
- `EE_DRY_RUN=true|false`
- `EE_RUN_AGENT_NOW=true|false`

Agent env passthrough examples:
- `AGENT_ADDR`
- `EASYENCLAVE_CONFIG`
- `EASYENCLAVE_NETWORK_NAME`
- `CONTROL_PLANE_URL`

## OpenAPI Codegen
```bash
cd v2
./tools/codegen.sh
```
