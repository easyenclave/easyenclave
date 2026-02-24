# EasyEnclave v2 (Go)

Clean-slate rewrite workspace for:
- `control-plane`
- `agent`
- `installer` (host agent installer/service bootstrapper)

## Quickstart

```bash
cd v2
go test ./...
go build ./cmd/control-plane ./cmd/agent ./cmd/installer
```

## Local run

```bash
cd v2
CONTROL_PLANE_ADDR=:8080 go run ./cmd/control-plane
AGENT_ADDR=:8000 go run ./cmd/agent
EE_SKIP_SYSTEMD=true EE_RUN_AGENT_NOW=true EE_INSTALL_ROOT=/tmp/easyenclave EE_SYSTEMD_DIR=/tmp go run ./cmd/installer
```

## OpenAPI Codegen

```bash
cd v2
./tools/codegen.sh
```
