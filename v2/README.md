# EasyEnclave v2 (Go)

Clean-slate rewrite workspace for:
- `control-plane`
- `agent`
- `eectl`

## Quickstart

```bash
cd v2
go test ./...
go build ./cmd/control-plane ./cmd/agent ./cmd/eectl
```

## Local run

```bash
cd v2
CONTROL_PLANE_ADDR=:8080 go run ./cmd/control-plane
AGENT_ADDR=:8000 go run ./cmd/agent
```

## OpenAPI Codegen

```bash
cd v2
./tools/codegen.sh
```
