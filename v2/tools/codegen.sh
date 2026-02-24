#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OAPI="${OAPI_CODEGEN_BIN:-${HOME}/go/bin/oapi-codegen}"

if [ ! -x "$OAPI" ]; then
  echo "oapi-codegen not found at $OAPI" >&2
  echo "Install with: go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest" >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/internal/gen/controlplaneapi" "$ROOT_DIR/internal/gen/agentapi"

"$OAPI" \
  -generate types,std-http,spec,skip-prune \
  -package controlplaneapi \
  -o "$ROOT_DIR/internal/gen/controlplaneapi/gen.go" \
  "$ROOT_DIR/api/openapi/control-plane.yaml"

"$OAPI" \
  -generate types,std-http,spec,skip-prune \
  -package agentapi \
  -o "$ROOT_DIR/internal/gen/agentapi/gen.go" \
  "$ROOT_DIR/api/openapi/agent-control.yaml"

cd "$ROOT_DIR"
go fmt ./internal/gen/...
