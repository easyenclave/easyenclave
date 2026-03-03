#!/usr/bin/env bash
# Shared linting script used by both pre-commit and CI
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "==> Running ruff check..."
ruff check scripts/

echo "==> Running ruff format check..."
ruff format --check scripts/

echo "==> Running shellcheck..."
find scripts/ packer/ -name "*.sh" -print0 | xargs -0 shellcheck --severity=warning

echo "==> Running actionlint..."
actionlint -config-file .github/actionlint.yaml

echo "==> All checks passed!"
