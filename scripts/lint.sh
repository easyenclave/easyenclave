#!/usr/bin/env bash
# Shared linting script used by both pre-commit and CI
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "==> Running ruff check..."
ruff check infra/ scripts/

echo "==> Running ruff format check..."
ruff format --check infra/ scripts/

echo "==> Running shellcheck..."
find infra/ scripts/ -name "*.sh" -print0 | xargs -0 shellcheck --severity=warning

echo "==> Running actionlint..."
actionlint -config-file .github/actionlint.yaml

echo "==> All checks passed!"
