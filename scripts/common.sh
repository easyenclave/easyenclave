#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "required command not found: $cmd" >&2
    exit 1
  }
}

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "required env var is missing: $name" >&2
    exit 1
  fi
}

gcloud_auth_with_key_json() {
  local key_var="$1"
  local project_var="$2"

  require_var "$key_var"
  require_var "$project_var"

  local key_file
  key_file="$(mktemp)"
  trap 'rm -f "$key_file"' RETURN

  printf '%s' "${!key_var}" > "$key_file"
  gcloud auth activate-service-account --key-file="$key_file" >/dev/null
  gcloud config set project "${!project_var}" >/dev/null
}
