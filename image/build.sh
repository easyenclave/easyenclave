#!/usr/bin/env bash
set -euo pipefail

docker build -f image/Dockerfile -t easyenclave/v2-agent:local .
echo "built easyenclave/v2-agent:local"
