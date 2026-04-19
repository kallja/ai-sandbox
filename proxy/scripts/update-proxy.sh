#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVCONTAINER_DIR="$(cd "$SCRIPT_DIR/../../.devcontainer" && pwd)"

$SCRIPT_DIR/build-proxy-image.sh
docker compose -p ai-sandbox -f $DEVCONTAINER_DIR/docker-compose.yml up -d proxy --force-recreate
