#!/bin/bash
# Tears down all services. Kill first for speed, then down to clean up.
set -euo pipefail

source "$(dirname "$0")/scripts/common.sh"
REPO_ROOT="$(repo_root)"
DC="docker compose -p $(compose_prefix "$REPO_ROOT") -f $REPO_ROOT/.devcontainer/docker-compose.yml"

echo "Stopping all services..." >&2
$DC kill
$DC down
