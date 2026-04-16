#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"

"$DIR/generate-certs.sh"
docker build -t ai-sandbox-proxy "$REPO_ROOT/proxy"
