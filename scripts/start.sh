#!/bin/bash
# Start the proxy and inject credentials.
# Runs on the HOST (macOS).
#
# Usage:
#   ./scripts/start.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

"$SCRIPT_DIR/generate-certs.sh"

echo "Starting proxy..." >&2
docker compose -f "$REPO_ROOT/docker-compose.yml" up -d --build --force-recreate

DC="docker compose -f $REPO_ROOT/docker-compose.yml"

echo "Extracting Claude Code credentials from macOS Keychain..." >&2
CREDS_JSON="$(security find-generic-password \
  -s "Claude Code-credentials" -a "$(whoami)" -w 2> /dev/null)" || true

if [ -z "${CREDS_JSON:-}" ]; then
  cat >&2 << 'MSG'
Error: Could not find Claude Code credentials in macOS Keychain.
The proxy needs these credentials to inject auth headers into API requests.

To fix this, log in with Claude Code on this machine:
  claude login

Then re-run this script.
MSG
else
  printf '%s' "$CREDS_JSON" | $DC exec -T proxy \
    bash -c 'mkdir -p ~/.config/proxy/secrets && cat > ~/.config/proxy/secrets/claude.json'
  echo "Credentials injected into proxy." >&2
fi

cleanup() {
  echo "" >&2
  echo "Stopping proxy..." >&2
  docker compose -f "$REPO_ROOT/docker-compose.yml" kill
}
trap cleanup INT TERM

echo "Ready. Following logs (Ctrl+C to stop)..." >&2
docker compose -f "$REPO_ROOT/docker-compose.yml" logs -f
