#!/bin/bash
# Run Claude Code CLI in the devcontainer.
# Runs on the HOST (macOS). Starts services if needed.
#
# Usage:
#   .devcontainer/run-claude.sh [claude args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DC="docker compose -f $REPO_ROOT/docker-compose.yml -f $SCRIPT_DIR/docker-compose.yml"

if ! $DC ps --status running claude --quiet 2>/dev/null | grep -q .; then
  echo "Container not running. Starting services..." >&2

  # Generate proxy CA certs if needed, then extract credentials
  "$REPO_ROOT/scripts/generate-certs.sh"
  "$SCRIPT_DIR/extract-credentials.sh"

  $DC up -d --build --force-recreate

  # Inject credentials into proxy
  SECRETS_FILE="$SCRIPT_DIR/.secrets/claude.json"
  if [ -f "$SECRETS_FILE" ] && [ "$(cat "$SECRETS_FILE")" != "{}" ]; then
    cat "$SECRETS_FILE" | $DC exec -T proxy \
      bash -c 'mkdir -p ~/.config/proxy/secrets && cat > ~/.config/proxy/secrets/claude.json'
    echo "Credentials injected into proxy." >&2
  else
    echo "Warning: No credentials available. Run 'claude login' on the host first." >&2
  fi
fi

if [ "${1:-}" = "stop" ]; then
  echo "Stopping all services..." >&2
  $DC kill
  exit 0
fi

$DC exec -u claude claude "${@:-claude}"
