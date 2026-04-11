#!/bin/bash
# Start the proxy-test environment and inject credentials.
# Runs on the HOST (macOS).
#
# Usage:
#   ./proxy-test/start.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting proxy-test services..." >&2
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build --force-recreate

DC="docker compose -f $SCRIPT_DIR/docker-compose.yml"

echo "Copying Claude config into claude-code container..." >&2
[ -f ~/.claude/settings.json ] && cat ~/.claude/settings.json | $DC exec -T claude-code \
  bash -c 'mkdir -p ~/.claude && cat > ~/.claude/settings.json'
[ -f ~/.claude.json ] && cat ~/.claude.json | $DC exec -T claude-code \
  bash -c 'cat > ~/.claude.json'

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
  exit 1
else
  printf '%s' "$CREDS_JSON" | $DC exec -T proxy \
    bash -c 'mkdir -p ~/.config/proxy/secrets && cat > ~/.config/proxy/secrets/claude.json'
  printf '%s' "$CREDS_JSON" | jq '{
    claudeAiOauth: {
      accessToken: "proxy-injected",
      refreshToken: "proxy-injected",
      expiresAt: .claudeAiOauth.expiresAt,
      scopes: .claudeAiOauth.scopes,
      subscriptionType: .claudeAiOauth.subscriptionType,
      rateLimitTier: .claudeAiOauth.rateLimitTier
    }
  }' | $DC exec -T claude-code \
    bash -c 'mkdir -p ~/.claude && cat > ~/.claude/.credentials.json'
  echo "Credentials injected into containers." >&2
fi

cleanup() {
  echo "" >&2
  echo "Stopping proxy-test services..." >&2
  docker compose -f "$SCRIPT_DIR/docker-compose.yml" kill
}
trap cleanup INT TERM

echo "Ready. Following logs (Ctrl+C to stop)..." >&2
docker compose -f "$SCRIPT_DIR/docker-compose.yml" logs -f
