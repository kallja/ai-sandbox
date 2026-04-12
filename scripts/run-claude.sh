#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DC="docker compose -f $REPO_ROOT/docker-compose.yml"

if ! $DC ps --status running claude-code --quiet 2>/dev/null | grep -q .; then
  echo "Container not running. Starting services..." >&2
  $DC up -d --build --force-recreate

  echo "Extracting Claude Code credentials from macOS Keychain..." >&2
  CREDS_JSON="$(security find-generic-password \
    -s "Claude Code-credentials" -a "$(whoami)" -w 2>/dev/null)" || true

  if [ -z "${CREDS_JSON:-}" ]; then
    echo "Warning: Could not find Claude Code credentials in macOS Keychain." >&2
    echo "Run 'claude login' on the host, then re-run this script." >&2
  else
    printf '%s' "$CREDS_JSON" | $DC exec -T proxy \
      bash -c 'mkdir -p ~/.config/proxy/secrets && cat > ~/.config/proxy/secrets/claude.json'
    printf '%s' "$CREDS_JSON" \
    | jq '{
      claudeAiOauth: {
        accessToken: "proxy-injected-accessToken",
        refreshToken: "proxy-injected-refreshToken",
        expiresAt: .claudeAiOauth.expiresAt,
        scopes: .claudeAiOauth.scopes,
        subscriptionType: .claudeAiOauth.subscriptionType,
        rateLimitTier: .claudeAiOauth.rateLimitTier
      }
    }'\
    | $DC exec -T claude-code \
      bash -c 'mkdir -p /home/claude/.claude && cat > /home/claude/.claude/.credentials.json && chown -R claude:claude /home/claude/.claude'
    echo "Credentials injected." >&2
  fi
fi

$DC exec -u claude claude-code claude
