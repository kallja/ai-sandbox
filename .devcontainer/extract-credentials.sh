#!/bin/bash
# Runs on the HOST (macOS) before docker compose up.
# Extracts Claude Code credentials from macOS Keychain for proxy injection.
set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "$0")" && pwd)/.secrets"
mkdir -p "$SECRETS_DIR"

CREDS_JSON="$(security find-generic-password \
  -s "Claude Code-credentials" -a "$(whoami)" -w 2>/dev/null)" || true

if [ -z "${CREDS_JSON:-}" ]; then
  echo "Warning: No Claude Code credentials found in Keychain." >&2
  echo "Run 'claude login' on the host first." >&2
  echo '{}' > "$SECRETS_DIR/claude.json"
else
  printf '%s' "$CREDS_JSON" > "$SECRETS_DIR/claude.json"
  echo "Credentials extracted for proxy." >&2
fi
