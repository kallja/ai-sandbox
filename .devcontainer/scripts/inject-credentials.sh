#!/bin/bash
# Reads Claude Code credentials from macOS Keychain and pipes them
# directly into the running proxy container. Never touches disk.
set -euo pipefail

source "$(dirname "$0")/common.sh"

CREDS_JSON="$(security find-generic-password -s "Claude Code-credentials" -a "$(whoami)" -w 2>/dev/null)" || true

if [ -z "${CREDS_JSON:-}" ]; then
  echo "Warning: No Claude Code credentials found in Keychain." >&2
  echo "Run 'claude login' on the host first." >&2
  exit 1
fi

printf '%s' "$CREDS_JSON" | $DC exec -T proxy \
  bash -c 'mkdir -p ~/.config/proxy/secrets && cat > ~/.config/proxy/secrets/claude.json'

echo "Credentials injected into proxy." >&2
