#!/bin/bash
# Shared variables for devcontainer scripts.
# Source this file, don't execute it.
#
# Convention: "ai-sandbox" in the main repo, "ai-sandbox-<dirname>" in worktrees.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -f "$REPO_ROOT/.git" ]; then
  PREFIX="ai-sandbox-$(basename "$REPO_ROOT")"
else
  PREFIX="ai-sandbox"
fi

DC="docker compose -p $PREFIX -f $REPO_ROOT/.devcontainer/docker-compose.yml"
