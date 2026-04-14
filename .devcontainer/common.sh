#!/bin/bash
# Shared variables for devcontainer scripts.
# Source this file, don't execute it.
#
# Convention: "ai-sandbox" in the main repo, "ai-sandbox-<dirname>" in worktrees.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -f "$REPO_ROOT/.git" ]; then
  PREFIX="ai-sandbox-$(basename "$REPO_ROOT")"
else
  PREFIX="ai-sandbox"
fi

DC="docker compose -p $PREFIX -f .devcontainer/docker-compose.yml -f .devcontainer/proxy/docker-compose.yml"
