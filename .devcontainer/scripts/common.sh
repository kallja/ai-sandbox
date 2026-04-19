#!/bin/bash
# Shared helpers for devcontainer scripts.
# Source this file, don't execute it.
#
# Convention: "ai-sandbox" in the main repo, "ai-sandbox-<dirname>" in worktrees.

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/../.." && pwd
}

compose_prefix() {
  local root="$1"
  if [ -f "$root/.git" ]; then
    echo "ai-sandbox-$(basename "$root")"
  else
    echo "ai-sandbox"
  fi
}
