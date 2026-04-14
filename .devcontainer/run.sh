#!/bin/bash
# Run Claude Code CLI in the devcontainer.
# Runs on the HOST (macOS). Starts services if needed.
#
# Usage:
#   .devcontainer/run-claude.sh [claude args...]
set -euo pipefail

source "$(dirname "$0")/scripts/common.sh"
COMPOSE_PROJECT_NAME="$PREFIX" devcontainer up --workspace-folder "$REPO_ROOT"
"$(dirname "$0")/scripts/inject-credentials.sh"

devcontainer exec --workspace-folder "$REPO_ROOT" "${@:-}"
