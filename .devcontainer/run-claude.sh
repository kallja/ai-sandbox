#!/bin/bash
# Run Claude Code CLI in the devcontainer.
# Runs on the HOST (macOS). Starts services if needed.
#
# Usage:
#   .devcontainer/run-claude.sh [claude args...]
set -euo pipefail

"$(dirname "$0")/run.sh" claude
