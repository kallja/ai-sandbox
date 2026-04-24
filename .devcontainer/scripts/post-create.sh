#!/bin/bash
# postCreateCommand — runs inside the container after creation.
# Replaces the __WORKSPACE_ROOT__ placeholder in .claude.json with the
# actual workspace path so the repo-trust dialog is pre-accepted.
set -euo pipefail

echo "Post-create command running ${PWD}"

sed -i "s|__WORKSPACE_ROOT__|$PWD|" /home/claude/.claude.json
