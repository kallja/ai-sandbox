#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <version>" >&2
    exit 1
}

[[ $# -eq 1 ]] || usage

VERSION="$1"
GCS_BUCKET="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

MANIFEST="$(curl -fsSL "${GCS_BUCKET}/${VERSION}/manifest.json")"

SHA_AMD64="$(jq -r '.platforms["linux-x64"].checksum' <<< "$MANIFEST")"
SHA_ARM64="$(jq -r '.platforms["linux-arm64"].checksum' <<< "$MANIFEST")"

"$SCRIPT_DIR/update-dockerfile-args.sh" CLAUDE_CODE "$VERSION" "$SHA_AMD64" "$SHA_ARM64"
