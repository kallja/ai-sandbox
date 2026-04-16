#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <version>" >&2
    exit 1
}

[[ $# -eq 1 ]] || usage

VERSION="$1"
GCS_BUCKET="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases"
DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/Dockerfile"

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "Dockerfile not found at $DOCKERFILE" >&2
    exit 1
fi

MANIFEST="$(curl -fsSL "${GCS_BUCKET}/${VERSION}/manifest.json")"

sha_for_platform() {
    python3 -c "
import json, sys
m = json.loads(sys.stdin.read())
print(m['platforms']['$1']['checksum'])
" <<< "$MANIFEST"
}

SHA_AMD64="$(sha_for_platform "linux-x64")"
SHA_ARM64="$(sha_for_platform "linux-arm64")"

sed -i '' \
    -e "s|^\(ARG CLAUDE_CODE_VERSION=\).*|\1${VERSION}|" \
    -e "s|^\(ARG CLAUDE_CODE_SHA256_AMD64=\).*|\1${SHA_AMD64}|" \
    -e "s|^\(ARG CLAUDE_CODE_SHA256_ARM64=\).*|\1${SHA_ARM64}|" \
    "$DOCKERFILE"

echo "Updated $DOCKERFILE:"
echo "  VERSION: $VERSION"
echo "  SHA256_AMD64: $SHA_AMD64"
echo "  SHA256_ARM64: $SHA_ARM64"
