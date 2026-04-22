#!/usr/bin/env bash
# Updates VERSION, SHA256_AMD64, and SHA256_ARM64 ARG lines in the Dockerfile
# for a given prefix (e.g. GO, CLAUDE_CODE).
set -euo pipefail

usage() {
    echo "Usage: $0 <arg_prefix> <version> <sha256_amd64> <sha256_arm64>" >&2
    echo "  e.g. $0 GO 1.26.2 abc123... def456..." >&2
    exit 1
}

[[ $# -eq 4 ]] || usage

PREFIX="$1"
VERSION="$2"
SHA_AMD64="$3"
SHA_ARM64="$4"
DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/Dockerfile"

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "Dockerfile not found at $DOCKERFILE" >&2
    exit 1
fi

sed -i '' \
    -e "s|^\(ARG ${PREFIX}_VERSION=\).*|\1${VERSION}|" \
    -e "s|^\(ARG ${PREFIX}_SHA256_AMD64=\).*|\1${SHA_AMD64}|" \
    -e "s|^\(ARG ${PREFIX}_SHA256_ARM64=\).*|\1${SHA_ARM64}|" \
    "$DOCKERFILE"

echo "Updated $DOCKERFILE:"
echo "  ${PREFIX}_VERSION: $VERSION"
echo "  ${PREFIX}_SHA256_AMD64: $SHA_AMD64"
echo "  ${PREFIX}_SHA256_ARM64: $SHA_ARM64"
