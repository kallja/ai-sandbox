#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <version> <sha256_amd64> <sha256_arm64>" >&2
    exit 1
}

[[ $# -eq 3 ]] || usage

VERSION="$1"
SHA256_AMD64="$2"
SHA256_ARM64="$3"
GCS_BUCKET="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  CLAUDE_ARCH="x64";  SHA256="$SHA256_AMD64" ;;
    aarch64) CLAUDE_ARCH="arm64"; SHA256="$SHA256_ARM64" ;;
    *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

curl -fsSL "${GCS_BUCKET}/${VERSION}/linux-${CLAUDE_ARCH}/claude" -o "${BIN_DIR}/claude"
ACTUAL_SHA256="$(sha256sum "${BIN_DIR}/claude" | cut -d' ' -f1)"
if [[ "$ACTUAL_SHA256" != "$SHA256" ]]; then
    echo "SHA256 mismatch for claude ${VERSION} (linux-${CLAUDE_ARCH})" >&2
    echo "  expected: ${SHA256}" >&2
    echo "  actual:   ${ACTUAL_SHA256}" >&2
    rm -f "${BIN_DIR}/claude"
    exit 1
fi
chmod +x "${BIN_DIR}/claude"
