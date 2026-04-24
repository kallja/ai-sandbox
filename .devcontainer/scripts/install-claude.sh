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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  CLAUDE_ARCH="x64";  SHA256="$SHA256_AMD64" ;;
    aarch64) CLAUDE_ARCH="arm64"; SHA256="$SHA256_ARM64" ;;
    *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

INSTALL_DIR="/opt/claude"
mkdir -p "$INSTALL_DIR"

"$SCRIPT_DIR/verified-download.sh" \
    "${GCS_BUCKET}/${VERSION}/linux-${CLAUDE_ARCH}/claude" \
    "$SHA256" \
    "${INSTALL_DIR}/claude"
chmod +x "${INSTALL_DIR}/claude"
ln -sf "${INSTALL_DIR}/claude" /usr/local/bin/claude
