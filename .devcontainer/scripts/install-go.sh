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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GO_ARCH="amd64"; SHA256="$SHA256_AMD64" ;;
    aarch64) GO_ARCH="arm64";  SHA256="$SHA256_ARM64" ;;
    *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TARBALL="/tmp/go${VERSION}.linux-${GO_ARCH}.tar.gz"

"$SCRIPT_DIR/verified-download.sh" \
    "https://go.dev/dl/go${VERSION}.linux-${GO_ARCH}.tar.gz" \
    "$SHA256" \
    "$TARBALL"
tar -C /usr/local -xzf "$TARBALL"
rm -f "$TARBALL"
