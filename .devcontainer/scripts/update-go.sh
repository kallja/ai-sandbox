#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <version>" >&2
    echo "  e.g. $0 1.26.2" >&2
    exit 1
}

[[ $# -eq 1 ]] || usage

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RELEASES="$(curl -fsSL "https://go.dev/dl/?mode=json")"
GO_VERSION_FILTER="go${VERSION}"

sha_for_arch() {
    jq -re --arg v "$GO_VERSION_FILTER" --arg arch "$1" \
        '.[] | select(.version == $v) | .files[] | select(.os == "linux" and .arch == $arch and .kind == "archive") | .sha256' \
        <<< "$RELEASES"
}

SHA_AMD64="$(sha_for_arch "amd64")"
SHA_ARM64="$(sha_for_arch "arm64")"

"$SCRIPT_DIR/update-dockerfile-args.sh" GO "$VERSION" "$SHA_AMD64" "$SHA_ARM64"
