#!/usr/bin/env bash
# Downloads a file and verifies its SHA256 checksum.
# Removes the file and exits 1 on mismatch.
set -euo pipefail

usage() {
    echo "Usage: $0 <url> <expected_sha256> <output_path>" >&2
    exit 1
}

[[ $# -eq 3 ]] || usage

URL="$1"
EXPECTED_SHA256="$2"
OUTPUT_PATH="$3"

curl -fsSL "$URL" -o "$OUTPUT_PATH"

ACTUAL_SHA256="$(sha256sum "$OUTPUT_PATH" | cut -d' ' -f1)"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    echo "SHA256 mismatch for $URL" >&2
    echo "  expected: $EXPECTED_SHA256" >&2
    echo "  actual:   $ACTUAL_SHA256" >&2
    rm -f "$OUTPUT_PATH"
    exit 1
fi
