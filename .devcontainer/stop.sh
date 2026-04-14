#!/bin/bash
# Tears down all services. Kill first for speed, then down to clean up.
set -euo pipefail

source "$(dirname "$0")/scripts/common.sh"

echo "Stopping all services..." >&2
$DC kill
$DC down
