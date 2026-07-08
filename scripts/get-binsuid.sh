#!/usr/bin/env bash
# Backward-compatible alias — use upgrade-binsuid.sh for install and updates.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/upgrade-binsuid.sh" "$@"
