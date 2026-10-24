#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command -v node >/dev/null 2>&1 || { printf '%s\n' 'Install Node24.19+ from https://nodejs.org/download/release/ before running the wizard.' >&2; exit 1; }
exec node "$SCRIPT_DIR/wizard.mjs" "$@"
