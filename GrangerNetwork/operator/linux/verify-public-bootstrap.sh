#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
"$ROOT/install-granger-node.sh"
PYTHONPATH="$ROOT/runtime/src" PYTHONNOUSERSITE=1 \
    "$ROOT/runtime/venv/bin/python3" -B "$ROOT/tools/operator_bundle.py" verify \
    --public-root "$ROOT/public"
