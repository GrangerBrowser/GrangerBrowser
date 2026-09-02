#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PID_FILE="$ROOT/run/granger-node.pid"
STATUS_FILE="$ROOT/run/status.json"
PYTHON_BIN="${PYTHON:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    printf 'Granger node runtime integrity: MANIFEST_INVALID (python3 unavailable)\n' >&2
    exit 78
}
integrity="$("$PYTHON_BIN" -B "$ROOT/tools/runtime_manifest.py" verify \
    --root "$ROOT" \
    --manifest "$ROOT/runtime-manifest.json" \
    --expected-protocol-version 3)" || {
    printf 'Granger node runtime integrity: %s\n' "$integrity" >&2
    exit 78
}
printf 'Granger node runtime integrity: %s\n' "$integrity"
if [[ ! -f "$PID_FILE" ]]; then
    printf 'Granger node: STOPPED\n'
    [[ ! -f "$STATUS_FILE" ]] || cat -- "$STATUS_FILE"
    exit 3
fi
pid="$(tr -d '[:space:]' <"$PID_FILE")"
if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || ! kill -0 "$pid" 2>/dev/null; then
    printf 'Granger node: STALE PID FILE\n' >&2
    exit 3
fi
cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
case "$cmdline" in
    *granger_network.operator*) ;;
    *) printf 'Granger node: PID %s belongs to another process\n' "$pid" >&2; exit 4 ;;
esac
printf 'Granger node: RUNNING (PID %s)\n' "$pid"
if [[ -f "$STATUS_FILE" ]]; then
    cat -- "$STATUS_FILE"
else
    "$ROOT/granger-node" inspect
fi
