#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PID_FILE="$ROOT/run/granger-node.pid"
if [[ ! -f "$PID_FILE" ]]; then
    printf 'Granger node is not running.\n'
    exit 0
fi
pid="$(tr -d '[:space:]' <"$PID_FILE")"
if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Invalid Granger node PID file.\n' >&2
    exit 1
fi
if ! kill -0 "$pid" 2>/dev/null; then
    rm -f -- "$PID_FILE" "$ROOT/run/ready.json"
    printf 'Removed stale Granger node PID file.\n'
    exit 0
fi
cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
case "$cmdline" in
    *granger_network.operator*) ;;
    *) printf 'PID %s is not the Granger node; refusing to signal it.\n' "$pid" >&2; exit 1 ;;
esac
kill -TERM "$pid"
for _attempt in $(seq 1 40); do
    if ! kill -0 "$pid" 2>/dev/null; then
        printf 'Granger node stopped cleanly.\n'
        exit 0
    fi
    sleep 0.5
done
printf 'Granger node did not stop within 20 seconds; no forced kill was sent.\n' >&2
exit 1
