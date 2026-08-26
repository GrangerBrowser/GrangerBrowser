#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PID_FILE="$ROOT/run/granger-node.pid"
READY_FILE="$ROOT/run/ready.json"
LOG_FILE="$ROOT/logs/granger-node.log"
umask 077
mkdir -p -- "$ROOT/state" "$ROOT/private" "$ROOT/public" "$ROOT/run" "$ROOT/logs"
chmod 0700 "$ROOT/state" "$ROOT/private" "$ROOT/run" "$ROOT/logs"
chmod 0755 "$ROOT/public"

if [[ -f "$PID_FILE" ]]; then
    pid="$(tr -d '[:space:]' <"$PID_FILE")"
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null; then
        printf 'Granger node is already running as PID %s.\n' "$pid"
        exit 0
    fi
    rm -f -- "$PID_FILE"
fi

"$ROOT/install-granger-node.sh"
"$ROOT/granger-node" prepare --bootstrap --relay >/dev/null
if [[ -f "$LOG_FILE" ]] && [[ "$(stat -c '%s' "$LOG_FILE")" -ge 16777216 ]]; then
    for index in 4 3 2 1; do
        [[ ! -f "$LOG_FILE.$index" ]] || mv -f -- "$LOG_FILE.$index" "$LOG_FILE.$((index + 1))"
    done
    mv -f -- "$LOG_FILE" "$LOG_FILE.1"
fi

nohup "$ROOT/granger-node" run --bootstrap --relay >>"$LOG_FILE" 2>&1 &
launcher_pid=$!
for _attempt in $(seq 1 60); do
    if [[ -f "$READY_FILE" && -f "$PID_FILE" ]]; then
        runtime_pid="$(tr -d '[:space:]' <"$PID_FILE")"
        if [[ "$runtime_pid" == "$launcher_pid" ]] && kill -0 "$runtime_pid" 2>/dev/null; then
            printf 'Granger node started as PID %s.\n' "$runtime_pid"
            cat -- "$READY_FILE"
            exit 0
        fi
    fi
    if ! kill -0 "$launcher_pid" 2>/dev/null; then
        printf 'Granger node exited during startup.\n' >&2
        tail -n 40 -- "$LOG_FILE" >&2 || true
        exit 1
    fi
    sleep 0.5
done
printf 'Granger node did not become ready within 30 seconds.\n' >&2
exit 1
