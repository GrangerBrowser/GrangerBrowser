#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
NETWORK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
STATE_DIR=""
BOOTSTRAP=""
AUTHORITY_PIN=""
TITLE="Granger physical WAN test"
READY_FILE=""
TIMEOUT_SECONDS=8
REPLICATION_FACTOR=3
MINIMUM_REPLICAS=2
while (($#)); do
  case "$1" in
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --bootstrap) BOOTSTRAP="$2"; shift 2 ;;
    --authority-pin) AUTHORITY_PIN="$2"; shift 2 ;;
    --title) TITLE="$2"; shift 2 ;;
    --ready-file) READY_FILE="$2"; shift 2 ;;
    --timeout) TIMEOUT_SECONDS="$2"; shift 2 ;;
    --replication-factor) REPLICATION_FACTOR="$2"; shift 2 ;;
    --minimum-replicas) MINIMUM_REPLICAS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$STATE_DIR" || -z "$BOOTSTRAP" || -z "$AUTHORITY_PIN" ]]; then
  echo "Usage: run-test-host.sh --state-dir DIR --bootstrap FILE --authority-pin FILE" >&2
  exit 2
fi
mkdir -p "$STATE_DIR"
[[ -n "$READY_FILE" ]] || READY_FILE="$STATE_DIR/host-ready.json"
FIXTURE_READY="$STATE_DIR/forum-ready.json"
export PYTHONPATH="$NETWORK_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
if [[ ! -f "$STATE_DIR/service-identity.json" ]]; then
  "$PYTHON_BIN" -m granger_network.wan_host init --state-dir "$STATE_DIR" --title "$TITLE"
fi
"$PYTHON_BIN" "$NETWORK_ROOT/tools/wan_forum_fixture.py" --ready-file "$FIXTURE_READY" &
FIXTURE_PID=$!
trap 'kill "$FIXTURE_PID" 2>/dev/null || true; wait "$FIXTURE_PID" 2>/dev/null || true' EXIT INT TERM
for _ in $(seq 1 200); do
  [[ -f "$FIXTURE_READY" ]] && break
  kill -0 "$FIXTURE_PID" 2>/dev/null || { echo "Loopback forum fixture exited" >&2; exit 1; }
  sleep 0.1
done
[[ -f "$FIXTURE_READY" ]] || { echo "Loopback forum fixture timed out" >&2; exit 1; }
UPSTREAM="127.0.0.1:$($PYTHON_BIN -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["port"])' "$FIXTURE_READY")"
"$PYTHON_BIN" -m granger_network.wan_host serve \
  --state-dir "$STATE_DIR" --bootstrap "$BOOTSTRAP" --authority-pin "$AUTHORITY_PIN" \
  --upstream "$UPSTREAM" --ready-file "$READY_FILE" --timeout "$TIMEOUT_SECONDS" \
  --introduction-points 2 --minimum-introduction-points 2 \
  --replication-factor "$REPLICATION_FACTOR" --minimum-replicas "$MINIMUM_REPLICAS" \
  --startup-attempts 8
