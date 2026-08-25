#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
NETWORK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
STATE_DIR=""
LISTEN_HOST=""
LISTEN_PORT=""
DESCRIPTOR_LIFETIME=86400
MAX_CONNECTIONS=128
READY_FILE=""
CAPTURE_FILE=""
DIAGNOSTICS_FILE=""
INIT_ONLY=0
PEERS=()

while (($#)); do
  case "$1" in
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --listen-host) LISTEN_HOST="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --descriptor-lifetime) DESCRIPTOR_LIFETIME="$2"; shift 2 ;;
    --max-connections) MAX_CONNECTIONS="$2"; shift 2 ;;
    --peer-descriptor) PEERS+=("$2"); shift 2 ;;
    --ready-file) READY_FILE="$2"; shift 2 ;;
    --capture) CAPTURE_FILE="$2"; shift 2 ;;
    --diagnostics) DIAGNOSTICS_FILE="$2"; shift 2 ;;
    --init-only) INIT_ONLY=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$STATE_DIR" || -z "$LISTEN_HOST" || -z "$LISTEN_PORT" ]]; then
  echo "Usage: run-bootstrap.sh --state-dir DIR --listen-host NUMERIC_IP --listen-port PORT [--peer-descriptor FILE] [--init-only]" >&2
  exit 2
fi
export PYTHONPATH="$NETWORK_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
if [[ ! -f "$STATE_DIR/node-descriptor.json" ]]; then
  "$PYTHON_BIN" -m granger_network.node init \
    --state-dir "$STATE_DIR" --listen-host "$LISTEN_HOST" --listen-port "$LISTEN_PORT" \
    --capability bootstrap --capability discovery \
    --descriptor-lifetime "$DESCRIPTOR_LIFETIME" \
    --max-connections "$MAX_CONNECTIONS" --max-circuits 32
fi
echo "Descriptor: $STATE_DIR/node-descriptor.json"
((INIT_ONLY)) && exit 0
ARGS=(-m granger_network.node run --state-dir "$STATE_DIR")
for peer in "${PEERS[@]}"; do ARGS+=(--peer-descriptor "$peer"); done
[[ -n "$READY_FILE" ]] && ARGS+=(--ready-file "$READY_FILE")
[[ -n "$CAPTURE_FILE" ]] && ARGS+=(--capture "$CAPTURE_FILE")
[[ -n "$DIAGNOSTICS_FILE" ]] && ARGS+=(--diagnostics "$DIAGNOSTICS_FILE")
exec "$PYTHON_BIN" "${ARGS[@]}"
