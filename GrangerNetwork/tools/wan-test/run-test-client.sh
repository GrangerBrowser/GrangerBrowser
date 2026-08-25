#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
NETWORK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
NAME=""
STATE_DIR=""
BOOTSTRAP=""
AUTHORITY_PIN=""
MESSAGE="GRANGER_PHYSICAL_WAN_MESSAGE_123"
REPORT=""
TIMEOUT_SECONDS=8
ROUTE_ATTEMPTS=8
REPLICATION_FACTOR=3
MINIMUM_REPLICAS=2
while (($#)); do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --bootstrap) BOOTSTRAP="$2"; shift 2 ;;
    --authority-pin) AUTHORITY_PIN="$2"; shift 2 ;;
    --message) MESSAGE="$2"; shift 2 ;;
    --report) REPORT="$2"; shift 2 ;;
    --timeout) TIMEOUT_SECONDS="$2"; shift 2 ;;
    --route-attempts) ROUTE_ATTEMPTS="$2"; shift 2 ;;
    --replication-factor) REPLICATION_FACTOR="$2"; shift 2 ;;
    --minimum-replicas) MINIMUM_REPLICAS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$NAME" || -z "$STATE_DIR" || -z "$BOOTSTRAP" || -z "$AUTHORITY_PIN" ]]; then
  echo "Usage: run-test-client.sh --name NAME.granger --state-dir DIR --bootstrap FILE --authority-pin FILE" >&2
  exit 2
fi
mkdir -p "$STATE_DIR"
[[ -n "$REPORT" ]] || REPORT="$STATE_DIR/client-report.json"
export PYTHONPATH="$NETWORK_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
"$PYTHON_BIN" -m granger_network.wan_client demo "$NAME" \
  --state-dir "$STATE_DIR" --bootstrap "$BOOTSTRAP" --authority-pin "$AUTHORITY_PIN" \
  --message "$MESSAGE" --report "$REPORT" --timeout "$TIMEOUT_SECONDS" \
  --route-attempts "$ROUTE_ATTEMPTS" --replication-factor "$REPLICATION_FACTOR" \
  --minimum-replicas "$MINIMUM_REPLICAS"
cat "$REPORT"
