#!/usr/bin/env bash
set -euo pipefail

OUTPUT_BASE=""
DURATION=180
INTERFACE="any"
while (($#)); do
  case "$1" in
    --output-base) OUTPUT_BASE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --interface) INTERFACE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$OUTPUT_BASE" ]]; then
  echo "Usage: capture-network.sh --output-base PATH [--duration SECONDS] [--interface NAME]" >&2
  exit 2
fi
command -v tcpdump >/dev/null || { echo "tcpdump is required" >&2; exit 1; }
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then SUDO=(); else SUDO=(sudo); fi
mkdir -p "$(dirname -- "$OUTPUT_BASE")"
PCAP="$OUTPUT_BASE.pcap"
set +e
timeout --signal=INT "$DURATION" "${SUDO[@]}" tcpdump -i "$INTERFACE" -s 0 -U -w "$PCAP"
STATUS=$?
set -e
if [[ $STATUS -ne 0 && $STATUS -ne 124 && $STATUS -ne 130 ]]; then
  echo "tcpdump failed with exit code $STATUS" >&2
  exit "$STATUS"
fi
test -s "$PCAP" || { echo "capture is empty: $PCAP" >&2; exit 1; }
sha256sum "$PCAP"
