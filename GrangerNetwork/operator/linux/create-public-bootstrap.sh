#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
GENERATION=""
LIFETIME=21600
PEERS=()
while (($#)); do
    case "$1" in
        --generation) GENERATION="$2"; shift 2 ;;
        --lifetime) LIFETIME="$2"; shift 2 ;;
        --peer-descriptor) PEERS+=("$2"); shift 2 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
if [[ ! "$GENERATION" =~ ^[1-9][0-9]*$ || ${#PEERS[@]} -lt 1 ]]; then
    printf 'Usage: %s --generation N --peer-descriptor SECOND-SEED.json [--peer-descriptor MORE.json]\n' "$0" >&2
    printf 'A valid BootstrapSet requires this node plus at least one independent reachable seed.\n' >&2
    exit 2
fi
[[ -f "$ROOT/public/node-descriptor.json" ]] \
    || { printf 'Start or prepare this node before creating a public bundle.\n' >&2; exit 2; }
"$ROOT/install-granger-node.sh"
mkdir -p -- "$ROOT/private/authorities" "$ROOT/public"
chmod 0700 "$ROOT/private" "$ROOT/private/authorities"
ARGS=(
    "$ROOT/runtime/venv/bin/python3" -B "$ROOT/tools/operator_bundle.py" create
    --private-root "$ROOT/private/authorities"
    --public-root "$ROOT/public"
    --descriptor "$ROOT/public/node-descriptor.json"
    --generation "$GENERATION"
    --lifetime "$LIFETIME"
)
for descriptor in "${PEERS[@]}"; do ARGS+=(--descriptor "$descriptor"); done
PYTHONPATH="$ROOT/runtime/src" PYTHONNOUSERSITE=1 "${ARGS[@]}"
printf 'Public bundle created in %s. Private authority state remains under private/.\n' "$ROOT/public"
