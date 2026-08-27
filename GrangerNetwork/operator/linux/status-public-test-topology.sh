#!/usr/bin/env bash
set -euo pipefail

CONFIG_ROOT="/etc/granger-node"
[[ -r "$CONFIG_ROOT/topology-nodes" ]] || {
    printf 'Granger topology is not installed.\n' >&2
    exit 3
}
while IFS= read -r node; do
    [[ -n "$node" ]] || continue
    printf '%s: %s\n' "$node" "$(systemctl is-active "granger-node@$node.service" || true)"
    status="/run/granger-node/$node-status.json"
    [[ ! -r "$status" ]] || cat -- "$status"
done <"$CONFIG_ROOT/topology-nodes"
