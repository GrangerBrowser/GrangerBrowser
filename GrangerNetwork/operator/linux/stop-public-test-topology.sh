#!/usr/bin/env bash
set -euo pipefail

CONFIG_ROOT="/etc/granger-node"
[[ "$(id -u)" -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
[[ -r "$CONFIG_ROOT/topology-nodes" ]] || exit 0
while IFS= read -r node; do
    [[ -n "$node" ]] || continue
    systemctl stop "granger-node@$node.service"
done <"$CONFIG_ROOT/topology-nodes"
printf 'Granger public test topology stopped.\n'
