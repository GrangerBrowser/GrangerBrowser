#!/usr/bin/env bash
set -euo pipefail

BASE_PORT=62441
NODE_COUNT=4
while (($#)); do
    case "$1" in
        --base-port) BASE_PORT="${2:-}"; shift 2 ;;
        --nodes) NODE_COUNT="${2:-}"; shift 2 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ "$(id -u)" -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
[[ "$BASE_PORT" =~ ^[0-9]+$ && "$NODE_COUNT" =~ ^[0-9]+$ ]] \
    || { printf 'Invalid port range.\n' >&2; exit 2; }
((BASE_PORT >= 49152 && NODE_COUNT >= 1 && BASE_PORT + NODE_COUNT - 1 <= 65535)) \
    || { printf 'Invalid port range.\n' >&2; exit 2; }
command -v nft >/dev/null 2>&1 || { printf 'nftables is required.\n' >&2; exit 1; }

FIRST_PORT="$BASE_PORT"
LAST_PORT="$((BASE_PORT + NODE_COUNT - 1))"
RULE_FILE="/etc/nftables.d/granger-filter.nft"
install -d -o root -g root -m 0755 /etc/nftables.d
cat >"$RULE_FILE" <<EOF
table inet granger_filter {
    chain input {
        type filter hook input priority 10; policy drop;
        ct state invalid drop
        ct state established,related accept
        iifname "lo" accept
        tcp dport 22 accept
        tcp dport ${FIRST_PORT}-${LAST_PORT} accept
        udp sport 67 udp dport 68 accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
    }
    chain forward {
        type filter hook forward priority 10; policy drop;
    }
}
EOF
chmod 0600 "$RULE_FILE"

nft list table inet granger_filter >/dev/null 2>&1 && nft delete table inet granger_filter
nft -f "$RULE_FILE"
printf 'Applied host firewall: TCP 22 and TCP %s-%s allowed inbound.\n' "$FIRST_PORT" "$LAST_PORT"
printf 'Verify a second SSH connection before enabling persistent nftables loading.\n'
