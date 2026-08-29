#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL_ROOT="/opt/granger-node"
CONFIG_ROOT="/etc/granger-node"
STATE_ROOT="/var/lib/granger-node"
LOG_ROOT="/var/log/granger-node"
PUBLIC_IP=""
BASE_PORT=62441
NODE_COUNT=4
GENERATION=1
BUNDLE_LIFETIME=43200

fail() {
    printf 'Granger topology install failed: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --public-ip) PUBLIC_IP="${2:-}"; shift 2 ;;
        --base-port) BASE_PORT="${2:-}"; shift 2 ;;
        --nodes) NODE_COUNT="${2:-}"; shift 2 ;;
        --generation) GENERATION="${2:-}"; shift 2 ;;
        --bundle-lifetime) BUNDLE_LIFETIME="${2:-}"; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || fail "run this installer as root"
[[ -n "$PUBLIC_IP" ]] || fail "--public-ip is required"
[[ "$BASE_PORT" =~ ^[0-9]+$ ]] || fail "base port is invalid"
[[ "$NODE_COUNT" =~ ^[0-9]+$ && "$NODE_COUNT" -ge 4 && "$NODE_COUNT" -le 8 ]] \
    || fail "--nodes must be between 4 and 8"
[[ "$GENERATION" =~ ^[1-9][0-9]*$ ]] || fail "generation is invalid"
[[ "$BUNDLE_LIFETIME" =~ ^[0-9]+$ && "$BUNDLE_LIFETIME" -ge 600 && "$BUNDLE_LIFETIME" -le 64800 ]] \
    || fail "bundle lifetime must be between 600 and 64800 seconds"
((BASE_PORT >= 49152 && BASE_PORT + NODE_COUNT - 1 <= 65535)) \
    || fail "the topology must use an available high TCP port range"

python3 - "$PUBLIC_IP" <<'PY' || fail "--public-ip must be a globally routable IPv4 address"
import ipaddress
import sys
address = ipaddress.ip_address(sys.argv[1])
assert address.version == 4 and address.is_global
PY
command -v runuser >/dev/null 2>&1 || fail "runuser is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

if ! getent group granger >/dev/null 2>&1; then
    groupadd --system granger
fi
if ! id -u granger >/dev/null 2>&1; then
    useradd --system --gid granger --home-dir "$STATE_ROOT" --no-create-home \
        --shell /usr/sbin/nologin granger
fi

install -d -o root -g root -m 0755 "$INSTALL_ROOT"
if [[ "$SOURCE_ROOT" != "$INSTALL_ROOT" ]]; then
    find "$INSTALL_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    cp -a -- "$SOURCE_ROOT/." "$INSTALL_ROOT/"
fi
find "$INSTALL_ROOT" -xdev -exec chown root:root {} +
chmod 0755 "$INSTALL_ROOT/granger-node" "$INSTALL_ROOT"/*.sh
"$INSTALL_ROOT/install-granger-node.sh"

install -d -o root -g granger -m 0750 "$CONFIG_ROOT"
install -d -o granger -g granger -m 0700 "$STATE_ROOT" "$LOG_ROOT"
install -d -o granger -g granger -m 0755 "$STATE_ROOT/public"
install -d -o granger -g granger -m 0700 "$STATE_ROOT/private/authorities"
install -d -o granger -g granger -m 0755 "$STATE_ROOT/public-bundle"

NODE_NAMES=()
for ((index = 0; index < NODE_COUNT; index++)); do
    printf -v suffix "\\$(printf '%03o' $((97 + index)))"
    node="node-$(printf '%b' "$suffix")"
    NODE_NAMES+=("$node")
    install -d -o granger -g granger -m 0700 "$STATE_ROOT/$node"
    install -d -o granger -g granger -m 0755 "$STATE_ROOT/public/$node"
done
printf '%s\n' "${NODE_NAMES[@]}" >"$CONFIG_ROOT/topology-nodes"
chown root:granger "$CONFIG_ROOT/topology-nodes"
chmod 0640 "$CONFIG_ROOT/topology-nodes"

write_configs() {
    local with_bootstrap="$1"
    python3 - "$PUBLIC_IP" "$BASE_PORT" "$NODE_COUNT" "$CONFIG_ROOT" "$STATE_ROOT" "$with_bootstrap" <<'PY'
import json
import pathlib
import sys

public_ip, base_port, count, config_root, state_root, with_bootstrap = sys.argv[1:]
base_port = int(base_port)
count = int(count)
config_root = pathlib.Path(config_root)
state_root = pathlib.Path(state_root)
names = [f"node-{chr(97 + index)}" for index in range(count)]
for index, name in enumerate(names):
    peers = []
    bootstrap = {"authorityPins": [], "bundles": []}
    if with_bootstrap == "yes":
        peers = [
            str(state_root / "public" / peer / "node-descriptor.json")
            for peer in names if peer != name
        ]
        bootstrap = {
            "authorityPins": [str(state_root / "public-bundle" / "bootstrap-authority.pin")],
            "bundles": [str(state_root / "public-bundle" / "bootstrap-set.json")],
        }
    document = {
        "advertise": {"host": public_ip, "port": base_port + index},
        "bootstrap": bootstrap,
        "capabilities": [
            "access", "bootstrap", "discovery", "entry", "introduction",
            "middle", "rendezvous", "service-relay",
        ],
        "descriptorLifetimeSeconds": 86400,
        "discoveryIntervalSeconds": 60,
        "listen": {"host": "0.0.0.0", "port": base_port + index},
        "peerDescriptors": peers,
        "relayPolicy": {
            "burstKiB": 4096,
            "connectionTimeoutSeconds": 10,
            "enabled": True,
            "idleTimeoutSeconds": 120,
            "maxBandwidthKiBPerSecond": 2048,
            "maxBytesPerCircuit": 67108864,
            "maxCircuits": 48,
            "maxConnections": 96,
            "maxStreams": 128,
            "memoryBudgetKiB": 131072,
        },
        "renewBeforeSeconds": 21600,
        "version": 1,
    }
    path = config_root / f"{name}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    chown root:granger "$CONFIG_ROOT"/node-*.json
    chmod 0640 "$CONFIG_ROOT"/node-*.json
}

write_configs no
for node in "${NODE_NAMES[@]}"; do
    runuser -u granger -- env \
        PYTHONPATH="$INSTALL_ROOT/runtime/src" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
        "$INSTALL_ROOT/runtime/venv/bin/python3" -B -m granger_network.operator prepare \
        --config "$CONFIG_ROOT/$node.json" \
        --state-dir "$STATE_ROOT/$node" \
        --public-dir "$STATE_ROOT/public/$node" >/dev/null
done

BUNDLE_ARGS=(
    "$INSTALL_ROOT/runtime/venv/bin/python3" -B "$INSTALL_ROOT/tools/operator_bundle.py" create
    --private-root "$STATE_ROOT/private/authorities"
    --public-root "$STATE_ROOT/public-bundle"
    --generation "$GENERATION"
    --lifetime "$BUNDLE_LIFETIME"
)
for node in "${NODE_NAMES[@]}"; do
    BUNDLE_ARGS+=(--descriptor "$STATE_ROOT/public/$node/node-descriptor.json")
done
runuser -u granger -- env \
    PYTHONPATH="$INSTALL_ROOT/runtime/src" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    "${BUNDLE_ARGS[@]}" >/dev/null
write_configs yes

install -o root -g root -m 0644 \
    "$INSTALL_ROOT/systemd/granger-node@.service" \
    /etc/systemd/system/granger-node@.service
systemctl daemon-reload
for node in "${NODE_NAMES[@]}"; do
    systemctl enable "granger-node@$node.service" >/dev/null
    systemctl restart "granger-node@$node.service"
done
for node in "${NODE_NAMES[@]}"; do
    for _attempt in $(seq 1 40); do
        [[ -s "/run/granger-node/$node/ready.json" ]] && break
        systemctl is-active --quiet "granger-node@$node.service" \
            || fail "$node did not remain active"
        sleep 0.25
    done
    [[ -s "/run/granger-node/$node/ready.json" ]] || fail "$node did not become ready"
done

printf 'SINGLE-PHYSICAL-HOST TEST TOPOLOGY installed.\n'
printf 'Physical hosts: 1\nLogical routers: %s\n' "$NODE_COUNT"
printf 'Public TCP ports: %s-%s\n' "$BASE_PORT" "$((BASE_PORT + NODE_COUNT - 1))"
printf 'Public bootstrap bundle: %s\n' "$STATE_ROOT/public-bundle"
for node in "${NODE_NAMES[@]}"; do
    runuser -u granger -- env PYTHONPATH="$INSTALL_ROOT/runtime/src" PYTHONNOUSERSITE=1 \
        "$INSTALL_ROOT/runtime/venv/bin/python3" -B -m granger_network.operator inspect \
        --state-dir "$STATE_ROOT/$node"
done
