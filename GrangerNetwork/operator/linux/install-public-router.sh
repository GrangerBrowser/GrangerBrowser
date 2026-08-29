#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL_ROOT="/opt/granger-node"
CONFIG_ROOT="/etc/granger-node"
STATE_ROOT="/var/lib/granger-node"
LOG_ROOT="/var/log/granger-node"
PUBLIC_IP=""
PORT=62441
NODE_NAME="router"
PUBLIC_BUNDLE_SOURCE=""

fail() {
    printf 'Granger public router install failed: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --public-ip) PUBLIC_IP="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; shift 2 ;;
        --node-name) NODE_NAME="${2:-}"; shift 2 ;;
        --public-bootstrap) PUBLIC_BUNDLE_SOURCE="${2:-}"; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || fail "run this installer as root"
[[ -n "$PUBLIC_IP" ]] || fail "--public-ip is required"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 49152 && "$PORT" -le 65535 ]] \
    || fail "--port must be a high TCP port between 49152 and 65535"
[[ "$NODE_NAME" =~ ^[a-z][a-z0-9-]{0,31}$ ]] \
    || fail "--node-name must match ^[a-z][a-z0-9-]{0,31}$"

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
    if systemctl list-unit-files "granger-node@$NODE_NAME.service" --no-legend \
        2>/dev/null | grep -q '^granger-node@'; then
        systemctl stop "granger-node@$NODE_NAME.service"
    fi
    find "$INSTALL_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    cp -a -- "$SOURCE_ROOT/." "$INSTALL_ROOT/"
fi
find "$INSTALL_ROOT" -xdev -exec chown root:root {} +
chmod 0755 "$INSTALL_ROOT/granger-node" "$INSTALL_ROOT"/*.sh
"$INSTALL_ROOT/install-granger-node.sh"

install -d -o root -g granger -m 0750 "$CONFIG_ROOT"
install -d -o granger -g granger -m 0700 "$STATE_ROOT" "$STATE_ROOT/$NODE_NAME" "$LOG_ROOT"
install -d -o granger -g granger -m 0755 "$STATE_ROOT/public" "$STATE_ROOT/public/$NODE_NAME"

BOOTSTRAP_ROOT="$CONFIG_ROOT/public-bootstrap"
if [[ -n "$PUBLIC_BUNDLE_SOURCE" ]]; then
    PUBLIC_BUNDLE_SOURCE="$(readlink -f -- "$PUBLIC_BUNDLE_SOURCE")"
    [[ -d "$PUBLIC_BUNDLE_SOURCE" ]] || fail "public bootstrap directory does not exist"
    required_files=(
        bootstrap-set.json
        bootstrap-authority.pin
        browser-wan.json
        config-authority.pin
    )
    for file in "${required_files[@]}"; do
        [[ -f "$PUBLIC_BUNDLE_SOURCE/$file" && ! -L "$PUBLIC_BUNDLE_SOURCE/$file" ]] \
            || fail "public bootstrap file is missing or unsafe: $file"
    done
    if grep -l '"privateKey"' "$PUBLIC_BUNDLE_SOURCE"/*.json >/dev/null 2>&1; then
        fail "public bootstrap contains private key material"
    fi
    staging="$CONFIG_ROOT/.public-bootstrap.$$"
    trap 'rm -rf -- "${staging:-}"' EXIT
    install -d -o root -g granger -m 0750 "$staging"
    for file in "${required_files[@]}"; do
        install -o root -g granger -m 0640 "$PUBLIC_BUNDLE_SOURCE/$file" "$staging/$file"
    done
    if [[ -f "$PUBLIC_BUNDLE_SOURCE/bootstrap-manifest.json" && \
          ! -L "$PUBLIC_BUNDLE_SOURCE/bootstrap-manifest.json" ]]; then
        install -o root -g granger -m 0640 \
            "$PUBLIC_BUNDLE_SOURCE/bootstrap-manifest.json" \
            "$staging/bootstrap-manifest.json"
    fi
    runuser -u granger -- env \
        PYTHONPATH="$INSTALL_ROOT/runtime/src" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
        "$INSTALL_ROOT/runtime/venv/bin/python3" -B \
        "$INSTALL_ROOT/tools/operator_bundle.py" verify --public-root "$staging" >/dev/null \
        || fail "public bootstrap signature or metadata validation failed"
    if [[ -d "$BOOTSTRAP_ROOT" ]]; then
        mv -- "$BOOTSTRAP_ROOT" "$CONFIG_ROOT/public-bootstrap.backup.$(date +%s)"
    fi
    mv -- "$staging" "$BOOTSTRAP_ROOT"
    trap - EXIT
fi

WITH_BOOTSTRAP=no
if [[ -f "$BOOTSTRAP_ROOT/bootstrap-set.json" && \
      -f "$BOOTSTRAP_ROOT/bootstrap-authority.pin" ]]; then
    WITH_BOOTSTRAP=yes
fi

python3 - "$PUBLIC_IP" "$PORT" "$CONFIG_ROOT/$NODE_NAME.json" \
    "$BOOTSTRAP_ROOT" "$WITH_BOOTSTRAP" <<'PY'
import json
import pathlib
import sys

public_ip, port, config_path, bootstrap_root, with_bootstrap = sys.argv[1:]
bootstrap = {"authorityPins": [], "bundles": []}
if with_bootstrap == "yes":
    root = pathlib.Path(bootstrap_root)
    bootstrap = {
        "authorityPins": [str(root / "bootstrap-authority.pin")],
        "bundles": [str(root / "bootstrap-set.json")],
    }
document = {
    "advertise": {"host": public_ip, "port": int(port)},
    "bootstrap": bootstrap,
    "capabilities": [
        "access", "bootstrap", "discovery", "entry", "introduction",
        "middle", "rendezvous", "service-relay",
    ],
    "descriptorLifetimeSeconds": 86400,
    "discoveryIntervalSeconds": 60,
    "listen": {"host": "0.0.0.0", "port": int(port)},
    "peerDescriptors": [],
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
path = pathlib.Path(config_path)
path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chown root:granger "$CONFIG_ROOT/$NODE_NAME.json"
chmod 0640 "$CONFIG_ROOT/$NODE_NAME.json"

runuser -u granger -- env \
    PYTHONPATH="$INSTALL_ROOT/runtime/src" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    "$INSTALL_ROOT/runtime/venv/bin/python3" -B -m granger_network.operator prepare \
    --config "$CONFIG_ROOT/$NODE_NAME.json" \
    --state-dir "$STATE_ROOT/$NODE_NAME" \
    --public-dir "$STATE_ROOT/public/$NODE_NAME" >/dev/null

install -o root -g root -m 0644 \
    "$INSTALL_ROOT/systemd/granger-node@.service" \
    /etc/systemd/system/granger-node@.service
systemctl daemon-reload
systemctl enable "granger-node@$NODE_NAME.service" >/dev/null
systemctl restart "granger-node@$NODE_NAME.service"
for _attempt in $(seq 1 40); do
    [[ -s "/run/granger-node/$NODE_NAME/ready.json" ]] && break
    systemctl is-active --quiet "granger-node@$NODE_NAME.service" \
        || fail "$NODE_NAME did not remain active"
    sleep 0.25
done
[[ -s "/run/granger-node/$NODE_NAME/ready.json" ]] \
    || fail "$NODE_NAME did not become ready"

printf 'Distributed public router installed.\n'
printf 'Node: %s\nPublic TCP endpoint: %s:%s\n' "$NODE_NAME" "$PUBLIC_IP" "$PORT"
printf 'Bootstrap configured: %s\n' "$WITH_BOOTSTRAP"
printf 'Public descriptor: %s\n' "$STATE_ROOT/public/$NODE_NAME/node-descriptor.json"
runuser -u granger -- env \
    PYTHONPATH="$INSTALL_ROOT/runtime/src" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    "$INSTALL_ROOT/runtime/venv/bin/python3" -B -m granger_network.operator inspect \
    --state-dir "$STATE_ROOT/$NODE_NAME"
