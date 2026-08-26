#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
RUNTIME="$ROOT/runtime"
VENV="$RUNTIME/venv"
PYTHON_BIN="${PYTHON:-python3}"

fail() {
    printf 'Granger node install failed: %s\n' "$*" >&2
    exit 1
}

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] \
    || fail "this package targets Linux x86_64"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "python3 is required"
"$PYTHON_BIN" - <<'PY' || fail "CPython 3.11 through 3.14 is required"
import platform
import sys
assert platform.python_implementation() == "CPython"
assert (3, 11) <= sys.version_info[:2] <= (3, 14)
PY
"$PYTHON_BIN" -m venv --help >/dev/null 2>&1 \
    || fail "python3-venv is required"

if [[ -x "$VENV/bin/python3" ]]; then
    PYTHONPATH="$RUNTIME/src" PYTHONNOUSERSITE=1 "$VENV/bin/python3" -B - <<'PY' \
        && exit 0
import cryptography
import granger_network
assert cryptography.__version__ == "49.0.0"
PY
fi

TEMP_VENV="$RUNTIME/.venv-$$"
case "$TEMP_VENV" in "$RUNTIME"/*) ;; *) fail "temporary venv escaped runtime root" ;; esac
cleanup() {
    [[ ! -e "$TEMP_VENV" ]] || rm -rf -- "$TEMP_VENV"
}
trap cleanup EXIT
"$PYTHON_BIN" -m venv "$TEMP_VENV"
"$TEMP_VENV/bin/python3" -m pip install \
    --disable-pip-version-check \
    --no-index \
    --find-links "$RUNTIME/wheels" \
    --require-hashes \
    -r "$RUNTIME/requirements-linux-x86_64.lock"
PYTHONPATH="$RUNTIME/src" PYTHONNOUSERSITE=1 "$TEMP_VENV/bin/python3" -B - <<'PY'
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from granger_network.peer import NODE_PROTOCOL_VERSION
from granger_network.protocol import VERSION_3

key = Ed25519PrivateKey.generate()
message = b"granger-node-offline-runtime"
key.public_key().verify(key.sign(message), message)
assert cryptography.__version__ == "49.0.0"
assert NODE_PROTOCOL_VERSION == VERSION_3 == 3
PY
[[ ! -e "$VENV" ]] || rm -rf -- "$VENV"
mv -- "$TEMP_VENV" "$VENV"
trap - EXIT
printf 'Granger node runtime installed from package-local wheels.\n'
