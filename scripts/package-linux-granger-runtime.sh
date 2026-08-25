#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appdir="${1:-}"

fail() {
    printf 'Linux Granger Network runtime packaging failed: %s\n' "$*" >&2
    exit 1
}

[[ -n "$appdir" ]] || fail "AppDir argument is required"
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] \
    || fail "only native Linux x86_64 packaging is supported"
for command_name in python3 jq ldd readelf; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command is unavailable: $command_name"
done

appdir="$(realpath -m "$appdir")"
runtime_root="$appdir/usr/bin/runtime/python"
case "$runtime_root" in
    "$appdir"/*) ;;
    *) fail "runtime path escaped AppDir" ;;
esac

probe="$({ python3 - <<'PY'
import json
import pathlib
import platform
import struct
import sys
import sysconfig
import cryptography
import cffi
import pycparser
import _cffi_backend

site = pathlib.Path(cryptography.__file__).resolve().parent.parent

def dist_info(name):
    matches = list(site.glob(f"{name}-*.dist-info"))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {name} dist-info directory")
    return matches[0]

print(json.dumps({
    "backend": str(pathlib.Path(_cffi_backend.__file__).resolve()),
    "bits": struct.calcsize("P") * 8,
    "cffi": str(pathlib.Path(cffi.__file__).resolve().parent),
    "cffiDist": str(dist_info("cffi")),
    "cffiVersion": cffi.__version__,
    "cryptography": str(pathlib.Path(cryptography.__file__).resolve().parent),
    "cryptographyDist": str(dist_info("cryptography")),
    "cryptographyVersion": cryptography.__version__,
    "executable": str(pathlib.Path(sys.executable).resolve()),
    "implementation": platform.python_implementation(),
    "pycparser": str(pathlib.Path(pycparser.__file__).resolve().parent),
    "pycparserDist": str(dist_info("pycparser")),
    "pycparserVersion": pycparser.__version__,
    "stdlib": sysconfig.get_path("stdlib"),
    "version": platform.python_version(),
    "versionDir": f"python{sys.version_info.major}.{sys.version_info.minor}",
}))
PY
} 2>&1)" || fail "$probe"

[[ "$(jq -r '.implementation' <<<"$probe")" == "CPython" ]] \
    || fail "CPython is required"
[[ "$(jq -r '.bits' <<<"$probe")" == "64" ]] || fail "x64 Python is required"
python3 - <<PY || fail "Python or cryptography version is unsupported"
import re
import sys
assert sys.version_info >= (3, 11)
version = $(jq -r '.cryptographyVersion|@json' <<<"$probe")
match = re.match(r"^(\d+)", version)
assert match and int(match.group(1)) >= 47
PY

python_source="$(jq -r '.executable' <<<"$probe")"
stdlib_source="$(jq -r '.stdlib' <<<"$probe")"
version_dir="$(jq -r '.versionDir' <<<"$probe")"
site_packages="$runtime_root/lib/$version_dir/site-packages"
rm -rf -- "$runtime_root"
mkdir -p "$runtime_root/bin" "$runtime_root/lib/$version_dir" "$site_packages"
cp -L -- "$python_source" "$runtime_root/bin/python3"
cp -a -- "$stdlib_source/." "$runtime_root/lib/$version_dir/"
rm -rf -- "$runtime_root/lib/$version_dir/site-packages" \
    "$runtime_root/lib/$version_dir/test" \
    "$runtime_root/lib/$version_dir/idlelib" \
    "$runtime_root/lib/$version_dir/tkinter" \
    "$runtime_root/lib/$version_dir/turtledemo" \
    "$runtime_root/lib/$version_dir/ensurepip" \
    "$runtime_root/lib/$version_dir/venv"
mkdir -p "$site_packages"

for key in cryptography cryptographyDist cffi cffiDist pycparser pycparserDist backend; do
    source_path="$(jq -r ".${key}" <<<"$probe")"
    [[ -e "$source_path" ]] || fail "Python runtime dependency is missing: $source_path"
    cp -aL -- "$source_path" "$site_packages/"
done
cp -a -- "$project_root/GrangerNetwork/src/granger_network" "$site_packages/"

libpython="$(ldd "$python_source" | awk '/libpython[0-9].*\.so/{print $3; exit}')"
if [[ -n "$libpython" && -f "$libpython" ]]; then
    cp -aL -- "$libpython" "$runtime_root/lib/$(basename "$libpython")"
fi
find "$runtime_root" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$runtime_root" -type f -name '*.pyc' -delete
chmod 0755 "$runtime_root/bin/python3"

python_license=""
for candidate in \
    "$(dirname "$stdlib_source")/LICENSE" \
    "$(dirname "$(dirname "$stdlib_source")")/LICENSE" \
    /usr/share/doc/python3/copyright; do
    if [[ -f "$candidate" ]]; then python_license="$candidate"; break; fi
done
[[ -n "$python_license" ]] || fail "Python license text is unavailable"
licenses="$appdir/usr/share/licenses/granger-browser"
mkdir -p "$licenses"
cp -aL -- "$python_license" "$licenses/Python-PSF.txt"

runtime_python="$runtime_root/bin/python3"
validation="$(
    LD_LIBRARY_PATH="$runtime_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    PYTHONHOME= PYTHONPATH= PYTHONUSERBASE= \
    "$runtime_python" -I -B - <<'PY'
import json
import pathlib
import struct
import sys
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from granger_network.browser_gateway import PROTOCOL_VERSION
from granger_network.hosting import HOSTING_VERSION, StaticSiteBridge
from granger_network.protocol import VERSION_3

key = Ed25519PrivateKey.generate()
message = b"granger-linux-app-local-runtime"
key.public_key().verify(key.sign(message), message)
print(json.dumps({
    "bits": struct.calcsize("P") * 8,
    "executable": str(pathlib.Path(sys.executable).resolve()),
    "hosting": HOSTING_VERSION,
    "hostingBridge": bool(StaticSiteBridge),
    "protocol": PROTOCOL_VERSION,
    "prefix": str(pathlib.Path(sys.prefix).resolve()),
    "wire": VERSION_3,
}))
PY
)" || fail "app-local Python validation failed"
[[ "$(jq -r '.bits' <<<"$validation")" == "64" \
   && "$(jq -r '.hosting' <<<"$validation")" == "1" \
   && "$(jq -r '.hostingBridge' <<<"$validation")" == "true" \
   && "$(jq -r '.protocol' <<<"$validation")" == "2" \
   && "$(jq -r '.wire' <<<"$validation")" == "3" ]] \
    || fail "app-local Python reported unexpected protocol state"

jq -n \
    --arg pythonVersion "$(jq -r '.version' <<<"$probe")" \
    --arg cryptographyVersion "$(jq -r '.cryptographyVersion' <<<"$probe")" \
    --arg cffiVersion "$(jq -r '.cffiVersion' <<<"$probe")" \
    --arg pycparserVersion "$(jq -r '.pycparserVersion' <<<"$probe")" \
    --arg sitePackages "runtime/python/lib/$version_dir/site-packages" \
    '{schemaVersion:1, architecture:"x86_64", pythonVersion:$pythonVersion,
      pythonLicense:"PSF-2.0", cryptographyVersion:$cryptographyVersion,
      cryptographyLicense:"Apache-2.0 OR BSD-3-Clause", cffiVersion:$cffiVersion,
      cffiLicense:"MIT", pycparserVersion:$pycparserVersion,
      pycparserLicense:"BSD-3-Clause", grangerNetworkVersion:"0.4.0",
      hostingVersion:1, sitePackages:$sitePackages, isolatedRuntime:true}' \
    >"$appdir/usr/bin/local-runtime-metadata.json"

printf 'Packaged Linux app-local Python %s for Granger Network.\n' \
    "$(jq -r '.version' <<<"$probe")"
