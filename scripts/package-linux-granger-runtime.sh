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
   && "$(jq -r '.hosting' <<<"$validation")" == "2" \
   && "$(jq -r '.hostingBridge' <<<"$validation")" == "true" \
   && "$(jq -r '.protocol' <<<"$validation")" == "2" \
   && "$(jq -r '.wire' <<<"$validation")" == "3" ]] \
    || fail "app-local Python reported unexpected protocol state"

wan_metadata='{"bundled":false,"configSha256":"","expiresAt":0,"generation":0,"networkId":"","protocolVersion":0}'
wan_source_root="${GRANGER_NETWORK_RELEASE_BUNDLE:-}"
if [[ -n "$wan_source_root" ]]; then
    wan_source_root="$(realpath -m "$wan_source_root")"
    wan_source_config="$wan_source_root/browser-wan.json"
    wan_source_trust="$wan_source_root/config-authority.pin"
    [[ -f "$wan_source_config" && -f "$wan_source_trust" ]] \
        || fail "signed WAN bundle requires browser-wan.json and config-authority.pin"
    wan_validation_code='import json,pathlib,sys
from granger_network.wan_config import load_browser_wan_config
p=pathlib.Path(sys.argv[1]).resolve(); t=pathlib.Path(sys.argv[2]).resolve()
c=load_browser_wan_config(p,trust_anchor_path=t,allow_legacy=False); r=p.parent
print(json.dumps({"authorityPin":c.authority_pin_path.relative_to(r).as_posix(),"bootstrap":c.bootstrap_path.relative_to(r).as_posix(),"configSha256":c.sha256,"expiresAt":c.expires_at,"generation":c.generation,"networkId":c.network_id,"protocolVersion":c.protocol_version},separators=(",",":"),sort_keys=True))'
    source_wan="$($runtime_python -I -B -c "$wan_validation_code" \
        "$wan_source_config" "$wan_source_trust")" \
        || fail "signed WAN release bundle validation failed"
    packaged_wan_bundle="$appdir/usr/bin/runtime/granger-network/bundle"
    packaged_wan_trust="$appdir/usr/bin/runtime/granger-network/trust"
    mkdir -p "$packaged_wan_bundle" "$packaged_wan_trust"
    cp -a -- "$wan_source_config" "$packaged_wan_bundle/browser-wan.json"
    cp -a -- "$wan_source_trust" "$packaged_wan_trust/config-authority.pin"
    for relative in "$(jq -r '.bootstrap' <<<"$source_wan")" \
                    "$(jq -r '.authorityPin' <<<"$source_wan")"; do
        source_member="$(realpath -m "$wan_source_root/$relative")"
        case "$source_member" in
            "$wan_source_root"/*) ;;
            *) fail "signed WAN bundle member escaped its source root: $relative" ;;
        esac
        [[ -f "$source_member" ]] || fail "signed WAN bundle member is missing: $relative"
        mkdir -p "$(dirname "$packaged_wan_bundle/$relative")"
        cp -a -- "$source_member" "$packaged_wan_bundle/$relative"
    done
    packaged_wan="$($runtime_python -I -B -c "$wan_validation_code" \
        "$packaged_wan_bundle/browser-wan.json" \
        "$packaged_wan_trust/config-authority.pin")" \
        || fail "packaged signed WAN bundle validation failed"
    [[ "$(jq -r '.configSha256' <<<"$packaged_wan")" \
        == "$(jq -r '.configSha256' <<<"$source_wan")" ]] \
        || fail "packaged signed WAN bundle does not match its validated source"
    wan_metadata="$(jq -c '{bundled:true,configSha256,expiresAt,generation,networkId,protocolVersion}' \
        <<<"$packaged_wan")"
fi

jq -n \
    --arg pythonVersion "$(jq -r '.version' <<<"$probe")" \
    --arg cryptographyVersion "$(jq -r '.cryptographyVersion' <<<"$probe")" \
    --arg cffiVersion "$(jq -r '.cffiVersion' <<<"$probe")" \
    --arg pycparserVersion "$(jq -r '.pycparserVersion' <<<"$probe")" \
    --arg sitePackages "runtime/python/lib/$version_dir/site-packages" \
    --argjson wan "$wan_metadata" \
    '{schemaVersion:1, architecture:"x86_64", pythonVersion:$pythonVersion,
      pythonLicense:"PSF-2.0", cryptographyVersion:$cryptographyVersion,
      cryptographyLicense:"Apache-2.0 OR BSD-3-Clause", cffiVersion:$cffiVersion,
      cffiLicense:"MIT", pycparserVersion:$pycparserVersion,
      pycparserLicense:"BSD-3-Clause", grangerNetworkVersion:"0.4.0",
      hostingVersion:2, sitePackages:$sitePackages, isolatedRuntime:true,
      signedWanBundle:$wan.bundled, wanConfigSha256:$wan.configSha256,
      wanConfigExpiresAt:$wan.expiresAt, wanConfigGeneration:$wan.generation,
      wanNetworkId:$wan.networkId, wanProtocolVersion:$wan.protocolVersion}' \
    >"$appdir/usr/bin/local-runtime-metadata.json"

printf 'Packaged Linux app-local Python %s for Granger Network.\n' \
    "$(jq -r '.version' <<<"$probe")"
