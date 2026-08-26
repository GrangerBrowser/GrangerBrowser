#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_root="$project_root/output/linux"
build_dir="$output_root/build"
appdir="$output_root/AppDir"
runtime_root="$project_root/output/linux-runtimes"
tools_root="$project_root/output/linux-tools"
version="0.4.4"
artifact="$output_root/GrangerBrowser-${version}-x86_64.AppImage"
qt_root="${QT_ROOT:-}"
source_head="${GRANGER_SOURCE_HEAD:-$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)}"

fail() {
    printf 'Linux AppImage build failed: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

for command_name in cmake ninja curl sha256sum file ldd readelf jq; do
    require_command "$command_name"
done
[[ "$(uname -s)" == "Linux" ]] || fail "this script must run natively on Linux"
[[ "$(uname -m)" == "x86_64" ]] || fail "only Linux x86_64 is supported"
[[ "$source_head" =~ ^[0-9a-f]{40}$ ]] || fail "GRANGER_SOURCE_HEAD must identify the committed source"
[[ -n "$qt_root" ]] || fail "QT_ROOT must point to Qt 6.11.2 linux_gcc_64"
qt_root="$(realpath -m "$qt_root")"
[[ -x "$qt_root/bin/qmake" ]] || fail "qmake is missing below QT_ROOT"
qt_version="$($qt_root/bin/qmake -query QT_VERSION)"
[[ "$qt_version" == "6.11.2" ]] || fail "expected Qt 6.11.2, got $qt_version"
[[ -f "$qt_root/lib/cmake/Qt6WebEngineWidgets/Qt6WebEngineWidgetsConfig.cmake" ]] \
    || fail "Qt WebEngineWidgets is missing from QT_ROOT"

mkdir -p "$output_root" "$tools_root"
output_root="$(realpath -m "$output_root")"
for path in "$build_dir" "$appdir" "$runtime_root" "$tools_root" "$artifact"; do
    resolved="$(realpath -m "$path")"
    case "$resolved" in
        "$(realpath -m "$project_root/output")"/*) ;;
        *) fail "generated path escaped output/: $resolved" ;;
    esac
done

"$project_root/scripts/fetch-linux-runtimes.sh" "$runtime_root"

rm -rf -- "$build_dir" "$appdir"
mkdir -p "$build_dir" "$appdir"
cmake -S "$project_root" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$qt_root" \
    -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$build_dir" --parallel "$(nproc)"
DESTDIR="$appdir" cmake --install "$build_dir" --config Release

browser="$appdir/usr/bin/GrangerBrowser"
[[ -x "$browser" ]] || fail "installed GrangerBrowser executable is missing"
mkdir -p "$appdir/usr/bin/runtime" "$appdir/usr/lib" \
    "$appdir/usr/share/licenses/granger-browser"
cp -a "$runtime_root/tor" "$appdir/usr/bin/runtime/"
cp -a "$runtime_root/i2p" "$appdir/usr/bin/runtime/"
bash "$project_root/scripts/package-linux-granger-runtime.sh" "$appdir"
cp -a "$project_root/NOTICE.txt" "$project_root/DISTRIBUTION.md" \
    "$appdir/usr/share/licenses/granger-browser/"
cp -a "$project_root/third_party/i2pd/LICENSE" \
    "$appdir/usr/share/licenses/granger-browser/i2pd-BSD-3-Clause.txt"
cp -a "$project_root/third_party/linuxdeploy/LICENSE.txt" \
    "$appdir/usr/share/licenses/granger-browser/linuxdeploy-MIT.txt"
cp -a "$project_root/third_party/linuxdeploy/LICENSE-appimage-plugin.txt" \
    "$appdir/usr/share/licenses/granger-browser/linuxdeploy-appimage-plugin-MIT.txt"
cp -a "$project_root/third_party/linuxdeploy/README.md" \
    "$appdir/usr/share/licenses/granger-browser/linuxdeploy-SOURCES.md"
cp -a "$runtime_root/tor/docs/." "$appdir/usr/share/licenses/granger-browser/"
if [[ -d "$qt_root/LICENSES" ]]; then
    cp -a "$qt_root/LICENSES" "$appdir/usr/share/licenses/granger-browser/Qt-LICENSES"
fi
nss_softokn="$(find /usr/lib /lib -type f -path '*/nss/libsoftokn3.so' -print -quit)"
[[ -n "$nss_softokn" ]] || fail "libnss3 softoken runtime is unavailable"
nss_module_dir="$(dirname "$nss_softokn")"
for module in libsoftokn3.so libfreebl3.so libfreeblpriv3.so libnssckbi.so; do
    [[ -f "$nss_module_dir/$module" ]] || fail "NSS runtime module is missing: $module"
    cp -L "$nss_module_dir/$module" "$appdir/usr/lib/$module"
done
[[ -f /usr/share/doc/libnss3/copyright ]] \
    || fail "libnss3 copyright record is unavailable"
cp -a /usr/share/doc/libnss3/copyright \
    "$appdir/usr/share/licenses/granger-browser/nss3-copyright.txt"
chmod 0755 "$browser" \
    "$appdir/usr/bin/runtime/tor/tor" \
    "$appdir/usr/bin/runtime/tor/pluggable_transports/lyrebird" \
    "$appdir/usr/bin/runtime/tor/pluggable_transports/conjure-client" \
    "$appdir/usr/bin/runtime/i2p/i2pd" \
    "$appdir/usr/bin/runtime/python/bin/python3" "$project_root/packaging/linux/AppRun"

linuxdeploy_url="https://github.com/linuxdeploy/linuxdeploy/releases/download/1-alpha-20251107-1/linuxdeploy-x86_64.AppImage"
linuxdeploy_sha256="c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d"
qt_plugin_url="https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/1-alpha-20250213-1/linuxdeploy-plugin-qt-x86_64.AppImage"
qt_plugin_sha256="15106be885c1c48a021198e7e1e9a48ce9d02a86dd0a1848f00bdbf3c1c92724"

download_tool() {
    local url="$1"
    local path="$2"
    local expected="$3"
    if [[ ! -f "$path" ]]; then
        curl --fail --location --proto '=https' --tlsv1.2 \
            --retry 3 --output "${path}.part" "$url"
        mv -- "${path}.part" "$path"
    fi
    printf '%s  %s\n' "$expected" "$path" | sha256sum --check --status \
        || fail "tool SHA-256 mismatch: $(basename "$path")"
    chmod 0755 "$path"
}

linuxdeploy="$tools_root/linuxdeploy"
qt_plugin="$tools_root/linuxdeploy-plugin-qt"
download_tool "$linuxdeploy_url" "$linuxdeploy" "$linuxdeploy_sha256"
download_tool "$qt_plugin_url" "$qt_plugin" "$qt_plugin_sha256"

export PATH="$tools_root:$qt_root/bin:$PATH"
export LD_LIBRARY_PATH="$qt_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export QMAKE="$qt_root/bin/qmake"
export VERSION="$version"
export LDAI_OUTPUT="$artifact"
export QML_SOURCES_PATHS="$project_root/granger"
export APPIMAGE_EXTRACT_AND_RUN=1

"$linuxdeploy" --appimage-extract-and-run \
    --appdir "$appdir" \
    --executable "$browser" \
    --executable "$appdir/usr/bin/runtime/i2p/i2pd" \
    --executable "$appdir/usr/bin/runtime/python/bin/python3" \
    --desktop-file "$project_root/packaging/linux/granger-browser.desktop" \
    --icon-file "$project_root/granger/resources/app-icon.png" \
    --custom-apprun "$project_root/packaging/linux/AppRun" \
    --plugin qt

required_files=(
    "usr/bin/GrangerBrowser"
    "usr/libexec/QtWebEngineProcess"
    "usr/resources/icudtl.dat"
    "usr/resources/qtwebengine_resources.pak"
    "usr/resources/qtwebengine_resources_100p.pak"
    "usr/resources/qtwebengine_resources_200p.pak"
    "usr/resources/qtwebengine_devtools_resources.pak"
    "usr/resources/v8_context_snapshot.bin"
    "usr/translations/qtwebengine_locales/en-US.pak"
    "usr/lib/libsoftokn3.so"
    "usr/lib/libfreebl3.so"
    "usr/lib/libfreeblpriv3.so"
    "usr/lib/libnssckbi.so"
    "usr/lib/libsqlite3.so.0"
    "usr/bin/runtime/tor/tor"
    "usr/bin/runtime/tor/libcrypto.so.3"
    "usr/bin/runtime/tor/libevent-2.1.so.7"
    "usr/bin/runtime/tor/libssl.so.3"
    "usr/bin/runtime/tor/data/geoip"
    "usr/bin/runtime/tor/data/geoip6"
    "usr/bin/runtime/tor/pluggable_transports/lyrebird"
    "usr/bin/runtime/tor/pluggable_transports/conjure-client"
    "usr/bin/runtime/tor/pluggable_transports/pt_config.json"
    "usr/bin/runtime/i2p/i2pd"
    "usr/bin/runtime/i2p/certificates"
    "usr/bin/runtime/python/bin/python3"
    "usr/bin/local-runtime-metadata.json"
    "usr/share/licenses/granger-browser/linuxdeploy-MIT.txt"
    "usr/share/licenses/granger-browser/linuxdeploy-appimage-plugin-MIT.txt"
    "usr/share/licenses/granger-browser/linuxdeploy-SOURCES.md"
    "usr/share/licenses/granger-browser/nss3-copyright.txt"
)
if [[ -n "${GRANGER_NETWORK_RELEASE_BUNDLE:-}" ]]; then
    required_files+=(
        "usr/bin/runtime/granger-network/bundle/browser-wan.json"
        "usr/bin/runtime/granger-network/trust/config-authority.pin"
    )
fi
for relative_path in "${required_files[@]}"; do
    [[ -e "$appdir/$relative_path" ]] || fail "AppDir is missing $relative_path"
done
python_site_packages="$(jq -r '.sitePackages' "$appdir/usr/bin/local-runtime-metadata.json")"
for relative_path in \
    "$python_site_packages/granger_network/browser_gateway.py" \
    "$python_site_packages/granger_network/hosting.py"; do
    [[ -f "$appdir/usr/bin/$relative_path" ]] \
        || fail "AppDir is missing $relative_path"
done
chmod 0755 "$appdir/usr/libexec/QtWebEngineProcess"
if [[ -e "$appdir/usr/bin/QtWebEngineProcess" \
      || -d "$appdir/usr/bin/resources" \
      || -d "$appdir/usr/bin/translations/qtwebengine_locales" ]]; then
    fail "AppDir contains a duplicate Qt WebEngine runtime layout"
fi

forbidden_system_runtime="$(find "$appdir/usr/lib" -maxdepth 2 -type f \
    \( -name 'libc.so.6' -o -name 'libpthread.so.0' -o -name 'libdl.so.2' \
       -o -name 'librt.so.1' -o -name 'ld-linux*.so*' \) -print -quit)"
if [[ -n "$forbidden_system_runtime" ]]; then
    printf '%s\n' "$forbidden_system_runtime" >&2
    fail "AppDir incorrectly bundles glibc or its loader"
fi
debug_runtime_matches="$({
    find "$appdir" -type f \( -name '*.debug' -o -name '*.pdb' \) -print
    find "$appdir/usr/lib" -maxdepth 1 -type f -name 'libQt6*d.so*' -print
} | sort -u)"
if [[ -n "$debug_runtime_matches" ]]; then
    printf '%s\n' "$debug_runtime_matches" >&2
    fail "AppDir contains a debug runtime"
fi
if grep -aFq "$project_root" "$browser"; then
    fail "GrangerBrowser contains an absolute build/source path"
fi

runtime_metadata="$runtime_root/runtime-metadata.json"
jq --arg qt "$qt_version" \
   --arg sourceHead "$source_head" \
   --arg linuxdeploy "1-alpha-20251107-1" \
   --arg linuxdeploySha "${linuxdeploy_sha256^^}" \
   --arg qtPlugin "1-alpha-20250213-1" \
   --arg qtPluginSha "${qt_plugin_sha256^^}" \
   '. + {
      grangerVersion: "0.4.4",
      architecture: "x86_64",
      qtVersion: $qt,
      qtWebEngineVersion: $qt,
      sourceHead: $sourceHead,
      appImageBuilder: "linuxdeploy",
      linuxdeployVersion: $linuxdeploy,
      linuxdeploySha256: $linuxdeploySha,
      linuxdeployQtPluginVersion: $qtPlugin,
      linuxdeployQtPluginSha256: $qtPluginSha,
      chromiumSandboxDisabled: false
   }' "$runtime_metadata" >"$appdir/usr/bin/deployment-metadata.json"

manifest_tmp="$output_root/release-manifest.json.tmp"
(
    cd "$appdir"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
) | jq -R -s '{algorithm:"SHA-256", files:(split("\n") | map(select(length > 0)))}' \
    >"$manifest_tmp"
mv -- "$manifest_tmp" "$appdir/usr/bin/release-manifest.json"

rm -f -- "$artifact"
(
    cd "$output_root"
    OUTPUT="$artifact" "$linuxdeploy" --appimage-extract-and-run \
        --appdir "$appdir" \
        --custom-apprun "$project_root/packaging/linux/AppRun" \
        --output appimage
)
[[ -f "$artifact" ]] || fail "linuxdeploy did not create $artifact"
chmod 0755 "$artifact"

artifact_sha256="$(sha256sum "$artifact" | awk '{print toupper($1)}')"
artifact_size="$(stat --format='%s' "$artifact")"
printf '%s  %s\n' "$artifact_sha256" "$(basename "$artifact")" \
    >"$output_root/SHA256SUMS-linux.txt"
jq -n --arg file "$(basename "$artifact")" \
    --arg sha256 "$artifact_sha256" --argjson size "$artifact_size" \
    --arg qt "$qt_version" --arg sourceHead "$source_head" \
    '{ok:true, artifact:$file, sizeBytes:$size, sha256:$sha256,
      architecture:"x86_64", qtVersion:$qt, sourceHead:$sourceHead,
      publicRelease:false}' \
    >"$output_root/linux-build-report.json"
printf '%s\n' "$source_head" >"$output_root/source-head.txt"

printf 'Created %s\nSHA-256 %s\n' "$artifact" "$artifact_sha256"
