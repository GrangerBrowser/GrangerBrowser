#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appimage="${1:-$project_root/output/linux/GrangerBrowser-0.4.4-x86_64.AppImage}"
report_root="${2:-$project_root/output/linux/acceptance}"

fail() {
    printf 'Linux AppImage acceptance failed: %s\n' "$*" >&2
    exit 1
}

for command_name in jq timeout sha256sum ldd file strings pgrep; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done
[[ -x "$appimage" ]] || fail "AppImage is missing or not executable: $appimage"
mkdir -p "$report_root"
report_root="$(realpath -m "$report_root")"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/granger-linux-acceptance-XXXXXX")"
xvfb_pid=""
app_pid=""
cleanup() {
    if [[ -n "$app_pid" ]] && kill -0 "$app_pid" 2>/dev/null; then
        kill -TERM "$app_pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$app_pid" 2>/dev/null || true
    fi
    if [[ -n "$xvfb_pid" ]] && kill -0 "$xvfb_pid" 2>/dev/null; then
        kill "$xvfb_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

if [[ -z "${DISPLAY:-}" ]]; then
    command -v Xvfb >/dev/null 2>&1 || fail "Xvfb is required in a headless environment"
    export DISPLAY=:97
    Xvfb "$DISPLAY" -screen 0 1366x768x24 -nolisten tcp >"$report_root/xvfb.log" 2>&1 &
    xvfb_pid=$!
    sleep 2
fi

detached_root="$test_root/detached package with spaces"
mkdir -p "$detached_root" "$test_root/home" "$test_root/xdg/config" \
    "$test_root/xdg/data" "$test_root/xdg/cache" "$test_root/xdg/runtime"
chmod 0700 "$test_root/xdg/runtime"
detached_app="$detached_root/GrangerBrowser-x86_64.AppImage"
cp -a "$appimage" "$detached_app"
chmod 0755 "$detached_app"

base_env=(
    "HOME=$test_root/home"
    "USER=${USER:-granger-test}"
    "LOGNAME=${LOGNAME:-${USER:-granger-test}}"
    "DISPLAY=$DISPLAY"
    "PATH=/usr/bin:/bin"
    "XDG_CONFIG_HOME=$test_root/xdg/config"
    "XDG_DATA_HOME=$test_root/xdg/data"
    "XDG_CACHE_HOME=$test_root/xdg/cache"
    "XDG_RUNTIME_DIR=$test_root/xdg/runtime"
    "QT_PLUGIN_PATH=/nonexistent/poisoned-qt/plugins"
    "QML2_IMPORT_PATH=/nonexistent/poisoned-qt/qml"
    "QTWEBENGINEPROCESS_PATH=/nonexistent/QtWebEngineProcess"
    "QTWEBENGINE_RESOURCES_PATH=/nonexistent/resources"
    "QTWEBENGINE_LOCALES_PATH=/nonexistent/locales"
    "QTWEBENGINE_DISABLE_SANDBOX=1"
    "QTWEBENGINE_CHROMIUM_FLAGS=--no-sandbox --no-proxy-server"
)

run_extracted() {
    local seconds="$1"
    shift
    timeout "$seconds" env -i "${base_env[@]}" APPIMAGE_EXTRACT_AND_RUN=1 \
        "$detached_app" "$@"
}

profile_report="$report_root/profile-state.json"
run_extracted 120 \
    --smoke-profile-state "--smoke-output=$profile_report" \
    >"$report_root/profile-state.log" 2>&1 \
    || fail "standalone Qt WebEngine profile smoke failed"
jq -e --arg data "$test_root/xdg/data" --arg cache "$test_root/xdg/cache" '
    .ok == true
    and (.qtVersion == "6.11.2")
    and (.qtWebEngineVersion == "6.11.2")
    and (.persistentStoragePath | startswith($data))
    and (.cachePath | startswith($cache))
    and (.webEngineProcessPath | endswith("/usr/bin/QtWebEngineProcess"))
    and (.webEngineResourcesPath | endswith("/usr/bin/resources"))
    and (.webEngineLocalesPath | endswith("/usr/bin/translations/qtwebengine_locales"))
' "$profile_report" >/dev/null || fail "profile/XDG/WebEngine runtime assertions failed"

routes_report="$report_root/private-route-deterministic.json"
run_extracted 120 \
    --smoke-private-routes "--smoke-output=$routes_report" \
    >"$report_root/private-route-deterministic.log" 2>&1 \
    || fail "deterministic private-route suite failed"
jq -e '.ok == true and .directBackendConnections == 0' "$routes_report" >/dev/null \
    || fail "deterministic private-route report did not pass"

strategy_report="$report_root/tor-strategies.json"
run_extracted 180 \
    --smoke-strategy-tests "--smoke-output=$strategy_report" \
    >"$report_root/tor-strategies.log" 2>&1 \
    || fail "bundled Tor strategy suite failed"
jq -e '.ok == true' "$strategy_report" >/dev/null \
    || fail "Tor strategy report did not pass"

direct_fuse_pass=false
if timeout 120 env -i "${base_env[@]}" \
    "$detached_app" --smoke-profile-state \
    "--smoke-output=$report_root/profile-state-fuse.json" \
    >"$report_root/profile-state-fuse.log" 2>&1; then
    direct_fuse_pass=true
fi

extract_root="$test_root/extracted"
mkdir -p "$extract_root"
(
    cd "$extract_root"
    "$detached_app" --appimage-extract >/dev/null
)
squashfs_root="$extract_root/squashfs-root"
[[ -x "$squashfs_root/AppRun" ]] || fail "AppImage extraction did not produce AppRun"
runtime_ld="$squashfs_root/usr/lib:$squashfs_root/usr/lib/x86_64-linux-gnu:$squashfs_root/usr/bin/runtime/tor"
unresolved_report="$report_root/unresolved-libraries.txt"
: >"$unresolved_report"
for executable in \
    "$squashfs_root/usr/bin/GrangerBrowser" \
    "$squashfs_root/usr/bin/QtWebEngineProcess" \
    "$squashfs_root/usr/bin/runtime/tor/tor" \
    "$squashfs_root/usr/bin/runtime/tor/pluggable_transports/lyrebird" \
    "$squashfs_root/usr/bin/runtime/tor/pluggable_transports/conjure-client" \
    "$squashfs_root/usr/bin/runtime/i2p/i2pd"; do
    output="$(LD_LIBRARY_PATH="$runtime_ld" ldd "$executable" 2>&1 || true)"
    if grep -F 'not found' <<<"$output" >>"$unresolved_report"; then
        printf '%s\n' "[$executable]" >>"$unresolved_report"
    fi
done
[[ ! -s "$unresolved_report" ]] || fail "AppImage has unresolved shared libraries"

before_qt="$(pgrep -f 'QtWebEngineProcess' || true)"
before_tor="$(pgrep -x tor || true)"
before_i2pd="$(pgrep -x i2pd || true)"
env -i "${base_env[@]}" APPIMAGE_EXTRACT_AND_RUN=1 \
    "$detached_app" >"$report_root/sandbox-runtime.log" 2>&1 &
app_pid=$!

renderer_pid=""
for _ in $(seq 1 120); do
    while read -r candidate; do
        [[ -n "$candidate" ]] || continue
        grep -qx "$candidate" <<<"$before_qt" && continue
        cmdline="$(tr '\0' ' ' <"/proc/$candidate/cmdline" 2>/dev/null || true)"
        if [[ "$cmdline" == *"--type=renderer"* ]]; then
            renderer_pid="$candidate"
            break
        fi
    done < <(pgrep -f 'QtWebEngineProcess' || true)
    [[ -n "$renderer_pid" ]] && break
    kill -0 "$app_pid" 2>/dev/null || break
    sleep 0.5
done
[[ -n "$renderer_pid" ]] || fail "no Qt WebEngine renderer process was observed"
renderer_status="$(cat "/proc/$renderer_pid/status")"
renderer_cmdline="$(tr '\0' ' ' <"/proc/$renderer_pid/cmdline")"
renderer_seccomp="$(awk '/^Seccomp:/ {print $2}' <<<"$renderer_status")"
renderer_no_new_privs="$(awk '/^NoNewPrivs:/ {print $2}' <<<"$renderer_status")"
[[ "$renderer_seccomp" == "2" ]] || fail "renderer seccomp mode is $renderer_seccomp, expected 2"
[[ "$renderer_cmdline" != *"--no-sandbox"* ]] || fail "renderer received --no-sandbox"

managed_pids=()
while read -r candidate; do
    [[ -n "$candidate" ]] || continue
    grep -qx "$candidate" <<<"$before_tor" || managed_pids+=("$candidate")
done < <(pgrep -x tor || true)
while read -r candidate; do
    [[ -n "$candidate" ]] || continue
    grep -qx "$candidate" <<<"$before_i2pd" || managed_pids+=("$candidate")
done < <(pgrep -x i2pd || true)

kill -TERM "$app_pid"
for _ in $(seq 1 80); do
    kill -0 "$app_pid" 2>/dev/null || break
    sleep 0.25
done
if kill -0 "$app_pid" 2>/dev/null; then
    fail "Granger did not exit after SIGTERM"
fi
wait "$app_pid" || true
app_pid=""
sleep 1
children_cleaned=true
for candidate in "$renderer_pid" "${managed_pids[@]}"; do
    if [[ -n "$candidate" ]] && kill -0 "$candidate" 2>/dev/null; then
        children_cleaned=false
    fi
done
[[ "$children_cleaned" == true ]] || fail "managed Linux child process survived browser shutdown"

source_references=false
if strings "$squashfs_root/usr/bin/GrangerBrowser" \
    | grep -Eq '/home/runner/work/|/GrangerBrowser/(build|output)/'; then
    source_references=true
fi
[[ "$source_references" == false ]] || fail "AppImage embeds a CI source/build path"

userns_value="unavailable"
if [[ -r /proc/sys/kernel/unprivileged_userns_clone ]]; then
    userns_value="$(cat /proc/sys/kernel/unprivileged_userns_clone)"
fi
artifact_sha256="$(sha256sum "$detached_app" | awk '{print toupper($1)}')"
artifact_size="$(stat --format='%s' "$detached_app")"

jq -n \
    --arg artifact "$(basename "$appimage")" \
    --arg sha256 "$artifact_sha256" \
    --argjson size "$artifact_size" \
    --argjson fuse "$direct_fuse_pass" \
    --arg rendererPid "$renderer_pid" \
    --arg seccomp "$renderer_seccomp" \
    --arg noNewPrivs "$renderer_no_new_privs" \
    --arg userns "$userns_value" \
    --arg xdgConfig "$test_root/xdg/config" \
    --arg xdgData "$test_root/xdg/data" \
    --arg xdgCache "$test_root/xdg/cache" \
    --arg xdgRuntime "$test_root/xdg/runtime" \
    '{ok:true, artifact:$artifact, sha256:$sha256, sizeBytes:$size,
      directFusedLaunch:$fuse, extractedLaunch:true, qtWebEngine:true,
      renderer:{pid:$rendererPid, seccomp:($seccomp|tonumber),
                noNewPrivs:($noNewPrivs|tonumber), noSandboxFlag:false},
      userNamespaces:$userns, childProcessesCleaned:true,
      unresolvedLibraries:0, sourceTreeReferences:false,
      xdg:{config:$xdgConfig,data:$xdgData,cache:$xdgCache,runtime:$xdgRuntime}}' \
    >"$report_root/appimage-acceptance.json"

[[ "$direct_fuse_pass" == true ]] \
    || fail "direct AppImage/FUSE launch failed; only extract-and-run worked"
printf 'Linux AppImage acceptance passed: %s\n' "$appimage"
