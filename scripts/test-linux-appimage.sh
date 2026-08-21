#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appimage="${1:-$project_root/output/linux/GrangerBrowser-0.4.4-x86_64.AppImage}"
report_root="${2:-$project_root/output/linux/acceptance}"

fail() {
    printf 'Linux AppImage acceptance failed: %s\n' "$*" >&2
    exit 1
}

for command_name in jq timeout sha256sum ldd file pgrep; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done
[[ -x "$appimage" ]] || fail "AppImage is missing or not executable: $appimage"
mkdir -p "$report_root"
report_root="$(realpath -m "$report_root")"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/granger-linux-acceptance-XXXXXX")"
xvfb_pid=""
app_pid=""
browser_pid=""
cleanup() {
    if [[ -n "$browser_pid" ]] && kill -0 "$browser_pid" 2>/dev/null; then
        kill -TERM "$browser_pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$browser_pid" 2>/dev/null || true
    fi
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
    "$test_root/xdg/data" "$test_root/xdg/cache" "$test_root/xdg/runtime" \
    "$test_root/granger/data" "$test_root/granger/settings"
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
    "GRANGER_RUNTIME_ROOT=/nonexistent/runtime"
    "GRANGER_TOR_PATH=/nonexistent/tor"
    "GRANGER_LYREBIRD_PATH=/nonexistent/lyrebird"
    "GRANGER_TRANSPORT_PATH=/nonexistent/transport"
    "GRANGER_I2P_PATH=/nonexistent/i2pd"
    "GRANGER_I2P_CERTS=/nonexistent/i2p-certificates"
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
    and (.profileUserAgent | contains("X11; Linux x86_64"))
    and (.javascriptUserAgent | contains("X11; Linux x86_64"))
    and (.persistentStoragePath | startswith($data))
    and (.cachePath | startswith($cache))
    and (.webEngineProcessPath | endswith("/usr/libexec/QtWebEngineProcess"))
    and (.webEngineResourcesPath | endswith("/usr/resources"))
    and (.webEngineLocalesPath | endswith("/usr/translations/qtwebengine_locales"))
' "$profile_report" >/dev/null || fail "profile/XDG/WebEngine runtime assertions failed"

privacy_report="$report_root/privacy-smoke.json"
run_extracted 300 \
    --smoke-privacy-tests "--smoke-output=$privacy_report" \
    >"$report_root/privacy-smoke.log" 2>&1 \
    || fail "standalone privacy suite failed"
jq -e '.ok == true' "$privacy_report" >/dev/null \
    || fail "standalone privacy report did not pass"

feature_report="$report_root/feature-smoke.json"
timeout 300 env -i "${base_env[@]}" \
    "GRANGER_DATA_ROOT=$test_root/granger/data" \
    "GRANGER_SETTINGS_ROOT=$test_root/granger/settings" \
    APPIMAGE_EXTRACT_AND_RUN=1 "$detached_app" \
    --smoke-feature-tests "--smoke-output=$feature_report" \
    >"$report_root/feature-smoke.log" 2>&1 \
    || fail "standalone feature suite failed"
jq -e '.ok == true' "$feature_report" >/dev/null \
    || fail "standalone feature report did not pass"

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
for runtime_file in libsoftokn3.so libfreebl3.so libfreeblpriv3.so \
    libnssckbi.so libsqlite3.so.0; do
    [[ -f "$squashfs_root/usr/lib/$runtime_file" ]] \
        || fail "AppImage is missing NSS runtime dependency: $runtime_file"
done
runtime_ld="$squashfs_root/usr/lib:$squashfs_root/usr/lib/x86_64-linux-gnu:$squashfs_root/usr/bin/runtime/tor"
unresolved_report="$report_root/unresolved-libraries.txt"
: >"$unresolved_report"
for executable in \
    "$squashfs_root/usr/bin/GrangerBrowser" \
    "$squashfs_root/usr/libexec/QtWebEngineProcess" \
    "$squashfs_root/usr/bin/runtime/tor/tor" \
    "$squashfs_root/usr/bin/runtime/tor/pluggable_transports/lyrebird" \
    "$squashfs_root/usr/bin/runtime/tor/pluggable_transports/conjure-client" \
    "$squashfs_root/usr/bin/runtime/i2p/i2pd" \
    "$squashfs_root/usr/lib/libsoftokn3.so" \
    "$squashfs_root/usr/lib/libfreebl3.so" \
    "$squashfs_root/usr/lib/libfreeblpriv3.so" \
    "$squashfs_root/usr/lib/libnssckbi.so"; do
    output="$(LD_LIBRARY_PATH="$runtime_ld" ldd "$executable" 2>&1 || true)"
    if grep -F 'not found' <<<"$output" >>"$unresolved_report"; then
        printf '%s\n' "[$executable]" >>"$unresolved_report"
    fi
done
[[ ! -s "$unresolved_report" ]] || fail "AppImage has unresolved shared libraries"

before_qt="$(pgrep -f 'QtWebEngineProcess' || true)"
before_tor="$(pgrep -x tor || true)"
before_i2pd="$(pgrep -x i2pd || true)"
sandbox_report="$report_root/renderer-sandbox.json"
env -i "${base_env[@]}" APPIMAGE_EXTRACT_AND_RUN=1 \
    "$detached_app" --smoke-renderer-sandbox "--smoke-output=$sandbox_report" \
    >"$report_root/sandbox-runtime.log" 2>&1 &
app_pid=$!

renderer_pid=""
renderer_detection=""
for _ in $(seq 1 120); do
    while read -r candidate; do
        [[ -n "$candidate" ]] || continue
        grep -qx "$candidate" <<<"$before_qt" && continue
        cmdline="$(tr '\0' ' ' <"/proc/$candidate/cmdline" 2>/dev/null || true)"
        if [[ "$cmdline" == *"--type=renderer"* ]]; then
            renderer_pid="$candidate"
            renderer_detection="explicit-renderer-command-line"
            break
        fi
        status="$(cat "/proc/$candidate/status" 2>/dev/null || true)"
        seccomp="$(awk '/^Seccomp:/ {print $2}' <<<"$status")"
        no_new_privs="$(awk '/^NoNewPrivs:/ {print $2}' <<<"$status")"
        threads="$(awk '/^Threads:/ {print $2}' <<<"$status")"
        parent_pid="$(awk '/^PPid:/ {print $2}' <<<"$status")"
        parent_cmdline="$(tr '\0' ' ' <"/proc/$parent_pid/cmdline" 2>/dev/null || true)"
        if [[ "$cmdline" == *"--type=zygote"* \
              && "$parent_cmdline" == *"QtWebEngineProcess"* \
              && "$seccomp" == "2" && "$no_new_privs" == "1" \
              && "${threads:-0}" -gt 1 ]]; then
            renderer_pid="$candidate"
            renderer_detection="sandboxed-zygote-child"
            break
        fi
    done < <(pgrep -f 'QtWebEngineProcess' || true)
    [[ -n "$renderer_pid" ]] && break
    kill -0 "$app_pid" 2>/dev/null || break
    sleep 0.5
done
[[ -n "$renderer_pid" ]] || fail "no Qt WebEngine renderer process was observed"
for _ in $(seq 1 40); do
    [[ -s "$sandbox_report" ]] && break
    kill -0 "$app_pid" 2>/dev/null || break
    sleep 0.25
done
jq -e '.ok == true and .pageLoaded == true
           and .javascriptExecuted == true and .value == 42' \
    "$sandbox_report" >/dev/null \
    || fail "Qt WebEngine renderer JavaScript probe did not pass"
renderer_status="$(cat "/proc/$renderer_pid/status")"
renderer_cmdline="$(tr '\0' ' ' <"/proc/$renderer_pid/cmdline")"
renderer_seccomp="$(awk '/^Seccomp:/ {print $2}' <<<"$renderer_status")"
renderer_no_new_privs="$(awk '/^NoNewPrivs:/ {print $2}' <<<"$renderer_status")"
[[ "$renderer_seccomp" == "2" ]] || fail "renderer seccomp mode is $renderer_seccomp, expected 2"
[[ "$renderer_no_new_privs" == "1" ]] \
    || fail "renderer NoNewPrivs is $renderer_no_new_privs, expected 1"
[[ "$renderer_cmdline" != *"--no-sandbox"* ]] || fail "renderer received --no-sandbox"
browser_pid="$(pgrep -P "$app_pid" | head -n 1 || true)"
[[ -n "$browser_pid" ]] || browser_pid="$app_pid"

managed_pids=()
while read -r candidate; do
    [[ -n "$candidate" ]] || continue
    grep -qx "$candidate" <<<"$before_tor" || managed_pids+=("$candidate")
done < <(pgrep -x tor || true)
while read -r candidate; do
    [[ -n "$candidate" ]] || continue
    grep -qx "$candidate" <<<"$before_i2pd" || managed_pids+=("$candidate")
done < <(pgrep -x i2pd || true)

kill -TERM "$browser_pid"
for _ in $(seq 1 80); do
    kill -0 "$browser_pid" 2>/dev/null || break
    sleep 0.25
done
if kill -0 "$browser_pid" 2>/dev/null; then
    fail "Granger did not exit after SIGTERM"
fi
browser_pid=""
for _ in $(seq 1 80); do
    kill -0 "$app_pid" 2>/dev/null || break
    sleep 0.25
done
if kill -0 "$app_pid" 2>/dev/null; then
    fail "AppImage runtime did not exit after Granger shutdown"
fi
wait "$app_pid" || true
app_pid=""
if grep -Fq 'Failed parsing rule:' "$report_root/sandbox-runtime.log"; then
    fail "Chromium rejected the packaged host resolver policy"
fi
for _ in $(seq 1 80); do
    children_cleaned=true
    for candidate in "$renderer_pid" "${managed_pids[@]}"; do
        if [[ -n "$candidate" ]] && kill -0 "$candidate" 2>/dev/null; then
            children_cleaned=false
        fi
    done
    [[ "$children_cleaned" == true ]] && break
    sleep 0.25
done
[[ "$children_cleaned" == true ]] || fail "managed Linux child process survived browser shutdown"

source_references=false
if grep -aEq '/home/runner/work/|/GrangerBrowser/(build|output)/' \
    "$squashfs_root/usr/bin/GrangerBrowser"; then
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
    --arg rendererDetection "$renderer_detection" \
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
                noNewPrivs:($noNewPrivs|tonumber), noSandboxFlag:false,
                javascriptExecuted:true, processDetection:$rendererDetection},
      userNamespaces:$userns, childProcessesCleaned:true,
      unresolvedLibraries:0, sourceTreeReferences:false,
      xdg:{config:$xdgConfig,data:$xdgData,cache:$xdgCache,runtime:$xdgRuntime}}' \
    >"$report_root/appimage-acceptance.json"

[[ "$direct_fuse_pass" == true ]] \
    || fail "direct AppImage/FUSE launch failed; only extract-and-run worked"
printf 'Linux AppImage acceptance passed: %s\n' "$appimage"
