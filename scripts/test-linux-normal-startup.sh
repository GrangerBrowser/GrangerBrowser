#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appimage="${1:-$project_root/output/linux/GrangerBrowser-0.4.5-x86_64.AppImage}"
report_root="${2:-$project_root/output/linux/normal-startup}"

fail() {
    printf 'Linux normal-startup acceptance failed: %s\n' "$*" >&2
    exit 1
}

for command_name in jq timeout sha256sum pgrep readlink; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done
[[ -x "$appimage" ]] || fail "AppImage is missing or not executable: $appimage"

project_processes_present() {
    pgrep -x GrangerBrowser >/dev/null 2>&1 \
        || pgrep -f '[Q]tWebEngineProcess' >/dev/null 2>&1 \
        || pgrep -f '[g]ranger_network\.browser_gateway' >/dev/null 2>&1 \
        || pgrep -f '/runtime/tor/[t]or([[:space:]]|$)' >/dev/null 2>&1 \
        || pgrep -f '/runtime/i2p/[i]2pd([[:space:]]|$)' >/dev/null 2>&1
}

if project_processes_present; then
    fail "acceptance requires a clean Granger process state"
fi

mkdir -p "$report_root"
report_root="$(realpath -m "$report_root")"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/granger-normal-startup-XXXXXX")"
mkdir -p "$test_root/home"
xvfb_pid=""
app_pid=""
browser_pid=""

stop_browser() {
    if [[ -n "$browser_pid" ]] && kill -0 "$browser_pid" 2>/dev/null; then
        kill -TERM "$browser_pid" 2>/dev/null || true
        for _ in $(seq 1 80); do
            kill -0 "$browser_pid" 2>/dev/null || break
            sleep 0.25
        done
        if kill -0 "$browser_pid" 2>/dev/null; then
            kill -KILL "$browser_pid" 2>/dev/null || true
        fi
    fi
    if [[ -n "$app_pid" ]] && kill -0 "$app_pid" 2>/dev/null; then
        kill -TERM "$app_pid" 2>/dev/null || true
        for _ in $(seq 1 40); do
            kill -0 "$app_pid" 2>/dev/null || break
            sleep 0.25
        done
        if kill -0 "$app_pid" 2>/dev/null; then
            kill -KILL "$app_pid" 2>/dev/null || true
        fi
    fi
    browser_pid=""
    app_pid=""
}

cleanup() {
    stop_browser
    if [[ -n "$xvfb_pid" ]] && kill -0 "$xvfb_pid" 2>/dev/null; then
        kill "$xvfb_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

if [[ -z "${DISPLAY:-}" ]]; then
    command -v Xvfb >/dev/null 2>&1 || fail "Xvfb is required in a headless environment"
    export DISPLAY=:96
    Xvfb "$DISPLAY" -screen 0 1366x768x24 -nolisten tcp \
        >"$report_root/xvfb.log" 2>&1 &
    xvfb_pid=$!
    sleep 2
fi

detached_root="$test_root/package with spaces"
detached_app="$detached_root/GrangerBrowser-0.4.5-x86_64.AppImage"
unrelated_cwd="$test_root/unrelated cwd"
mkdir -p "$detached_root" "$unrelated_cwd"
cp -a "$appimage" "$detached_app"
chmod 0755 "$detached_app"

extract_root="$test_root/extracted"
mkdir -p "$extract_root"
(
    cd "$extract_root"
    "$detached_app" --appimage-extract >/dev/null
)
appdir="$extract_root/squashfs-root"
metadata="$appdir/usr/bin/local-runtime-metadata.json"
[[ -x "$appdir/usr/bin/GrangerBrowser" ]] || fail "packaged browser is missing"
[[ -x "$appdir/usr/bin/runtime/python/bin/python3" ]] \
    || fail "bundled Granger Python runtime is missing"
[[ -f "$appdir/usr/bin/runtime/granger-network/bundle/browser-wan.json" ]] \
    || fail "signed WAN bundle is missing"
[[ -f "$appdir/usr/bin/runtime/granger-network/trust/config-authority.pin" ]] \
    || fail "WAN authority pin is missing"
[[ -f "$metadata" ]] || fail "local runtime metadata is missing"
site_packages="$(jq -r '.sitePackages' "$metadata")"
[[ -f "$appdir/usr/bin/$site_packages/granger_network/browser_gateway.py" ]] \
    || fail "bundled Granger gateway module is missing"
jq -e '.signedWanBundle == true
       and (.wanConfigGeneration | type == "number" and . >= 1)
       and (.wanConfigExpiresAt | type == "number" and . > now)
       and (.wanNetworkId | type == "string" and length > 0)' \
    "$metadata" >/dev/null || fail "signed WAN metadata is invalid or expired"

make_profile() {
    local profile="$1"
    mkdir -p "$profile/config" "$profile/data" "$profile/cache" "$profile/runtime"
    chmod 0700 "$profile/runtime"
}

start_normal_browser() {
    local profile="$1"
    local log_stem="$2"
    make_profile "$profile"
    (
        cd "$unrelated_cwd"
        exec env -i \
            HOME="$test_root/home" USER="${USER:-granger-test}" \
            LOGNAME="${LOGNAME:-${USER:-granger-test}}" \
            PATH=/usr/bin:/bin DISPLAY="$DISPLAY" \
            XDG_CONFIG_HOME="$profile/config" \
            XDG_DATA_HOME="$profile/data" \
            XDG_CACHE_HOME="$profile/cache" \
            XDG_RUNTIME_DIR="$profile/runtime" \
            "$detached_app"
    ) >"$report_root/$log_stem.stdout.log" 2>"$report_root/$log_stem.stderr.log" &
    app_pid=$!
    browser_pid=""
    for _ in $(seq 1 120); do
        if ! kill -0 "$app_pid" 2>/dev/null; then break; fi
        executable="$(readlink -f "/proc/$app_pid/exe" 2>/dev/null || true)"
        if [[ "${executable##*/}" == "GrangerBrowser" ]]; then
            browser_pid="$app_pid"
            break
        fi
        browser_pid="$(pgrep -P "$app_pid" -f '/usr/bin/GrangerBrowser' | head -n 1 || true)"
        [[ -n "$browser_pid" ]] && break
        sleep 0.5
    done
    [[ -n "$browser_pid" ]] || fail "normal AppImage launch did not produce GrangerBrowser"
}

wait_for_gateway() {
    local previous="${1:-}"
    local gateway=""
    for _ in $(seq 1 120); do
        gateway="$(pgrep -P "$browser_pid" -f 'granger_network\.browser_gateway' | head -n 1 || true)"
        if [[ -n "$gateway" && "$gateway" != "$previous" ]]; then
            printf '%s\n' "$gateway"
            return 0
        fi
        kill -0 "$browser_pid" 2>/dev/null || break
        sleep 0.5
    done
    return 1
}

normal_profile="$test_root/normal-profile"
start_normal_browser "$normal_profile" normal-launch
gateway_pid="$(wait_for_gateway)" || fail "normal AppImage launch did not start Granger Network"
gateway_executable="$(readlink -f "/proc/$gateway_pid/exe")"
[[ "$gateway_executable" == */usr/bin/runtime/python/bin/python3* ]] \
    || fail "Granger Network used a non-bundled Python runtime"
browser_cwd="$(readlink -f "/proc/$browser_pid/cwd")"
[[ "$browser_cwd" == "$unrelated_cwd" ]] || fail "browser depends on the package directory as CWD"

kill -TERM "$gateway_pid"
for _ in $(seq 1 40); do
    kill -0 "$gateway_pid" 2>/dev/null || break
    sleep 0.25
done
replacement_gateway="$(wait_for_gateway "$gateway_pid")" \
    || fail "Granger Network worker did not recover after controlled termination"
[[ "$replacement_gateway" != "$gateway_pid" ]] || fail "worker recovery reused a dead process"

tracked_pids=("$gateway_pid" "$replacement_gateway")
while read -r child; do
    [[ -n "$child" ]] && tracked_pids+=("$child")
done < <(pgrep -P "$browser_pid" || true)
stop_browser
sleep 2
for pid in "${tracked_pids[@]}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        fail "project-owned child survived browser shutdown"
    fi
done

restart_profile="$test_root/restart-profile"
start_normal_browser "$restart_profile" restart-launch
restart_gateway="$(wait_for_gateway)" || fail "Granger Network did not autostart after browser restart"
stop_browser
sleep 2
if kill -0 "$restart_gateway" 2>/dev/null; then
    fail "Granger Network worker survived restart-test shutdown"
fi

startup_profile="$test_root/startup-profile"
make_profile "$startup_profile"
startup_report="$report_root/granger-network-startup.json"
(
    cd "$unrelated_cwd"
    timeout 180 env -i \
        HOME="$test_root/home" USER="${USER:-granger-test}" \
        LOGNAME="${LOGNAME:-${USER:-granger-test}}" \
        PATH=/usr/bin:/bin DISPLAY="$DISPLAY" \
        XDG_CONFIG_HOME="$startup_profile/config" \
        XDG_DATA_HOME="$startup_profile/data" \
        XDG_CACHE_HOME="$startup_profile/cache" \
        XDG_RUNTIME_DIR="$startup_profile/runtime" \
        "$detached_app" --smoke-granger-network-startup \
        "--smoke-output=$startup_report"
) >"$report_root/startup-gate.stdout.log" 2>"$report_root/startup-gate.stderr.log" \
    || fail "production-bundle startup gate failed"
jq -e '.ok == true
       and .productionBundleOnly == true
       and .runtime.appLocalRuntime == true
       and .runtime.wanConfigBundled == true
       and .runtime.wanConfigInstalled == true
       and .runtime.workerRunning == true
       and .runtime.ready == true
       and .runtime.gatewayMode == "wan"
       and .runtime.dnsRequests == 0
       and .runtime.networkHealth.state == "CONNECTED"
       and .runtime.networkHealth.dhtReady == true
       and .runtime.networkHealth.authenticatedPeers >= 2' \
    "$startup_report" >/dev/null || fail "production-bundle startup assertions failed"

sleep 2
if project_processes_present; then
    fail "normal-startup acceptance left an orphan process"
fi

artifact_sha256="$(sha256sum "$detached_app" | awk '{print toupper($1)}')"
artifact_size="$(stat --format='%s' "$detached_app")"
generation="$(jq -r '.wanConfigGeneration' "$metadata")"
expires_at="$(jq -r '.wanConfigExpiresAt' "$metadata")"
authenticated_peers="$(jq -r '.runtime.networkHealth.authenticatedPeers' "$startup_report")"
jq -n \
    --arg artifact "$(basename "$appimage")" \
    --arg sha256 "$artifact_sha256" \
    --argjson size "$artifact_size" \
    --argjson generation "$generation" \
    --argjson expiresAt "$expires_at" \
    --argjson authenticatedPeers "$authenticated_peers" \
    '{ok:true, artifact:$artifact, sha256:$sha256, sizeBytes:$size,
      normalLaunch:true, arbitraryCwd:true, pathWithSpaces:true,
      bundledRuntime:true, signedWanBundle:true, wanGeneration:$generation,
      wanExpiresAt:$expiresAt, grangerNetworkAutostart:true,
      workerRecovery:true, restart:true, orphanProcesses:0,
      connected:true, dhtReady:true, authenticatedPeers:$authenticatedPeers,
      dnsRequests:0}' >"$report_root/normal-startup-acceptance.json"

printf 'Linux normal-startup acceptance passed: %s\n' "$appimage"
