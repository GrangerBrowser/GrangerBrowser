#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appimage="${1:-$project_root/output/linux/GrangerBrowser-0.4.5-x86_64.AppImage}"
report_root="${2:-$project_root/output/linux/hosting-lifecycle}"

fail() {
    printf 'Linux hosting lifecycle acceptance failed: %s\n' "$*" >&2
    exit 1
}

for command_name in jq pgrep python3 realpath; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done
[[ -x "$appimage" ]] || fail "AppImage is missing or not executable: $appimage"
[[ -d "$project_root/GrangerNetwork/examples/site" ]] \
    || fail "static hosting fixture is missing"

mkdir -p "$report_root"
report_root="$(realpath -m "$report_root")"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/granger-hosting-lifecycle-XXXXXX")"
mkdir -p "$test_root/home"
xvfb_pid=""
backend_pid=""

project_processes_present() {
    pgrep -x GrangerBrowser >/dev/null 2>&1 \
        || pgrep -f '[Q]tWebEngineProcess' >/dev/null 2>&1 \
        || pgrep -f '[g]ranger_network\.browser_gateway' >/dev/null 2>&1 \
        || pgrep -f '[g]ranger_network\.hosting serve' >/dev/null 2>&1 \
        || pgrep -f '/runtime/tor/[t]or([[:space:]]|$)' >/dev/null 2>&1 \
        || pgrep -f '/runtime/i2p/[i]2pd([[:space:]]|$)' >/dev/null 2>&1
}

cleanup() {
    if [[ -n "$backend_pid" ]] && kill -0 "$backend_pid" 2>/dev/null; then
        kill -TERM "$backend_pid" 2>/dev/null || true
        wait "$backend_pid" 2>/dev/null || true
    fi
    if [[ -n "$xvfb_pid" ]] && kill -0 "$xvfb_pid" 2>/dev/null; then
        kill -TERM "$xvfb_pid" 2>/dev/null || true
        wait "$xvfb_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

if project_processes_present; then
    fail "acceptance requires a clean Granger process state"
fi

if [[ -z "${DISPLAY:-}" ]]; then
    command -v Xvfb >/dev/null 2>&1 || fail "Xvfb is required in a headless environment"
    export DISPLAY=:95
    Xvfb "$DISPLAY" -screen 0 1366x768x24 -nolisten tcp \
        >"$report_root/xvfb.log" 2>&1 &
    xvfb_pid=$!
    sleep 2
fi

backend_ready="$test_root/backend.json"
PYTHONPATH="$project_root/GrangerNetwork/src" \
    python3 "$project_root/GrangerNetwork/tools/wan_forum_fixture.py" \
        --ready-file "$backend_ready" \
        >"$report_root/backend.log" 2>&1 &
backend_pid=$!
for _ in $(seq 1 100); do
    [[ -s "$backend_ready" ]] && break
    kill -0 "$backend_pid" 2>/dev/null || fail "local application fixture exited"
    sleep 0.1
done
[[ -s "$backend_ready" ]] || fail "local application fixture did not become ready"
backend_port="$(jq -r '.port' "$backend_ready")"
[[ "$backend_port" =~ ^[0-9]+$ ]] || fail "fixture port is invalid"

run_segment() {
    local segment="$1"
    local profile="$test_root/$segment"
    local result="$report_root/$segment.json"
    local trace="$report_root/trace-$segment"
    mkdir -p "$profile/config" "$profile/data" "$profile/cache" \
        "$profile/runtime" "$profile/granger/data" "$profile/granger/settings" "$trace"
    chmod 0700 "$profile/runtime"
    env -i \
        HOME="$test_root/home" USER="${USER:-granger-test}" \
        LOGNAME="${LOGNAME:-${USER:-granger-test}}" \
        PATH=/usr/bin:/bin DISPLAY="$DISPLAY" \
        XDG_CONFIG_HOME="$profile/config" \
        XDG_DATA_HOME="$profile/data" \
        XDG_CACHE_HOME="$profile/cache" \
        XDG_RUNTIME_DIR="$profile/runtime" \
        GRANGER_DATA_ROOT="$profile/granger/data" \
        GRANGER_SETTINGS_ROOT="$profile/granger/settings" \
        GRANGER_ACCEPTANCE_TRACE_DIR="$trace" \
        APPIMAGE_EXTRACT_AND_RUN=1 \
        python3 "$project_root/GrangerNetwork/tools/acceptance_diagnostics.py" \
        --directory "$trace" \
        --qt-trace "$result.stages.json" \
        --timeout 300 \
        -- "$appimage" \
        --smoke-granger-hosting \
        "--smoke-output=$result" \
        "--granger-hosting-source=$project_root/GrangerNetwork/examples/site" \
        "--granger-hosting-entry-page=index.html" \
        "--granger-hosting-backend-port=$backend_port" \
        "--granger-hosting-segment=$segment" \
        || {
            cp "$trace/stdout.log" "$report_root/$segment.stdout.log" 2>/dev/null || true
            cp "$trace/stderr.log" "$report_root/$segment.stderr.log" 2>/dev/null || true
            fail "$segment segment failed or exceeded 300 seconds"
        }
    cp "$trace/stdout.log" "$report_root/$segment.stdout.log"
    cp "$trace/stderr.log" "$report_root/$segment.stderr.log"
    jq -e --arg segment "$segment" '
        .ok == true and .segment == $segment
        and .dnsRequests == 0 and .directFallback == false
    ' "$result" >/dev/null || fail "$segment result assertions failed"
    jq -e '
        (.completed | length) > 0
        and ([.completed[].result] | all(. == "PASS"))
        and (.active == {})
    ' "$result.stages.json" >/dev/null || fail "$segment stage trace contains a failure"
    sleep 2
    if project_processes_present; then
        fail "$segment segment left a project-owned process"
    fi
}

run_segment content
run_segment restart
run_segment replacement

jq -n \
    --slurpfile content "$report_root/content.json" \
    --slurpfile restart "$report_root/restart.json" \
    --slurpfile replacement "$report_root/replacement.json" \
    '{
      ok: ($content[0].ok and $restart[0].ok and $replacement[0].ok),
      deadlineSecondsPerSegment: 300,
      content: {
        create: $content[0].created,
        publish: $content[0].online,
        get: $content[0].initialGet,
        assets: $content[0].assets,
        secondDocument: $content[0].secondDocument,
        stop: $content[0].stopped,
        failClosed: $content[0].offlineFailClosed,
        delete: $content[0].removed
      },
      restart: {
        stop: $restart[0].stopped,
        start: $restart[0].restarted,
        get: $restart[0].recoveryGet,
        delete: $restart[0].removed
      },
      replacement: {
        deleteA: $replacement[0].removed,
        createB: $replacement[0].replacementCreated,
        publishB: $replacement[0].replacementOnline,
        getB: $replacement[0].replacementGet,
        postB: $replacement[0].replacementPost,
        deleteB: $replacement[0].replacementRemoved
      },
      privacy: {dnsRequests: 0, directFallback: false, dnsFallback: false},
      orphanProcesses: 0
    }' >"$report_root/hosting-lifecycle-acceptance.json"

jq -e '.ok == true' "$report_root/hosting-lifecycle-acceptance.json" >/dev/null \
    || fail "aggregate lifecycle assertions failed"
printf 'Linux hosting lifecycle acceptance passed: %s\n' "$appimage"
