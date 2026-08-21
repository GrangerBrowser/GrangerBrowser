#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appimage="${1:-$project_root/output/linux/GrangerBrowser-0.4.4-x86_64.AppImage}"
report_root="${2:-$project_root/output/linux/acceptance/live}"
run_failover="${GRANGER_LINUX_FULL_LIVE_ACCEPTANCE:-1}"

fail() {
    printf 'Linux private-route acceptance failed: %s\n' "$*" >&2
    exit 1
}

for command_name in jq timeout ss sudo python3 Xvfb; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done
[[ -x "$appimage" ]] || fail "AppImage is unavailable: $appimage"
sudo -n true >/dev/null 2>&1 || fail "passwordless sudo is required for socket ownership sampling"
mkdir -p "$report_root"

test_root="$(mktemp -d "${TMPDIR:-/tmp}/granger-live-routes-XXXXXX")"
xvfb_pid=""
monitor_pid=""
case_pid=""
cleanup() {
    [[ -z "$monitor_pid" ]] || kill "$monitor_pid" 2>/dev/null || true
    if [[ -n "$case_pid" ]] && kill -0 "$case_pid" 2>/dev/null; then
        kill -TERM "$case_pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$case_pid" 2>/dev/null || true
    fi
    [[ -z "$xvfb_pid" ]] || kill "$xvfb_pid" 2>/dev/null || true
    rm -rf -- "$test_root"
}
trap cleanup EXIT

if [[ -z "${DISPLAY:-}" ]]; then
    export DISPLAY=:96
    Xvfb "$DISPLAY" -screen 0 1366x768x24 -nolisten tcp >"$report_root/xvfb.log" 2>&1 &
    xvfb_pid=$!
    sleep 2
fi

mkdir -p "$test_root/home" "$test_root/xdg/config" "$test_root/xdg/data" \
    "$test_root/xdg/cache" "$test_root/xdg/runtime"
chmod 0700 "$test_root/xdg/runtime"
tcp_samples="$report_root/browser-tcp-sockets.txt"
udp_samples="$report_root/browser-udp-sockets.txt"
: >"$tcp_samples"
: >"$udp_samples"

sample_sockets() {
    while true; do
        sudo -n ss -H -tnp 2>/dev/null \
            | grep -E 'GrangerBrowser|QtWebEngineProc' >>"$tcp_samples" || true
        sudo -n ss -H -unp 2>/dev/null \
            | grep -E 'GrangerBrowser|QtWebEngineProc' >>"$udp_samples" || true
        sleep 0.2
    done
}

base_env=(
    "HOME=$test_root/home"
    "USER=${USER:-runner}"
    "LOGNAME=${LOGNAME:-${USER:-runner}}"
    "DISPLAY=$DISPLAY"
    "PATH=/usr/bin:/bin"
    "XDG_CONFIG_HOME=$test_root/xdg/config"
    "XDG_DATA_HOME=$test_root/xdg/data"
    "XDG_CACHE_HOME=$test_root/xdg/cache"
    "XDG_RUNTIME_DIR=$test_root/xdg/runtime"
    "GRANGER_RUNTIME_ROOT=/nonexistent/runtime"
    "GRANGER_TOR_PATH=/nonexistent/tor"
    "GRANGER_LYREBIRD_PATH=/nonexistent/lyrebird"
    "GRANGER_TRANSPORT_PATH=/nonexistent/transport"
    "GRANGER_I2P_PATH=/nonexistent/i2pd"
    "GRANGER_I2P_CERTS=/nonexistent/i2p-certificates"
    "APPIMAGE_EXTRACT_AND_RUN=1"
)

run_case() {
    local name="$1"
    local seconds="$2"
    shift 2
    sample_sockets &
    monitor_pid=$!
    set +e
    env -i "${base_env[@]}" timeout --signal=TERM --kill-after=20 "$seconds" \
        "$appimage" "$@" >"$report_root/${name}.log" 2>&1 &
    case_pid=$!
    wait "$case_pid"
    case_exit=$?
    set -e
    case_pid=""
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
    monitor_pid=""
    [[ "$case_exit" -eq 0 ]] || fail "$name exited with code $case_exit"
}

i2p_report="$report_root/i2p-runtime.json"
run_case i2p-runtime 900 \
    --smoke-i2p-runtime "--smoke-output=$i2p_report" --smoke-timeout-ms=360000
jq -e '
    .ok == true and .firstRouteVerified == true and .secondRouteVerified == true
    and .externalB32Connected == true and .humanReadableConnected == true
    and .unknownNameBlocked == true and .stopped == true
    and .outproxyConfigured == false
' "$i2p_report" >/dev/null || fail "I2P runtime assertions failed"

tor_report="$report_root/tor-automatic.json"
run_case tor-automatic 900 \
    --smoke-automatic-route "--smoke-output=$tor_report"
jq -e '.ok == true and .routeVerified == true and .bootstrapProgress == 100' \
    "$tor_report" >/dev/null || fail "managed Tor route assertions failed"

failover_pass=true
if [[ "$run_failover" == "1" ]]; then
    for scenario in tor-loss i2p-loss both-loss; do
        scenario_report="$report_root/${scenario}.json"
        run_case "$scenario" 1200 \
            "--private-route-live-acceptance=$scenario" \
            "--acceptance-output=$scenario_report" \
            --acceptance-timeout-ms=900000
        jq -e '.ok == true and .killAccepted == true and .blockedAfterLoss == true' \
            "$scenario_report" >/dev/null \
            || { failover_pass=false; fail "$scenario assertions failed"; }
    done
fi

socket_audit="$report_root/socket-audit.json"
python3 - "$tcp_samples" "$udp_samples" "$socket_audit" <<'PY'
import ipaddress
import json
import re
import sys

tcp_path, udp_path, report_path = sys.argv[1:]

def endpoint_tokens(line):
    prefix = line.split("users:", 1)[0]
    return [token for token in prefix.split() if ":" in token]

def endpoint_ip(token):
    token = token.strip()
    if token.startswith("[") and "]" in token:
        return token[1:token.index("]")]
    host, _, _ = token.rpartition(":")
    return host.strip("[]")

def loopback(token):
    host = endpoint_ip(token)
    if host in {"*", "0.0.0.0", "::", ""}:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"

tcp_lines = sorted(set(open(tcp_path, encoding="utf-8", errors="replace").read().splitlines()))
udp_lines = sorted(set(open(udp_path, encoding="utf-8", errors="replace").read().splitlines()))
direct_tcp = []
for line in tcp_lines:
    endpoints = endpoint_tokens(line)
    if not endpoints or not loopback(endpoints[-1]):
        direct_tcp.append(line)
direct_udp = []
for line in udp_lines:
    endpoints = endpoint_tokens(line)
    if not endpoints or any(not loopback(endpoint) for endpoint in endpoints):
        direct_udp.append(line)

report = {
    "ok": not direct_tcp and not direct_udp,
    "method": "root ss process ownership sampling at 200 ms",
    "tcpSampleCount": len(tcp_lines),
    "udpSampleCount": len(udp_lines),
    "directTcp": direct_tcp,
    "directUdp": direct_udp,
}
with open(report_path, "w", encoding="utf-8") as output:
    json.dump(report, output, indent=2)
PY
jq -e '.ok == true and (.directTcp | length) == 0 and (.directUdp | length) == 0' \
    "$socket_audit" >/dev/null || fail "browser or renderer owned a non-loopback socket"

jq -n \
    --argjson failover "$failover_pass" \
    --argjson fullFailover "$([[ "$run_failover" == "1" ]] && echo true || echo false)" \
    '{ok:true,torRouting:true,i2pRouting:true,i2pB32:true,i2pHumanNaming:true,
      i2pUnknownNameBlocked:true,torRecoveryTested:$fullFailover,
      i2pRecoveryTested:true,allRoutesLossTested:$fullFailover,
      failoverPassed:$failover,directOwnedTcpSockets:0,directOwnedUdpSockets:0,
      socketSamplingIntervalMs:200,processSocketAcceptance:"PASS",
      packetLevelAcceptance:"UNVERIFIED"}' \
    >"$report_root/live-private-route-summary.json"

printf 'Linux managed Tor/I2P and fail-closed live acceptance passed.\n'
