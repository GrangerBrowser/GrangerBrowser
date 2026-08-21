#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
appimage="${1:-$project_root/output/linux/GrangerBrowser-0.4.4-x86_64.AppImage}"
report_root="${2:-$project_root/output/linux/acceptance}"
report="$report_root/network-namespace-fail-closed.json"

mkdir -p "$report_root"

skip() {
    jq -n --arg reason "$1" \
        '{ok:false,status:"UNVERIFIED",reason:$reason,packetLevelAcceptance:"UNVERIFIED"}' \
        >"$report"
    printf 'Linux network namespace acceptance unavailable: %s\n' "$1" >&2
    exit 77
}

for command_name in ip tcpdump jq python3 timeout sudo Xvfb; do
    command -v "$command_name" >/dev/null 2>&1 || skip "missing command: $command_name"
done
[[ -x "$appimage" ]] || skip "AppImage is unavailable"
sudo -n true >/dev/null 2>&1 || skip "passwordless sudo is unavailable"

suffix="$$"
namespace="granger-fc-$suffix"
host_if="gfh$suffix"
ns_if="gfn$suffix"
octet=$((suffix % 180 + 20))
host_address="10.203.${octet}.1"
namespace_address="10.203.${octet}.2"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/granger-fail-closed-XXXXXX")"
pcap="$report_root/network-namespace-fail-closed.pcap"
listener_log="$report_root/network-namespace-listener.log"
xvfb_log="$report_root/network-namespace-xvfb.log"
tcpdump_pid=""
listener_pid=""
xvfb_pid=""

cleanup() {
    if [[ -n "$tcpdump_pid" ]]; then
        sudo -n kill "$tcpdump_pid" 2>/dev/null || true
        wait "$tcpdump_pid" 2>/dev/null || true
    fi
    if [[ -n "$listener_pid" ]]; then
        kill "$listener_pid" 2>/dev/null || true
        wait "$listener_pid" 2>/dev/null || true
    fi
    if [[ -n "$xvfb_pid" ]]; then
        kill "$xvfb_pid" 2>/dev/null || true
        wait "$xvfb_pid" 2>/dev/null || true
    fi
    sudo -n ip link delete "$host_if" 2>/dev/null || true
    sudo -n ip netns delete "$namespace" 2>/dev/null || true
    sudo -n chown -R "$(id -u):$(id -g)" "$report_root" 2>/dev/null || true
    rm -rf -- "$test_root"
}
trap cleanup EXIT

if ! sudo -n ip netns add "$namespace"; then
    skip "kernel denied network namespace creation"
fi
sudo -n ip link add "$host_if" type veth peer name "$ns_if"
sudo -n ip link set "$ns_if" netns "$namespace"
sudo -n ip address add "$host_address/24" dev "$host_if"
sudo -n ip link set "$host_if" up
sudo -n ip netns exec "$namespace" ip link set lo up
sudo -n ip netns exec "$namespace" ip address add "$namespace_address/24" dev "$ns_if"
sudo -n ip netns exec "$namespace" ip link set "$ns_if" up
sudo -n ip netns exec "$namespace" ip route add default via "$host_address"
sudo -n sysctl -q -w "net.ipv6.conf.${host_if}.disable_ipv6=1" >/dev/null || true
sudo -n ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null || true

python3 -m http.server 18080 --bind "$host_address" >"$listener_log" 2>&1 &
listener_pid=$!
export DISPLAY=:98
Xvfb "$DISPLAY" -screen 0 1280x720x24 -nolisten tcp >"$xvfb_log" 2>&1 &
xvfb_pid=$!
sleep 2

mkdir -p "$test_root/home" "$test_root/xdg/config" "$test_root/xdg/data" \
    "$test_root/xdg/cache" "$test_root/xdg/runtime"
chmod 0700 "$test_root/xdg/runtime"

sudo -n ip netns exec "$namespace" tcpdump -U -i any -nn \
    -w "$pcap" "host $host_address or port 53" >/dev/null 2>&1 &
tcpdump_pid=$!
sleep 1

namespace_env=(
    "HOME=$test_root/home"
    "USER=${USER:-runner}"
    "LOGNAME=${LOGNAME:-${USER:-runner}}"
    "DISPLAY=$DISPLAY"
    "PATH=/usr/bin:/bin"
    "XDG_CONFIG_HOME=$test_root/xdg/config"
    "XDG_DATA_HOME=$test_root/xdg/data"
    "XDG_CACHE_HOME=$test_root/xdg/cache"
    "XDG_RUNTIME_DIR=$test_root/xdg/runtime"
    "QTWEBENGINE_DISABLE_SANDBOX=1"
    "QTWEBENGINE_CHROMIUM_FLAGS=--no-sandbox --no-proxy-server --proxy-bypass-list=*"
    "APPIMAGE_EXTRACT_AND_RUN=1"
)

run_in_namespace() {
    sudo -n ip netns exec "$namespace" sudo -n -u "${USER:-runner}" \
        env -i "${namespace_env[@]}" timeout 60 "$appimage" "$@"
}

set +e
run_in_namespace \
    "--smoke-url=http://${host_address}:18080/direct-path-probe" \
    "--smoke-output=$report_root/non-loopback-navigation.json" \
    >"$report_root/non-loopback-navigation.log" 2>&1
non_loopback_exit=$?
run_in_namespace \
    "--smoke-url=http://granger-network-negative-test.invalid.i2p/" \
    "--smoke-output=$report_root/i2p-dns-navigation.json" \
    >"$report_root/i2p-dns-navigation.log" 2>&1
i2p_exit=$?
run_in_namespace --no-sandbox \
    "--smoke-url=http://${host_address}:18080/no-sandbox-probe" \
    "--smoke-output=$report_root/no-sandbox-rejection.json" \
    >"$report_root/no-sandbox-rejection.log" 2>&1
no_sandbox_exit=$?
run_in_namespace --no-proxy-server \
    "--smoke-url=http://${host_address}:18080/no-proxy-probe" \
    "--smoke-output=$report_root/no-proxy-rejection.json" \
    >"$report_root/no-proxy-rejection.log" 2>&1
no_proxy_exit=$?
set -e

sleep 2
sudo -n kill "$tcpdump_pid" 2>/dev/null || true
wait "$tcpdump_pid" 2>/dev/null || true
tcpdump_pid=""
sudo -n chown "$(id -u):$(id -g)" "$pcap" 2>/dev/null || true
packet_count="$(tcpdump -nn -r "$pcap" 2>/dev/null | wc -l)"
listener_requests="$(grep -Ec '"(GET|POST|CONNECT|HEAD) ' "$listener_log" || true)"

non_loopback_blocked=false
i2p_blocked=false
if [[ "$non_loopback_exit" -ne 0 ]] && jq -e '
    .ok == false and .blockedTestGateway == true
    and (.startupProcessProxy | startswith("socks5://127.0.0.1:"))
    and (.chromiumFlags | contains("--host-resolver-rules=MAP * ~NOTFOUND"))
    and (.chromiumFlags | contains("--no-sandbox") | not)
    and (.chromiumFlags | contains("--no-proxy-server") | not)
' "$report_root/non-loopback-navigation.json" >/dev/null 2>&1; then
    non_loopback_blocked=true
fi
if [[ "$i2p_exit" -ne 0 ]] && jq -e '
    .ok == false and .blockedTestGateway == true
    and (.chromiumFlags | contains("--host-resolver-rules=MAP * ~NOTFOUND"))
' "$report_root/i2p-dns-navigation.json" >/dev/null 2>&1; then
    i2p_blocked=true
fi

ok=false
if [[ "$non_loopback_blocked" == true && "$i2p_blocked" == true \
      && "$no_sandbox_exit" -eq 8 && "$no_proxy_exit" -eq 8 \
      && "$packet_count" -eq 0 && "$listener_requests" -eq 0 ]]; then
    ok=true
fi

jq -n \
    --argjson ok "$ok" \
    --arg namespace "$namespace" \
    --arg hostInterface "$host_if" \
    --arg target "$host_address:18080" \
    --argjson packets "$packet_count" \
    --argjson requests "$listener_requests" \
    --argjson nonLoopbackBlocked "$non_loopback_blocked" \
    --argjson i2pBlocked "$i2p_blocked" \
    --argjson noSandboxExit "$no_sandbox_exit" \
    --argjson noProxyExit "$no_proxy_exit" \
    '{ok:$ok,status:(if $ok then "PASS" else "FAIL" end),
      method:"network namespace + veth + tcpdump",
      namespace:$namespace,hostInterface:$hostInterface,target:$target,
      capturedPackets:$packets,listenerRequests:$requests,
      directTcpPackets:$packets,directUdpPackets:$packets,systemDnsPackets:$packets,
      nonLoopbackNavigationBlocked:$nonLoopbackBlocked,
      i2pNavigationBlockedWithoutDns:$i2pBlocked,
      noSandboxArgumentExit:$noSandboxExit,noProxyArgumentExit:$noProxyExit,
      packetLevelAcceptance:(if $ok then "PASS" else "FAIL" end)}' \
    >"$report"

[[ "$ok" == true ]] || fail "network namespace observed a fail-closed regression"
printf 'Linux network namespace fail-closed acceptance passed. Captured packets: %s\n' "$packet_count"
