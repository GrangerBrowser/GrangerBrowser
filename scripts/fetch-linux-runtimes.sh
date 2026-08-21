#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_root="$project_root/output"
destination="${1:-$output_root/linux-runtimes}"

tor_bundle_version="15.0.20"
tor_version="0.4.9.11"
lyrebird_version="0.8.1"
tor_asset="tor-expert-bundle-linux-x86_64-${tor_bundle_version}.tar.gz"
tor_url="https://archive.torproject.org/tor-package-archive/torbrowser/${tor_bundle_version}/${tor_asset}"
tor_signature_url="${tor_url}.asc"
tor_key_url="https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf"
tor_archive_sha256="3b39a2a7fbf43ef28b9ae0a6afca02a12935232f81769e4fef7472d6b5676eaf"
tor_signature_sha256="174428a9f7449d812954ba1b213913d935efb995a670f1c43b788289946c93a0"
tor_key_sha256="c2ed2cb463bf384630f2c746448399ab944c3aeade4619f940f07372a57780d7"
tor_key_fingerprint="EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"

i2pd_version="2.61.0"
i2pd_asset="i2pd_2.61.0-1jammy1_amd64.deb"
i2pd_url="https://github.com/PurpleI2P/i2pd/releases/download/${i2pd_version}/${i2pd_asset}"
i2pd_archive_sha256="09348999d4561c46037e3cc2aa2b9d76ec7ac3007db2c1d4a9f92b20b9ca8687"
i2pd_binary_sha256="252823e8f3dde6232d2a178027d2a249afa81b7a4595273bcdb4cd3500852b1"

fail() {
    printf 'Linux runtime staging failed: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

for command_name in curl sha256sum tar gpg dpkg-deb find; do
    require_command "$command_name"
done

mkdir -p "$output_root"
output_root="$(realpath -m "$output_root")"
destination="$(realpath -m "$destination")"
case "$destination" in
    "$output_root"/*) ;;
    *) fail "runtime output must remain below $output_root" ;;
esac

download_root="$output_root/third-party/linux-downloads"
mkdir -p "$download_root"

download_pinned() {
    local url="$1"
    local path="$2"
    local expected="$3"
    if [[ ! -f "$path" ]]; then
        curl --fail --location --proto '=https' --tlsv1.2 \
            --retry 3 --output "${path}.part" "$url"
        mv -- "${path}.part" "$path"
    fi
    printf '%s  %s\n' "$expected" "$path" | sha256sum --check --status \
        || fail "SHA-256 mismatch for $(basename "$path")"
}

tor_archive="$download_root/$tor_asset"
tor_signature="$download_root/${tor_asset}.asc"
tor_key="$download_root/tor-browser-developers-key.gpg"
download_pinned "$tor_url" "$tor_archive" "$tor_archive_sha256"
download_pinned "$tor_signature_url" "$tor_signature" "$tor_signature_sha256"
download_pinned "$tor_key_url" "$tor_key" "$tor_key_sha256"

gpg_home="$(mktemp -d "$output_root/.gnupg-tor-linux-XXXXXX")"
tor_extract="$(mktemp -d "$output_root/.tor-linux-XXXXXX")"
i2pd_extract="$(mktemp -d "$output_root/.i2pd-linux-XXXXXX")"
cleanup() {
    rm -rf -- "$gpg_home" "$tor_extract" "$i2pd_extract"
}
trap cleanup EXIT
chmod 700 "$gpg_home"
gpg --batch --homedir "$gpg_home" --import "$tor_key" >/dev/null 2>&1
gpg --batch --homedir "$gpg_home" --with-colons --fingerprint \
    | grep -Fq "fpr:::::::::${tor_key_fingerprint}:" \
    || fail "Tor signing-key fingerprint mismatch"
signature_status="$(gpg --batch --homedir "$gpg_home" --status-fd 1 \
    --verify "$tor_signature" "$tor_archive" 2>&1)" \
    || fail "Tor archive signature validation failed"
grep -Fq "[GNUPG:] VALIDSIG ${tor_key_fingerprint}" <<<"$signature_status" \
    || fail "Tor archive was not signed by the pinned Tor Browser Developers key"

if tar -tzf "$tor_archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    fail "Tor archive contains an unsafe path"
fi
tar -xzf "$tor_archive" -C "$tor_extract"

declare -A tor_file_hashes=(
    ["tor/tor"]="3d3d7c6bdcaf0f55d55a7c28f2ea6c52cb3d2785a6bd9e466bdfb29e841f2780"
    ["tor/pluggable_transports/lyrebird"]="63f1fd917851e406cfe8ae5750c6a9ca1c48ca59dd3195f207ac15af2efa1522"
    ["tor/pluggable_transports/conjure-client"]="10cf795f21f136a38c1989dc93b6b687a9d30a91775873f006524b08634732c0"
    ["tor/pluggable_transports/pt_config.json"]="2f7cf039710e96b70ea7d45473b905f9a6ce9a8b65e9f03e2507135ae8c75407"
    ["data/geoip"]="af9ccd060a712d090ee07d5678b5d45b0038ec1573116fae724a6695a8485703"
    ["data/geoip6"]="2393124667ba2cc4c806f226a33b2ef7a8188d1ba55831c1a5d3dca2b062514"
)
for relative_path in "${!tor_file_hashes[@]}"; do
    file_path="$tor_extract/$relative_path"
    [[ -f "$file_path" ]] || fail "Tor archive is missing $relative_path"
    printf '%s  %s\n' "${tor_file_hashes[$relative_path]}" "$file_path" \
        | sha256sum --check --status || fail "unexpected Tor file: $relative_path"
done

tor_output="$(LD_LIBRARY_PATH="$tor_extract/tor" "$tor_extract/tor/tor" --version 2>&1)"
grep -Eq "^Tor version ${tor_version}([ .]|$)" <<<"$tor_output" \
    || fail "unexpected Tor version: $tor_output"
lyrebird_output="$("$tor_extract/tor/pluggable_transports/lyrebird" --version 2>&1)"
grep -Eq "^lyrebird ${lyrebird_version}([ .]|$)" <<<"$lyrebird_output" \
    || fail "unexpected lyrebird version: $lyrebird_output"

i2pd_archive="$download_root/$i2pd_asset"
download_pinned "$i2pd_url" "$i2pd_archive" "$i2pd_archive_sha256"
[[ "$(dpkg-deb --field "$i2pd_archive" Architecture)" == "amd64" ]] \
    || fail "i2pd package architecture is not amd64"
[[ "$(dpkg-deb --field "$i2pd_archive" Version)" == "2.61.0-1jammy1" ]] \
    || fail "i2pd package version mismatch"
dpkg-deb --extract "$i2pd_archive" "$i2pd_extract"
printf '%s  %s\n' "$i2pd_binary_sha256" "$i2pd_extract/usr/bin/i2pd" \
    | sha256sum --check --status || fail "i2pd binary hash mismatch"
certificate_count="$(find "$i2pd_extract/usr/share/i2pd/certificates" -type f | wc -l)"
[[ "$certificate_count" -ge 20 ]] || fail "i2pd certificate bundle is incomplete"
i2pd_output="$("$i2pd_extract/usr/bin/i2pd" --version 2>&1)"
grep -Fq "$i2pd_version" <<<"$i2pd_output" \
    || fail "unexpected i2pd version: $i2pd_output"

rm -rf -- "$destination"
mkdir -p "$destination/tor/data" "$destination/i2p"
cp -a "$tor_extract/tor/tor" "$tor_extract/tor/"*.so.* "$destination/tor/"
cp -a "$tor_extract/tor/pluggable_transports" "$destination/tor/"
cp -a "$tor_extract/data/geoip" "$tor_extract/data/geoip6" "$destination/tor/data/"
cp -a "$tor_extract/docs" "$destination/tor/"
cp -a "$i2pd_extract/usr/bin/i2pd" "$destination/i2p/"
cp -a "$i2pd_extract/usr/share/i2pd/certificates" "$destination/i2p/"
cp -a "$project_root/third_party/i2pd/LICENSE" "$destination/i2p/LICENSE.txt"

cat >"$destination/runtime-metadata.json" <<EOF
{
  "platform": "linux-x86_64",
  "torBundleVersion": "$tor_bundle_version",
  "torVersion": "$tor_version",
  "torSource": "$tor_url",
  "torArchiveSha256": "${tor_archive_sha256^^}",
  "torSignatureVerified": true,
  "torSigningKeyFingerprint": "$tor_key_fingerprint",
  "torSha256": "${tor_file_hashes[tor/tor]^^}",
  "lyrebirdVersion": "$lyrebird_version",
  "lyrebirdSha256": "${tor_file_hashes[tor/pluggable_transports/lyrebird]^^}",
  "conjureSha256": "${tor_file_hashes[tor/pluggable_transports/conjure-client]^^}",
  "i2pdVersion": "$i2pd_version",
  "i2pdSource": "$i2pd_url",
  "i2pdArchiveSha256": "${i2pd_archive_sha256^^}",
  "i2pdSha256": "${i2pd_binary_sha256^^}",
  "i2pdCertificateCount": $certificate_count,
  "i2pdLicense": "BSD-3-Clause"
}
EOF

printf 'Linux privacy runtimes staged at %s\n' "$destination"
