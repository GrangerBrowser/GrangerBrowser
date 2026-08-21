# Cross-device privacy testing

Granger's external privacy audit is local and opt-in. It does not upload
diagnostics or claim cross-device validation from one computer.

## Capture

Use the same packaged build and window size on each Windows test computer. Give
each run fresh data and settings roots, then run:

```powershell
& '.\GrangerBrowser.exe' `
  --smoke-external-privacy-audit `
  --smoke-output='C:\GrangerAudit\external-audit.json' `
  --smoke-capture-dir='C:\GrangerAudit\captures'
```

The audit must report a verified Tor route and must not modify the production
privacy policy. Keep the JSON locally and transfer it by a method chosen by the
tester; Granger does not upload it.

The packaged audit now fails when the first external Tor document receives a
screen identity that does not match its physical letterboxed viewport. Confirm
these fields before comparing machines:

```text
ok = true
routeVerified = true
firstDocumentPolicyConfirmed = true
firstDocumentEvidence.viewportBucketed = true
strictEvidence.viewportBucketed = true
strictEvidence.screenStandardized = true
```

Run the audit again after each of these changes, using the same application
window size for the pair being compared:

| Variable | Suggested values |
| --- | --- |
| Monitor | 1366x768, 1920x1080, 2560x1440 when physically available |
| Windows scaling | 100%, 125%, 150%, 175%, 200% |
| Window | restored, maximized, fullscreen |
| Sidebar | hidden, compact, expanded |

Do not infer a physical monitor or DPI result that was not actually measured.

## Controlled delayed surfaces

Run the packaged controlled privacy suite on each machine as well:

```powershell
& '.\GrangerBrowser.exe' `
  --smoke-privacy-tests `
  --smoke-output='C:\GrangerAudit\privacy-tests.json'
```

The suite samples `speechSynthesis.getVoices()` immediately, after 100 ms,
after 1 second, and after 5 seconds, including `voiceschanged`. It also samples
`enumerateDevices()` before permission and checks that camera, microphone,
geolocation, clipboard, and notification session decisions are scoped to one
Space. It does not simulate a user granting access to physical hardware.

For an after-permission hardware check, use a disposable origin and fresh Space:

1. Record `enumerateDevices()` before permission.
2. Grant one requested camera or microphone permission through the real prompt.
3. Record count, label, `deviceId`, and `groupId` after permission.
4. Revoke the permission and repeat in a new tab, another Space, and after restart.
5. Keep the reports local and remove the disposable Space when finished.

Tor profile WebRTC remains disabled by policy, so a Tor test must not manufacture
a successful camera or microphone grant merely to populate the report.

## Compare

From the source checkout, compare reports captured on distinct machines:

```powershell
.\scripts\compare-privacy-audits.ps1 `
  -ReportPath 'D:\PC-A\external-audit.json','D:\PC-B\external-audit.json' `
  -OutputPath 'output\cross-device-comparison.json'
```

The comparator excludes route-specific exit IP, circuit, and resolver rows. It
compares the standardized JavaScript surface, font hashes, API restrictions,
and normalized transport signatures. With only one report it returns
`pending-second-device`, not a successful cross-device claim.

A match is evidence that the measured surfaces are uniform for those runs. It
is not a promise of anonymity and does not eliminate every Qt/Chromium or
network-layer fingerprint.

## VPN, TUN, system proxy, and Xray

The network-environment smoke records local Windows route/proxy evidence without
making a direct fallback request:

```powershell
& '.\GrangerBrowser.exe' `
  --smoke-network-environment `
  --smoke-output='C:\GrangerAudit\network-environment.json'
```

For each real environment (no VPN, VPN/TUN, Xray TUN, Xray system proxy, local
SOCKS5, and local HTTP proxy), start Granger with a fresh profile and apply the
managed Tor-without-bridges strategy. Record bootstrap progress, route verification,
the redacted network diagnosis, and the last Tor error. Repeat with the network
tool enabled before startup and enabled after startup. A detected VPN alone is
not a failure; the conflict warning is valid only after Tor actually fails and
the local evidence identifies a probable conflict.

Never mark a scenario as passed when Tor did not reach route verification. A
Tor failure must remain fail-closed, with no browser, DNS, download, favicon,
WebSocket, or background request switched to Direct.
