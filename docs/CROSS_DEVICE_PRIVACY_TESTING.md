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
