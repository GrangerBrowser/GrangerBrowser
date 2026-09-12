# Windows Artifact Signing

No trusted project code-signing certificate is configured in the inspected
CurrentUser certificate store. Actual trusted signing is blocked until the
maintainer provisions a legitimate certificate/provider. Do not generate a
self-signed substitute, export signing keys, alter Defender, or remove
Mark-of-the-Web to suppress warnings.

## Current Artifact Chain

1. `scripts/compile-release.ps1` produces the project browser executable.
2. `scripts/package-release.ps1` deploys Qt and other runtime dependencies.
3. `scripts/package-local-granger-runtime.ps1` adds the Python network runtime.
4. Package metadata and portable ZIP hashes are computed.
5. `scripts/New-InstallerManifest.ps1` binds the package hash and metadata.
6. `scripts/build-installer.ps1` embeds that ZIP and manifest in a native setup.

For a future authorized signed release, sign the project-owned browser binary
before step 2, verify the staged copy before steps 4-5, then sign and timestamp
the finished installer after step 6. Recompute final installer hashes after
signing. Do not re-sign Qt, Microsoft, Python, Tor, or other third-party files.
Do not modify a signed file after verification. A signed executable does not
authenticate an independently replaced Python source tree; packaged runtime
integrity and a signed update manifest are separate required checks.

The future signing operation should use the certificate store or an approved
HSM-backed provider through Windows SDK SignTool. Select the authorized public
certificate thumbprint explicitly; do not select an arbitrary store certificate.
Use SHA-256 file digests and RFC 3161 timestamps with SHA-256 timestamp digests.
Verify with the Authenticode policy (`verify /pa /all /tw`) and require a valid
timestamp, expected publisher, and successful trust verification. Run signing
only against an isolated release candidate and keep the last accepted package
until the signed candidate passes acceptance.

## Read-only Audit

`scripts/Sign-WindowsCandidate.ps1` provides the explicit signing hook for an
owner-provisioned CurrentUser certificate/HSM provider. It accepts only the two
project-owned executables in build or isolated candidate directories. It rejects
missing/expired/non-code-signing certificates and non-Microsoft signing tools.
The certificate is consumed through SignTool; no key is read or exported.

Required parameters are `-Path`, `-CertificateThumbprint`, `-TimestampUrl`, and
`-SignToolPath`. The timestamp endpoint must be the owner's approved HTTPS
RFC 3161 endpoint. No endpoint or publisher is selected automatically. The hook
signs with `/fd SHA256 /td SHA256`, timestamps, verifies, then reports the final
hash. It does not run as part of an ordinary unsigned local build. Missing
credentials remain a hard blocker, not a reason to create a replacement.

The independently signed installer can feed the
[verified update preparation pipeline](ReleaseUpdates.md); that pipeline's
release-authority pin also remains unconfigured.

```powershell
./scripts/Test-WindowsArtifactTrust.ps1 -Path @(
    'release/.local-staging/GrangerBrowser.exe',
    'output/distribution/GrangerSetup.exe'
)
```

`-RequireTrustedSignature` makes an unsigned, invalid, untimestamped, or
unexpected-publisher artifact fail the gate. `-ExpectedCertificateThumbprint`
accepts only the public certificate identifier, never a key or password.
This audit does not sign artifacts or change Windows trust policy.

Unknown publisher, certificate validation failure, reputation warning, PUA and
malware detection are distinct outcomes. Signing alone does not guarantee that
SmartScreen reputation warnings disappear. A real first-launch test on a clean
machine remains necessary.

References: [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool),
[Microsoft Defender SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/).
