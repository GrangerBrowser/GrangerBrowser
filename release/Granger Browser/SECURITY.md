# Security Policy

## Supported Release

Security fixes target the current packaged Granger Browser release. Reports
should include the exact application version, Qt version, Qt WebEngine version,
and Chromium version shown by the affected build.

## Reporting A Vulnerability

Use the repository host's private security-advisory feature when it is
available. Otherwise, contact the maintainer privately through the same channel
that supplied the source or release. Do not publish exploit details before the
maintainer has had a reasonable opportunity to investigate and ship a fix.

Include reproducible steps, expected and actual behavior, the affected URL or
component, and a minimal test artifact when one is necessary. Remove secrets
and personal data before sending a report.

Never attach a production browser profile, cookies, credentials, browsing
history, real private bridge lines, generated torrc files, or logs containing
sensitive origins. Use an isolated test profile and synthetic bridge data.

## Scope

Useful reports include direct-network fallback, DNS or WebRTC leaks, profile or
Space isolation failures, unsafe filesystem cleanup, certificate-validation
bypass, internal-page privilege escalation, package tampering, and disclosure
of user data. Tor exit behavior, global traffic correlation, compromised host
systems, and third-party site vulnerabilities are outside the application's
control unless Granger Browser introduces the exposure.

Granger Browser does not promise anonymity. Connection, bootstrap, and browser
route verification are separate states and should be reported separately.
