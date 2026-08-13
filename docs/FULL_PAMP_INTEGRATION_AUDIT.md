# Full Pamp integration audit

Audit date: 2026-08-13

## Scope

The sibling `pentest` checkout is the full Python Pamp application. It is not
Pamp Lite and is not part of the Granger Browser source tree or runtime.

Audited revision:

`c544c38a48d4c186a02cc7f7d854f942bd8ce152`

The checkout contained user/runtime changes before the audit. They were not
reset, deleted, staged, or copied into the browser repository.

## Verification

The tracked Pamp test suite was run with `PYTHONDONTWRITEBYTECODE=1`:

- Python 3.14.5
- 50 tests passed
- 0 tests failed
- no new checkout changes were produced by the test run

The test result verifies the currently installed development environment. It
does not prove that Pamp can be embedded safely in Granger Browser.

The audit was repeated on 2026-08-13 with `PYTHONDONTWRITEBYTECODE=1` against
the same revision and the pre-existing dirty checkout state. Python 3.14.5 ran
all 50 tracked unit tests in 1.241 seconds: 50 passed and 0 failed. The test run
did not add another checkout change. No active target scan was launched.

## Production decision

Full Pamp is deliberately not packaged in Granger Browser. The audited source
does not currently satisfy the browser's production route and licensing gates:

1. There is no repository-level license grant in the Pamp checkout.
2. Network modules call `requests`, `socket`, Playwright Chromium, and `nmap`
   directly. They do not consume Granger's verified-route contract.
3. Playwright creates a separate browser/network context and could bypass the
   current QWebEngine profile, request interceptor, DNS policy, and fail-closed
   route state.
4. Packaging would require a Python runtime and third-party dependency/license
   inventory that the current desktop release intentionally does not ship.
5. Active scanning behavior requires a separate authorization and product
   policy; it must not be invoked implicitly from ordinary browsing.

Copying or obfuscating the Python files would not fix any of these properties.
It would only hide an unsafe integration.

## Release invariant

The packaged browser contains the native C++ Pamp Lite implementation and its
attribution. It must not contain a `pentest` or full-Pamp directory, a Python
executable, app-local Python DLLs, or Python source/module payloads. Package
creation, canonical promotion, and copied-package acceptance independently
reject full-Pamp directories and `.py`, `.pyc`, `.pyz`, `.pyd`, or `.whl`
payloads. The packaged feature smoke also verifies that Pamp Lite attribution is
compiled while neither a `pentest` nor `pamp` runtime directory is present.

## Requirements before integration

Full Pamp can become a production component only after all of the following are
implemented and reviewed:

- an explicit repository-level license and complete dependency notices;
- one network adapter that rejects work without a verified Granger route;
- SOCKS remote-DNS handling for every HTTP, socket, Playwright, and scanner path;
- route-loss cancellation with a network-level no-direct-fallback test;
- a dedicated, non-persistent identity boundary and explicit user authorization;
- deterministic packaging plus detection, import, runtime, and packaged tests.

Until then, keeping full Pamp separate is the privacy-preserving result, not a
missing asset-protection step.
