# Granger Browser Content Blocking sources

Granger Browser Content Blocking is a native Qt WebEngine request interceptor. It is not uBlock Origin.

| List | Distribution | Update URL | License | Default |
| --- | --- | --- | --- | --- |
| EasyList | Bundled snapshot plus controlled update | https://easylist.to/easylist/easylist.txt | GPL-3.0-or-later OR CC-BY-SA-3.0-or-later; bundled under CC BY-SA | Enabled in Standard/Strict |
| EasyPrivacy | Bundled snapshot plus controlled update | https://easylist.to/easylist/easyprivacy.txt | GPL-3.0-or-later OR CC-BY-SA-3.0-or-later; bundled under CC BY-SA | Enabled in Standard/Strict |
| AdGuard URL Tracking Protection | Downloaded to user data after a validated update | https://filters.adtidy.org/extension/ublock/filters/17.txt | GPL-3.0-only | Enabled when a valid cache exists |
| AdGuard Russian filter | Downloaded to user data after a validated update | https://filters.adtidy.org/extension/ublock/filters/1.txt | GPL-3.0-only | Controlled by Russian regional filter setting |
| Granger Browser supplements | Bundled project-maintained data | Local resource | Granger Browser project terms | Purpose-specific |

Updates are made only to the fixed URLs above. Granger Browser does not include the current page, browsing history, search terms, cookies, or profile identifiers in update requests. Responses have a 20 MB limit and 20 second timeout, must decode as UTF-8, must meet a source-specific minimum rule count, and are replaced atomically with `QSaveFile`. A failed validation leaves the previous list active.

Supported syntax includes host and URL patterns, `||`/`|` anchors, wildcards and separators, first/third-party conditions, common resource types, domain includes/excludes, `important`, exceptions, supported cosmetic selectors, `badfilter`, and simple named `removeparam`. Unsupported procedural cosmetic filters, scriptlets, response rewriting, CSP injection, extension redirects, and arbitrary regular-expression `removeparam` values are counted and skipped.
