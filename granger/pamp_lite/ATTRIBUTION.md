# Pamp Lite integration

Granger Browser Pamp Lite is a clean-room native C++ implementation. It uses the
general idea of a structured, explainable security report after an architectural
review of the local `pentest`/Pamp material, but it does not copy that project's
Python implementation, templates, branding, active scanners, or assets.

The reviewed project has no repository-level license file. For that reason no
source code from it is incorporated into Granger Browser and no license grant is
assumed.

Included capabilities are deliberately passive:

- an immutable snapshot of browser state already available to Qt WebEngine;
- fixed DNS-over-HTTPS queries to Cloudflare's documented endpoint;
- RDAP bootstrap queries through `https://rdap.org/`;
- IP-to-ASN DNS mapping through Team Cymru's documented public service;
- local, explainable report generation.

Every enrichment request uses a hidden `QWebEnginePage` attached to the source
profile. The browser's configured proxy, request interceptor, content policy,
and Tor route therefore remain in force. There is no system resolver, raw
socket, Python worker, localhost API, port scan, crawler, exploit request, or
direct-network fallback.

Public protocol and service references:

- RFC 9082 and RFC 9083, Registration Data Access Protocol
- IANA RDAP bootstrap registries
- Cloudflare DNS-over-HTTPS JSON API documentation
- Team Cymru IP-to-ASN Mapping Service documentation
