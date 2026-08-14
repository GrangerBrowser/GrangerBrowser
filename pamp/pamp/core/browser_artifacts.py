from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .models import digest_value, mask_value


SERVICE_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Google Analytics", "analytics", ("google-analytics.com", "/analytics.js", "gtag/js", "_ga=")),
    ("Google Tag Manager", "tag manager", ("googletagmanager.com", "gtm.js")),
    ("Yandex Metrica", "analytics", ("mc.yandex", "metrika", "yandex.ru/metrika")),
    ("Hotjar", "analytics", ("hotjar.com", "hj.js")),
    ("Cloudflare", "cdn/security", ("cloudflare", "cf-ray", "cdnjs.cloudflare.com")),
    ("Sentry", "error monitoring", ("sentry.io", "sentry-cdn.com", "__sentry")),
    ("Intercom", "support", ("intercom.io", "intercomcdn.com")),
    ("Stripe", "payments", ("js.stripe.com", "api.stripe.com")),
    ("Facebook Pixel", "analytics", ("connect.facebook.net", "fbevents.js", "_fbp")),
    ("Telegram Widgets", "widget", ("telegram.org/js/telegram-widget", "t.me/")),
    ("YouTube", "media", ("youtube.com", "youtu.be", "youtube-nocookie.com")),
    ("CDN", "cdn", ("cdn.jsdelivr.net", "unpkg.com", "gstatic.com", "akamai", "cloudfront.net", "fastly")),
)
SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
PUBLIC_KEY_RE = re.compile(r"\b(?:pk_(?:live|test)_[A-Za-z0-9_]+|AIza[0-9A-Za-z_-]{20,}|-----BEGIN PUBLIC KEY-----)", re.I)
FEATURE_FLAG_RE = re.compile(r"\b(?:feature[_-]?flags?|enable[A-Z][A-Za-z0-9_]+|is[A-Z][A-Za-z0-9_]+Enabled)\b")


def sanitize_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "")
        domain = str(cookie.get("domain") or "")
        path = str(cookie.get("path") or "")
        if not name:
            continue
        key = f"{domain}|{path}|{name}"
        if key in seen:
            continue
        seen.add(key)
        value = cookie.get("value", "")
        output.append(
            {
                "name": name,
                "domain": domain,
                "path": path,
                "expires": cookie.get("expires"),
                "secure": bool(cookie.get("secure", False)),
                "httponly": bool(cookie.get("httpOnly", cookie.get("httponly", False))),
                "samesite": str(cookie.get("sameSite") or cookie.get("samesite") or ""),
                "size": len(str(value or "")),
                "value_preview": mask_value(value),
                "value_digest": digest_value(value),
            }
        )
    output.sort(key=lambda item: (item.get("domain") or "", item.get("name") or ""))
    return output[:240]


def interpret_security_headers(headers: dict[str, Any]) -> list[dict[str, str]]:
    normalized = {str(key).lower(): str(value or "") for key, value in (headers or {}).items()}
    rows = []
    for header in SECURITY_HEADERS:
        raw_value = normalized.get(header.lower(), "")
        value = "" if raw_value.strip().lower() == "missing" else raw_value
        rows.append(
            {
                "header": header,
                "value": value or "missing",
                "status": "present" if value else "missing",
                "interpretation": _header_interpretation(header, value),
            }
        )
    return rows


def detect_third_party_services(network_requests: list[dict[str, Any]], html: str = "") -> list[dict[str, str]]:
    haystack_items = [html or ""]
    for request in network_requests or []:
        haystack_items.append(str(request.get("url") or ""))
        haystack_items.append(str(request.get("response_headers") or ""))
    haystack = "\n".join(haystack_items).lower()
    services = []
    for name, service_type, patterns in SERVICE_PATTERNS:
        matched = [pattern for pattern in patterns if pattern.lower() in haystack]
        if not matched:
            continue
        where = _service_locations(network_requests, patterns)
        services.append(
            {
                "name": name,
                "type": service_type,
                "source": ", ".join(matched[:3]),
                "where_found": ", ".join(where[:4]) or "HTML/network",
            }
        )
    return services


def build_javascript_intelligence(
    network_requests: list[dict[str, Any]],
    js_findings: list[dict[str, Any]] | None = None,
    base_url: str = "",
) -> dict[str, Any]:
    files = []
    seen_files = set()
    findings = []
    domains = set()
    subdomains = set()
    websockets = set()
    endpoints = set()
    base_host = (urlparse(base_url).hostname or "").lower()

    for request in network_requests or []:
        if str(request.get("resource_type") or "").lower() != "script":
            continue
        url = str(request.get("url") or "")
        if not url or url in seen_files:
            continue
        seen_files.add(url)
        files.append(
            {
                "url": url,
                "size": int(request.get("response_size") or 0),
                "type": str(request.get("content_type") or "script"),
                "source": "devtools network",
                "page": str(request.get("source_page") or ""),
            }
        )
        host = (urlparse(url).hostname or "").lower()
        if host:
            domains.add(host)
            if base_host and host.endswith("." + base_host):
                subdomains.add(host)

    for row in js_findings or []:
        url = str(row.get("url") or "")
        fragment = str(row.get("fragment") or "")
        source_file = str(row.get("source_js") or row.get("source_file") or "")
        finding_type = str(row.get("type") or "route")
        confidence = int(row.get("confidence") or 50)
        if url:
            endpoints.add(url)
            if url.startswith(("ws://", "wss://")):
                websockets.add(url)
        for domain in DOMAIN_RE.findall(" ".join([url, fragment, source_file])):
            domains.add(domain.lower())
            if base_host and domain.lower().endswith("." + base_host):
                subdomains.add(domain.lower())
        for match in PUBLIC_KEY_RE.finditer(fragment):
            findings.append(_finding(source_file, "public_key", mask_value(match.group(0)), confidence + 15))
        for match in FEATURE_FLAG_RE.finditer(fragment):
            findings.append(_finding(source_file, "feature_flag", match.group(0), confidence))
        if "config" in fragment.lower():
            findings.append(_finding(source_file, "config_object", fragment[:180], confidence))
        if url:
            findings.append(_finding(source_file, finding_type, url, confidence))

    return {
        "files": files[:220],
        "api_endpoints": sorted(endpoints)[:240],
        "graphql_endpoints": sorted(item for item in endpoints if "graphql" in item.lower() or "/gql" in item.lower())[:80],
        "websocket_urls": sorted(websockets)[:80],
        "domains": sorted(domains)[:180],
        "subdomains": sorted(subdomains)[:160],
        "routes": sorted(endpoints)[:240],
        "findings": _dedupe_findings(findings)[:240],
        "summary": {
            "files": len(files),
            "findings": len(findings),
            "domains": len(domains),
            "subdomains": len(subdomains),
            "routes": len(endpoints),
        },
    }


def _service_locations(network_requests: list[dict[str, Any]], patterns: tuple[str, ...]) -> list[str]:
    locations = []
    lowered_patterns = [pattern.lower() for pattern in patterns]
    for request in network_requests or []:
        url = str(request.get("url") or "")
        if any(pattern in url.lower() for pattern in lowered_patterns):
            host = urlparse(url).hostname or url
            if host not in locations:
                locations.append(host)
    return locations


def _header_interpretation(header: str, value: str) -> str:
    if not value:
        return "missing security control"
    lowered = header.lower()
    if lowered == "content-security-policy":
        return "content execution policy present"
    if lowered == "strict-transport-security":
        return "HTTPS downgrade protection present"
    if lowered == "x-frame-options":
        return "clickjacking protection present"
    if lowered == "x-content-type-options":
        return "MIME sniffing protection present"
    if lowered == "referrer-policy":
        return "referrer leakage policy present"
    if lowered == "permissions-policy":
        return "browser feature policy present"
    if lowered.startswith("cross-origin"):
        return "cross-origin isolation/resource policy present"
    return "present"


def _finding(source_file: str, source_type: str, value: str, confidence: int) -> dict[str, Any]:
    return {
        "source_file": source_file,
        "source_type": source_type,
        "value": value,
        "confidence": max(0, min(int(confidence), 100)),
    }


def _dedupe_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows:
        key = f"{row.get('source_file')}|{row.get('source_type')}|{row.get('value')}"
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    output.sort(key=lambda item: (-int(item.get("confidence") or 0), item.get("source_type") or ""))
    return output
