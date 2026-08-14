from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .port_surface import port_surface_notes


JS_MARKERS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("Webpack runtime", "bundler", re.compile(r"\b__webpack_require__\b|webpackChunk", re.I)),
    ("Webpack chunk", "chunk", re.compile(r"\b(?:webpackChunk|chunkId|\.chunk\.js)\b", re.I)),
    ("Vite", "bundler", re.compile(r"/@vite/client|__vite__|vite/modulepreload", re.I)),
    ("Dynamic import", "loader", re.compile(r"\bimport\s*\(", re.I)),
    ("fetch()", "network", re.compile(r"\bfetch\s*\(", re.I)),
    ("axios", "network", re.compile(r"\baxios(?:\.|\s*\()", re.I)),
    ("XMLHttpRequest", "network", re.compile(r"\bXMLHttpRequest\b", re.I)),
    ("GraphQL", "api", re.compile(r"\bgraphql\b|/gql\b", re.I)),
    ("WebSocket", "realtime", re.compile(r"\bWebSocket\s*\(|wss?://", re.I)),
    ("JWT pattern", "credential", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b")),
    ("Bearer pattern", "credential", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{12,}", re.I)),
    ("Firebase", "service", re.compile(r"\bfirebase(?:app)?\.com\b|firebaseConfig", re.I)),
    ("Supabase", "service", re.compile(r"\bsupabase\b|supabase\.co", re.I)),
    ("Stripe", "service", re.compile(r"\bstripe\b|js\.stripe\.com", re.I)),
    ("Google Maps", "service", re.compile(r"maps\.googleapis\.com|google\.maps\.", re.I)),
    ("Sentry", "service", re.compile(r"\bSentry\.init\b|sentry\.io|__SENTRY__", re.I)),
)


def timeline_event(event: str, *, source: str = "domain_analysis", detail: str = "") -> dict[str, str]:
    return {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event": event,
        "source": source,
        "detail": detail,
    }


def build_response_comparison(probes: list[dict[str, Any]]) -> list[dict[str, str]]:
    live = {str(row.get("scheme") or ""): row for row in probes if row.get("live")}
    http = live.get("http")
    https = live.get("https")
    if not http or not https:
        return []

    comparisons = (
        ("Status", http.get("status_code"), https.get("status_code")),
        ("Server", http.get("server"), https.get("server")),
        ("Title", http.get("title"), https.get("title")),
        ("Content type", http.get("content_type"), https.get("content_type")),
        ("Content length", http.get("content_length"), https.get("content_length")),
        ("Final URL", http.get("final_url"), https.get("final_url")),
        ("Redirect chain", _redirect_text(http), _redirect_text(https)),
        ("Cookies", ", ".join(http.get("cookie_names") or []), ", ".join(https.get("cookie_names") or [])),
        ("Headers", _header_names(http), _header_names(https)),
    )
    rows = []
    for field, http_value, https_value in comparisons:
        left = _text(http_value)
        right = _text(https_value)
        rows.append(
            {
                "field": field,
                "http": left or "No data",
                "https": right or "No data",
                "changed": "yes" if left != right else "no",
            }
        )
    return rows


def build_javascript_intelligence(
    html_signals: dict[str, Any],
    js_intel: dict[str, Any],
    devtools: dict[str, Any],
    technologies: list[dict[str, Any]],
) -> dict[str, Any]:
    scripts = []
    seen_scripts = set()
    fetched = {str(row.get("url") or ""): row for row in js_intel.get("scripts") or []}
    devtools_files = (
        ((devtools.get("javascript_intelligence") or {}).get("files") or [])
        + (((devtools.get("devtools_intelligence") or {}).get("javascript") or {}).get("files") or [])
    )
    for url in (html_signals.get("script_links") or []) + [str(row.get("url") or "") for row in devtools_files]:
        if not url or url in seen_scripts:
            continue
        seen_scripts.add(url)
        row = fetched.get(url) or {}
        scripts.append(
            {
                "url": url,
                "source": row.get("source") or "HTML script tag",
                "size": row.get("size") or 0,
                "status": row.get("status") or "observed",
            }
        )

    marker_rows = list(js_intel.get("markers") or [])
    for row in (((devtools.get("javascript_intelligence") or {}).get("findings") or [])):
        marker_rows.append(
            {
                "name": str(row.get("source_type") or row.get("type") or "JavaScript finding"),
                "category": "browser",
                "evidence": str(row.get("value") or row.get("detail") or ""),
                "source": str(row.get("source_file") or "DevTools"),
            }
        )

    frameworks = [
        {
            "name": str(row.get("name") or ""),
            "version": str(row.get("version") or "Unknown Version"),
            "confidence": str(row.get("confidence") or ""),
            "source": str(row.get("source") or ""),
        }
        for row in technologies
        if str(row.get("category") or "").lower() in {"frontend", "language / backend"}
    ]
    endpoints = []
    for row in (js_intel.get("api_endpoints") or []) + (js_intel.get("js_findings") or []):
        value = str(row.get("endpoint") or row.get("url") or "")
        if value:
            endpoints.append(
                {
                    "url": value,
                    "type": str(row.get("type") or "api"),
                    "source": str(row.get("source_file") or row.get("source") or "JavaScript"),
                    "confidence": str(row.get("confidence") or ""),
                }
            )
    return {
        "scripts": _dedupe(scripts, ("url",))[:220],
        "inline_scripts": list(html_signals.get("inline_scripts") or [])[:120],
        "frameworks": _dedupe(frameworks, ("name",))[:80],
        "markers": _dedupe(marker_rows, ("name", "source", "evidence"))[:220],
        "endpoints": _dedupe(endpoints, ("url", "source"))[:240],
        "source_maps": list(js_intel.get("source_map_links") or html_signals.get("source_map_links") or [])[:120],
    }


def scan_javascript_text(text: str, source: str) -> list[dict[str, str]]:
    rows = []
    for name, category, pattern in JS_MARKERS:
        match = pattern.search(text or "")
        if not match:
            continue
        evidence = re.sub(r"\s+", " ", (text or "")[max(0, match.start() - 45) : match.end() + 90]).strip()
        if category == "credential":
            evidence = f"{name} detected; value masked"
        rows.append(
            {
                "name": name,
                "category": category,
                "evidence": evidence[:180],
                "source": source,
            }
        )
    return rows


def build_cdn_detection(technologies: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows = []
    for row in technologies:
        category = str(row.get("category") or "").lower()
        name = str(row.get("name") or "")
        if "cdn" not in category and name not in {
            "Cloudflare",
            "Akamai",
            "Fastly",
            "Vercel",
            "Netlify",
            "AWS CloudFront",
            "Azure Front Door",
            "BunnyCDN",
            "Google CDN",
        }:
            continue
        rows.append(
            {
                "name": name,
                "confidence": str(row.get("confidence") or "medium"),
                "evidence": str(row.get("evidence") or ""),
                "source": str(row.get("source") or "HTTP fingerprint"),
            }
        )
    return _dedupe(rows, ("name",))[:40]


def build_analyst_notes(data: dict[str, Any]) -> list[str]:
    surface = data.get("http_surface") or {}
    notes = list(surface.get("analyst_notes") or [])
    technologies = data.get("technologies") or data.get("detected_technology_details") or []
    for row in technologies:
        if str(row.get("confidence") or "").lower() != "high":
            continue
        name = str(row.get("name") or "")
        source = str(row.get("source") or _source_from_evidence(str(row.get("evidence") or "")))
        if name:
            notes.append(f"{name} detected through {source}.")

    html = data.get("html") or {}
    inline_count = len(html.get("inline_scripts") or [])
    missing_csp = any(str(row.get("name") or "") == "Missing CSP" for row in data.get("security_signals") or [])
    if missing_csp and inline_count:
        notes.append(f"CSP is missing while {inline_count} inline JavaScript block(s) are present.")

    for path in data.get("interesting_paths") or []:
        name = str(path.get("path") or "")
        status = str(path.get("status") or path.get("status_code") or "")
        if name in {"/admin", "/admin/"} and status:
            notes.append(f"Admin endpoint exists and returns {status}.")
        if name == "/robots.txt" and path.get("entry_count"):
            notes.append(f"robots.txt exposes {path.get('entry_count')} directive(s).")

    server = str(surface.get("server") or "")
    if server and "/" not in server:
        notes.append(f"{server} version is hidden.")
    elif server:
        notes.append(f"Server version is exposed as {server}.")

    discovery = data.get("discovery") or {}
    for row in discovery.get("findings") or []:
        path = str(row.get("path") or "")
        status = str(row.get("status_code") or row.get("status") or "")
        if path in {"admin", "admin/"}:
            notes.append(f"Discovery confirmed /{path.rstrip('/')} with HTTP {status}.")
            break
    if not surface.get("primary_url"):
        notes.append("No live HTTP service detected; the report contains DNS and registration intelligence only.")
    js_intelligence = data.get("js_intelligence") or {}
    js_summary = js_intelligence.get("summary") or {}
    endpoint_count = int(js_summary.get("api_endpoints") or 0)
    if endpoint_count:
        notes.append(f"JavaScript and browser network exposed {endpoint_count} probable API endpoint(s).")
    secret_count = int(js_summary.get("secret_like_values") or 0)
    if secret_count:
        notes.append(f"{secret_count} masked secret-like JavaScript value(s) require manual validation.")

    oauth = data.get("oauth_intelligence") or {}
    providers = [str(row.get("name") or "") for row in oauth.get("providers") or [] if row.get("name")]
    if providers:
        notes.append(f"OAuth/OIDC provider markers detected: {', '.join(providers[:4])}.")
    if oauth.get("callback_urls"):
        notes.append(f"{len(oauth.get('callback_urls') or [])} authentication callback route(s) should be checked against provider allowlists.")

    traffic = data.get("traffic_chain") or {}
    traffic_summary = traffic.get("summary") or {}
    total_requests = int(traffic_summary.get("total_requests") or 0)
    if total_requests:
        notes.append(
            "Traffic Chain captured "
            f"{total_requests} browser request(s), "
            f"{int(traffic_summary.get('api_requests') or 0)} API request(s), "
            f"{int(traffic_summary.get('third_party_requests') or 0)} third-party request(s), "
            f"{int(traffic_summary.get('failed_requests') or 0)} failed request(s)."
        )

    cloud = data.get("cloud_buckets") or {}
    public_cloud = [row for row in cloud.get("verified") or [] if row.get("status") == "public"]
    if public_cloud:
        notes.append(f"{len(public_cloud)} referenced cloud storage endpoint(s) are publicly reachable.")
    elif cloud.get("candidates"):
        notes.append("Cloud storage references were detected, but no public endpoint was confirmed.")

    favicon = data.get("favicon_intelligence") or {}
    if favicon.get("matches"):
        names = [str(row.get("name") or "") for row in favicon.get("matches") or [] if row.get("name")]
        notes.append(f"Favicon fingerprint matched {', '.join(names[:3])}.")
    elif favicon.get("icons"):
        notes.append("Favicon hashes were collected but did not match the local fingerprint database.")
    port_notes = port_surface_notes(data.get("port_surface") or {})
    return _unique_notes([*port_notes, *notes])[:18]


def _source_from_evidence(evidence: str) -> str:
    lowered = evidence.lower()
    if "server header" in lowered:
        return "Server header"
    if "generator" in lowered:
        return "Meta Generator"
    if "cookie" in lowered:
        return "Cookie"
    if "asset" in lowered or "path" in lowered:
        return "HTML/JS asset"
    if "header" in lowered:
        return "Response header"
    return "HTML marker"


def _redirect_text(row: dict[str, Any]) -> str:
    chain = row.get("redirect_chain") or []
    if not chain:
        return "none"
    return " -> ".join(str(item.get("to") or "") for item in chain)


def _header_names(row: dict[str, Any]) -> str:
    headers = row.get("headers") or {}
    if isinstance(headers, dict):
        return ", ".join(sorted(str(key) for key in headers))
    return ""


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _dedupe(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows:
        key = tuple(str(row.get(item) or "") for item in keys)
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _unique_notes(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        output.append(text)
    return output
