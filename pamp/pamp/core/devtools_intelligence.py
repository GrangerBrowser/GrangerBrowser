from __future__ import annotations

from collections import Counter
from typing import Any

from .api_intelligence import build_api_intelligence, legacy_endpoint_rows
from .browser_artifacts import build_javascript_intelligence, detect_third_party_services, interpret_security_headers, sanitize_cookies
from .network_intelligence import network_statistics, normalize_network_requests
from .storage_intelligence import storage_summary


def build_devtools_intelligence(
    *,
    base_url: str,
    final_url: str,
    network_requests: list[dict[str, Any]],
    cookies: list[dict[str, Any]],
    storage: dict[str, Any],
    html: str = "",
    js_findings: list[dict[str, Any]] | None = None,
    security_headers: dict[str, Any] | None = None,
    websocket_events: list[dict[str, Any]] | None = None,
    console_errors: list[str] | None = None,
    errors: list[str] | None = None,
    duration_ms: int = 0,
) -> dict[str, Any]:
    normalized_network = normalize_network_requests(network_requests, final_url or base_url)
    js_intel = build_javascript_intelligence(normalized_network, js_findings or [], base_url=base_url)
    api_intel = build_api_intelligence(normalized_network, js_intel.get("findings") or js_findings or [], base_url=base_url)
    websocket_intel = _websocket_intelligence(normalized_network, websocket_events or [])
    cookie_intel = sanitize_cookies(cookies)
    header_rows = interpret_security_headers(security_headers or _main_document_headers(normalized_network))
    third_party = detect_third_party_services(normalized_network, html)
    discovery_seeds = _discovery_seeds(api_intel, websocket_intel, js_intel)
    findings = _top_findings(
        api_intel=api_intel,
        websocket_intel=websocket_intel,
        storage=storage,
        cookie_intel=cookie_intel,
        js_intel=js_intel,
        security_headers=header_rows,
        third_party=third_party,
    )
    stats = network_statistics(normalized_network)
    stats["storage"] = storage_summary(storage)
    stats["cookies"] = len(cookie_intel)
    stats["console_errors"] = len(console_errors or [])
    stats["duration_ms"] = duration_ms
    summary = {
        "network_requests": len(normalized_network),
        "api_endpoints": len(api_intel.get("endpoints") or []),
        "graphql": len(api_intel.get("graphql") or []),
        "websockets": len(websocket_intel),
        "storage_objects": sum(storage_summary(storage).values()),
        "cookies": len(cookie_intel),
        "javascript_files": len(js_intel.get("files") or []),
        "third_party_services": len(third_party),
        "top_findings": len(findings),
    }
    return {
        "summary": summary,
        "network": {"requests": normalized_network, "statistics": stats},
        "api": api_intel,
        "graphql": api_intel.get("graphql") or [],
        "websockets": websocket_intel,
        "storage": storage,
        "cookies": cookie_intel,
        "javascript": js_intel,
        "security_headers": header_rows,
        "third_party_services": third_party,
        "interesting_findings": findings,
        "statistics": stats,
        "discovery_seeds": discovery_seeds,
        "legacy_api_endpoints": legacy_endpoint_rows(api_intel),
        "debug": {
            "captured_requests": len(network_requests or []),
            "normalized_requests": len(normalized_network),
            "resource_types": dict(Counter(row.get("resource_type") or "other" for row in normalized_network)),
            "errors": list(errors or [])[:120],
        },
    }


def enrich_devtools_intelligence(
    devtools: dict[str, Any],
    *,
    base_url: str,
    js_intel: dict[str, Any] | None = None,
    security_headers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    devtools = dict(devtools or {})
    existing_cookies = list(devtools.get("cookie_intelligence") or [])
    existing_storage = {
        "localStorage": list(devtools.get("localStorage") or []),
        "sessionStorage": list(devtools.get("sessionStorage") or []),
        "indexedDB": list(devtools.get("indexedDB") or []),
        "cacheStorage": list(devtools.get("cacheStorage") or []),
    }
    intelligence = build_devtools_intelligence(
        base_url=base_url,
        final_url=str(devtools.get("final_url") or base_url),
        network_requests=list(devtools.get("network_requests") or []),
        cookies=list(devtools.get("_raw_cookies") or []),
        storage=existing_storage,
        html=str(devtools.get("_html_preview") or ""),
        js_findings=list((js_intel or {}).get("js_findings") or []),
        security_headers=security_headers or {},
        websocket_events=list(devtools.get("_websocket_events") or []),
        console_errors=list(devtools.get("console_errors") or []),
        errors=list(devtools.get("errors") or []),
        duration_ms=int(devtools.get("duration_ms") or 0),
    )
    if existing_cookies and not intelligence.get("cookies"):
        intelligence["cookies"] = existing_cookies
        intelligence["summary"]["cookies"] = len(existing_cookies)
        intelligence["statistics"]["cookies"] = len(existing_cookies)
    _merge_intelligence(devtools, intelligence)
    return devtools


def _merge_intelligence(devtools: dict[str, Any], intelligence: dict[str, Any]) -> None:
    devtools["devtools_intelligence"] = intelligence
    devtools["network_intelligence"] = intelligence.get("network") or {}
    devtools["api_intelligence"] = intelligence.get("api") or {}
    devtools["graphql_intelligence"] = intelligence.get("graphql") or []
    devtools["websocket_intelligence"] = intelligence.get("websockets") or []
    devtools["storage_intelligence"] = intelligence.get("storage") or {}
    devtools["cookie_intelligence"] = intelligence.get("cookies") or []
    devtools["javascript_intelligence"] = intelligence.get("javascript") or {}
    devtools["security_headers_intelligence"] = intelligence.get("security_headers") or []
    devtools["third_party_services"] = intelligence.get("third_party_services") or []
    devtools["interesting_findings"] = intelligence.get("interesting_findings") or []
    devtools["statistics"] = intelligence.get("statistics") or {}
    devtools["discovery_seeds"] = intelligence.get("discovery_seeds") or []
    devtools["api_endpoints"] = intelligence.get("legacy_api_endpoints") or devtools.get("api_endpoints") or []
    devtools["api_endpoint_candidates"] = [row.get("endpoint") for row in devtools["api_endpoints"] if row.get("endpoint")][:250]


def _websocket_intelligence(
    network_requests: list[dict[str, Any]],
    websocket_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for request in network_requests:
        url = str(request.get("url") or "")
        if request.get("resource_type") != "websocket" and not url.startswith(("ws://", "wss://")):
            continue
        rows[url] = {
            "url": url,
            "protocol": "wss" if url.startswith("wss://") else "ws" if url.startswith("ws://") else "",
            "source_page": str(request.get("source_page") or ""),
            "messages_count": 0,
            "status": "observed",
        }
    for event in websocket_events:
        url = str(event.get("url") or "")
        if not url:
            continue
        row = rows.setdefault(
            url,
            {
                "url": url,
                "protocol": str(event.get("protocol") or ""),
                "source_page": str(event.get("source_page") or ""),
                "messages_count": 0,
                "status": "observed",
            },
        )
        row["messages_count"] = max(int(row.get("messages_count") or 0), int(event.get("messages_count") or 0))
        row["status"] = str(event.get("status") or row.get("status") or "observed")
    return sorted(rows.values(), key=lambda item: item.get("url") or "")[:120]


def _main_document_headers(network_requests: list[dict[str, Any]]) -> dict[str, Any]:
    for request in network_requests:
        if request.get("resource_type") == "document":
            return request.get("response_headers") or {}
    return {}


def _discovery_seeds(api_intel: dict[str, Any], websocket_intel: list[dict[str, Any]], js_intel: dict[str, Any]) -> list[str]:
    seeds = []
    seeds.extend(api_intel.get("discovery_seeds") or [])
    seeds.extend(row.get("url") or "" for row in websocket_intel)
    seeds.extend(js_intel.get("api_endpoints") or [])
    seeds.extend(js_intel.get("graphql_endpoints") or [])
    seeds.extend(js_intel.get("websocket_urls") or [])
    seeds.extend(f"https://{domain}" for domain in js_intel.get("subdomains") or [])
    output = []
    seen = set()
    for seed in seeds:
        seed = str(seed or "").strip()
        if not seed or seed in seen:
            continue
        seen.add(seed)
        output.append(seed)
    return output[:350]


def _top_findings(
    *,
    api_intel: dict[str, Any],
    websocket_intel: list[dict[str, Any]],
    storage: dict[str, Any],
    cookie_intel: list[dict[str, Any]],
    js_intel: dict[str, Any],
    security_headers: list[dict[str, str]],
    third_party: list[dict[str, str]],
) -> list[dict[str, Any]]:
    findings = []
    for endpoint in api_intel.get("endpoints") or []:
        score = 35
        if "GraphQL" in str(endpoint.get("classification") or ""):
            score += 35
        if endpoint.get("internal"):
            score += 10
        if endpoint.get("method") and endpoint.get("method") != "GET":
            score += 8
        findings.append(_finding(score, "API", endpoint.get("url"), endpoint.get("classification"), endpoint.get("source")))
    for row in websocket_intel:
        findings.append(_finding(75, "WebSocket", row.get("url"), f"{row.get('messages_count')} messages", row.get("source_page")))
    for group_name in ("localStorage", "sessionStorage", "indexedDB", "cacheStorage"):
        for row in storage.get(group_name) or []:
            score = 20 + int(row.get("risk_score") or 0)
            findings.append(_finding(score, "Storage", row.get("key"), row.get("type"), row.get("source")))
    for row in js_intel.get("findings") or []:
        score = 25 + int(row.get("confidence") or 0)
        findings.append(_finding(score, "JavaScript", row.get("value"), row.get("source_type"), row.get("source_file")))
    for header in security_headers:
        if header.get("status") == "missing":
            findings.append(_finding(45, "Security Header", header.get("header"), "missing", "response headers"))
    for service in third_party:
        findings.append(_finding(25, "Third Party", service.get("name"), service.get("type"), service.get("where_found")))
    for cookie in cookie_intel:
        if not cookie.get("secure") or not cookie.get("httponly"):
            findings.append(_finding(35, "Cookie", cookie.get("name"), "weak flags", cookie.get("domain")))
    output = []
    seen = set()
    for finding in sorted(findings, key=lambda item: -int(item.get("score") or 0)):
        key = f"{finding.get('type')}|{finding.get('value')}|{finding.get('detail')}"
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
        if len(output) >= 20:
            break
    return output


def _finding(score: int, item_type: str, value: Any, detail: Any, source: Any) -> dict[str, Any]:
    return {
        "score": max(0, min(int(score), 100)),
        "type": str(item_type or ""),
        "value": str(value or ""),
        "detail": str(detail or ""),
        "source": str(source or ""),
    }
