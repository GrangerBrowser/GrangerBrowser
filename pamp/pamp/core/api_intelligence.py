from __future__ import annotations

from collections import defaultdict
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse


API_KEYWORDS = (
    "api",
    "rest",
    "graphql",
    "gql",
    "ajax",
    "auth",
    "login",
    "oauth",
    "token",
    "backend",
    "webhook",
    "callback",
    "upload",
    "download",
    "v1",
    "v2",
    "v3",
)
GRAPHQL_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)


def build_api_intelligence(
    network_requests: list[dict[str, Any]],
    js_findings: list[dict[str, Any]] | None = None,
    base_url: str = "",
) -> dict[str, Any]:
    base_host = (urlparse(base_url).hostname or "").lower()
    grouped: dict[str, dict[str, Any]] = {}
    graphql_rows: dict[str, dict[str, Any]] = {}

    for request in network_requests:
        if not _is_api_request(request):
            continue
        endpoint = _endpoint_row_from_request(request, base_host)
        key = f"{endpoint['method']}|{endpoint['url']}"
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = endpoint
        else:
            existing["times_seen"] += endpoint["times_seen"]
            existing["response_size"] = max(existing["response_size"], endpoint["response_size"])
            existing["status"] = endpoint["status"] or existing["status"]
        if _is_graphql_request(request):
            _merge_graphql_row(graphql_rows, _graphql_row_from_request(request))

    for finding in js_findings or []:
        url = str(finding.get("url") or finding.get("endpoint") or finding.get("value") or "")
        if not url:
            continue
        if not url.startswith(("http://", "https://", "ws://", "wss://", "/")):
            continue
        parsed = urlparse(url)
        endpoint = {
            "url": url,
            "method": str(finding.get("method") or "GET"),
            "content_type": "",
            "response_type": "unknown",
            "source": "javascript",
            "page": base_url,
            "first_seen": "",
            "times_seen": 1,
            "status": "",
            "response_size": 0,
            "classification": _classification(url, "", "javascript", parsed.hostname or "", base_host),
            "internal": _is_internal(parsed.hostname or "", base_host),
        }
        key = f"{endpoint['method']}|{endpoint['url']}"
        grouped.setdefault(key, endpoint)
        if "graphql" in url.lower() or str(finding.get("type") or "").lower() == "graphql":
            _merge_graphql_row(
                graphql_rows,
                {
                    "endpoint": url,
                    "source_page": base_url,
                    "source_request": "javascript",
                    "headers": {},
                    "operation_names": [],
                    "query_names": [],
                    "mutation_names": [],
                },
            )

    endpoints = sorted(grouped.values(), key=lambda item: (-_endpoint_score(item), item.get("url") or ""))[:300]
    graphql = sorted(graphql_rows.values(), key=lambda item: item.get("endpoint") or "")[:80]
    return {
        "endpoints": endpoints,
        "graphql": graphql,
        "discovery_seeds": _discovery_seeds(endpoints, graphql),
        "summary": {
            "endpoints": len(endpoints),
            "graphql": len(graphql),
            "internal": sum(1 for item in endpoints if item.get("internal")),
            "json": sum(1 for item in endpoints if item.get("response_type") == "json"),
        },
    }


def legacy_endpoint_rows(api_intel: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for endpoint in api_intel.get("endpoints") or []:
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        rows.append(
            {
                "endpoint": url,
                "source_file": str(endpoint.get("source") or "devtools network"),
                "method": str(endpoint.get("method") or ""),
                "risk": "Medium" if "graphql" in url.lower() else "Low",
                "notes": str(endpoint.get("classification") or endpoint.get("response_type") or ""),
            }
        )
    return rows[:300]


def _is_api_request(request: dict[str, Any]) -> bool:
    resource_type = str(request.get("resource_type") or "").lower()
    content_type = str(request.get("content_type") or "").lower()
    url = str(request.get("url") or "")
    lowered = url.lower()
    if resource_type in {"xhr", "fetch", "websocket"}:
        return True
    if any(marker in content_type for marker in ("json", "graphql", "javascript")) and resource_type not in {"script"}:
        return True
    parsed = urlparse(url)
    segments = [segment for segment in re.split(r"[/._-]+", parsed.path.lower()) if segment]
    if any(segment in API_KEYWORDS or re.fullmatch(r"v\d+", segment) for segment in segments):
        return True
    query_keys = [key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return any(any(keyword in key for keyword in API_KEYWORDS if keyword != "api") for key in query_keys)


def _endpoint_row_from_request(request: dict[str, Any], base_host: str) -> dict[str, Any]:
    url = str(request.get("url") or "")
    parsed = urlparse(url)
    content_type = str(request.get("content_type") or "")
    resource_type = str(request.get("resource_type") or "")
    return {
        "url": url,
        "method": str(request.get("method") or "GET"),
        "content_type": content_type,
        "response_type": _response_type(content_type, url),
        "source": "devtools network",
        "page": str(request.get("source_page") or ""),
        "first_seen": str(request.get("timestamp") or ""),
        "times_seen": int(request.get("times_seen") or 1),
        "status": request.get("status"),
        "response_size": int(request.get("response_size") or 0),
        "classification": _classification(url, content_type, resource_type, parsed.hostname or "", base_host),
        "internal": _is_internal(parsed.hostname or "", base_host),
    }


def _is_graphql_request(request: dict[str, Any]) -> bool:
    haystack = " ".join(
        [
            str(request.get("url") or ""),
            str(request.get("content_type") or ""),
            str(request.get("post_data_preview") or ""),
        ]
    ).lower()
    return any(marker in haystack for marker in ("graphql", "/gql", "apollo", "relay", "operationname"))


def _graphql_row_from_request(request: dict[str, Any]) -> dict[str, Any]:
    post_data = str(request.get("post_data_preview") or "")
    operation_names, query_names, mutation_names = _graphql_names(post_data)
    return {
        "endpoint": str(request.get("url") or ""),
        "source_page": str(request.get("source_page") or ""),
        "source_request": f"{request.get('method') or 'GET'} {request.get('url') or ''}",
        "headers": request.get("request_headers") or {},
        "operation_names": operation_names,
        "query_names": query_names,
        "mutation_names": mutation_names,
    }


def _merge_graphql_row(rows: dict[str, dict[str, Any]], row: dict[str, Any]) -> None:
    endpoint = str(row.get("endpoint") or "")
    if not endpoint:
        return
    existing = rows.get(endpoint)
    if existing is None:
        rows[endpoint] = row
        return
    for key in ("operation_names", "query_names", "mutation_names"):
        values = sorted({*(existing.get(key) or []), *(row.get(key) or [])})
        existing[key] = values[:80]
    if not existing.get("source_page"):
        existing["source_page"] = row.get("source_page") or ""


def _graphql_names(payload: str) -> tuple[list[str], list[str], list[str]]:
    operation_names = set()
    query_names = set()
    mutation_names = set()
    try:
        decoded = json.loads(payload)
        if isinstance(decoded, dict):
            if decoded.get("operationName"):
                operation_names.add(str(decoded["operationName"]))
            payload = json.dumps(decoded, ensure_ascii=False)
    except Exception:
        pass
    for match in GRAPHQL_RE.finditer(payload or ""):
        op_type = match.group(1).lower()
        name = match.group(2)
        operation_names.add(name)
        if op_type == "mutation":
            mutation_names.add(name)
        elif op_type == "query":
            query_names.add(name)
    return sorted(operation_names), sorted(query_names), sorted(mutation_names)


def _response_type(content_type: str, url: str) -> str:
    lowered = f"{content_type} {url}".lower()
    if "graphql" in lowered:
        return "graphql"
    if "json" in lowered:
        return "json"
    if "html" in lowered:
        return "html"
    if "xml" in lowered:
        return "xml"
    if any(marker in lowered for marker in ("image/", "font/", "video/", "audio/")):
        return "binary"
    return "text" if "text/" in lowered else "unknown"


def _classification(url: str, content_type: str, resource_type: str, host: str, base_host: str) -> str:
    lowered = f"{url} {content_type} {resource_type}".lower()
    labels = []
    if "graphql" in lowered or "/gql" in lowered:
        labels.append("GraphQL")
    if "json" in lowered:
        labels.append("JSON endpoint")
    if "xhr" in lowered or "fetch" in lowered or "ajax" in lowered:
        labels.append("AJAX endpoint")
    if any(marker in lowered for marker in ("/api/", ".api.", "api.")):
        labels.append("REST API")
    if _is_internal(host, base_host):
        labels.append("Internal endpoint")
    if not labels:
        labels.append("Backend endpoint")
    return ", ".join(dict.fromkeys(labels))


def _is_internal(host: str, base_host: str) -> bool:
    host = (host or "").lower()
    base_host = (base_host or "").lower()
    return bool(host and base_host and (host == base_host or host.endswith("." + base_host)))


def _endpoint_score(endpoint: dict[str, Any]) -> int:
    score = 10
    text = f"{endpoint.get('url')} {endpoint.get('classification')} {endpoint.get('response_type')}".lower()
    if "graphql" in text:
        score += 45
    if "json" in text:
        score += 20
    if endpoint.get("method") and endpoint.get("method") != "GET":
        score += 12
    if endpoint.get("internal"):
        score += 8
    return score


def _discovery_seeds(endpoints: list[dict[str, Any]], graphql: list[dict[str, Any]]) -> list[str]:
    seeds = []
    for endpoint in endpoints:
        seeds.append(str(endpoint.get("url") or ""))
    for row in graphql:
        seeds.append(str(row.get("endpoint") or ""))
    output = []
    seen = set()
    for seed in seeds:
        if not seed or seed in seen:
            continue
        seen.add(seed)
        output.append(seed)
    return output[:300]
