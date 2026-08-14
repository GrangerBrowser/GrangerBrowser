from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlparse


def run_devtools_agent(domain_data: dict[str, Any] | None = None) -> dict[str, Any]:
    domain_data = domain_data or {}
    devtools = domain_data.get("devtools") or {}
    intelligence = devtools.get("devtools_intelligence") or {}
    intel_summary = intelligence.get("summary") or {}
    requests = list(devtools.get("network_requests") or [])
    parameterized_requests = [
        item
        for item in requests
        if parse_qsl(urlparse(str(item.get("url") or "")).query, keep_blank_values=True)
    ]
    return {
        "agent": {"name": "devtools_agent", "role": "browser network and client-side artifacts"},
        "network_requests": requests[:400],
        "api_endpoints": list(devtools.get("api_endpoints") or [])[:250],
        "forms": list(devtools.get("forms") or [])[:100],
        "localStorage_keys": list(devtools.get("localStorage_keys") or [])[:120],
        "sessionStorage_keys": list(devtools.get("sessionStorage_keys") or [])[:120],
        "cookies_names": list(devtools.get("cookies_names") or [])[:160],
        "console_errors": list(devtools.get("console_errors") or [])[:160],
        "graphql": list(devtools.get("graphql_intelligence") or [])[:80],
        "websockets": list(devtools.get("websocket_intelligence") or [])[:120],
        "storage": devtools.get("storage_intelligence") or {},
        "cookies": list(devtools.get("cookie_intelligence") or [])[:160],
        "javascript": devtools.get("javascript_intelligence") or {},
        "third_party_services": list(devtools.get("third_party_services") or [])[:120],
        "interesting_findings": list(devtools.get("interesting_findings") or [])[:20],
        "parameterized_requests": parameterized_requests[:220],
        "summary": {
            "network_requests": len(requests),
            "api_endpoints": len(devtools.get("api_endpoints") or []),
            "graphql": intel_summary.get("graphql") or len(devtools.get("graphql_intelligence") or []),
            "websockets": intel_summary.get("websockets") or len(devtools.get("websocket_intelligence") or []),
            "storage_objects": intel_summary.get("storage_objects") or 0,
            "cookies": intel_summary.get("cookies") or len(devtools.get("cookie_intelligence") or []),
            "javascript_files": intel_summary.get("javascript_files") or 0,
            "third_party_services": intel_summary.get("third_party_services") or len(devtools.get("third_party_services") or []),
            "forms": len(devtools.get("forms") or []),
            "parameterized_requests": len(parameterized_requests),
            "console_errors": len(devtools.get("console_errors") or []),
        },
    }
