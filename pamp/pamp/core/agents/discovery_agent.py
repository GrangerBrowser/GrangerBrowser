from __future__ import annotations

from typing import Any

from ..ffuf_discovery import run_discovery


def run_discovery_agent(
    target: str,
    domain_data: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    domain_data = domain_data or {}
    http = domain_data.get("http") or {}
    scan_target = http.get("final_url") or http.get("url") or target
    discovery_config = dict(config or {})
    discovery_config["seed_urls"] = _seed_urls(domain_data, discovery_config.get("seed_urls") or [])
    result = run_discovery(scan_target, config=discovery_config)
    result["js_findings"] = list(domain_data.get("js_findings") or [])[:160]
    result["agent"] = {
        "name": "discovery_agent",
        "input_target": target,
        "scan_target": scan_target,
        "role": "route and public resource discovery",
        "seed_count": len(discovery_config["seed_urls"]),
        "interesting_endpoints": discovery_endpoint_rows(result),
    }
    return result


def _seed_urls(domain_data: dict[str, Any], existing: list[Any]) -> list[str]:
    html = domain_data.get("html") or {}
    devtools = domain_data.get("devtools") or {}
    seeds = [str(item) for item in existing if str(item).strip()]
    for key in (
        "api_endpoint_candidates",
        "login_admin_paths",
        "source_map_links",
        "script_links",
    ):
        seeds.extend(str(item) for item in html.get(key) or [] if str(item).strip())
    for row in domain_data.get("api_endpoints") or []:
        endpoint = row.get("endpoint") if isinstance(row, dict) else row
        if endpoint:
            seeds.append(str(endpoint))
    for row in domain_data.get("js_findings") or []:
        endpoint = row.get("url") if isinstance(row, dict) else row
        if endpoint:
            seeds.append(str(endpoint))
    for key in ("api_endpoint_candidates", "dom_links", "loaded_js", "websocket_urls"):
        seeds.extend(str(item) for item in devtools.get(key) or [] if str(item).strip())
    seeds.extend(str(item) for item in devtools.get("discovery_seeds") or [] if str(item).strip())
    api_intel = devtools.get("api_intelligence") or {}
    for row in api_intel.get("endpoints") or []:
        seeds.append(str(row.get("url") or ""))
    for row in devtools.get("graphql_intelligence") or []:
        seeds.append(str(row.get("endpoint") or ""))
    for row in devtools.get("websocket_intelligence") or []:
        seeds.append(str(row.get("url") or ""))
    js_intel = devtools.get("javascript_intelligence") or {}
    for key in ("api_endpoints", "graphql_endpoints", "websocket_urls", "routes"):
        seeds.extend(str(item) for item in js_intel.get(key) or [] if str(item).strip())
    for domain in list(js_intel.get("subdomains") or []) + list(js_intel.get("domains") or []):
        domain = str(domain).strip()
        if domain:
            seeds.append(f"https://{domain}")
    for item in ("robots.txt", "sitemap.xml", "security.txt", "manifest.json"):
        seeds.append(item)
    output = []
    seen = set()
    for seed in seeds:
        key = seed.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(key)
    return output[:300]


def discovery_endpoint_rows(discovery: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    seen = set()
    for item in discovery.get("findings") or []:
        category = str(item.get("category") or "")
        if category not in {"api", "admin", "auth", "docs", "backup", "config", "sourcemap", "public", "graphql", "swagger"}:
            continue
        url = str(item.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        rows.append(
            {
                "endpoint": url,
                "source_file": str(item.get("source_wordlist") or "discovery"),
                "method": "GET",
                "risk": _risk_for_category(category),
                "notes": f"discovery category: {category}",
            }
        )
    return rows[:250]


def _risk_for_category(category: str) -> str:
    if category in {"admin", "auth", "backup", "config", "sourcemap"}:
        return "Medium"
    return "Low"
