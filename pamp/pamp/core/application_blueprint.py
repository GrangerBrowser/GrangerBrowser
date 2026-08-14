from __future__ import annotations

from collections import Counter
import re
from typing import Any
from urllib.parse import urlparse

from .models import digest_value


NODE_TYPES = {
    "domain",
    "ip",
    "asn",
    "dns",
    "tls",
    "server",
    "technology",
    "frontend",
    "api",
    "oauth",
    "cloud",
    "bucket",
    "port",
    "third_party",
    "social",
    "route",
    "recovered_route",
    "dynamic_import",
    "high_interest_route",
    "hidden_api_cluster",
    "parameter_cluster",
    "permission_route_cluster",
    "route_risk_cluster",
    "finding",
}
EDGE_TYPES = {
    "resolves_to",
    "hosted_on",
    "protected_by",
    "uses",
    "exposes",
    "calls",
    "authenticates_with",
    "serves",
    "loads",
    "linked_to",
    "has_finding",
    "recovers",
    "imports",
    "relates_to",
}

MAX_DOMAIN_NODES = 90
MAX_DNS_NODES = 80
MAX_TECHNOLOGY_NODES = 80
MAX_FRONTEND_NODES = 90
MAX_API_NODES = 180
MAX_EXTERNAL_SERVICE_NODES = 90
MAX_PORT_NODES = 80
MAX_SOCIAL_NODES = 90
MAX_ROUTE_NODES = 160
MAX_JS_ROUTE_NODES = 90
MAX_DYNAMIC_IMPORT_NODES = 70
MAX_FINDING_NODES = 120

FRONTEND_TECHNOLOGIES = {
    "angular",
    "bootstrap",
    "gatsby",
    "jquery",
    "next.js",
    "nuxt",
    "react",
    "remix",
    "svelte",
    "vue",
}
SERVER_TECHNOLOGIES = {
    "apache",
    "caddy",
    "express",
    "iis",
    "nginx",
    "openresty",
    "tomcat",
}
PROTECTION_TECHNOLOGIES = {
    "akamai",
    "cloudflare",
    "fastly",
    "imperva",
    "ngenix",
    "recaptcha",
    "turnstile",
}
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "warning": 2, "high": 3, "critical": 4}
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_application_blueprint(data: dict[str, Any]) -> dict[str, Any]:
    """Build a compact architecture graph from already collected Pamp data."""
    graph = _BlueprintGraph()
    domain = _clean_domain(data.get("domain") or data.get("host") or data.get("input"))
    domain_id = ""
    if domain:
        domain_id = graph.add_node(
            "domain",
            domain,
            label=domain,
            title="Primary Domain",
            description="Primary analyzed web application domain.",
            confidence="high",
            source_modules=["domain", "dns", "http_surface"],
            data={
                "domain": domain,
                "primary_url": _first_text(
                    (data.get("http_surface") or {}).get("primary_url"),
                    (data.get("http") or {}).get("final_url"),
                    (data.get("http") or {}).get("url"),
                ),
                "status_code": _first_text(
                    (data.get("http_surface") or {}).get("status_code"),
                    (data.get("http") or {}).get("status_code"),
                ),
            },
        )

    _add_dns_nodes(graph, data, domain_id, domain)
    _add_tls_nodes(graph, data, domain_id, domain)
    _add_http_nodes(graph, data, domain_id)
    _add_technology_nodes(graph, data, domain_id)
    _add_javascript_nodes(graph, data, domain_id, domain)
    _add_api_nodes(graph, data, domain_id, domain)
    _add_application_route_nodes(graph, data, domain_id, domain)
    _add_oauth_nodes(graph, data, domain_id, domain)
    _add_cloud_nodes(graph, data, domain_id)
    _add_port_nodes(graph, data, domain_id)
    _add_social_nodes(graph, data, domain_id)
    _add_traffic_nodes(graph, data, domain_id, domain)
    _add_finding_nodes(graph, data, domain_id)
    _add_insights(graph, data, domain_id, domain)

    return graph.to_dict()


class _BlueprintGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.insights: list[dict[str, Any]] = []
        self._insight_titles: set[str] = set()
        self._kind_counts: Counter[str] = Counter()

    def add_node(
        self,
        node_type: str,
        value: Any,
        *,
        label: str | None = None,
        title: str = "",
        description: str = "",
        risk: str = "info",
        confidence: str = "medium",
        source_modules: list[str] | None = None,
        data: dict[str, Any] | None = None,
    ) -> str:
        if node_type not in NODE_TYPES:
            return ""
        raw_value = _text(value)
        if not raw_value:
            return ""
        limit = _node_limit(node_type)
        node_id = _node_id(node_type, raw_value)
        if node_id not in self.nodes and limit and self._kind_counts[node_type] >= limit:
            return ""
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label or _label_for(node_type, raw_value),
                "title": title or _title_for(node_type),
                "description": description,
                "risk": _normalize_risk(risk),
                "confidence": _normalize_confidence(confidence),
                "source_modules": _dedupe(source_modules or []),
                "data": _compact_dict(data or {}),
            }
            self._kind_counts[node_type] += 1
            return node_id

        node = self.nodes[node_id]
        node["source_modules"] = _dedupe([*node.get("source_modules", []), *(source_modules or [])])
        node["risk"] = _max_risk(node.get("risk"), risk)
        node["confidence"] = _max_confidence(node.get("confidence"), confidence)
        if title and not node.get("title"):
            node["title"] = title
        if description and not node.get("description"):
            node["description"] = description
        if label and len(label) < len(_text(node.get("label"))):
            node["label"] = label
        if data:
            merged = dict(node.get("data") or {})
            merged.update(_compact_dict(data))
            node["data"] = merged
        return node_id

    def add_edge(
        self,
        from_id: str,
        to_id: str,
        edge_type: str,
        *,
        label: str = "",
        confidence: str = "medium",
        source_modules: list[str] | None = None,
    ) -> str:
        if not from_id or not to_id or from_id == to_id or edge_type not in EDGE_TYPES:
            return ""
        edge_id = f"edge:{digest_value(f'{from_id}|{edge_type}|{to_id}')}"
        if edge_id not in self.edges:
            self.edges[edge_id] = {
                "id": edge_id,
                "from": from_id,
                "to": to_id,
                "type": edge_type,
                "label": label or edge_type,
                "confidence": _normalize_confidence(confidence),
                "source_modules": _dedupe(source_modules or []),
            }
            return edge_id
        edge = self.edges[edge_id]
        edge["confidence"] = _max_confidence(edge.get("confidence"), confidence)
        edge["source_modules"] = _dedupe([*edge.get("source_modules", []), *(source_modules or [])])
        return edge_id

    def add_insight(
        self,
        title: str,
        *,
        risk: str = "info",
        confidence: str = "medium",
        source_modules: list[str] | None = None,
        related_node_ids: list[str] | None = None,
    ) -> None:
        clean_title = _text(title)
        if not clean_title or clean_title in self._insight_titles:
            return
        self._insight_titles.add(clean_title)
        self.insights.append(
            {
                "id": f"insight:{digest_value(clean_title.lower())}",
                "title": clean_title,
                "risk": _normalize_risk(risk),
                "confidence": _normalize_confidence(confidence),
                "source_modules": _dedupe(source_modules or []),
                "related_node_ids": [item for item in _dedupe(related_node_ids or []) if item in self.nodes],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        nodes = list(self.nodes.values())
        edges = list(self.edges.values())
        type_counts = Counter(node.get("type") for node in nodes)
        return {
            "status": "completed",
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "domains": type_counts.get("domain", 0),
                "technologies": (
                    type_counts.get("technology", 0)
                    + type_counts.get("frontend", 0)
                    + type_counts.get("server", 0)
                ),
                "apis": type_counts.get("api", 0),
                "external_services": (
                    type_counts.get("third_party", 0)
                    + type_counts.get("cloud", 0)
                    + type_counts.get("bucket", 0)
                    + type_counts.get("oauth", 0)
                ),
                "routes": (
                    type_counts.get("route", 0)
                    + type_counts.get("recovered_route", 0)
                    + type_counts.get("high_interest_route", 0)
                    + type_counts.get("dynamic_import", 0)
                ),
                "risks": type_counts.get("finding", 0),
            },
            "nodes": nodes,
            "edges": edges,
            "insights": self.insights,
        }


def _add_dns_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    dns = data.get("dns") or {}
    ip_values = [
        *as_list(data.get("linked_ip_addresses")),
        *as_list(dns.get("A")),
        *as_list(dns.get("AAAA")),
    ]
    for ip in _unique(ip_values, MAX_DNS_NODES):
        ip_id = graph.add_node(
            "ip",
            ip,
            title="Resolved IP Address",
            description="IP address resolved from collected DNS data.",
            confidence="high",
            source_modules=["dns"],
            data={"record_type": "A/AAAA"},
        )
        graph.add_edge(domain_id, ip_id, "resolves_to", label="resolves to", confidence="high", source_modules=["dns"])

    for record_type in ("NS", "MX", "CNAME", "CAA"):
        for record in _unique(as_list(dns.get(record_type)), MAX_DNS_NODES):
            dns_id = graph.add_node(
                "dns",
                f"{record_type}:{record}",
                label=f"{record_type} {record}",
                title=f"{record_type} Record",
                description="DNS record collected during domain analysis.",
                confidence="high",
                source_modules=["dns"],
                data={"record_type": record_type, "value": record},
            )
            graph.add_edge(domain_id, dns_id, "linked_to", label=record_type, confidence="high", source_modules=["dns"])

    for subdomain in _unique(as_list(data.get("subdomains")), MAX_DOMAIN_NODES):
        clean = _clean_domain(subdomain)
        if not clean or clean == domain:
            continue
        subdomain_id = graph.add_node(
            "domain",
            clean,
            title="Discovered Subdomain",
            description="Subdomain found in existing Pamp data.",
            confidence="medium",
            source_modules=["dns", "tls"],
            data={"domain": clean},
        )
        graph.add_edge(domain_id, subdomain_id, "linked_to", label="subdomain", source_modules=["dns", "tls"])

    for row in as_list(data.get("asn_bgp")):
        if not isinstance(row, dict):
            continue
        label = _asn_label(row)
        if not label:
            continue
        asn_id = graph.add_node(
            "asn",
            label,
            label=label,
            title="ASN / Network",
            description="Network owner data associated with a resolved IP.",
            confidence="medium",
            source_modules=["dns"],
            data={
                "ip": row.get("ip"),
                "name": row.get("name"),
                "handle": row.get("handle"),
                "bgp_prefix": row.get("bgp_prefix"),
                "country": row.get("country"),
            },
        )
        ip_value = _text(row.get("ip"))
        ip_id = graph.add_node("ip", ip_value, title="Resolved IP Address", confidence="high", source_modules=["dns"]) if ip_value else ""
        graph.add_edge(ip_id or domain_id, asn_id, "hosted_on", label="hosted on", source_modules=["dns"])


def _add_tls_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    tls = data.get("tls_certificate") or {}
    if not isinstance(tls, dict) or not any(tls.get(key) for key in ("issuer", "subject", "fingerprint_sha256", "tls_version")):
        return
    verification_error = _text(tls.get("verification_error"))
    days_remaining = _safe_int(tls.get("days_remaining"))
    tls_id = graph.add_node(
        "tls",
        tls.get("fingerprint_sha256") or f"{domain}:{tls.get('issuer')}:{tls.get('valid_to')}",
        label=_first_text(tls.get("issuer"), tls.get("subject"), "TLS certificate"),
        title="TLS Certificate",
        description="Certificate and TLS posture associated with the target domain.",
        risk="medium" if verification_error or (days_remaining is not None and days_remaining <= 14) else "info",
        confidence="high",
        source_modules=["tls"],
        data={
            "subject": tls.get("subject"),
            "issuer": tls.get("issuer"),
            "valid_from": tls.get("valid_from") or tls.get("not_before"),
            "valid_to": tls.get("valid_to") or tls.get("not_after"),
            "tls_version": tls.get("tls_version"),
            "cipher_suite": tls.get("cipher_suite"),
            "days_remaining": tls.get("days_remaining"),
            "verification_error": verification_error,
            "san_domains": tls.get("san_domains") or tls.get("subject_alt_names"),
        },
    )
    graph.add_edge(domain_id, tls_id, "protected_by", label="protected by", confidence="high", source_modules=["tls"])


def _add_http_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str) -> None:
    http = data.get("http") or {}
    surface = data.get("http_surface") or {}
    headers = surface.get("headers") or http.get("headers") or {}
    server = _first_text(surface.get("server"), http.get("server"), _header(headers, "server"))
    if not server:
        for probe in as_list(surface.get("probes")):
            if isinstance(probe, dict):
                server = _first_text(probe.get("server"), _header(probe.get("headers") or {}, "server"))
                if server:
                    break
    if server:
        server_id = graph.add_node(
            "server",
            server,
            title="HTTP Server",
            description="Server header or HTTP surface server hint.",
            confidence="high",
            source_modules=["http_surface"],
            data={"server": server},
        )
        graph.add_edge(domain_id, server_id, "uses", label="uses", confidence="high", source_modules=["http_surface"])

    powered_by = _first_text(surface.get("powered_by"), http.get("powered_by"), _header(headers, "x-powered-by"))
    if powered_by:
        tech_id = graph.add_node(
            "technology",
            powered_by,
            title="Powered By",
            description="X-Powered-By or equivalent HTTP hint.",
            confidence="medium",
            source_modules=["http_surface"],
            data={"powered_by": powered_by},
        )
        graph.add_edge(domain_id, tech_id, "uses", label="uses", source_modules=["http_surface"])


def _add_technology_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str) -> None:
    for name, row in _technology_candidates(data):
        kind = _technology_kind(name, row)
        edge_type = "protected_by" if _is_protection_technology(name, row) else "uses"
        node_id = graph.add_node(
            kind,
            name,
            label=name,
            title=_title_for(kind),
            description=_text(row.get("evidence") if isinstance(row, dict) else ""),
            risk=_text(row.get("risk") if isinstance(row, dict) else "") or "info",
            confidence=_text(row.get("confidence") if isinstance(row, dict) else "") or "medium",
            source_modules=["technology_fingerprinting"],
            data={
                "name": name,
                "category": row.get("category") if isinstance(row, dict) else "",
                "version": row.get("version") if isinstance(row, dict) else "",
                "source": row.get("source") if isinstance(row, dict) else "",
                "evidence": row.get("evidence") if isinstance(row, dict) else "",
            },
        )
        graph.add_edge(domain_id, node_id, edge_type, label=edge_type.replace("_", " "), source_modules=["technology_fingerprinting"])


def _add_javascript_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    js = data.get("js_intelligence") or data.get("javascript_intelligence") or {}
    if not isinstance(js, dict):
        return
    for row in as_list(js.get("files"))[:MAX_FRONTEND_NODES]:
        url = _row_value(row)
        if not url:
            continue
        label = _url_label(url)
        js_id = graph.add_node(
            "frontend",
            url,
            label=label,
            title="JavaScript Asset",
            description="Browser-visible JavaScript asset collected by Pamp.",
            risk=_text(row.get("risk") if isinstance(row, dict) else "") or "info",
            confidence=_text(row.get("confidence") if isinstance(row, dict) else "") or "medium",
            source_modules=["javascript_intelligence"],
            data={
                "url": url,
                "status": row.get("status") if isinstance(row, dict) else "",
                "size": row.get("size") if isinstance(row, dict) else "",
                "sha256": row.get("sha256") if isinstance(row, dict) else "",
                "source": row.get("source") if isinstance(row, dict) else "",
            },
        )
        graph.add_edge(domain_id, js_id, "loads", label="loads", source_modules=["javascript_intelligence"])

    for key in ("api_endpoints", "graphql", "websockets"):
        for row in as_list(js.get(key))[:MAX_API_NODES]:
            value = _row_value(row)
            if not value:
                continue
            _add_api_node(graph, domain_id, domain, row, value, ["javascript_intelligence"], kind_hint=key)


def _add_api_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    rows = [
        *as_list(data.get("api_endpoints")),
        *as_list(data.get("api_endpoint_candidates")),
    ]
    devtools = data.get("devtools") or {}
    rows.extend(as_list(devtools.get("api_endpoints")))
    api_intel = devtools.get("api_intelligence") or {}
    rows.extend(as_list(api_intel.get("endpoints")))
    discovery = data.get("discovery") or {}
    rows.extend(as_list(discovery.get("api_endpoints")))
    seen: set[str] = set()
    for row in rows:
        value = _endpoint_value(row)
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        if len(seen) > MAX_API_NODES:
            break
        _add_api_node(graph, domain_id, domain, row, value, ["api_discovery"])


def _add_api_node(
    graph: _BlueprintGraph,
    domain_id: str,
    domain: str,
    row: Any,
    value: str,
    source_modules: list[str],
    *,
    kind_hint: str = "",
) -> str:
    method = _text(row.get("method") if isinstance(row, dict) else "")
    label = _api_label(value, method, kind_hint)
    node_id = graph.add_node(
        "api",
        value,
        label=label,
        title="API Endpoint" if kind_hint != "websockets" else "WebSocket Endpoint",
        description="Endpoint discovered in existing HTML, JavaScript, browser, or discovery data.",
        risk=_text(row.get("risk") if isinstance(row, dict) else "") or "info",
        confidence=_text(row.get("confidence") if isinstance(row, dict) else "") or "medium",
        source_modules=source_modules,
        data={
            "endpoint": value,
            "method": method,
            "source_file": row.get("source_file") if isinstance(row, dict) else "",
            "source": row.get("source") if isinstance(row, dict) else "",
            "notes": row.get("notes") if isinstance(row, dict) else "",
            "type": kind_hint or row.get("type") if isinstance(row, dict) else kind_hint,
        },
    )
    graph.add_edge(domain_id, node_id, "calls", label="calls", source_modules=source_modules)
    host = _host_from_url(value)
    if host and domain and not _is_same_site(host, domain):
        service_id = graph.add_node(
            "third_party",
            host,
            label=host,
            title="External Service",
            description="External host referenced by an API endpoint.",
            confidence="medium",
            source_modules=source_modules,
            data={"host": host},
        )
        graph.add_edge(domain_id, service_id, "calls", label="calls", source_modules=source_modules)
        graph.add_edge(node_id, service_id, "hosted_on", label="hosted on", source_modules=source_modules)
    return node_id


def _add_application_route_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    route_intel = data.get("application_route_intelligence") or {}
    if not isinstance(route_intel, dict):
        return

    routes = as_list(route_intel.get("routes"))
    js_routes = as_list(route_intel.get("javascript_routes"))
    dynamic_imports = as_list(route_intel.get("dynamic_imports"))
    endpoints_by_url = {
        _text(row.get("absolute_url")).lower(): row
        for row in as_list(route_intel.get("endpoints"))
        if isinstance(row, dict) and _text(row.get("absolute_url"))
    }

    route_ids_by_url: dict[str, str] = {}
    route_ids_by_path: dict[str, str] = {}
    for row in routes[:MAX_ROUTE_NODES]:
        if not isinstance(row, dict):
            continue
        value = _first_text(row.get("absolute_url"), row.get("path"))
        if not value:
            continue
        category = _text(row.get("category")) or "unknown"
        node_type = "high_interest_route" if row.get("high_interest") else "recovered_route" if row.get("recovered") and not row.get("observed") else "route"
        route_id = graph.add_node(
            node_type,
            value,
            label=_route_label(row, value),
            title=_route_title(node_type),
            description=_text(row.get("risk_hint")) or "Application route recovered from HTML, DOM, JavaScript, browser traffic, or discovery data.",
            risk=_route_risk(row),
            confidence=_text(row.get("confidence")) or "medium",
            source_modules=["application_route_intelligence"],
            data={
                "path": row.get("path"),
                "absolute_url": row.get("absolute_url"),
                "host": row.get("host"),
                "category": category,
                "observed": row.get("observed"),
                "recovered": row.get("recovered"),
                "static_asset": row.get("static_asset"),
                "sources": row.get("sources"),
                "evidence_count": row.get("evidence_count"),
                "risk_hint": row.get("risk_hint"),
            },
        )
        if not route_id:
            continue
        route_ids_by_url[_text(row.get("absolute_url")).lower()] = route_id
        route_ids_by_path[_text(row.get("path")).split("?", 1)[0].rstrip("/").lower() or "/"] = route_id
        graph.add_edge(domain_id, route_id, "linked_to", label="route", source_modules=["application_route_intelligence"])

        endpoint = endpoints_by_url.get(_text(row.get("absolute_url")).lower())
        if category in {"api", "graphql", "websocket"}:
            api_id = _add_api_node(graph, domain_id, domain, endpoint or row, value, ["application_route_intelligence"], kind_hint=category)
            graph.add_edge(route_id, api_id, "calls", label="route calls", source_modules=["application_route_intelligence"])
        elif category == "auth":
            auth_id = graph.add_node(
                "oauth",
                value,
                label=_route_label(row, value),
                title="Authentication Route",
                description="Authentication-related route recovered by Application Route Intelligence.",
                risk=_route_risk(row),
                confidence=_text(row.get("confidence")) or "medium",
                source_modules=["application_route_intelligence"],
                data={"route": value, "category": category, "observed": row.get("observed")},
            )
            graph.add_edge(route_id, auth_id, "authenticates_with", label="auth route", source_modules=["application_route_intelligence"])

    for row in js_routes[:MAX_JS_ROUTE_NODES]:
        if not isinstance(row, dict):
            continue
        value = _first_text(row.get("absolute_url"), row.get("path"))
        if not value:
            continue
        route_id = route_ids_by_url.get(value.lower())
        if not route_id:
            route_id = graph.add_node(
                "recovered_route",
                value,
                label=_js_route_label(row, value),
                title="JS Recovered Route",
                description=_text(row.get("reason")) or "Route recovered from JavaScript route/navigation/network patterns.",
                risk=_route_risk(row),
                confidence=_text(row.get("confidence")) or "medium",
                source_modules=["application_route_intelligence"],
                data=_compact_dict(row),
            )
            graph.add_edge(domain_id, route_id, "linked_to", label="recovered route", source_modules=["application_route_intelligence"])
        source_file = _text(row.get("source_file"))
        js_id = _route_source_js_node(graph, source_file)
        graph.add_edge(js_id or domain_id, route_id, "recovers", label="recovers", source_modules=["application_route_intelligence"])

    for row in dynamic_imports[:MAX_DYNAMIC_IMPORT_NODES]:
        if not isinstance(row, dict):
            continue
        value = _first_text(row.get("resolved_url"), row.get("import_path"))
        if not value:
            continue
        import_id = graph.add_node(
            "dynamic_import",
            value,
            label=_dynamic_import_label(row, value),
            title="Dynamic Import",
            description=_text(row.get("risk_hint")) or "Lazy-loaded module or chunk reference recovered by Application Route Intelligence.",
            risk=_route_risk(row),
            confidence=_text(row.get("confidence")) or "medium",
            source_modules=["application_route_intelligence"],
            data={
                "import_path": row.get("import_path"),
                "resolved_url": row.get("resolved_url"),
                "source_file": row.get("source_file"),
                "chunk_name": row.get("chunk_name"),
                "framework_hint": row.get("framework_hint"),
                "category": row.get("category"),
                "risk_hint": row.get("risk_hint"),
                "evidence": row.get("evidence"),
            },
        )
        graph.add_edge(domain_id, import_id, "imports", label="dynamic import", source_modules=["application_route_intelligence"])
        js_id = _route_source_js_node(graph, _text(row.get("source_file")))
        graph.add_edge(js_id or domain_id, import_id, "imports", label="imports", source_modules=["application_route_intelligence"])

    _add_katana_level_2_clusters(graph, route_intel, domain_id, route_ids_by_path)


def _add_katana_level_2_clusters(
    graph: _BlueprintGraph,
    route_intel: dict[str, Any],
    domain_id: str,
    route_ids_by_path: dict[str, str],
) -> None:
    level_2 = route_intel.get("katana_level_2") or {}
    if not isinstance(level_2, dict) or level_2.get("status") != "completed":
        return
    source_modules = ["application_route_intelligence.katana_level_2"]
    summary = level_2.get("summary") or {}
    parameters = as_list(level_2.get("parameters"))
    hidden_apis = as_list(level_2.get("hidden_api_hosts"))
    permissions = as_list(level_2.get("permission_mappings"))
    risks = as_list(level_2.get("route_risk_candidates"))

    cluster_specs = (
        (
            "hidden_api_cluster",
            hidden_apis,
            "Hidden API Recovery",
            "Recovered API hosts and endpoints grouped to keep the architecture map compact.",
            "medium",
            {"hosts": _unique([row.get("host") for row in hidden_apis if isinstance(row, dict)], 20)},
        ),
        (
            "parameter_cluster",
            parameters,
            "Parameter Intelligence",
            "Route parameters grouped by category; individual parameters remain available in the report.",
            "medium" if int(summary.get("interesting_parameters") or 0) else "low",
            {"categories": dict(Counter(_text(row.get("category")) or "unknown" for row in parameters if isinstance(row, dict)))},
        ),
        (
            "permission_route_cluster",
            permissions,
            "Permission Routes",
            "Routes with explicit role, permission, guard, scope, policy, or authentication hints.",
            "high" if permissions else "info",
            {"routes": _unique([row.get("route") for row in permissions if isinstance(row, dict)], 20)},
        ),
        (
            "route_risk_cluster",
            risks,
            "Route Risk Candidates",
            "Rule-based route candidates for manual verification; no vulnerability is asserted.",
            "high" if any(isinstance(row, dict) and _text(row.get("risk_level")).lower() == "high" for row in risks) else "medium",
            {"candidates": _unique([row.get("title") for row in risks if isinstance(row, dict)], 20)},
        ),
    )
    cluster_ids: dict[str, str] = {}
    for node_type, rows, label, description, risk, extra_data in cluster_specs:
        if not rows:
            continue
        cluster_id = graph.add_node(
            node_type,
            f"{label}:{len(rows)}",
            label=f"{label} ({len(rows)})",
            title=label,
            description=description,
            risk=risk,
            confidence="medium",
            source_modules=source_modules,
            data={"count": len(rows), **extra_data},
        )
        if not cluster_id:
            continue
        cluster_ids[node_type] = cluster_id
        graph.add_edge(domain_id, cluster_id, "linked_to", label="Level 2 intelligence", source_modules=source_modules)

    for node_type, rows in (("permission_route_cluster", permissions), ("route_risk_cluster", risks), ("parameter_cluster", parameters)):
        cluster_id = cluster_ids.get(node_type)
        if not cluster_id:
            continue
        linked: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            path = _text(row.get("route")).split("?", 1)[0].rstrip("/").lower() or "/"
            route_id = route_ids_by_path.get(path)
            if not route_id or route_id in linked:
                continue
            linked.add(route_id)
            graph.add_edge(cluster_id, route_id, "relates_to", label="correlates", source_modules=source_modules)
            if len(linked) >= 16:
                break


def _add_oauth_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    oauth = data.get("oauth_intelligence") or {}
    if not isinstance(oauth, dict):
        return
    for row in [*as_list(oauth.get("providers")), *as_list(oauth.get("auth_routes")), *as_list(oauth.get("callback_urls")), *as_list(oauth.get("oidc_metadata")), *as_list(oauth.get("session_indicators"))]:
        value = _oauth_value(row)
        if not value:
            continue
        node_id = graph.add_node(
            "oauth",
            value,
            label=_oauth_label(row, value),
            title="OAuth / Session Indicator",
            description="Authentication or session indicator collected by OAuth Intelligence.",
            risk=_text(row.get("risk") if isinstance(row, dict) else "") or "info",
            confidence=_text(row.get("confidence") if isinstance(row, dict) else "") or "medium",
            source_modules=["oauth_intelligence"],
            data=_compact_dict(row if isinstance(row, dict) else {"value": value}),
        )
        graph.add_edge(domain_id, node_id, "authenticates_with", label="authenticates with", source_modules=["oauth_intelligence"])
        host = _host_from_url(value)
        if host and domain and not _is_same_site(host, domain):
            service_id = graph.add_node("third_party", host, title="External Service", source_modules=["oauth_intelligence"], data={"host": host})
            graph.add_edge(node_id, service_id, "hosted_on", label="hosted on", source_modules=["oauth_intelligence"])


def _add_cloud_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str) -> None:
    cloud = data.get("cloud_buckets") or {}
    if not isinstance(cloud, dict):
        return
    rows = [*as_list(cloud.get("candidates")), *as_list(cloud.get("verified")), *as_list(cloud.get("public_objects"))]
    seen: set[str] = set()
    for row in rows:
        value = _row_value(row)
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        provider = _cloud_provider(row, value)
        bucket_id = graph.add_node(
            "bucket",
            value,
            label=_bucket_label(value),
            title="Cloud Bucket",
            description="Cloud storage reference discovered in existing Pamp data.",
            risk=_text(row.get("risk") if isinstance(row, dict) else "") or ("high" if _text(row.get("status") if isinstance(row, dict) else "") == "public" else "info"),
            confidence=_text(row.get("confidence") if isinstance(row, dict) else "") or "medium",
            source_modules=["cloud_bucket_intelligence"],
            data=_compact_dict(row if isinstance(row, dict) else {"value": value}),
        )
        graph.add_edge(domain_id, bucket_id, "exposes", label="exposes", source_modules=["cloud_bucket_intelligence"])
        if provider:
            cloud_id = graph.add_node(
                "cloud",
                provider,
                label=provider,
                title="Cloud Provider",
                description="Cloud provider inferred from discovered storage reference.",
                confidence="medium",
                source_modules=["cloud_bucket_intelligence"],
                data={"provider": provider},
            )
            graph.add_edge(domain_id, cloud_id, "uses", label="uses", source_modules=["cloud_bucket_intelligence"])
            graph.add_edge(bucket_id, cloud_id, "hosted_on", label="hosted on", source_modules=["cloud_bucket_intelligence"])


def _add_port_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str) -> None:
    surface = data.get("port_surface") or {}
    if not isinstance(surface, dict):
        return
    target_ip = _text(surface.get("ip"))
    target_id = graph.add_node("ip", target_ip, title="Scanned IP Address", confidence="high", source_modules=["port_surface"]) if target_ip else domain_id
    for row in as_list(surface.get("open_ports"))[:MAX_PORT_NODES]:
        if not isinstance(row, dict):
            continue
        port = _text(row.get("port"))
        if not port:
            continue
        protocol = _text(row.get("protocol")) or "tcp"
        service = _text(row.get("service"))
        label = f"{protocol}/{port}" + (f" {service}" if service else "")
        risk = _text(row.get("risk")) or ("medium" if row.get("sensitive") else "info")
        port_id = graph.add_node(
            "port",
            f"{target_ip or 'domain'}:{protocol}:{port}:{service}",
            label=label,
            title="Open Network Port",
            description="Open port reported by Port Surface Intelligence / Nmap.",
            risk=risk,
            confidence="high",
            source_modules=["port_surface"],
            data={
                "ip": target_ip,
                "port": row.get("port"),
                "protocol": protocol,
                "service": service,
                "product": row.get("product"),
                "version": row.get("version"),
                "risk_reason": row.get("risk_reason"),
            },
        )
        graph.add_edge(target_id, port_id, "exposes", label="exposes", confidence="high", source_modules=["port_surface"])
        product = _text(row.get("product"))
        if product:
            product_id = graph.add_node("server", product, title="Port Service Product", confidence="medium", source_modules=["port_surface"], data={"product": product})
            graph.add_edge(port_id, product_id, "serves", label="serves", source_modules=["port_surface"])


def _add_social_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str) -> None:
    social = data.get("social_intelligence") or {}
    profiles = as_list(social.get("profiles")) if isinstance(social, dict) else []
    if not profiles:
        profiles = as_list(data.get("social_profiles"))
    if not profiles:
        profiles = [{"url": item} for item in as_list(data.get("social_links"))]
    for row in profiles[:MAX_SOCIAL_NODES]:
        if not isinstance(row, dict):
            continue
        url = _text(row.get("url") or row.get("href"))
        if not url:
            continue
        label = _social_label(row, url)
        node_id = graph.add_node(
            "social",
            url,
            label=label,
            title="Social Profile",
            description="Social profile or public social link associated with the application.",
            confidence=_text(row.get("confidence")) or "medium",
            source_modules=["social_intelligence"],
            data={
                "platform": row.get("platform"),
                "url": url,
                "handle": row.get("handle") or row.get("username"),
                "verified": row.get("verified"),
                "fetch_status": row.get("fetch_status"),
                "source": row.get("source"),
            },
        )
        graph.add_edge(domain_id, node_id, "linked_to", label="linked to", source_modules=["social_intelligence"])


def _add_traffic_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    traffic = data.get("traffic_chain") or {}
    if not isinstance(traffic, dict):
        return
    host_counts: Counter[str] = Counter()
    host_resources: dict[str, set[str]] = {}
    api_values: list[dict[str, Any]] = []
    for row in as_list(traffic.get("requests")):
        if not isinstance(row, dict):
            continue
        url = _text(row.get("url"))
        host = _host_from_url(url) or _text(row.get("domain"))
        if host:
            host_counts[host] += 1
            host_resources.setdefault(host, set()).add(_text(row.get("resource_type") or row.get("display_type") or "request"))
        if _is_api_request(row, url):
            api_values.append(row)

    for host, count in host_counts.most_common(MAX_EXTERNAL_SERVICE_NODES):
        if not host or not domain_id:
            continue
        if domain and _is_same_site(host, domain):
            if host == domain:
                continue
            node_id = graph.add_node(
                "domain",
                host,
                title="Application Subdomain",
                description="Same-site host observed in browser traffic.",
                confidence="medium",
                source_modules=["traffic_chain"],
                data={"host": host, "requests": count, "resource_types": sorted(host_resources.get(host) or [])},
            )
            graph.add_edge(domain_id, node_id, "linked_to", label="traffic host", source_modules=["traffic_chain"])
            continue
        node_id = graph.add_node(
            "third_party",
            host,
            label=host,
            title="External Service",
            description="Third-party host observed in browser traffic.",
            confidence="medium",
            source_modules=["traffic_chain"],
            data={"host": host, "requests": count, "resource_types": sorted(host_resources.get(host) or [])},
        )
        edge_type = "loads" if _host_is_static_only(host_resources.get(host) or set()) else "calls"
        graph.add_edge(domain_id, node_id, edge_type, label=edge_type, source_modules=["traffic_chain"])

    seen_api: set[str] = set()
    for row in api_values[:MAX_API_NODES]:
        value = _text(row.get("url"))
        key = value.lower()
        if not value or key in seen_api:
            continue
        seen_api.add(key)
        _add_api_node(graph, domain_id, domain, row, value, ["traffic_chain"])


def _add_finding_nodes(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str) -> None:
    rows: list[tuple[dict[str, Any], str]] = []
    rows.extend((row, "security_findings") for row in as_list(data.get("security_findings")) if isinstance(row, dict))
    rows.extend((row, "security_findings") for row in as_list(data.get("security_signals")) if isinstance(row, dict))
    sqli = data.get("sqli_analysis") or {}
    rows.extend((row, "security_findings") for row in as_list(sqli.get("findings")) if isinstance(row, dict))
    for row, source in rows[:MAX_FINDING_NODES]:
        label = _finding_label(row)
        if not label:
            continue
        risk = _finding_risk(row)
        node_id = graph.add_node(
            "finding",
            f"{label}:{row.get('evidence') or row.get('url') or row.get('detail')}",
            label=label,
            title="Security Finding",
            description=_text(row.get("evidence") or row.get("notes") or row.get("detail")),
            risk=risk,
            confidence=_text(row.get("confidence")) or ("high" if risk in {"high", "critical"} else "medium"),
            source_modules=[source],
            data=_compact_dict(row),
        )
        graph.add_edge(domain_id, node_id, "has_finding", label="has finding", source_modules=[source])
        for route_id in _matching_route_node_ids(graph, row):
            graph.add_edge(route_id, node_id, "has_finding", label="route finding", source_modules=[source, "application_route_intelligence"])


def _add_insights(graph: _BlueprintGraph, data: dict[str, Any], domain_id: str, domain: str) -> None:
    cloudflare_nodes = [
        node["id"]
        for node in graph.nodes.values()
        if "cloudflare" in _text(node.get("label")).lower()
    ]
    dns_text = " ".join(_text(item) for item in as_list((data.get("dns") or {}).get("NS")))
    if cloudflare_nodes or "cloudflare" in dns_text.lower():
        graph.add_insight(
            "Application is protected by Cloudflare.",
            confidence="high" if cloudflare_nodes else "medium",
            source_modules=["dns", "technology_fingerprinting", "traffic_chain"],
            related_node_ids=[domain_id, *cloudflare_nodes],
        )

    api_nodes = [node["id"] for node in graph.nodes.values() if node.get("type") == "api"]
    if api_nodes:
        graph.add_insight(
            "Public API endpoints were discovered.",
            risk="medium",
            confidence="high",
            source_modules=["api_discovery", "javascript_intelligence", "traffic_chain"],
            related_node_ids=[domain_id, *api_nodes[:12]],
        )

    oauth_nodes = [node["id"] for node in graph.nodes.values() if node.get("type") == "oauth"]
    if oauth_nodes:
        graph.add_insight(
            "OAuth or session integration indicators are present.",
            confidence="medium",
            source_modules=["oauth_intelligence"],
            related_node_ids=[domain_id, *oauth_nodes[:12]],
        )

    port_nodes = [node["id"] for node in graph.nodes.values() if node.get("type") == "port"]
    if port_nodes:
        graph.add_insight(
            "Open network ports extend the attack surface.",
            risk="medium",
            confidence="high",
            source_modules=["port_surface"],
            related_node_ids=[domain_id, *port_nodes[:12]],
        )

    social_nodes = [node["id"] for node in graph.nodes.values() if node.get("type") == "social"]
    if social_nodes:
        graph.add_insight(
            "Social profiles are linked to the application.",
            confidence="high",
            source_modules=["social_intelligence"],
            related_node_ids=[domain_id, *social_nodes[:12]],
        )

    tls = data.get("tls_certificate") or {}
    days_remaining = _safe_int(tls.get("days_remaining") if isinstance(tls, dict) else None)
    if isinstance(tls, dict) and (tls.get("issuer") or tls.get("subject")) and not tls.get("verification_error") and (days_remaining is None or days_remaining > 0):
        tls_nodes = [node["id"] for node in graph.nodes.values() if node.get("type") == "tls"]
        graph.add_insight(
            "TLS certificate is valid and associated with the target domain.",
            confidence="high",
            source_modules=["tls"],
            related_node_ids=[domain_id, *tls_nodes],
        )

    third_party_nodes = [node["id"] for node in graph.nodes.values() if node.get("type") in {"third_party", "cloud", "bucket"}]
    if third_party_nodes:
        graph.add_insight(
            "External services are part of the application runtime surface.",
            confidence="medium",
            source_modules=["traffic_chain", "cloud_bucket_intelligence", "devtools_intelligence"],
            related_node_ids=[domain_id, *third_party_nodes[:12]],
        )

    for note in _unique(as_list(data.get("analyst_notes")), 5):
        graph.add_insight(
            note,
            confidence="medium",
            source_modules=["analyst_notes"],
            related_node_ids=[domain_id],
        )


def _node_limit(node_type: str) -> int:
    return {
        "api": MAX_API_NODES,
        "domain": MAX_DOMAIN_NODES,
        "dns": MAX_DNS_NODES,
        "technology": MAX_TECHNOLOGY_NODES,
        "frontend": MAX_FRONTEND_NODES,
        "third_party": MAX_EXTERNAL_SERVICE_NODES,
        "port": MAX_PORT_NODES,
        "social": MAX_SOCIAL_NODES,
        "route": MAX_ROUTE_NODES,
        "recovered_route": MAX_JS_ROUTE_NODES,
        "dynamic_import": MAX_DYNAMIC_IMPORT_NODES,
        "high_interest_route": MAX_ROUTE_NODES,
        "hidden_api_cluster": 1,
        "parameter_cluster": 1,
        "permission_route_cluster": 1,
        "route_risk_cluster": 1,
        "finding": MAX_FINDING_NODES,
    }.get(node_type, 0)


def _node_id(node_type: str, value: str) -> str:
    key = _text(value).strip().lower()
    if node_type in {"domain", "ip", "asn", "server", "technology", "frontend", "oauth", "cloud", "port", "route", "recovered_route", "dynamic_import", "high_interest_route"}:
        simple = re.sub(r"[^a-z0-9_.:/@+-]+", "-", key).strip("-")
        if simple and len(simple) <= 96:
            return f"{node_type}:{simple}"
    return f"{node_type}:{digest_value(key)}"


def _title_for(node_type: str) -> str:
    return {
        "domain": "Domain",
        "ip": "IP Address",
        "asn": "ASN / Network",
        "dns": "DNS Record",
        "tls": "TLS Certificate",
        "server": "Server",
        "technology": "Technology",
        "frontend": "Frontend Asset",
        "api": "API Endpoint",
        "oauth": "OAuth / Auth",
        "cloud": "Cloud Provider",
        "bucket": "Cloud Bucket",
        "port": "Open Port",
        "third_party": "Third-party Service",
        "social": "Social Profile",
        "route": "Application Route",
        "recovered_route": "JS Recovered Route",
        "dynamic_import": "Dynamic Import",
        "high_interest_route": "High Interest Route",
        "hidden_api_cluster": "Hidden API Cluster",
        "parameter_cluster": "Parameter Cluster",
        "permission_route_cluster": "Permission Route Cluster",
        "route_risk_cluster": "Route Risk Cluster",
        "finding": "Security Finding",
    }.get(node_type, node_type)


def _label_for(node_type: str, value: str) -> str:
    if node_type in {"api", "frontend", "bucket", "route", "recovered_route", "dynamic_import", "high_interest_route"}:
        return _url_label(value)
    return value


def _technology_candidates(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    output: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for row in as_list(data.get("technologies")) + as_list(data.get("detected_technology_details")):
        if isinstance(row, dict):
            name = _text(row.get("name") or row.get("technology") or row.get("label"))
            if name and name.lower() not in seen:
                seen.add(name.lower())
                output.append((name, row))
    for item in as_list(data.get("detected_technologies")):
        name = _text(item)
        if name and name.lower() not in seen:
            seen.add(name.lower())
            output.append((name, {"name": name, "source": "detected_technologies"}))
    return output[:MAX_TECHNOLOGY_NODES]


def _technology_kind(name: str, row: dict[str, Any]) -> str:
    lowered = name.lower()
    category = _text(row.get("category")).lower()
    if lowered in SERVER_TECHNOLOGIES or "server" in category:
        return "server"
    if lowered in FRONTEND_TECHNOLOGIES or "frontend" in category or "cms" in category:
        return "frontend"
    if _is_protection_technology(name, row):
        return "third_party"
    return "technology"


def _is_protection_technology(name: str, row: dict[str, Any]) -> bool:
    lowered = name.lower()
    category = _text(row.get("category")).lower()
    return any(marker in lowered for marker in PROTECTION_TECHNOLOGIES) or any(
        marker in category for marker in ("cdn", "waf", "protection")
    )


def _endpoint_value(row: Any) -> str:
    if isinstance(row, dict):
        return _first_text(row.get("endpoint"), row.get("url"), row.get("value"), row.get("href"))
    return _text(row)


def _row_value(row: Any) -> str:
    if isinstance(row, dict):
        return _first_text(row.get("value"), row.get("url"), row.get("endpoint"), row.get("href"), row.get("name"))
    return _text(row)


def _oauth_value(row: Any) -> str:
    if isinstance(row, dict):
        return _first_text(row.get("provider"), row.get("name"), row.get("value"), row.get("url"), row.get("issuer"), row.get("authorization_endpoint"))
    return _text(row)


def _oauth_label(row: Any, value: str) -> str:
    if isinstance(row, dict):
        provider = _first_text(row.get("provider"), row.get("name"))
        if provider:
            return provider
    return _api_label(value)


def _api_label(value: str, method: str = "", kind_hint: str = "") -> str:
    parsed = urlparse(value)
    if kind_hint == "graphql" and not parsed.scheme:
        return f"GraphQL: {value}"
    if parsed.scheme and parsed.netloc:
        label = parsed.path or "/"
        if parsed.query:
            label = f"{label}?{parsed.query}"
        if parsed.netloc:
            label = f"{parsed.netloc}{label}"
    else:
        label = value
    if method:
        return f"{method.upper()} {label}"
    return label[:140]


def _route_label(row: dict[str, Any], value: str) -> str:
    method = _text(row.get("method"))
    path = _first_text(row.get("path"), value)
    label = _api_label(path or value, method)
    category = _text(row.get("category"))
    if category and category not in {"unknown", "public"}:
        return f"{category}: {label}"[:140]
    return label[:140]


def _js_route_label(row: dict[str, Any], value: str) -> str:
    pattern = _text(row.get("matched_pattern"))
    label = _api_label(_first_text(row.get("path"), value), _text(row.get("method")))
    return f"{pattern}: {label}"[:140] if pattern else label[:140]


def _dynamic_import_label(row: dict[str, Any], value: str) -> str:
    chunk = _first_text(row.get("chunk_name"), row.get("import_path"), value)
    return _url_label(chunk)


def _route_title(node_type: str) -> str:
    return {
        "route": "Application Route",
        "recovered_route": "JS Recovered Route",
        "high_interest_route": "High Interest Route",
    }.get(node_type, "Application Route")


def _route_risk(row: dict[str, Any]) -> str:
    explicit = _normalize_risk(_first_text(row.get("risk"), row.get("risk_hint"), row.get("category")))
    category = _text(row.get("category")).lower()
    if category in {"admin", "internal", "debug", "graphql", "websocket"}:
        return _max_risk(explicit, "medium")
    if category in {"auth", "upload", "download", "staging", "dev", "test", "metrics"}:
        return _max_risk(explicit, "low")
    return explicit


def _route_source_js_node(graph: _BlueprintGraph, source_file: str) -> str:
    source = _text(source_file)
    if not source:
        return ""
    return graph.add_node(
        "frontend",
        source,
        label=_url_label(source),
        title="JavaScript Asset",
        description="JavaScript source associated with recovered application routes.",
        confidence="medium",
        source_modules=["application_route_intelligence"],
        data={"source_file": source},
    )


def _matching_route_node_ids(graph: _BlueprintGraph, finding_row: dict[str, Any]) -> list[str]:
    haystack = " ".join(_text(finding_row.get(key)).lower() for key in ("url", "endpoint", "path", "detail", "evidence", "notes", "parameter"))
    if not haystack:
        return []
    matches: list[str] = []
    for node in graph.nodes.values():
        if node.get("type") not in {"route", "recovered_route", "high_interest_route"}:
            continue
        data = node.get("data") or {}
        candidates = [
            _text(data.get("absolute_url")).lower(),
            _text(data.get("path")).lower(),
            _text(node.get("label")).lower(),
        ]
        if any(candidate and candidate in haystack for candidate in candidates):
            matches.append(_text(node.get("id")))
            if len(matches) >= 8:
                break
    return matches


def _url_label(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        path = parsed.path.rstrip("/") or "/"
        name = path.rsplit("/", 1)[-1] or parsed.netloc
        if len(name) < 4:
            name = f"{parsed.netloc}{path}"
        return name[:96]
    return value[:96]


def _bucket_label(value: str) -> str:
    parsed = urlparse(value)
    if parsed.netloc:
        return parsed.netloc
    return value[:96]


def _cloud_provider(row: Any, value: str) -> str:
    if isinstance(row, dict):
        provider = _first_text(row.get("provider"), row.get("cloud"), row.get("service"))
        if provider:
            return provider
    lowered = value.lower()
    if "amazonaws.com" in lowered or ".s3." in lowered:
        return "AWS S3"
    if "storage.googleapis.com" in lowered:
        return "Google Cloud Storage"
    if "blob.core.windows.net" in lowered:
        return "Azure Blob Storage"
    return ""


def _social_label(row: dict[str, Any], url: str) -> str:
    platform = _text(row.get("platform"))
    handle = _text(row.get("handle") or row.get("username") or row.get("display_name"))
    if platform and handle:
        return f"{platform}: {handle}"
    return platform or handle or _url_label(url)


def _finding_label(row: dict[str, Any]) -> str:
    return _first_text(row.get("name"), row.get("detail"), row.get("type"), row.get("parameter"), row.get("url"))


def _finding_risk(row: dict[str, Any]) -> str:
    explicit = _normalize_risk(_first_text(row.get("risk"), row.get("level"), row.get("severity")))
    if explicit != "info":
        return explicit
    text_value = " ".join(_text(row.get(key)).lower() for key in ("type", "detail", "name", "evidence", "url"))
    if any(marker in text_value for marker in (".env", "phpinfo", "backup", "dump.sql", "db.sql", "secret", "token")):
        return "high"
    if any(marker in text_value for marker in ("sensitive", "missing", "exposed", "login", "openapi", "swagger")):
        return "medium"
    return "info"


def _is_api_request(row: dict[str, Any], url: str) -> bool:
    lowered = url.lower()
    resource = _text(row.get("resource_type") or row.get("display_type")).lower()
    category = _text(row.get("category")).lower()
    return (
        category in {"api", "auth", "graphql", "websocket"}
        or resource in {"xhr", "fetch", "websocket"}
        or any(marker in lowered for marker in ("/api/", "/graphql", "/auth/", "/oauth/", "/session"))
    )


def _host_is_static_only(resources: set[str]) -> bool:
    lowered = {item.lower() for item in resources}
    return bool(lowered) and lowered <= {"script", "stylesheet", "image", "font", "media", "other", "css"}


def _host_from_url(value: str) -> str:
    parsed = urlparse(_text(value))
    return (parsed.hostname or "").lower()


def _is_same_site(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith(f".{domain}")


def _clean_domain(value: Any) -> str:
    raw = _text(value).strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    raw = raw.strip(".")
    return raw if "." in raw and " " not in raw else ""


def _asn_label(row: dict[str, Any]) -> str:
    asn = _text(row.get("asn"))
    if asn:
        return asn if asn.upper().startswith("AS") else f"AS{asn}"
    return _first_text(row.get("name"), row.get("handle"))


def _header(headers: dict[str, Any], name: str) -> str:
    if not isinstance(headers, dict):
        return ""
    lowered = name.lower()
    for key, value in headers.items():
        if _text(key).lower() == lowered:
            return _text(value)
    return ""


def _normalize_risk(value: Any) -> str:
    raw = _text(value).strip().lower()
    if raw in {"critical", "high", "medium", "warning", "low", "info"}:
        return "medium" if raw == "warning" else raw
    if any(marker in raw for marker in ("critical", "severe")):
        return "critical"
    if any(marker in raw for marker in ("high", "danger")):
        return "high"
    if any(marker in raw for marker in ("medium", "warn", "exposed", "missing")):
        return "medium"
    if any(marker in raw for marker in ("low", "ok", "success")):
        return "low"
    return "info"


def _normalize_confidence(value: Any) -> str:
    raw = _text(value).strip().lower()
    return raw if raw in CONFIDENCE_ORDER else "medium"


def _max_risk(left: Any, right: Any) -> str:
    left_norm = _normalize_risk(left)
    right_norm = _normalize_risk(right)
    return left_norm if RISK_ORDER[left_norm] >= RISK_ORDER[right_norm] else right_norm


def _max_confidence(left: Any, right: Any) -> str:
    left_norm = _normalize_confidence(left)
    right_norm = _normalize_confidence(right)
    return left_norm if CONFIDENCE_ORDER[left_norm] >= CONFIDENCE_ORDER[right_norm] else right_norm


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_text(*values: Any) -> str:
    for value in values:
        raw = _text(value)
        if raw:
            return raw
    return ""


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _unique(values: list[Any], limit: int) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _text(value)
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        output.append(text)
        if len(output) >= limit:
            break
    return output


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _compact_dict(value: dict[str, Any], limit: int = 24) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, Any] = {}
    for key, item in value.items():
        if len(output) >= limit:
            break
        if str(key).startswith("_"):
            continue
        output[str(key)] = _compact_value(item)
    return output


def _compact_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_compact_value(item) for item in value[:20]]
    if isinstance(value, dict):
        return _compact_dict(value, limit=12)
    return str(value)
