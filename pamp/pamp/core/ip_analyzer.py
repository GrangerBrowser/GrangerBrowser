from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import re
import socket
import ssl
import time
import traceback
from typing import Any
from urllib.parse import urlparse

import requests

from .models import utc_now
from .port_surface import analyze_port_surface


REQUEST_TIMEOUT = 8
IP_NMAP_TIMEOUT = 240
WEB_PROBE_LIMIT = 8
WEB_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9443}
DATACENTER_KEYWORDS = (
    "hosting",
    "cloud",
    "datacenter",
    "data center",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "akamai",
    "cloudflare",
    "leaseweb",
    "vultr",
    "colo",
    "server",
)
CLOUD_PROVIDERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Amazon Web Services", ("amazon", "amazonaws", "aws", "ec2")),
    ("Microsoft Azure", ("microsoft", "azure")),
    ("Google Cloud", ("google cloud", "googleusercontent", "gcp")),
    ("Cloudflare", ("cloudflare",)),
    ("Akamai", ("akamai", "linode")),
    ("Fastly", ("fastly",)),
    ("DigitalOcean", ("digitalocean",)),
    ("OVHcloud", ("ovh",)),
    ("Hetzner", ("hetzner",)),
    ("Vultr", ("vultr",)),
    ("Leaseweb", ("leaseweb",)),
)
CDN_MARKERS = ("cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "cdn77", "bunnycdn", "imperva")
WAF_MARKERS = ("cloudflare", "imperva", "incapsula", "sucuri", "akamai", "fastly")
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
MANAGEMENT_PORTS = {22, 23, 3389, 5900, 5985, 5986, 2375, 2376, 6443, 10250}


def analyze_ip(
    ip: str,
    *,
    scan_ports: bool = True,
    nmap_timeout: int = IP_NMAP_TIMEOUT,
    debug_log: Any | None = None,
) -> dict[str, Any]:
    """Analyze an IP as an infrastructure target and retain legacy top-level fields."""
    started = time.monotonic()
    checked_at = utc_now()
    ip = ip.strip()
    errors: list[str] = []
    timeline: list[dict[str, Any]] = []

    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc

    _timeline(timeline, "IP validation", "completed", "Input parsed as IPv4" if parsed_ip.version == 4 else "Input parsed as IPv6")
    ip_api = _ip_api_lookup(ip, errors)
    _timeline(timeline, "Geolocation", "completed" if ip_api else "partial", ip_api.get("country") or "No geolocation returned")
    rdap = _rdap_lookup(ip, errors)
    _timeline(timeline, "Registry and ASN", "completed" if rdap else "partial", rdap.get("handle") or "No RDAP allocation returned")
    reverse_dns = _reverse_dns(ip, errors)
    _timeline(timeline, "Reverse DNS", "completed" if reverse_dns else "not_found", reverse_dns or "No PTR record")

    as_label = ip_api.get("as") or ""
    asn = _extract_asn(as_label) or rdap.get("asn") or ""
    as_name = ip_api.get("asname") or _as_name(as_label)
    organization = ip_api.get("org") or rdap.get("name") or ""
    provider_name = ip_api.get("isp") or organization
    hosting_signals = _hosting_signals(ip_api, rdap, organization, provider_name)
    tor_exit = _is_tor_exit(ip, errors) if not parsed_ip.is_private else False
    proxy_signals = _proxy_signals(ip_api, tor_exit)

    if scan_ports and not parsed_ip.is_private:
        try:
            port_surface = analyze_port_surface(ip, ip, timeout=nmap_timeout, debug_log=debug_log)
        except Exception as exc:
            reason = f"{type(exc).__name__}: {exc}"
            errors.append(f"Port surface: {reason}")
            if debug_log:
                try:
                    debug_log(f"[IP][PORT_SURFACE] {reason}\n{traceback.format_exc()}")
                except Exception:
                    pass
            port_surface = _failed_port_surface(ip, reason)
    else:
        port_surface = _skipped_port_surface(ip, "Port scan disabled" if not scan_ports else "Private IP target")
    errors.extend(str(item) for item in (port_surface.get("errors") or []) if str(item).strip())
    _timeline(
        timeline,
        "Nmap ports",
        str(port_surface.get("status") or "unknown"),
        f"{(port_surface.get('summary') or {}).get('open_ports') or 0} open port(s)",
        duration_ms=port_surface.get("duration_ms"),
    )

    open_ports = [row for row in (port_surface.get("open_ports") or []) if isinstance(row, dict)]
    http_observations = _probe_http_services(ip, open_ports, errors) if not parsed_ip.is_private else []
    _timeline(timeline, "HTTP services", "completed" if http_observations else "not_found", f"{len(http_observations)} HTTP observation(s)")
    tls_observations = _probe_tls_services(ip, open_ports, errors) if not parsed_ip.is_private else []
    _timeline(timeline, "TLS services", "completed" if tls_observations else "not_found", f"{len(tls_observations)} TLS observation(s)")

    provider = _provider_intelligence(ip_api, rdap, organization, provider_name, reverse_dns, http_observations)
    geo = _geo_intelligence(ip_api, rdap)
    registry = _registry_intelligence(rdap, geo)
    ports = _port_rows(open_ports)
    services = _service_rows(ports)
    technologies = _technology_rows(ports, http_observations, tls_observations)
    classification = _classify_infrastructure(provider, ports, http_observations)
    relationships = _relationships(ip, reverse_dns, rdap, ports, services, technologies, http_observations, tls_observations)
    risk_signals = _risk_signals(ip, parsed_ip, ports, services, provider, classification, reverse_dns, tls_observations)
    relationships["findings"] = [row.get("title") for row in risk_signals]
    infrastructure_blueprint = _ip_blueprint(ip, asn, provider, ports, services, technologies, risk_signals)
    evidence = _evidence_rows(ip_api, rdap, reverse_dns, provider, port_surface, http_observations, tls_observations, risk_signals)
    insights = _insights(classification, ports, provider, risk_signals)
    duration_ms = round((time.monotonic() - started) * 1000)
    _timeline(timeline, "Risk signals", "completed", f"{len(risk_signals)} analytical signal(s)")
    _timeline(timeline, "IP report model", "completed", "Infrastructure intelligence normalized", duration_ms=duration_ms)

    summary = {
        "ip": ip,
        "country": geo.get("country") or "",
        "country_code": geo.get("country_code") or "",
        "region": geo.get("region") or "",
        "city": geo.get("city") or "",
        "asn": asn,
        "as_name": as_name,
        "organization": organization,
        "hosting_provider": provider_name,
        "cloud_provider": provider.get("cloud_provider") or "",
        "reverse_dns": reverse_dns,
        "detected_services": len(services),
        "open_ports": len(ports),
        "detected_technologies": len(technologies),
        "last_scan": checked_at,
        "scan_duration_ms": duration_ms,
        "infrastructure_role": classification.get("primary_role") or "Unknown",
        "risk_signals": len(risk_signals),
    }
    ip_intelligence = {
        "status": "completed" if not errors else "partial",
        "summary": summary,
        "geo": geo,
        "asn": {"number": asn, "name": as_name, "label": as_label, "organization": organization},
        "provider": provider,
        "registry": registry,
        "classification": classification,
        "services": services,
        "ports": ports,
        "technologies": technologies,
        "relationships": relationships,
        "blueprint": infrastructure_blueprint,
        "timeline": timeline,
        "risk_signals": risk_signals,
        "evidence": evidence,
        "insights": insights,
        "http_observations": http_observations,
        "tls_observations": tls_observations,
        "scan": port_surface,
    }

    risk_flags = []
    if parsed_ip.is_private:
        risk_flags.append("private_ip")
    if hosting_signals:
        risk_flags.append("hosting_or_datacenter")
    if proxy_signals:
        risk_flags.append("vpn_proxy_tor")
    risk_flags.extend(str(row.get("type") or "") for row in risk_signals if row.get("type"))

    return {
        "ip": ip,
        "version": parsed_ip.version,
        "is_private": parsed_ip.is_private,
        "country": geo.get("country") or "",
        "country_code": geo.get("country_code") or "",
        "region": geo.get("region") or "",
        "region_name": geo.get("region") or "",
        "city": geo.get("city") or "",
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "timezone": geo.get("timezone") or "",
        "asn": asn,
        "as_label": as_label,
        "as_name": as_name,
        "organization": organization,
        "isp": provider_name,
        "provider": provider_name,
        "reverse_dns": reverse_dns,
        "hosting_datacenter": bool(hosting_signals),
        "hosting_or_datacenter": bool(hosting_signals),
        "hosting_signals": hosting_signals,
        "vpn_proxy_tor": bool(proxy_signals),
        "vpn_proxy_tor_signals": proxy_signals,
        "risk_flags": _unique(risk_flags),
        "rdap": rdap,
        "port_surface": port_surface,
        "ip_intelligence": ip_intelligence,
        "reputation": {"status": "not_scored", "reason": "No keyless public reputation source configured"},
        "source": "ip-api.com, rdap.org, reverse_dns, torproject.org, nmap",
        "sources": ["ip-api.com", "rdap.org", "reverse_dns", "torproject.org", "nmap"],
        "checked_at": checked_at,
        "duration_ms": duration_ms,
        "errors": _unique(errors),
    }


def _ip_api_lookup(ip: str, errors: list[str]) -> dict[str, Any]:
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,offset,currency,as,asname,org,isp,mobile,proxy,hosting,query"
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") == "fail":
            errors.append(f"ip-api.com: {payload.get('message', 'lookup failed')}")
            return {}
        return payload
    except Exception as exc:
        errors.append(f"ip-api.com: {exc}")
        return {}


def _rdap_lookup(ip: str, errors: list[str]) -> dict[str, Any]:
    try:
        response = requests.get(f"https://rdap.org/ip/{ip}", timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        notices = []
        for notice in payload.get("notices") or []:
            title = notice.get("title")
            if title:
                notices.append(title)
        abuse_contacts = _rdap_abuse_contacts(payload.get("entities") or [])
        cidrs = [
            {
                "version": row.get("v4prefix") and 4 or row.get("v6prefix") and 6 or "",
                "prefix": row.get("v4prefix") or row.get("v6prefix") or "",
                "length": row.get("length"),
            }
            for row in (payload.get("cidr0_cidrs") or [])
            if isinstance(row, dict)
        ]
        events = [
            {"action": row.get("eventAction") or "", "date": row.get("eventDate") or ""}
            for row in (payload.get("events") or [])
            if isinstance(row, dict)
        ]
        return {
            "handle": payload.get("handle") or "",
            "name": payload.get("name") or "",
            "type": payload.get("type") or "",
            "country": payload.get("country") or "",
            "start_address": payload.get("startAddress") or "",
            "end_address": payload.get("endAddress") or "",
            "parent_handle": payload.get("parentHandle") or "",
            "port43": payload.get("port43") or "",
            "network_type": payload.get("type") or "",
            "abuse_contacts": abuse_contacts,
            "cidrs": cidrs,
            "events": events,
            "notices": notices,
            "asn": payload.get("asn") or "",
        }
    except Exception as exc:
        errors.append(f"rdap.org: {exc}")
        return {}


def _reverse_dns(ip: str, errors: list[str]) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as exc:
        errors.append(f"reverse_dns: {exc}")
        return ""


@lru_cache(maxsize=1)
def _tor_exit_list() -> set[str]:
    response = requests.get(
        "https://check.torproject.org/torbulkexitlist",
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return {line.strip() for line in response.text.splitlines() if line.strip()}


def _is_tor_exit(ip: str, errors: list[str]) -> bool:
    try:
        return ip in _tor_exit_list()
    except Exception as exc:
        errors.append(f"tor_exit_list: {exc}")
        return False


def _extract_asn(as_label: str) -> str:
    if not as_label:
        return ""
    first = as_label.split()[0]
    return first if first.upper().startswith("AS") else ""


def _hosting_signals(
    ip_api: dict[str, Any],
    rdap: dict[str, Any],
    organization: str,
    provider: str,
) -> list[str]:
    signals: list[str] = []
    if ip_api.get("hosting") is True:
        signals.append("ip-api hosting flag")

    haystack = " ".join(
        str(value)
        for value in [
            organization,
            provider,
            ip_api.get("asname") or "",
            rdap.get("name") or "",
            rdap.get("handle") or "",
        ]
    ).lower()
    for keyword in DATACENTER_KEYWORDS:
        if keyword in haystack:
            signals.append(f"provider keyword: {keyword}")

    return sorted(set(signals))


def _proxy_signals(ip_api: dict[str, Any], tor_exit: bool) -> list[str]:
    signals: list[str] = []
    if ip_api.get("proxy") is True:
        signals.append("ip-api proxy flag")
    if tor_exit:
        signals.append("Tor exit node")
    return signals


def _geo_intelligence(ip_api: dict[str, Any], rdap: dict[str, Any]) -> dict[str, Any]:
    country_code = str(ip_api.get("countryCode") or rdap.get("country") or "").upper()
    return {
        "country": ip_api.get("country") or "",
        "country_code": country_code,
        "region": ip_api.get("regionName") or ip_api.get("region") or "",
        "region_code": ip_api.get("region") or "",
        "city": ip_api.get("city") or "",
        "postal_code": ip_api.get("zip") or "",
        "latitude": ip_api.get("lat"),
        "longitude": ip_api.get("lon"),
        "timezone": ip_api.get("timezone") or "",
        "utc_offset_seconds": ip_api.get("offset"),
        "currency": ip_api.get("currency") or "",
        "internet_registry": _registry_name(str(rdap.get("port43") or ""), country_code),
        "network_region": rdap.get("country") or country_code,
    }


def _registry_intelligence(rdap: dict[str, Any], geo: dict[str, Any]) -> dict[str, Any]:
    return {
        "registry": geo.get("internet_registry") or "",
        "handle": rdap.get("handle") or "",
        "name": rdap.get("name") or "",
        "type": rdap.get("type") or rdap.get("network_type") or "",
        "country": rdap.get("country") or geo.get("country_code") or "",
        "start_address": rdap.get("start_address") or "",
        "end_address": rdap.get("end_address") or "",
        "parent_handle": rdap.get("parent_handle") or "",
        "cidrs": rdap.get("cidrs") or [],
        "events": rdap.get("events") or [],
        "abuse_contacts": rdap.get("abuse_contacts") or [],
        "notices": rdap.get("notices") or [],
    }


def _provider_intelligence(
    ip_api: dict[str, Any],
    rdap: dict[str, Any],
    organization: str,
    provider: str,
    reverse_dns: str,
    http_observations: list[dict[str, Any]],
) -> dict[str, Any]:
    header_text = " ".join(
        str(value)
        for row in http_observations
        for value in (row.get("server"), row.get("via"), row.get("powered_by"))
        if value
    )
    haystack = " ".join(
        str(value)
        for value in (
            organization,
            provider,
            ip_api.get("asname"),
            ip_api.get("as"),
            rdap.get("name"),
            rdap.get("handle"),
            reverse_dns,
            header_text,
        )
        if value
    ).lower()
    cloud_provider = ""
    cloud_evidence: list[str] = []
    for name, markers in CLOUD_PROVIDERS:
        matched = [marker for marker in markers if marker in haystack]
        if matched:
            cloud_provider = name
            cloud_evidence.extend(f"provider marker: {marker}" for marker in matched)
            break
    cdn_markers = [marker for marker in CDN_MARKERS if marker in haystack]
    waf_markers = [marker for marker in WAF_MARKERS if marker in haystack]
    return {
        "organization": organization,
        "provider": provider,
        "isp": ip_api.get("isp") or provider,
        "hosting": bool(ip_api.get("hosting") or _hosting_signals(ip_api, rdap, organization, provider)),
        "mobile_network": bool(ip_api.get("mobile")),
        "cloud": bool(cloud_provider),
        "cloud_provider": cloud_provider,
        "cloud_evidence": _unique(cloud_evidence),
        "cdn": bool(cdn_markers),
        "cdn_provider": _provider_from_markers(cdn_markers, cloud_provider),
        "cdn_evidence": [f"infrastructure marker: {marker}" for marker in cdn_markers],
        "waf": bool(waf_markers),
        "waf_provider": _provider_from_markers(waf_markers, cloud_provider),
        "waf_evidence": [f"infrastructure marker: {marker}" for marker in waf_markers],
        "reverse_dns": reverse_dns,
        "abuse_contacts": rdap.get("abuse_contacts") or [],
    }


def _classify_infrastructure(
    provider: dict[str, Any],
    ports: list[dict[str, Any]],
    http_observations: list[dict[str, Any]],
) -> dict[str, Any]:
    port_numbers = {int(row.get("port") or 0) for row in ports}
    roles: list[dict[str, str]] = []

    def add(role: str, confidence: str, evidence: str) -> None:
        if role not in {row["role"] for row in roles}:
            roles.append({"role": role, "confidence": confidence, "evidence": evidence})

    if provider.get("cdn"):
        add("Likely CDN Edge", "high", ", ".join(provider.get("cdn_evidence") or []) or "CDN provider marker")
    if provider.get("waf"):
        add("Likely WAF Edge", "medium", ", ".join(provider.get("waf_evidence") or []) or "WAF provider marker")
    if provider.get("cloud"):
        add("Cloud", "high", str(provider.get("cloud_provider") or "Cloud provider marker"))
    if port_numbers & MAIL_PORTS:
        add("Mail", "high", f"Mail ports: {', '.join(str(port) for port in sorted(port_numbers & MAIL_PORTS))}")
    if 53 in port_numbers:
        add("DNS", "high", "Port 53 is open")
    if http_observations and not provider.get("cdn") and not provider.get("waf"):
        add("Origin Candidate", "medium", "Direct web service observed without CDN/WAF provider markers; requires manual verification")
    if any("json" in str(row.get("content_type") or "").lower() for row in http_observations):
        add("API Backend", "medium", "HTTP service returned a JSON content type")
    if not roles:
        add("Unknown", "low", "Available evidence does not support a more specific role")
    return {
        "primary_role": roles[0]["role"],
        "roles": roles,
        "is_likely_edge": bool(provider.get("cdn") or provider.get("waf")),
        "origin_asserted": False,
    }


def _port_rows(open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in open_ports:
        port = int(row.get("port") or 0)
        service = str(row.get("service") or "unknown")
        risk_hint = str(row.get("risk_reason") or "")
        if not risk_hint and service == "unknown":
            risk_hint = "Unknown public service requires manual verification."
        elif not risk_hint and port in WEB_PORTS:
            risk_hint = "Public web service observed."
        rows.append(
            {
                "port": port,
                "state": row.get("state") or "open",
                "protocol": row.get("protocol") or "tcp",
                "service": service,
                "product": row.get("product") or "",
                "version": row.get("version") or "",
                "extra_info": row.get("extra_info") or "",
                "cpe": row.get("cpe") or [],
                "risk": row.get("risk") or ("warning" if risk_hint else "info"),
                "risk_hint": risk_hint,
            }
        )
    return sorted(rows, key=lambda row: (int(row.get("port") or 0), str(row.get("protocol") or "")))


def _service_rows(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in ports:
        service = str(row.get("service") or "unknown")
        product = str(row.get("product") or "")
        label = _service_label(int(row.get("port") or 0), service, product)
        rows.append(
            {
                "name": label,
                "icon": _service_icon(label),
                "port": row.get("port"),
                "protocol": row.get("protocol") or "tcp",
                "version": " ".join(value for value in (product, str(row.get("version") or "")) if value).strip(),
                "description": _service_description(label),
                "risk_hint": row.get("risk_hint") or "",
            }
        )
    return rows


def _technology_rows(
    ports: list[dict[str, Any]],
    http_observations: list[dict[str, Any]],
    tls_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in ports:
        product = str(row.get("product") or "").strip()
        if product:
            rows.append({"name": product, "version": row.get("version") or "", "source": f"Nmap port {row.get('port')}", "confidence": "high"})
        for cpe in row.get("cpe") or []:
            rows.append({"name": str(cpe), "version": row.get("version") or "", "source": f"Nmap CPE port {row.get('port')}", "confidence": "high"})
    for row in http_observations:
        for key, label in (("server", "HTTP Server"), ("powered_by", "X-Powered-By")):
            value = str(row.get(key) or "").strip()
            if value:
                rows.append({"name": value, "version": "", "source": f"{label} on port {row.get('port')}", "confidence": "high"})
    for row in tls_observations:
        if row.get("tls_version"):
            rows.append({"name": str(row.get("tls_version")), "version": "", "source": f"TLS port {row.get('port')}", "confidence": "high"})
    return _dedupe_dicts(rows, ("name", "source"))[:120]


def _relationships(
    ip: str,
    reverse_dns: str,
    rdap: dict[str, Any],
    ports: list[dict[str, Any]],
    services: list[dict[str, Any]],
    technologies: list[dict[str, Any]],
    http_observations: list[dict[str, Any]],
    tls_observations: list[dict[str, Any]],
) -> dict[str, Any]:
    domains = [reverse_dns] if reverse_dns else []
    for row in tls_observations:
        domains.extend(str(value) for value in row.get("san_dns") or [])
    for row in http_observations:
        location = str(row.get("location") or "")
        host = urlparse(location).hostname if location else ""
        if host:
            domains.append(host)
    domains = _unique([value.lstrip("*.") for value in domains if value])
    return {
        "ip": ip,
        "domains": domains,
        "subdomains": [value for value in domains if value.count(".") >= 2],
        "certificates": [
            {"port": row.get("port"), "subject": row.get("subject") or "", "issuer": row.get("issuer") or "", "san_dns": row.get("san_dns") or []}
            for row in tls_observations
        ],
        "routes": _unique([str(row.get("location") or "") for row in http_observations if row.get("location")]),
        "open_ports": [row.get("port") for row in ports],
        "services": [row.get("name") for row in services],
        "technologies": [row.get("name") for row in technologies],
        "findings": [],
        "network_range": _first_cidr(rdap),
    }


def _ip_blueprint(
    ip: str,
    asn: str,
    provider: dict[str, Any],
    ports: list[dict[str, Any]],
    services: list[dict[str, Any]],
    technologies: list[dict[str, Any]],
    risks: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [{"id": f"ip:{ip}", "type": "ip", "label": ip, "risk": "info"}]
    edges: list[dict[str, Any]] = []
    previous_id = f"ip:{ip}"

    def add_node(node_id: str, node_type: str, label: str, risk: str = "info") -> str:
        if not label:
            return ""
        nodes.append({"id": node_id, "type": node_type, "label": label, "risk": risk})
        return node_id

    if asn:
        asn_id = add_node(f"asn:{_slug(asn)}", "asn", asn)
        edges.append({"from": previous_id, "to": asn_id, "type": "announced_by"})
        previous_id = asn_id
    provider_label = str(provider.get("provider") or provider.get("organization") or provider.get("cloud_provider") or "")
    if provider_label:
        provider_id = add_node(f"provider:{_slug(provider_label)}", "provider", provider_label)
        edges.append({"from": previous_id, "to": provider_id, "type": "operated_by"})
        previous_id = provider_id

    def add_group(group_type: str, values: list[str], edge_type: str, risk: str = "info") -> str:
        if not values:
            return ""
        label = f"{group_type.replace('_', ' ').title()} ({len(values)})"
        node_id = add_node(f"{group_type}:{_slug(ip)}", group_type, label, risk)
        edges.append({"from": previous_id, "to": node_id, "type": edge_type})
        nodes[-1]["items"] = values[:24]
        return node_id

    ports_id = add_group("open_ports", [str(row.get("port")) for row in ports], "exposes", "medium" if ports else "info")
    services_id = add_group("services", [str(row.get("name") or "") for row in services], "serves")
    technologies_id = add_group("technologies", [str(row.get("name") or "") for row in technologies], "uses")
    findings_id = add_group("findings", [str(row.get("title") or "") for row in risks], "has_signal", "high" if any(row.get("risk") == "high" for row in risks) else "medium")
    chain_ids = [node_id for node_id in (ports_id, services_id, technologies_id, findings_id) if node_id]
    for left, right in zip(chain_ids, chain_ids[1:]):
        edges.append({"from": left, "to": right, "type": "relates_to"})
    return {"status": "completed", "summary": {"nodes": len(nodes), "edges": len(edges)}, "nodes": nodes, "edges": edges}


def _risk_signals(
    ip: str,
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ports: list[dict[str, Any]],
    services: list[dict[str, Any]],
    provider: dict[str, Any],
    classification: dict[str, Any],
    reverse_dns: str,
    tls_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    port_numbers = {int(row.get("port") or 0) for row in ports}
    web_ports = sorted(port for port in port_numbers if port in WEB_PORTS)
    output: list[dict[str, Any]] = []

    def add(signal_type: str, title: str, risk: str, confidence: str, detail: str, evidence: str, source: str) -> None:
        output.append(
            {
                "id": f"ip-risk:{_slug(signal_type)}",
                "type": signal_type,
                "title": title,
                "risk": risk,
                "confidence": confidence,
                "detail": detail,
                "evidence": evidence,
                "source": source,
                "confirmed": False,
            }
        )

    if 22 in port_numbers:
        add("public_ssh", "Public SSH", "medium", "high", "SSH is reachable and should be reviewed against the intended exposure policy.", "TCP/22 open", "Nmap")
    if len(web_ports) > 1:
        add("multiple_web_services", "Multiple Web Services", "medium", "high", "Multiple public web listeners increase the review surface.", ", ".join(str(port) for port in web_ports), "Nmap")
    legacy_tls = [row for row in tls_observations if str(row.get("tls_version") or "") in {"TLSv1", "TLSv1.1", "SSLv3"}]
    if legacy_tls:
        add("legacy_tls", "Legacy TLS", "high", "high", "A legacy TLS protocol was negotiated and requires manual validation.", ", ".join(f"{row.get('tls_version')}:{row.get('port')}" for row in legacy_tls), "TLS handshake")
    unknown = [row for row in ports if str(row.get("service") or "").lower() == "unknown"]
    if unknown:
        add("unknown_service", "Unknown Service", "medium", "high", "One or more open ports could not be identified by the lightweight service scan.", ", ".join(str(row.get("port")) for row in unknown), "Nmap")
    if len(ports) >= 5:
        add("multiple_exposed_ports", "Multiple Exposed Ports", "medium", "high", "The number of reachable services warrants exposure review.", f"{len(ports)} open ports", "Nmap")
    if provider.get("cloud"):
        add("cloud_provider_detected", "Cloud Provider Detected", "info", "medium", "Provider evidence indicates cloud-hosted infrastructure.", str(provider.get("cloud_provider") or "cloud marker"), "Provider classification")
    if provider.get("cdn"):
        add("cdn_edge", "Likely CDN Edge", "info", "high", "Provider markers indicate this IP likely serves as a CDN edge; it is not identified as origin.", ", ".join(provider.get("cdn_evidence") or []), "Provider classification")
    if classification.get("primary_role") == "Origin Candidate":
        add("origin_candidate", "Origin Candidate", "medium", "medium", "A directly reachable web service without CDN/WAF markers may be an origin candidate and requires manual verification.", f"Direct web ports on {ip}", "Infrastructure classification")
    if reverse_dns and not _reverse_dns_resolves_to(reverse_dns, ip):
        add("reverse_dns_mismatch", "Reverse DNS Mismatch", "low", "medium", "The PTR hostname did not resolve back to the analyzed IP during verification.", reverse_dns, "DNS")
    if parsed_ip.version == 6:
        add("ipv6_exposure", "IPv6 Exposure", "info", "high", "The analyzed public target is directly reachable over IPv6.", ip, "Input")
    if port_numbers & DATABASE_PORTS:
        add("database_service", "Database Service Exposure Candidate", "high", "high", "A database-associated port is publicly reachable and requires manual verification.", ", ".join(str(port) for port in sorted(port_numbers & DATABASE_PORTS)), "Nmap")
    remote_management = sorted((port_numbers & MANAGEMENT_PORTS) - {22})
    if remote_management:
        add("remote_management", "Public Remote Management Candidate", "high", "high", "A remote management port is publicly reachable and requires exposure-policy verification.", ", ".join(str(port) for port in remote_management), "Nmap")
    if len(port_numbers & MANAGEMENT_PORTS) > 1:
        add("management_services", "Multiple Management Services", "high", "high", "Multiple remote management services are reachable and require exposure review.", ", ".join(str(port) for port in sorted(port_numbers & MANAGEMENT_PORTS)), "Nmap")
    return output


def _evidence_rows(
    ip_api: dict[str, Any],
    rdap: dict[str, Any],
    reverse_dns: str,
    provider: dict[str, Any],
    port_surface: dict[str, Any],
    http_observations: list[dict[str, Any]],
    tls_observations: list[dict[str, Any]],
    risk_signals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = [
        {"title": "Geolocation", "source": "ip-api.com", "category": "geo", "evidence": {key: ip_api.get(key) for key in ("country", "countryCode", "regionName", "city", "lat", "lon") if ip_api.get(key) not in (None, "")}},
        {"title": "Network allocation", "source": "RDAP", "category": "registry", "evidence": {key: rdap.get(key) for key in ("handle", "name", "start_address", "end_address", "port43") if rdap.get(key)}},
        {"title": "Reverse DNS", "source": "DNS", "category": "dns", "evidence": reverse_dns},
        {"title": "Provider classification", "source": "Provider rules", "category": "provider", "evidence": {key: provider.get(key) for key in ("cloud_provider", "cdn_provider", "waf_provider", "cloud_evidence", "cdn_evidence", "waf_evidence") if provider.get(key)}},
        {"title": "Port scan", "source": "Nmap", "category": "ports", "evidence": {"status": port_surface.get("status"), "profile": port_surface.get("profile"), "summary": port_surface.get("summary")}},
    ]
    rows.extend({"title": f"HTTP port {row.get('port')}", "source": "HTTP probe", "category": "http", "evidence": row} for row in http_observations)
    rows.extend({"title": f"TLS port {row.get('port')}", "source": "TLS handshake", "category": "tls", "evidence": row} for row in tls_observations)
    rows.extend({"title": row.get("title"), "source": row.get("source"), "category": "risk", "evidence": row.get("evidence")} for row in risk_signals)
    return [row for row in rows if row.get("evidence") not in (None, "", {}, [])]


def _insights(
    classification: dict[str, Any],
    ports: list[dict[str, Any]],
    provider: dict[str, Any],
    risks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    output = [
        {
            "title": f"Infrastructure role: {classification.get('primary_role') or 'Unknown'}",
            "risk": "info",
            "confidence": (classification.get("roles") or [{}])[0].get("confidence") or "low",
            "detail": (classification.get("roles") or [{}])[0].get("evidence") or "Manual verification recommended.",
        }
    ]
    if ports:
        output.append({"title": "Public service surface identified", "risk": "medium", "confidence": "high", "detail": f"{len(ports)} open port(s) and {len({row.get('service') for row in ports})} service type(s)."})
    if provider.get("cloud_provider"):
        output.append({"title": "Cloud infrastructure evidence", "risk": "info", "confidence": "medium", "detail": str(provider.get("cloud_provider"))})
    high_risks = sum(1 for row in risks if row.get("risk") == "high")
    if high_risks:
        output.append({"title": "High-priority manual review candidates", "risk": "high", "confidence": "high", "detail": f"{high_risks} rule-based signal(s); no vulnerability is asserted."})
    return output


def _probe_http_services(ip: str, ports: list[dict[str, Any]], errors: list[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    host = f"[{ip}]" if ":" in ip else ip
    candidates = [row for row in ports if _is_web_row(row)][:WEB_PROBE_LIMIT]
    for row in candidates:
        port = int(row.get("port") or 0)
        secure = port in {443, 8443, 9443} or str(row.get("tunnel") or "").lower() == "ssl" or str(row.get("service") or "").lower().startswith("https")
        scheme = "https" if secure else "http"
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        url = f"{scheme}://{host}{'' if default_port else f':{port}'}/"
        try:
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
                stream=True,
                headers={"User-Agent": "Pamp-IP-Intelligence/1.0"},
            )
            output.append(
                {
                    "url": url,
                    "port": port,
                    "scheme": scheme,
                    "status": response.status_code,
                    "server": response.headers.get("Server") or "",
                    "powered_by": response.headers.get("X-Powered-By") or "",
                    "via": response.headers.get("Via") or "",
                    "content_type": response.headers.get("Content-Type") or "",
                    "location": response.headers.get("Location") or "",
                    "headers": {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() in {"server", "x-powered-by", "via", "content-type", "location", "cf-ray", "x-cache", "x-sucuri-id"}
                    },
                }
            )
            response.close()
        except Exception as exc:
            errors.append(f"http_probe {url}: {exc}")
    return output


def _probe_tls_services(ip: str, ports: list[dict[str, Any]], errors: list[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    candidates = [row for row in ports if int(row.get("port") or 0) in {443, 465, 636, 853, 993, 995, 8443, 9443} or str(row.get("tunnel") or "").lower() == "ssl"][:6]
    for row in candidates:
        port = int(row.get("port") or 0)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=REQUEST_TIMEOUT) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=None if ":" in ip else ip) as tls_socket:
                    certificate = tls_socket.getpeercert(binary_form=True)
                    output.append(_certificate_row(certificate, port, tls_socket.version() or ""))
        except Exception as exc:
            errors.append(f"tls_probe {ip}:{port}: {exc}")
    return output


def _certificate_row(der_bytes: bytes | None, port: int, tls_version: str) -> dict[str, Any]:
    row: dict[str, Any] = {"port": port, "tls_version": tls_version, "subject": "", "issuer": "", "san_dns": [], "san_ip": [], "not_before": "", "not_after": "", "days_remaining": None}
    if not der_bytes:
        return row
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        certificate = x509.load_der_x509_certificate(der_bytes)
        row["subject"] = _certificate_name(certificate.subject, NameOID.COMMON_NAME)
        row["issuer"] = _certificate_name(certificate.issuer, NameOID.COMMON_NAME)
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            row["san_dns"] = san.get_values_for_type(x509.DNSName)
            row["san_ip"] = [str(value) for value in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass
        not_before = getattr(certificate, "not_valid_before_utc", certificate.not_valid_before.replace(tzinfo=timezone.utc))
        not_after = getattr(certificate, "not_valid_after_utc", certificate.not_valid_after.replace(tzinfo=timezone.utc))
        row["not_before"] = not_before.isoformat()
        row["not_after"] = not_after.isoformat()
        row["days_remaining"] = (not_after - datetime.now(timezone.utc)).days
        row["serial_number"] = str(certificate.serial_number)
    except Exception:
        pass
    return row


def _rdap_abuse_contacts(entities: list[Any]) -> list[str]:
    contacts: list[str] = []
    for entity in entities:
        if not isinstance(entity, dict) or "abuse" not in [str(role).lower() for role in (entity.get("roles") or [])]:
            continue
        vcard = entity.get("vcardArray") or []
        fields = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        for field in fields:
            if isinstance(field, list) and len(field) >= 4 and str(field[0]).lower() in {"email", "tel"}:
                contacts.append(str(field[3]))
    return _unique(contacts)


def _registry_name(port43: str, country_code: str) -> str:
    lowered = port43.lower()
    if "arin" in lowered:
        return "ARIN"
    if "ripe" in lowered:
        return "RIPE NCC"
    if "apnic" in lowered:
        return "APNIC"
    if "lacnic" in lowered:
        return "LACNIC"
    if "afrinic" in lowered:
        return "AFRINIC"
    return {
        "US": "ARIN",
        "CA": "ARIN",
        "BR": "LACNIC",
        "AU": "APNIC",
        "JP": "APNIC",
        "CN": "APNIC",
        "ZA": "AFRINIC",
    }.get(country_code, "")


def _provider_from_markers(markers: list[str], cloud_provider: str) -> str:
    if cloud_provider and any(marker in cloud_provider.lower() for marker in markers):
        return cloud_provider
    return markers[0].title() if markers else ""


def _service_label(port: int, service: str, product: str) -> str:
    combined = f"{service} {product}".lower()
    known = (
        ("HTTPS", port in {443, 8443, 9443} or "https" in combined or "ssl/http" in combined),
        ("HTTP", service.lower().startswith("http")),
        ("SSH", port == 22 or "ssh" in combined),
        ("FTP", port == 21 or "ftp" in combined),
        ("SMTP", port in {25, 465, 587} or "smtp" in combined),
        ("RDP", port == 3389 or "rdp" in combined or "ms-wbt" in combined),
        ("MySQL", port == 3306 or "mysql" in combined),
        ("Redis", port == 6379 or "redis" in combined),
        ("MongoDB", port == 27017 or "mongo" in combined),
        ("Docker", port in {2375, 2376} or "docker" in combined),
        ("Kubernetes", port in {6443, 10250} or "kubernetes" in combined),
        ("DNS", port == 53 or service.lower() == "domain"),
    )
    return next((label for label, matched in known if matched), product or service or "Unknown")


def _service_icon(label: str) -> str:
    return {
        "HTTPS": "TLS",
        "HTTP": "WEB",
        "SSH": "SSH",
        "FTP": "FTP",
        "SMTP": "MAIL",
        "RDP": "RDP",
        "MySQL": "SQL",
        "Redis": "RDS",
        "MongoDB": "MDB",
        "Docker": "DOC",
        "Kubernetes": "K8S",
        "DNS": "DNS",
    }.get(label, "SRV")


def _service_description(label: str) -> str:
    return {
        "HTTPS": "Encrypted web service",
        "HTTP": "Web service",
        "SSH": "Secure remote administration",
        "FTP": "File transfer service",
        "SMTP": "Mail transport service",
        "RDP": "Remote desktop service",
        "MySQL": "Relational database service",
        "Redis": "In-memory data store",
        "MongoDB": "Document database service",
        "Docker": "Container management service",
        "Kubernetes": "Container orchestration service",
        "DNS": "Domain name service",
    }.get(label, "Network service identified by Nmap")


def _is_web_row(row: dict[str, Any]) -> bool:
    port = int(row.get("port") or 0)
    service = str(row.get("service") or "").lower()
    tunnel = str(row.get("tunnel") or "").lower()
    return port in WEB_PORTS or service.startswith("http") or (tunnel == "ssl" and service == "http")


def _as_name(as_label: str) -> str:
    parts = str(as_label or "").split(maxsplit=1)
    return parts[1] if len(parts) > 1 else ""


def _certificate_name(name: Any, oid: Any) -> str:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else ""


def _reverse_dns_resolves_to(hostname: str, ip: str) -> bool:
    try:
        return ip in {str(value) for value in socket.getaddrinfo(hostname, None) for value in [value[4][0]]}
    except Exception:
        return False


def _first_cidr(rdap: dict[str, Any]) -> str:
    for row in rdap.get("cidrs") or []:
        if isinstance(row, dict) and row.get("prefix") and row.get("length") is not None:
            return f"{row['prefix']}/{row['length']}"
    start = str(rdap.get("start_address") or "")
    end = str(rdap.get("end_address") or "")
    return f"{start} - {end}" if start and end else start or end


def _skipped_port_surface(ip: str, reason: str) -> dict[str, Any]:
    return {
        "scanner": "nmap",
        "profile": "service-light-top-1000",
        "target": ip,
        "ip": ip,
        "status": "skipped",
        "reason": reason,
        "skip_reason": reason,
        "open_ports": [],
        "summary": {"open_ports": 0, "services_identified": 0, "sensitive_services": 0, "web_services": 0, "non_web_services": 0, "service_names": []},
        "duration_ms": 0,
        "errors": [],
    }


def _failed_port_surface(ip: str, reason: str) -> dict[str, Any]:
    result = _skipped_port_surface(ip, reason)
    result["status"] = "failed"
    result["errors"] = [reason]
    return result


def _timeline(
    rows: list[dict[str, Any]],
    stage: str,
    status: str,
    detail: str,
    *,
    duration_ms: Any = None,
) -> None:
    rows.append(
        {
            "stage": stage,
            "status": status,
            "detail": detail,
            "time": utc_now(),
            "duration_ms": duration_ms,
        }
    )


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-") or "signal"


def _unique(values: list[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        output.append(text)
    return output


def _dedupe_dicts(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = "|".join(str(row.get(field) or "").lower() for field in keys)
        if not key.strip("|") or key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output
