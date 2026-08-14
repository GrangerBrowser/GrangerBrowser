from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

import requests


REQUEST_TIMEOUT = 12
WAYBACK_LIMIT = 200
WAYBACK_CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
CRT_SH_ENDPOINT = "https://crt.sh/"
INTERESTING_PATH_KEYWORDS = (
    "admin",
    "login",
    "api",
    "backup",
    "uploads",
    "wp",
    "graphql",
)
TECH_HINTS = {
    "WordPress": ("wp-content", "wp-includes", "wp-json"),
    "GraphQL": ("graphql",),
    "Next.js": ("_next/static", "__next"),
    "Nuxt": ("_nuxt/",),
    "Angular": ("main-es2015", "ngsw.json"),
    "React": ("react", "static/js"),
    "Vite": ("@vite", "vite/client"),
    "Webpack": ("webpack",),
}


def collect_historical_intelligence(
    domain: str,
    certificate_transparency: list[dict[str, Any]] | None = None,
    tls_certificate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    debug: dict[str, Any] = {
        "wayback_request_url": "",
        "wayback_first_request_url": "",
        "wayback_last_request_url": "",
        "wayback_count": 0,
        "crtsh_request_url": "",
        "crtsh_fallback_request_url": "",
        "crtsh_certificate_count": 0,
        "crtsh_subdomain_count": 0,
        "unavailable_sources": [],
    }
    wayback = _collect_wayback(domain, errors, debug)
    certs, cert_subdomains, cert_timeline = _collect_crtsh(domain, errors, debug)
    if not certs:
        certs, cert_subdomains, cert_timeline = _certificate_fallbacks(
            domain,
            certificate_transparency or [],
            tls_certificate or {},
            debug,
        )
    wayback_subdomains = _subdomains_from_urls(domain, [row["url"] for row in wayback.get("historical_urls", [])])
    historical_subdomains = sorted(set(cert_subdomains) | set(wayback_subdomains))[:240]
    old_technologies = _infer_technologies([row["url"] for row in wayback.get("historical_urls", [])])
    artifact_timeline = _artifact_timeline(wayback, cert_timeline, historical_subdomains)
    status = "partial" if errors else "done"
    return {
        "status": status,
        "sources": ["Wayback Machine CDX API", "crt.sh Certificate Transparency"],
        "historical_ips": [],
        "historical_nameservers": [],
        "historical_mx": [],
        "historical_technologies": old_technologies,
        "wayback": wayback,
        "certificate_history": certs,
        "historical_subdomains": historical_subdomains,
        "artifact_timeline": artifact_timeline,
        "unavailable_sources": debug["unavailable_sources"],
        "debug": debug,
        "errors": errors,
    }


def _collect_wayback(domain: str, errors: list[str], debug: dict[str, Any]) -> dict[str, Any]:
    sample_params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "collapse": "urlkey",
        "limit": str(WAYBACK_LIMIT),
    }
    first_params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "limit": "1",
    }
    last_params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "limit": "-1",
    }
    debug["wayback_request_url"] = _request_url(WAYBACK_CDX_ENDPOINT, sample_params)
    debug["wayback_first_request_url"] = _request_url(WAYBACK_CDX_ENDPOINT, first_params)
    debug["wayback_last_request_url"] = _request_url(WAYBACK_CDX_ENDPOINT, last_params)
    rows = _wayback_rows(sample_params, errors)
    first_rows = _wayback_rows(first_params, errors)
    last_rows = _wayback_rows(last_params, errors)
    debug["wayback_count"] = len(rows)
    historical_urls = [_wayback_output_row(row) for row in rows]
    top_urls = [
        {"url": url, "count": count, "href": url}
        for url, count in Counter(row["url"] for row in historical_urls).most_common(30)
    ]
    interesting_urls = [
        row
        for row in historical_urls
        if any(keyword in urlparse(row["url"]).path.lower() for keyword in INTERESTING_PATH_KEYWORDS)
    ][:80]
    return {
        "sampled_snapshot_count": len(rows),
        "limit": WAYBACK_LIMIT,
        "first_snapshot": _wayback_output_row(first_rows[0]) if first_rows else {},
        "last_snapshot": _wayback_output_row(last_rows[0]) if last_rows else {},
        "top_urls": top_urls,
        "interesting_urls": interesting_urls,
        "historical_urls": historical_urls[:WAYBACK_LIMIT],
    }


def _wayback_rows(params: dict[str, str], errors: list[str]) -> list[dict[str, str]]:
    try:
        response = requests.get(
            WAYBACK_CDX_ENDPOINT,
            params=params,
            headers={"User-Agent": "Pamp/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        errors.append(f"Wayback CDX: {exc}")
        return []
    if not isinstance(payload, list) or len(payload) < 2:
        return []
    headers = [str(item) for item in payload[0]]
    rows = []
    for raw in payload[1:]:
        if not isinstance(raw, list):
            continue
        row = {headers[index]: str(value) for index, value in enumerate(raw[: len(headers)])}
        if row.get("original"):
            rows.append(row)
    return rows


def _wayback_output_row(row: dict[str, str]) -> dict[str, str]:
    url = row.get("original") or row.get("url") or ""
    timestamp = row.get("timestamp") or ""
    return {
        "timestamp": timestamp,
        "date": _wayback_date(timestamp),
        "url": url,
        "href": url,
        "status": row.get("statuscode") or "",
        "mimetype": row.get("mimetype") or "",
        "digest": row.get("digest") or "",
        "tags": _interesting_tags(url),
    }


def _collect_crtsh(
    domain: str,
    errors: list[str],
    debug: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
    params = {"q": f"%.{domain}", "output": "json"}
    debug["crtsh_request_url"] = _request_url(CRT_SH_ENDPOINT, params)
    payload = _crtsh_query(params, errors)
    if not payload:
        fallback_params = {"q": domain, "output": "json"}
        debug["crtsh_fallback_request_url"] = _request_url(CRT_SH_ENDPOINT, fallback_params)
        payload = _crtsh_query(fallback_params, errors)
    rows = payload if isinstance(payload, list) else []
    certs = []
    subdomains = set()
    timeline_rows = []
    seen = set()
    for row in rows:
        names = _cert_names(row, domain)
        if not names:
            continue
        for name in names:
            if name != domain:
                subdomains.add(name)
        cert_id = str(row.get("id") or row.get("min_cert_id") or "")
        issuer = str(row.get("issuer_name") or "")
        not_before = str(row.get("not_before") or "")
        not_after = str(row.get("not_after") or "")
        key = (cert_id, issuer, not_before, not_after, tuple(names))
        if key in seen:
            continue
        seen.add(key)
        certs.append(
            {
                "cert_id": cert_id,
                "names": names[:20],
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "entry_timestamp": str(row.get("entry_timestamp") or ""),
                "reference_url": f"https://crt.sh/?id={cert_id}" if cert_id else debug["crtsh_request_url"],
            }
        )
        for name in names:
            timeline_rows.append(
                {
                    "type": "certificate_san",
                    "value": name,
                    "first_seen": not_before or str(row.get("entry_timestamp") or ""),
                    "last_seen": not_after,
                    "source": "crt.sh",
                }
            )
        if len(certs) >= 180:
            break
    debug["crtsh_certificate_count"] = len(certs)
    debug["crtsh_subdomain_count"] = len(subdomains)
    return certs, sorted(subdomains)[:240], timeline_rows


def _certificate_fallbacks(
    domain: str,
    certificate_transparency: list[dict[str, Any]],
    tls_certificate: dict[str, Any],
    debug: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
    certs = []
    subdomains = set()
    timeline_rows = []
    seen = set()
    for row in certificate_transparency:
        names = _fallback_names([row.get("name")], domain)
        if not names:
            continue
        key = (tuple(names), row.get("issuer"), row.get("not_before"), row.get("not_after"))
        if key in seen:
            continue
        seen.add(key)
        certs.append(
            {
                "cert_id": str(row.get("cert_id") or ""),
                "names": names,
                "issuer": str(row.get("issuer") or ""),
                "not_before": str(row.get("not_before") or ""),
                "not_after": str(row.get("not_after") or ""),
                "entry_timestamp": "",
                "reference_url": debug.get("crtsh_request_url") or "https://crt.sh/",
            }
        )
        _add_cert_timeline(timeline_rows, names, row.get("not_before") or "", row.get("not_after") or "", "crt.sh current query")
        subdomains.update(name for name in names if name != domain)
    if not certs and tls_certificate:
        names = _fallback_names(
            (tls_certificate.get("san_domains") or []) + (tls_certificate.get("subject_alt_names") or []),
            domain,
        )
        if not names and tls_certificate.get("subject"):
            names = [domain]
        if names:
            certs.append(
                {
                    "cert_id": str(tls_certificate.get("serial") or tls_certificate.get("serial_number") or ""),
                    "names": names,
                    "issuer": str(tls_certificate.get("issuer") or ""),
                    "not_before": str(tls_certificate.get("valid_from") or tls_certificate.get("not_before") or ""),
                    "not_after": str(tls_certificate.get("valid_to") or tls_certificate.get("not_after") or ""),
                    "entry_timestamp": "",
                    "reference_url": debug.get("crtsh_request_url") or "",
                }
            )
            _add_cert_timeline(
                timeline_rows,
                names,
                str(tls_certificate.get("valid_from") or tls_certificate.get("not_before") or ""),
                str(tls_certificate.get("valid_to") or tls_certificate.get("not_after") or ""),
                "TLS current certificate fallback",
            )
            subdomains.update(name for name in names if name != domain)
    debug["crtsh_certificate_count"] = len(certs)
    debug["crtsh_subdomain_count"] = len(subdomains)
    return certs, sorted(subdomains)[:240], timeline_rows


def _fallback_names(values: list[Any], domain: str) -> list[str]:
    output = []
    seen = set()
    for value in values:
        cleaned = str(value or "").lower().strip().strip(".")
        if cleaned.startswith("*."):
            cleaned = cleaned[2:]
        if not cleaned.endswith(domain) or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def _add_cert_timeline(
    rows: list[dict[str, str]],
    names: list[str],
    first_seen: str,
    last_seen: str,
    source: str,
) -> None:
    for name in names:
        rows.append(
            {
                "type": "certificate_san",
                "value": name,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "source": source,
            }
        )


def _crtsh_query(params: dict[str, str], errors: list[str]) -> Any:
    try:
        response = requests.get(
            CRT_SH_ENDPOINT,
            params=params,
            headers={"User-Agent": "Pamp/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        errors.append(f"crt.sh history {params.get('q')}: {exc}")
        return []


def _cert_names(row: dict[str, Any], domain: str) -> list[str]:
    values = []
    for key in ("name_value", "common_name"):
        raw = str(row.get(key) or "")
        values.extend(raw.splitlines())
    output = []
    seen = set()
    for value in values:
        cleaned = value.strip().lower().strip(".")
        if cleaned.startswith("*."):
            cleaned = cleaned[2:]
        if not cleaned.endswith(domain) or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def _artifact_timeline(
    wayback: dict[str, Any],
    cert_timeline: list[dict[str, str]],
    subdomains: list[str],
) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str], dict[str, str]] = {}
    for row in wayback.get("historical_urls") or []:
        _add_timeline(grouped, "wayback_url", row.get("url", ""), row.get("date", ""), row.get("date", ""), "Wayback")
    for row in cert_timeline:
        _add_timeline(
            grouped,
            row.get("type", "certificate_san"),
            row.get("value", ""),
            row.get("first_seen", ""),
            row.get("last_seen", ""),
            row.get("source", "crt.sh"),
        )
    for subdomain in subdomains:
        _add_timeline(grouped, "historical_subdomain", subdomain, "", "", "crt.sh/Wayback")
    return sorted(grouped.values(), key=lambda item: (item.get("first_seen") or "9999", item.get("value") or ""))[:180]


def _add_timeline(
    grouped: dict[tuple[str, str], dict[str, str]],
    item_type: str,
    value: str,
    first_seen: str,
    last_seen: str,
    source: str,
) -> None:
    if not value:
        return
    key = (item_type, value)
    row = grouped.setdefault(
        key,
        {"type": item_type, "value": value, "first_seen": first_seen, "last_seen": last_seen, "source": source},
    )
    if first_seen and (not row.get("first_seen") or first_seen < row["first_seen"]):
        row["first_seen"] = first_seen
    if last_seen and (not row.get("last_seen") or last_seen > row["last_seen"]):
        row["last_seen"] = last_seen


def _subdomains_from_urls(domain: str, urls: list[str]) -> list[str]:
    found = set()
    for url in urls:
        host = (urlparse(url).hostname or "").lower().strip(".")
        if host.endswith(f".{domain}"):
            found.add(host)
    return sorted(found)


def _infer_technologies(urls: list[str]) -> list[str]:
    text = "\n".join(urls).lower()
    return sorted(name for name, hints in TECH_HINTS.items() if any(hint in text for hint in hints))


def _interesting_tags(url: str) -> list[str]:
    path = urlparse(url).path.lower()
    return [keyword for keyword in INTERESTING_PATH_KEYWORDS if keyword in path]


def _wayback_date(timestamp: str) -> str:
    if not timestamp or len(timestamp) < 8:
        return ""
    try:
        parsed = datetime.strptime(timestamp[:14].ljust(14, "0"), "%Y%m%d%H%M%S")
        return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return timestamp


def _request_url(url: str, params: dict[str, Any]) -> str:
    return f"{url}?{urlencode(params, doseq=True)}"
