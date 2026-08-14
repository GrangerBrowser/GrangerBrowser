from __future__ import annotations

from collections import defaultdict
import csv
import ipaddress
from io import StringIO
from typing import Any
from urllib.parse import quote, urlparse

import requests


REQUEST_TIMEOUT = 10
MAX_HOST_CHECKS = 6
MAX_IP_CHECKS = 4
MAX_URL_CHECKS = 8
MAX_FEED_BYTES = 2_500_000
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
OTX_ENDPOINT = "https://otx.alienvault.com/api/v1/indicators"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHTANK_FEED = "https://data.phishtank.com/data/online-valid.csv"


def collect_reputation_intelligence(
    domain: str,
    linked_ips: list[str],
    devtools: dict[str, Any],
    endpoints: list[dict[str, Any]],
    html_signals: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    debug: dict[str, Any] = {
        "feeds_checked": [],
        "feeds_unavailable": [],
        "requests": [],
        "indicator_counts": {},
    }
    indicators = _collect_indicators(domain, linked_ips, devtools, endpoints, html_signals)
    debug["indicator_counts"] = {
        "domains": len(indicators["domains"]),
        "ips": len(indicators["ips"]),
        "urls": len(indicators["urls"]),
    }
    hits: list[dict[str, Any]] = []
    clean_sources: set[str] = set()

    _check_urlhaus(indicators, hits, clean_sources, errors, debug)
    _check_threatfox(indicators, hits, clean_sources, errors, debug)
    _check_otx(indicators, hits, clean_sources, errors, debug)
    _check_openphish(indicators, hits, clean_sources, errors, debug)
    _check_phishtank(indicators, hits, clean_sources, errors, debug)

    hits = _dedupe_hits(hits)
    hit_sources = {hit["source"] for hit in hits}
    clean_sources = {source for source in clean_sources if source not in hit_sources}
    summary = _summary(hits, clean_sources, debug["feeds_unavailable"])
    return {
        "status": "partial" if errors else "done",
        "summary": summary,
        "indicators_checked": indicators,
        "matched_indicators": hits,
        "suspicious_urls": [hit for hit in hits if hit.get("indicator_type") == "url"][:80],
        "threat_feed_hits": _group_hits(hits),
        "clean_sources": sorted(clean_sources),
        "unavailable_sources": debug["feeds_unavailable"],
        "debug": debug,
        "errors": errors,
    }


def _collect_indicators(
    domain: str,
    linked_ips: list[str],
    devtools: dict[str, Any],
    endpoints: list[dict[str, Any]],
    html_signals: dict[str, Any],
) -> dict[str, list[str]]:
    urls = []
    for item in endpoints or []:
        endpoint = str(item.get("endpoint") or "").strip()
        if endpoint.startswith(("http://", "https://")):
            urls.append(endpoint)
    for item in devtools.get("network_requests") or []:
        url = str(item.get("url") or "").strip()
        if url.startswith(("http://", "https://")):
            urls.append(url)
    for key in ("external_links", "script_links", "external_js", "external_css", "social_links"):
        for value in html_signals.get(key) or []:
            if str(value).startswith(("http://", "https://")):
                urls.append(str(value))
    domains = {domain}
    for url in urls:
        host = (urlparse(url).hostname or "").lower().strip(".")
        if host:
            domains.add(host)
    ips = []
    for ip in linked_ips:
        raw = str(ip).strip()
        if _valid_ip(raw):
            ips.append(raw)
    return {
        "domains": _limit_sorted(domains, MAX_HOST_CHECKS),
        "ips": _limit_sorted(ips, MAX_IP_CHECKS),
        "urls": _limit_sorted(urls, MAX_URL_CHECKS),
    }


def _check_urlhaus(
    indicators: dict[str, list[str]],
    hits: list[dict[str, Any]],
    clean_sources: set[str],
    errors: list[str],
    debug: dict[str, Any],
) -> None:
    source = "URLHaus"
    source_hits = 0
    success = False
    for host in indicators["domains"] + indicators["ips"]:
        try:
            debug["requests"].append({"source": source, "url": URLHAUS_HOST_ENDPOINT, "indicator": host})
            response = requests.post(URLHAUS_HOST_ENDPOINT, data={"host": host}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            success = True
            if payload.get("query_status") == "ok":
                for url_row in payload.get("urls") or []:
                    hits.append(
                        _hit(
                            source=source,
                            indicator=str(url_row.get("url") or host),
                            indicator_type="url",
                            status=str(url_row.get("url_status") or "listed"),
                            risk="High" if str(url_row.get("url_status") or "").lower() != "offline" else "Medium",
                            first_seen=str(url_row.get("date_added") or ""),
                            last_seen=str(url_row.get("last_online") or ""),
                            tags=url_row.get("tags") or [],
                            reference_url=str(url_row.get("urlhaus_reference") or "https://urlhaus.abuse.ch/"),
                        )
                    )
                    source_hits += 1
        except Exception as exc:
            _unavailable(source, f"host {host}: {exc}", errors, debug)
            break
    for url in indicators["urls"][:MAX_URL_CHECKS]:
        try:
            debug["requests"].append({"source": source, "url": URLHAUS_URL_ENDPOINT, "indicator": url})
            response = requests.post(URLHAUS_URL_ENDPOINT, data={"url": url}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            success = True
            if payload.get("query_status") == "ok":
                hits.append(
                    _hit(
                        source=source,
                        indicator=url,
                        indicator_type="url",
                        status=str(payload.get("url_status") or "listed"),
                        risk="High" if str(payload.get("url_status") or "").lower() != "offline" else "Medium",
                        first_seen=str(payload.get("date_added") or ""),
                        last_seen=str(payload.get("last_online") or ""),
                        tags=payload.get("tags") or [],
                        reference_url=str(payload.get("urlhaus_reference") or "https://urlhaus.abuse.ch/"),
                    )
                )
                source_hits += 1
        except Exception as exc:
            _unavailable(source, f"url {url}: {exc}", errors, debug)
            break
    if success:
        debug["feeds_checked"].append(source)
        if source_hits == 0:
            clean_sources.add(source)


def _check_threatfox(
    indicators: dict[str, list[str]],
    hits: list[dict[str, Any]],
    clean_sources: set[str],
    errors: list[str],
    debug: dict[str, Any],
) -> None:
    source = "ThreatFox"
    source_hits = 0
    success = False
    for indicator in (indicators["domains"] + indicators["ips"])[: MAX_HOST_CHECKS + MAX_IP_CHECKS]:
        try:
            debug["requests"].append({"source": source, "url": THREATFOX_ENDPOINT, "indicator": indicator})
            response = requests.post(
                THREATFOX_ENDPOINT,
                json={"query": "search_ioc", "search_term": indicator},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
            success = True
            if payload.get("query_status") == "ok":
                for row in payload.get("data") or []:
                    ioc = str(row.get("ioc") or indicator)
                    hits.append(
                        _hit(
                            source=source,
                            indicator=ioc,
                            indicator_type=_indicator_type(ioc),
                            status=str(row.get("ioc_type") or "listed"),
                            risk="High",
                            first_seen=str(row.get("first_seen") or ""),
                            last_seen=str(row.get("last_seen") or ""),
                            tags=[row.get("malware_printable"), row.get("threat_type"), row.get("confidence_level")],
                            reference_url=str(row.get("reference") or "https://threatfox.abuse.ch/"),
                        )
                    )
                    source_hits += 1
        except Exception as exc:
            _unavailable(source, f"{indicator}: {exc}", errors, debug)
            break
    if success:
        debug["feeds_checked"].append(source)
        if source_hits == 0:
            clean_sources.add(source)


def _check_otx(
    indicators: dict[str, list[str]],
    hits: list[dict[str, Any]],
    clean_sources: set[str],
    errors: list[str],
    debug: dict[str, Any],
) -> None:
    source = "AlienVault OTX"
    source_hits = 0
    success = False
    for domain in indicators["domains"][:MAX_HOST_CHECKS]:
        source_hits += _otx_indicator("domain", domain, hits, errors, debug)
        success = True
    for ip in indicators["ips"][:MAX_IP_CHECKS]:
        source_hits += _otx_indicator("IPv6" if ":" in ip else "IPv4", ip, hits, errors, debug)
        success = True
    if success:
        debug["feeds_checked"].append(source)
        if source_hits == 0:
            clean_sources.add(source)


def _otx_indicator(
    otx_type: str,
    indicator: str,
    hits: list[dict[str, Any]],
    errors: list[str],
    debug: dict[str, Any],
) -> int:
    source = "AlienVault OTX"
    url = f"{OTX_ENDPOINT}/{otx_type}/{quote(indicator, safe='')}/general"
    try:
        debug["requests"].append({"source": source, "url": url, "indicator": indicator})
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        _unavailable(source, f"{indicator}: {exc}", errors, debug)
        return 0
    pulse_info = payload.get("pulse_info") or {}
    count = int(pulse_info.get("count") or 0)
    if count <= 0:
        return 0
    tags = []
    for pulse in pulse_info.get("pulses") or []:
        tags.extend(pulse.get("tags") or [])
    hits.append(
        _hit(
            source=source,
            indicator=indicator,
            indicator_type=_indicator_type(indicator),
            status=f"{count} pulses",
            risk="High" if count >= 3 else "Medium",
            tags=tags[:12],
            reference_url=f"https://otx.alienvault.com/indicator/{otx_type}/{quote(indicator, safe='')}",
        )
    )
    return 1


def _check_openphish(
    indicators: dict[str, list[str]],
    hits: list[dict[str, Any]],
    clean_sources: set[str],
    errors: list[str],
    debug: dict[str, Any],
) -> None:
    source = "OpenPhish"
    try:
        debug["requests"].append({"source": source, "url": OPENPHISH_FEED, "indicator": "feed"})
        text = _fetch_limited_text(OPENPHISH_FEED)
        debug["feeds_checked"].append(source)
    except Exception as exc:
        _unavailable(source, str(exc), errors, debug)
        return
    source_hits = 0
    needles = set(indicators["domains"] + indicators["urls"])
    for line in text.splitlines():
        url = line.strip()
        if not url:
            continue
        host = (urlparse(url).hostname or "").lower()
        if url in needles or host in needles:
            hits.append(
                _hit(
                    source=source,
                    indicator=url,
                    indicator_type="url",
                    status="listed",
                    risk="High",
                    reference_url="https://openphish.com/",
                )
            )
            source_hits += 1
    if source_hits == 0:
        clean_sources.add(source)


def _check_phishtank(
    indicators: dict[str, list[str]],
    hits: list[dict[str, Any]],
    clean_sources: set[str],
    errors: list[str],
    debug: dict[str, Any],
) -> None:
    source = "PhishTank"
    try:
        debug["requests"].append({"source": source, "url": PHISHTANK_FEED, "indicator": "feed"})
        text = _fetch_limited_text(PHISHTANK_FEED)
        debug["feeds_checked"].append(source)
    except Exception as exc:
        _unavailable(source, str(exc), errors, debug)
        return
    source_hits = 0
    needles = set(indicators["domains"] + indicators["urls"])
    try:
        reader = csv.DictReader(StringIO(text))
        for row in reader:
            url = (row.get("url") or "").strip()
            host = (urlparse(url).hostname or "").lower()
            if url in needles or host in needles:
                hits.append(
                    _hit(
                        source=source,
                        indicator=url,
                        indicator_type="url",
                        status=str(row.get("verified") or "listed"),
                        risk="High",
                        first_seen=str(row.get("submission_time") or ""),
                        reference_url=str(row.get("phish_detail_url") or "https://phishtank.org/"),
                    )
                )
                source_hits += 1
    except Exception as exc:
        _unavailable(source, f"parse: {exc}", errors, debug)
        return
    if source_hits == 0:
        clean_sources.add(source)


def _fetch_limited_text(url: str) -> str:
    response = requests.get(url, headers={"User-Agent": "Pamp/1.0"}, timeout=REQUEST_TIMEOUT, stream=True)
    response.raise_for_status()
    chunks: list[str] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=32768):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_FEED_BYTES:
                break
            chunks.append(chunk.decode("utf-8", errors="replace"))
    finally:
        response.close()
    return "".join(chunks)


def _summary(
    hits: list[dict[str, Any]],
    clean_sources: set[str],
    unavailable_sources: list[dict[str, str]],
) -> dict[str, Any]:
    risk_order = {"Low": 1, "Medium": 2, "High": 3}
    max_risk = "Low"
    for hit in hits:
        if risk_order.get(str(hit.get("risk")), 0) > risk_order.get(max_risk, 0):
            max_risk = str(hit.get("risk"))
    return {
        "hits": len(hits),
        "max_risk": max_risk if hits else "Low",
        "clean_sources": len(clean_sources),
        "unavailable_sources": len(unavailable_sources),
        "message": "" if hits else "No public reputation hits found",
    }


def _group_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for hit in hits:
        grouped[str(hit.get("source") or "Unknown")].append(hit)
    return [{"source": source, "count": len(rows), "items": rows[:30]} for source, rows in sorted(grouped.items())]


def _hit(
    source: str,
    indicator: str,
    indicator_type: str,
    status: str,
    risk: str,
    first_seen: str = "",
    last_seen: str = "",
    tags: list[Any] | None = None,
    reference_url: str = "",
) -> dict[str, Any]:
    clean_tags = [str(tag) for tag in tags or [] if tag]
    return {
        "source": source,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "status": status,
        "risk": risk if risk in {"Low", "Medium", "High"} else "Medium",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "tags": sorted(set(clean_tags))[:16],
        "reference_url": reference_url,
    }


def _dedupe_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for hit in hits:
        key = (hit.get("source"), hit.get("indicator"), hit.get("status"))
        if key in seen:
            continue
        seen.add(key)
        output.append(hit)
    return output[:180]


def _unavailable(source: str, error: str, errors: list[str], debug: dict[str, Any]) -> None:
    message = f"{source}: {error}"
    errors.append(message)
    row = {"source": source, "error": error}
    if row not in debug["feeds_unavailable"]:
        debug["feeds_unavailable"].append(row)


def _indicator_type(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    if _valid_ip(value):
        return "ip"
    return "domain"


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _limit_sorted(values: Any, limit: int) -> list[str]:
    output = []
    seen = set()
    for value in sorted(str(item).strip() for item in values if str(item).strip()):
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
        if len(output) >= limit:
            break
    return output
