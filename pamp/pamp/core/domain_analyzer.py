from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import re
import socket
import ssl
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from .cloud_bucket_intelligence import analyze_cloud_buckets
from .application_route_intelligence import build_application_route_intelligence
from .data_decoder import decode_items, extract_query_values, sanitize_url
from .devtools_intelligence import enrich_devtools_intelligence
from .endpoint_utils import is_probable_endpoint, normalize_endpoint
from .favicon_intelligence import analyze_favicons
from .fingerprint import fingerprint_technologies
from .historical_intelligence import collect_historical_intelligence
from .http_surface import INTERESTING_PATHS as HTTP_INTERESTING_PATHS
from .http_surface import analyze_http_surface, analyst_notes
from .js_intelligence import analyze_javascript
from .oauth_intelligence import analyze_oauth
from .port_surface import analyze_port_surface
from .reputation_intelligence import collect_reputation_intelligence
from .report_intelligence import (
    build_analyst_notes,
    build_cdn_detection,
    build_javascript_intelligence,
    scan_javascript_text,
    timeline_event,
)
from .sensitive_file_checker import check_sensitive_files
from .social_intelligence import build_social_intelligence, collect_social_profiles
from .traffic_chain import build_traffic_chain, traffic_note
from .web_deep_parser import parse_web_deep


REQUEST_TIMEOUT = 10
DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DNS_TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Server",
    "X-Powered-By",
)
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim")
TRACKER_PATTERNS = {
    "Google Analytics": ("google-analytics.com", "gtag/js", "analytics.js", "_ga"),
    "Google Tag Manager": ("googletagmanager.com", "gtm.js"),
    "Meta Pixel": ("connect.facebook.net", "fbevents.js", "_fbp"),
    "Yandex Metrica": ("mc.yandex", "metrika"),
    "Cloudflare": ("cloudflare", "cf-ray"),
    "Hotjar": ("hotjar.com", "hj.js"),
    "TikTok Pixel": ("analytics.tiktok.com", "ttq"),
    "LinkedIn Insight": ("snap.licdn.com", "linkedin_partner_id"),
    "Microsoft Clarity": ("clarity.ms", "clarity("),
    "reCAPTCHA": ("google.com/recaptcha", "grecaptcha"),
    "hCaptcha": ("hcaptcha.com", "hcaptcha"),
}
TECH_PATTERNS = {
    "Cloudflare": ("cf-ray", "cloudflare"),
    "Nginx": ("nginx",),
    "Apache": ("apache",),
    "LiteSpeed": ("litespeed",),
    "Node": ("node.js", "nodejs"),
    "Express": ("x-powered-by: express", "express"),
    "PHP": ("php", "x-powered-by: php"),
    "Laravel": ("laravel", "x-powered-by: laravel"),
    "WordPress": ("wp-content", "wp-includes"),
    "React": ("react", "data-reactroot"),
    "Next.js": ("__next_data__", "_next/static"),
    "Vue": ("vue.js", "__vue__"),
    "Nuxt": ("__nuxt", "_nuxt/"),
    "Angular": ("ng-version", "angular"),
    "jQuery": ("jquery",),
    "Bootstrap": ("bootstrap",),
    "Tailwind": ("tailwind",),
    "Webpack": ("webpack",),
    "Vite": ("/@vite", "vite/client", "type=\"module\""),
}
API_ENDPOINT_PATTERN = re.compile(
    r"""((?:https?|wss?)://[^\s"'<>\\]+|/(?:api/|graphql\b|rest/|v1/|v2/|auth\b|login\b|admin\b|token\b|oauth\b|callback\b|webhook\b|upload\b|download\b)[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]*)""",
    re.IGNORECASE,
)
JS_ROUTE_PATTERN = re.compile(
    r"""((?:https?|wss?)://[^\s"'<>\\]+|(?:\.\.?/)?(?:api|rest|v\d+|graphql|auth|login|admin|token|oauth|callback|webhook|upload|download)(?:[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]*)|/(?:api/|graphql\b|rest/|v1/|v2/|auth\b|login\b|admin\b|token\b|oauth\b|callback\b|webhook\b|upload\b|download\b)[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]*)""",
    re.IGNORECASE,
)
REPORT_ENDPOINT_KEYWORDS = (
    "api",
    "auth",
    "login",
    "admin",
    "oauth",
    "graphql",
    "token",
    "webhook",
    "callback",
    "upload",
    "download",
)
IGNORED_ENDPOINT_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".css",
    ".ico",
)
STATIC_ASSET_PATTERN = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|woff2?|css|ico)(?:$|[?#&]|&amp;|%26|\\u0026|&q;)",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
LOGIN_ADMIN_PATTERN = re.compile(r"(/admin|/login|/signin|/sign-in|/wp-admin|/user/login|/account|/auth)", re.I)
SOCIAL_HOSTS = (
    "t.me",
    "telegram.me",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "github.com",
    "linkedin.com",
    "youtube.com",
    "youtu.be",
    "vk.com",
    "tiktok.com",
    "ok.ru",
    "wa.me",
    "discord.gg",
    "discord.com",
    "reddit.com",
    "pinterest.com",
    "pin.it",
    "medium.com",
    "spotify.com",
    "steamcommunity.com",
    "store.steampowered.com",
    "twitch.tv",
)


def analyze_domain(
    domain_input: str,
    debug_log: Any | None = None,
    artifact_dir: str | Path | None = None,
    traffic_log: Any | None = None,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    domain = normalize_domain(domain_input)
    if not domain:
        raise ValueError("Domain is empty")

    target_is_ip = _is_ip_literal(domain)
    errors: list[str] = []
    execution_log: list[dict[str, str]] = []
    analyst_timeline = [timeline_event("Domain analysis started", detail=domain)]
    _notify_progress(progress_callback, 0, "progress.dns", "active")
    if target_is_ip:
        dns_records = {record_type: [] for record_type in DNS_TYPE_CODES}
        execution_log.append({"stage": "dns", "status": "skipped for IP input"})
    else:
        dns_records = _collect_dns(domain, errors, execution_log)
    analyst_timeline.append(
        timeline_event(
            "DNS resolved" if any(dns_records.values()) else "DNS lookup completed without records",
            source="dns",
            detail=f"{sum(len(values) for values in dns_records.values())} record(s)",
        )
    )
    _notify_progress(progress_callback, 1, "progress.dns")
    linked_ips = sorted(set(dns_records.get("A", []) + dns_records.get("AAAA", [])))
    if target_is_ip:
        linked_ips = [domain]
    port_target_ip = _select_port_target(linked_ips)
    analyst_timeline.append(
        timeline_event(
            "Port scan started",
            source="port_surface",
            detail=port_target_ip or "no resolved IP address",
        )
    )
    background_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pamp-network")
    port_future = background_executor.submit(analyze_port_surface, domain, port_target_ip, debug_log=debug_log)
    reverse_dns_future = background_executor.submit(_reverse_dns_for_ips, linked_ips, errors)
    email_auth_future = background_executor.submit(
        lambda: {"spf": [], "dmarc": [], "dkim_hints": []}
        if target_is_ip
        else _email_auth(domain, dns_records, errors)
    )
    http_surface_future = background_executor.submit(
        analyze_http_surface,
        domain,
        original_input=domain_input,
        debug_log=debug_log,
    )
    _notify_progress(progress_callback, 1, "progress.http", "active")
    http_surface = _safe_module_result(
        http_surface_future,
        "http_surface",
        _empty_http_surface,
        errors,
        execution_log,
        debug_log,
    )
    reverse_dns = _safe_module_result(
        reverse_dns_future, "reverse_dns", list, errors, execution_log, debug_log
    )
    email_auth = _safe_module_result(
        email_auth_future,
        "email_auth",
        lambda: {"spf": [], "dmarc": [], "dkim_hints": []},
        errors,
        execution_log,
        debug_log,
    )
    errors.extend(http_surface.get("errors") or [])
    html = http_surface.pop("_html", "")
    http_surface.pop("_body_text", None)
    http_info = _legacy_http_info(http_surface)
    base_url = http_surface.get("final_url") or http_surface.get("primary_url") or ""
    execution_log.append(
        {
            "stage": "http_surface",
            "status": str(http_surface.get("status_code") or "no live HTTP service"),
        }
    )
    analyst_timeline.append(
        timeline_event(
            "HTTPS available" if str(base_url).startswith("https://") else "HTTP surface checked",
            source="http_surface",
            detail=base_url or "no live HTTP service",
        )
    )
    _notify_progress(progress_callback, 2, "progress.http")
    redirect_rows = list(http_surface.get("redirect_chain") or [])
    for probe in http_surface.get("probes") or []:
        redirect_rows.extend(probe.get("redirect_chain") or [])
    for row in _dedupe_dicts(redirect_rows, ("from", "to", "status")):
        analyst_timeline.append(
            timeline_event(
                "Redirect detected",
                source="http_surface",
                detail=f"{row.get('status')} {row.get('from')} -> {row.get('to')}",
            )
        )
    html_signals = _parse_html(domain, base_url, html, errors)
    analyst_timeline.append(
        timeline_event(
            "HTML intelligence extracted",
            source="html",
            detail=f"{len(html_signals.get('meta_tags') or [])} meta tag(s), {len(html_signals.get('html_comments') or [])} notable comment(s)",
        )
    )
    social_profiles: list[dict[str, Any]] = []
    social_intelligence = build_social_intelligence(social_profiles, domain)
    _notify_progress(progress_callback, 2, "progress.infrastructure", "active")
    rdap_log: list[dict[str, str]] = []
    tls_log: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="pamp-infrastructure") as infrastructure_executor:
        js_intel_future = infrastructure_executor.submit(
            _collect_js_intel,
            html_signals.get("script_links", []),
            base_url,
            errors,
        )
        rdap_future = infrastructure_executor.submit(
            lambda: {} if target_is_ip else _domain_rdap(domain, errors, rdap_log)
        )
        tls_future = infrastructure_executor.submit(_tls_certificate, domain, errors, tls_log)
        asn_future = infrastructure_executor.submit(_asn_bgp_for_ips, linked_ips, errors)
        certificate_future = infrastructure_executor.submit(
            lambda: [] if target_is_ip else _certificate_transparency(domain, errors)
        )
        _notify_progress(progress_callback, 2, "progress.browser", "active")
        if base_url and not target_is_ip:
            devtools = _safe_module_call(
                lambda: parse_web_deep(base_url, output_dir=artifact_dir, traffic_callback=traffic_log),
                "devtools",
                lambda: {"available": False, "errors": ["Browser analysis failed"]},
                errors,
                execution_log,
                debug_log,
            )
            execution_log.append({"stage": "devtools", "status": "ok" if devtools.get("available") else "partial"})
        else:
            reason = "skipped for IP input" if target_is_ip else "skipped"
            devtools = {"available": False, "errors": [] if target_is_ip else ["No live HTTP service detected"]}
            execution_log.append({"stage": "devtools", "status": reason})
        js_intel = _safe_module_result(
            js_intel_future, "js_collection", dict, errors, execution_log, debug_log
        )
        rdap_info = _safe_module_result(
            rdap_future, "rdap", dict, errors, execution_log, debug_log
        )
        tls_info = _safe_module_result(
            tls_future, "tls", dict, errors, execution_log, debug_log
        )
        asn_bgp = _safe_module_result(
            asn_future, "asn_bgp", list, errors, execution_log, debug_log
        )
        certificate_transparency = _safe_module_result(
            certificate_future,
            "certificate_transparency",
            list,
            errors,
            execution_log,
            debug_log,
        )
    if target_is_ip:
        execution_log.append({"stage": "rdap", "status": "skipped for IP input"})
        execution_log.append({"stage": "certificate_transparency", "status": "skipped for IP input"})
    else:
        execution_log.extend(rdap_log)
    execution_log.extend(tls_log)
    _merge_tls_into_http_surface(http_surface, tls_info)
    analyst_timeline.append(
        timeline_event(
            "TLS certificate inspected" if tls_info else "TLS inspection unavailable",
            source="tls",
            detail=str(tls_info.get("tls_version") or ""),
        )
    )
    _notify_progress(progress_callback, 3, "progress.infrastructure")
    _notify_progress(progress_callback, 4, "progress.browser")
    security_headers = _security_headers(http_info.get("headers") or {}) if http_info.get("status_code") is not None else {}
    if base_url and not target_is_ip:
        devtools = _safe_module_call(
            lambda: enrich_devtools_intelligence(
                devtools,
                base_url=base_url,
                js_intel=js_intel,
                security_headers=security_headers,
            ),
            "devtools_enrichment",
            lambda: devtools,
            errors,
            execution_log,
            debug_log,
        )
    _notify_progress(progress_callback, 4, "progress.traffic", "active")
    social_links, social_link_sources = _social_links_from_collected_data(html_signals, devtools)
    html_signals["social_links"] = social_links
    social_profiles = _safe_module_call(
        lambda: collect_social_profiles(
            social_links,
            errors,
            execution_log,
            link_sources=social_link_sources,
        ),
        "social_intelligence",
        list,
        errors,
        execution_log,
        debug_log,
    )
    social_intelligence = build_social_intelligence(social_profiles, domain)
    traffic_chain = (
        _safe_module_call(
            lambda: build_traffic_chain(
                target=domain,
                final_url=str(devtools.get("final_url") or base_url),
                devtools=devtools,
                debug_log=debug_log,
            ),
            "traffic_chain",
            lambda: _empty_traffic_chain(domain, "Traffic Chain module failed"),
            errors,
            execution_log,
            debug_log,
        )
        if base_url and not target_is_ip
        else _empty_traffic_chain(
            domain,
            "IP input in domain analysis" if target_is_ip else "No live HTTP service detected",
        )
    )
    execution_log.append(
        {
            "stage": "traffic_chain",
            "status": f"{(traffic_chain.get('summary') or {}).get('total_requests') or 0} request(s)",
        }
    )
    if (traffic_chain.get("summary") or {}).get("total_requests"):
        analyst_timeline.append(
            timeline_event(
                "Traffic Chain captured",
                source="traffic_chain",
                detail=traffic_note(traffic_chain),
            )
        )
    _notify_progress(progress_callback, 5, "progress.traffic")
    _notify_progress(progress_callback, 5, "progress.application_intelligence", "active")
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="pamp-application") as application_executor:
        js_intelligence_future = application_executor.submit(
            lambda: analyze_javascript(
                base_url=base_url,
                html_text=html,
                html_signals=html_signals,
                devtools=devtools,
                debug_log=debug_log,
            )
            if base_url
            else _empty_js_intelligence()
        )
        favicon_future = application_executor.submit(
            lambda: analyze_favicons(
                base_url=base_url,
                html_text=html,
                existing_favicon=http_surface.get("favicon") or {},
                debug_log=debug_log,
            )
            if base_url
            else _empty_favicon_intelligence()
        )
        sensitive_future = application_executor.submit(
            lambda: check_sensitive_files(
                base_url,
                known_paths=http_surface.get("interesting_paths") or [],
                skip_paths=HTTP_INTERESTING_PATHS,
            )
            if base_url and not target_is_ip
            else {"findings": [], "checked_paths": [], "errors": []}
        )
        js_intelligence = _safe_module_result(
            js_intelligence_future,
            "js_intelligence",
            _empty_js_intelligence,
            errors,
            execution_log,
            debug_log,
        )
        favicon_intelligence = _safe_module_result(
            favicon_future,
            "favicon_intelligence",
            _empty_favicon_intelligence,
            errors,
            execution_log,
            debug_log,
        )
        sensitive_files = _safe_module_result(
            sensitive_future,
            "sensitive_files",
            lambda: {"findings": [], "checked_paths": [], "errors": []},
            errors,
            execution_log,
            debug_log,
        )
    execution_log.append(
        {
            "stage": "js_intelligence",
            "status": (
                f"{len(js_intelligence.get('files') or [])} resource(s), "
                f"{len(js_intelligence.get('api_endpoints') or [])} endpoint(s)"
            ),
        }
    )
    execution_log.append(
        {
            "stage": "favicon_intelligence",
            "status": f"{len(favicon_intelligence.get('icons') or [])} icon(s)",
        }
    )
    oauth_intelligence = (
        _safe_module_call(
            lambda: analyze_oauth(
                base_url=base_url,
                sources=_oauth_sources(
                    html=html,
                    html_signals=html_signals,
                    js_intelligence=js_intelligence,
                    devtools=devtools,
                    http_surface=http_surface,
                ),
                debug_log=debug_log,
            ),
            "oauth_intelligence",
            _empty_oauth_intelligence,
            errors,
            execution_log,
            debug_log,
        )
        if base_url
        else _empty_oauth_intelligence()
    )
    execution_log.append(
        {
            "stage": "oauth_intelligence",
            "status": f"{len(oauth_intelligence.get('providers') or [])} provider(s)",
        }
    )
    if base_url and not target_is_ip:
        execution_log.append({"stage": "sensitive_files", "status": f"{len(sensitive_files.get('findings') or [])} found"})
    else:
        execution_log.append({"stage": "sensitive_files", "status": "skipped for IP input" if target_is_ip else "skipped"})
    _notify_progress(progress_callback, 6, "progress.application_intelligence")
    api_endpoints = _merge_api_endpoints(
        html_signals.get("api_endpoints", []),
        js_intel.get("api_endpoints", []),
        devtools.get("api_endpoints", []),
        _legacy_js_endpoint_rows(js_intelligence),
    )

    combined_text = _combined_detection_text(http_info, html, html_signals, js_intel, devtools)
    technology_fingerprints = _safe_module_call(
        lambda: fingerprint_technologies(
            http_surface,
            html=html,
            html_signals=html_signals,
            js_intel=js_intel,
            devtools=devtools,
        ),
        "technology_fingerprint",
        list,
        errors,
        execution_log,
        debug_log,
    )
    http_surface["technologies"] = technology_fingerprints
    http_surface["analyst_notes"] = analyst_notes(http_surface)
    for technology in technology_fingerprints:
        analyst_timeline.append(
            timeline_event(
                f"{technology.get('name')} detected",
                source="fingerprint",
                detail=str(technology.get("evidence") or ""),
            )
        )
    technologies = _merge_technology_names(
        [item.get("name") for item in technology_fingerprints]
        + _detect_patterns(TECH_PATTERNS, combined_text)
        + list(devtools.get("technologies") or [])
    )
    tracker_hints = sorted(
        set(_detect_patterns(TRACKER_PATTERNS, combined_text))
        | set(devtools.get("trackers") or [])
    )
    cookie_names = sorted(set((http_info.get("cookie_names") or []) + (devtools.get("cookies_names") or [])))
    decoded_artifacts = _decoded_artifacts(
        html=html,
        http_info=http_info,
        html_signals=html_signals,
        js_intel=js_intel,
        devtools=devtools,
        cookie_names=cookie_names,
    )
    security_findings = _security_findings(
        base_url=base_url,
        security_headers=security_headers,
        html_signals=html_signals,
        js_intel=js_intel,
        sensitive_files=sensitive_files,
        devtools=devtools,
        html=html,
    )
    _notify_progress(progress_callback, 7, "progress.security")
    _notify_progress(progress_callback, 7, "progress.historical", "active")
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="pamp-context") as context_executor:
        historical_future = context_executor.submit(
            lambda: {"status": "skipped", "sources": [], "errors": [], "debug": {"reason": "IP input in domain analysis"}}
            if target_is_ip
            else collect_historical_intelligence(
                domain,
                certificate_transparency=certificate_transparency,
                tls_certificate=tls_info,
            )
        )
        reputation_future = context_executor.submit(
            lambda: {"status": "skipped", "summary": {"message": "IP input in domain analysis"}, "errors": [], "debug": {}}
            if target_is_ip
            else collect_reputation_intelligence(
                domain=domain,
                linked_ips=linked_ips,
                devtools=devtools,
                endpoints=api_endpoints,
                html_signals=html_signals,
            )
        )
        historical_intelligence = _safe_module_result(
            historical_future,
            "historical_intelligence",
            lambda: {"status": "failed", "sources": [], "errors": ["Module failed"], "debug": {}},
            errors,
            execution_log,
            debug_log,
        )
        reputation_intelligence = _safe_module_result(
            reputation_future,
            "reputation_intelligence",
            lambda: {"status": "failed", "summary": {}, "errors": ["Module failed"], "debug": {}},
            errors,
            execution_log,
            debug_log,
        )
    execution_log.append(
        {
            "stage": "historical_intelligence",
            "status": _source_coverage_status(
                historical_intelligence,
                len(historical_intelligence.get("sources") or []) or 2,
            ),
        }
    )
    cloud_buckets = _safe_module_call(
        lambda: analyze_cloud_buckets(
            _cloud_sources(
                html=html,
                html_signals=html_signals,
                js_intelligence=js_intelligence,
                devtools=devtools,
                http_surface=http_surface,
                historical=historical_intelligence,
            ),
            debug_log=debug_log,
        ),
        "cloud_bucket_intelligence",
        lambda: {"candidates": [], "verified": [], "public_objects": [], "errors": ["Module failed"]},
        errors,
        execution_log,
        debug_log,
    )
    execution_log.append(
        {
            "stage": "cloud_bucket_intelligence",
            "status": f"{len(cloud_buckets.get('candidates') or [])} candidate(s)",
        }
    )
    execution_log.append(
        {
            "stage": "reputation_intelligence",
            "status": _source_coverage_status(reputation_intelligence, 5),
        }
    )
    _notify_progress(progress_callback, 8, "progress.historical")

    javascript_intelligence = _safe_module_call(
        lambda: build_javascript_intelligence(
            html_signals,
            js_intel,
            devtools,
            technology_fingerprints,
        ),
        "javascript_report_intelligence",
        dict,
        errors,
        execution_log,
        debug_log,
    )
    cdn_detection = _safe_module_call(
        lambda: build_cdn_detection(technology_fingerprints),
        "cdn_detection",
        list,
        errors,
        execution_log,
        debug_log,
    )
    for path in http_surface.get("interesting_paths") or []:
        analyst_timeline.append(
            timeline_event(
                f"{path.get('path')} discovered",
                source=str(path.get("source") or "http_surface"),
                detail=f"HTTP {path.get('status')}",
            )
        )
    for signal in http_surface.get("security_signals") or []:
        analyst_timeline.append(
            timeline_event(
                str(signal.get("name") or "Security signal"),
                source=str(signal.get("source") or "security"),
                detail=str(signal.get("evidence") or ""),
            )
        )

    _notify_progress(progress_callback, 8, "progress.port_surface", "active")
    port_surface = _safe_module_result(
        port_future,
        "port_surface",
        lambda: _empty_port_surface("Port scan module failed"),
        errors,
        execution_log,
        debug_log,
    )
    background_executor.shutdown(wait=True, cancel_futures=False)
    port_summary = port_surface.get("summary") or {}
    execution_log.append(
        {
            "stage": "port_surface",
            "status": (
                f"{port_summary.get('open_ports') or 0} open port(s); "
                f"{port_surface.get('status') or 'unknown'}"
            ),
        }
    )
    analyst_timeline.append(
        timeline_event(
            "Port scan completed",
            source="port_surface",
            detail=f"{port_summary.get('open_ports') or 0} open port(s); {port_surface.get('status') or 'unknown'}",
        )
    )
    for port in port_surface.get("open_ports") or []:
        if not port.get("sensitive"):
            continue
        analyst_timeline.append(
            timeline_event(
                f"Potentially sensitive service: {port.get('risk_label') or port.get('service') or 'unknown'}",
                source="port_surface",
                detail=f"{port.get('port')}/{port.get('protocol') or 'tcp'}",
            )
        )
    _notify_progress(progress_callback, 9, "progress.port_surface")

    result = {
        "type": "domain_analysis",
        "input": domain_input,
        "host": domain,
        "domain": domain,
        "dns": dns_records,
        "reverse_dns": reverse_dns,
        "email_auth": email_auth,
        "spf": email_auth.get("spf", []),
        "dmarc": email_auth.get("dmarc", []),
        "rdap": rdap_info,
        "whois": rdap_info,
        "asn_bgp": asn_bgp,
        "tls_certificate": tls_info,
        "certificate_transparency": certificate_transparency,
        "subdomains": _merge_subdomains(domain, certificate_transparency, html_signals, devtools),
        "http": http_info,
        "http_surface": http_surface,
        "security_headers": security_headers,
        "security_signals": http_surface.get("security_signals") or [],
        "html": html_signals,
        "devtools": devtools,
        "traffic_chain": traffic_chain,
        "screenshot": devtools.get("screenshot") or {},
        "javascript_intelligence": javascript_intelligence,
        "js_intelligence": js_intelligence,
        "favicon_intelligence": favicon_intelligence,
        "cloud_buckets": cloud_buckets,
        "oauth_intelligence": oauth_intelligence,
        "html_comment_intelligence": html_signals.get("html_comments") or [],
        "meta_tag_intelligence": html_signals.get("meta_tags") or [],
        "cdn_detection": cdn_detection,
        "sensitive_public_files": sensitive_files,
        "historical_intelligence": historical_intelligence,
        "reputation_intelligence": reputation_intelligence,
        "security_findings": security_findings,
        "technologies": technology_fingerprints,
        "detected_technology_details": technology_fingerprints,
        "detected_technologies": technologies,
        "interesting_paths": http_surface.get("interesting_paths") or [],
        "analyst_notes": [],
        "analytics_tracker_hints": tracker_hints,
        "cookie_names": cookie_names,
        "external_js_links": html_signals.get("external_js", []),
        "external_css_links": html_signals.get("external_css", []),
        "api_endpoints": api_endpoints,
        "api_endpoint_candidates": [item["endpoint"] for item in api_endpoints][:250],
        "js_findings": js_intel.get("js_findings", [])[:250],
        "decoded_classified_artifacts": decoded_artifacts,
        "emails": sorted(set(html_signals.get("emails", []) + js_intel.get("emails", [])))[:250],
        "phones": sorted(set(html_signals.get("phones", []) + js_intel.get("phones", [])))[:250],
        "telegram_links": html_signals.get("telegram_links", []),
        "social_links": html_signals.get("social_links", []),
        "social_profiles": social_profiles,
        "social_intelligence": social_intelligence,
        "linked_ip_addresses": linked_ips,
        "port_surface": port_surface,
        "sources": [
            "Cloudflare DNS over HTTPS",
            "rdap.org",
            "rdap.org IP",
            "crt.sh",
            "TLS socket",
            "HTTP response",
            "HTML parser",
            "Playwright Chromium",
            "DevTools Intelligence",
            "Pamp Traffic Chain",
            "Pamp JS Intelligence",
            "Pamp Favicon Intelligence",
            "Pamp Cloud Bucket Intelligence",
            "Pamp OAuth Intelligence",
            "Nmap service detection",
            "fixed sensitive path checker",
            "Wayback Machine CDX API",
            "crt.sh historical query",
            "URLHaus",
            "OpenPhish",
            "PhishTank",
            "AlienVault OTX",
            "ThreatFox",
            "Public social profile metadata",
        ],
        "execution_log": execution_log,
        "analyst_timeline": analyst_timeline,
        "timestamp": _utc_compact_timestamp(),
        "errors": (
            errors
            + (devtools.get("errors") or [])
            + (traffic_chain.get("errors") or [])
            + (sensitive_files.get("errors") or [])
            + (historical_intelligence.get("errors") or [])
            + (reputation_intelligence.get("errors") or [])
            + (js_intelligence.get("errors") or [])
            + (favicon_intelligence.get("errors") or [])
            + (cloud_buckets.get("errors") or [])
            + (oauth_intelligence.get("errors") or [])
            + (port_surface.get("errors") or [])
        ),
    }
    _notify_progress(progress_callback, 9, "progress.routes", "active")
    result["application_route_intelligence"] = _safe_module_call(
        lambda: build_application_route_intelligence(result, html_text=html),
        "application_route_intelligence",
        lambda: {"status": "failed", "summary": {}, "routes": [], "errors": ["Module failed"]},
        result["errors"],
        result["execution_log"],
        debug_log,
    )
    route_summary = result["application_route_intelligence"].get("summary") or {}
    result["execution_log"].append(
        {
            "stage": "application_route_intelligence",
            "status": f"{route_summary.get('total_routes') or 0} route(s)",
        }
    )
    result["analyst_timeline"].append(
        timeline_event(
            "Application Route Intelligence completed",
            source="application_route_intelligence",
            detail=f"{route_summary.get('total_routes') or 0} route(s), {route_summary.get('high_interest') or 0} high-interest",
        )
    )
    result["analyst_notes"] = _safe_module_call(
        lambda: build_analyst_notes(result),
        "analyst_notes",
        list,
        result["errors"],
        result["execution_log"],
        debug_log,
    )
    result["http_surface"]["analyst_notes"] = result["analyst_notes"]
    result["analyst_timeline"].append(
        timeline_event(
            "Domain analysis completed",
            detail=f"{len(result.get('security_signals') or [])} passive signal(s)",
        )
    )
    _notify_progress(progress_callback, 10, "progress.complete")
    return result


def _notify_progress(
    callback: Any | None,
    completed: int,
    label_key: str,
    status: str = "completed",
    total: int = 10,
) -> None:
    if callback is None:
        return
    try:
        callback(completed, total, label_key, status)
    except Exception:
        # Progress output must never interrupt analysis.
        return


def _safe_module_result(
    future: Any,
    stage: str,
    fallback_factory: Any,
    errors: list[str],
    execution_log: list[dict[str, str]],
    debug_log: Any | None,
) -> Any:
    return _safe_module_call(
        future.result,
        stage,
        fallback_factory,
        errors,
        execution_log,
        debug_log,
    )


def _safe_module_call(
    operation: Any,
    stage: str,
    fallback_factory: Any,
    errors: list[str],
    execution_log: list[dict[str, str]],
    debug_log: Any | None,
) -> Any:
    try:
        return operation()
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        errors.append(f"{stage}: {reason}")
        execution_log.append({"stage": stage, "status": f"failed: {reason}"})
        if debug_log:
            try:
                debug_log(f"[DOMAIN][{stage.upper()}] {reason}\n{traceback.format_exc()}")
            except Exception:
                pass
        return fallback_factory()


def _empty_http_surface() -> dict[str, Any]:
    return {
        "status_code": None,
        "primary_url": "",
        "final_url": "",
        "headers": {},
        "probes": [],
        "redirect_chain": [],
        "interesting_paths": [],
        "security_signals": [],
        "cookies": [],
        "errors": ["HTTP surface module failed"],
        "_html": "",
        "_body_text": "",
    }


def _empty_port_surface(reason: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "skip_reason": reason,
        "open_ports": [],
        "summary": {"open_ports": 0, "services_identified": 0, "sensitive_services": 0},
        "errors": [reason],
    }


def _source_coverage_status(payload: dict[str, Any], total_sources: int) -> str:
    unavailable = {
        str(item.get("source") or item.get("name") or item)
        if isinstance(item, dict)
        else str(item)
        for item in payload.get("unavailable_sources") or []
        if item
    }
    available = max(0, total_sources - len(unavailable))
    status = str(payload.get("status") or "partial")
    return f"{available} of {total_sources} sources; {status}"


def _empty_js_intelligence() -> dict[str, Any]:
    return {
        "files": [],
        "api_endpoints": [],
        "graphql": [],
        "websockets": [],
        "third_party_sdks": [],
        "secret_like_values": [],
        "config_objects": [],
        "suspicious_strings": [],
        "summary": {},
        "errors": [],
    }


def _empty_traffic_chain(target: str, reason: str) -> dict[str, Any]:
    return {
        "type": "traffic_chain",
        "target": target,
        "final_url": "",
        "summary": {
            "total_requests": 0,
            "total_bytes": 0,
            "load_time_ms": 0,
            "domcontentloaded_ms": 0,
            "load_event_ms": 0,
            "network_idle_ms": 0,
            "domains": 0,
            "third_party_requests": 0,
            "failed_requests": 0,
            "api_requests": 0,
            "websockets": 0,
        },
        "requests": [],
        "critical_path": [],
        "domains": [],
        "api_requests": [],
        "third_party": [],
        "failed_requests": [],
        "slow_requests": [],
        "websockets": [],
        "console_messages": [],
        "page_errors": [],
        "lifecycle": {},
        "limits": {},
        "errors": [reason] if reason else [],
        "timestamp": _utc_compact_timestamp(),
    }


def _empty_favicon_intelligence() -> dict[str, Any]:
    return {
        "icons": [],
        "primary_icon": {},
        "hashes": {},
        "matches": [],
        "summary": {},
        "errors": [],
    }


def _empty_oauth_intelligence() -> dict[str, Any]:
    return {
        "providers": [],
        "auth_routes": [],
        "callback_urls": [],
        "client_ids": [],
        "scopes": [],
        "oidc_metadata": [],
        "session_indicators": [],
        "summary": {},
        "errors": [],
    }


def _legacy_js_endpoint_rows(js_intelligence: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for item in (js_intelligence.get("api_endpoints") or []) + (js_intelligence.get("websockets") or []):
        endpoint = str(item.get("endpoint") or item.get("value") or "")
        if not endpoint:
            continue
        rows.append(
            {
                "endpoint": endpoint,
                "source_file": str(item.get("source_js") or item.get("source") or ""),
                "method": str(item.get("method") or ""),
                "risk": str(item.get("risk") or "low").title(),
                "notes": str(item.get("notes") or "Pamp JS Intelligence"),
            }
        )
    return rows


def _oauth_sources(
    html: str,
    html_signals: dict[str, Any],
    js_intelligence: dict[str, Any],
    devtools: dict[str, Any],
    http_surface: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {"source": "HTML", "value": html},
        {"source": "HTML links and forms", "value": html_signals},
        {"source": "JavaScript Intelligence", "value": js_intelligence},
        {"source": "DevTools network", "value": devtools.get("network_requests") or []},
        {"source": "Browser storage", "value": {
            "cookies": devtools.get("cookies") or devtools.get("cookies_names") or [],
            "local_storage": devtools.get("local_storage") or [],
            "session_storage": devtools.get("session_storage") or [],
        }},
        {"source": "HTTP redirects and cookies", "value": {
            "redirects": http_surface.get("redirect_chain") or [],
            "cookies": http_surface.get("cookies") or [],
        }},
    ]


def _cloud_sources(
    html: str,
    html_signals: dict[str, Any],
    js_intelligence: dict[str, Any],
    devtools: dict[str, Any],
    http_surface: dict[str, Any],
    historical: dict[str, Any],
) -> list[dict[str, Any]]:
    wayback = historical.get("wayback") or {}
    return [
        {"source": "HTML", "value": html},
        {"source": "HTML assets", "value": html_signals},
        {"source": "JavaScript Intelligence", "value": js_intelligence},
        {"source": "DevTools network", "value": devtools.get("network_requests") or []},
        {"source": "HTTP headers", "value": http_surface.get("headers") or {}},
        {"source": "robots/sitemap paths", "value": http_surface.get("interesting_paths") or []},
        {
            "source": "Wayback URLs",
            "value": (wayback.get("historical_urls") or []) + (wayback.get("interesting_urls") or []),
        },
    ]


def normalize_domain(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    else:
        raw = raw.split("/", 1)[0].split("?", 1)[0]
    raw = raw.strip().strip(".").lower()
    if ":" in raw and not raw.startswith("["):
        raw = raw.split(":", 1)[0]
    try:
        return raw.encode("idna").decode("ascii")
    except Exception:
        return raw


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _select_port_target(values: list[str]) -> str:
    parsed = []
    for value in values:
        try:
            parsed.append(ipaddress.ip_address(value))
        except ValueError:
            continue
    parsed.sort(key=lambda address: (address.version != 4, int(address)))
    return str(parsed[0]) if parsed else ""


def _legacy_http_info(http_surface: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": http_surface.get("primary_url") or "",
        "final_url": http_surface.get("final_url") or "",
        "redirect_chain": http_surface.get("redirect_chain") or [],
        "status_code": http_surface.get("status_code"),
        "server": http_surface.get("server") or "",
        "x_powered_by": http_surface.get("x_powered_by") or "",
        "content_type": http_surface.get("content_type") or "",
        "content_length": http_surface.get("content_length"),
        "headers": http_surface.get("headers") or {},
        "cookie_names": http_surface.get("cookie_names") or [],
        "cookies": http_surface.get("cookies") or [],
        "title": http_surface.get("title"),
        "response_time_ms": http_surface.get("response_time_ms"),
        "body_hash": http_surface.get("body_hash"),
        "favicon": http_surface.get("favicon") or {},
    }


def _merge_tls_into_http_surface(http_surface: dict[str, Any], tls_info: dict[str, Any]) -> None:
    if not tls_info:
        return
    http_surface["tls_enabled"] = True
    http_surface["tls_issuer"] = http_surface.get("tls_issuer") or tls_info.get("issuer") or ""
    http_surface["tls_expires"] = (
        http_surface.get("tls_expires")
        or tls_info.get("valid_to")
        or tls_info.get("not_after")
        or ""
    )
    tls = dict(http_surface.get("tls") or {})
    for target_key, source_key in (
        ("issuer", "issuer"),
        ("expires", "valid_to"),
        ("fingerprint_sha256", "fingerprint_sha256"),
        ("tls_version", "tls_version"),
        ("cipher_suite", "cipher_suite"),
        ("cipher_bits", "cipher_bits"),
        ("signature_algorithm", "signature_algorithm"),
        ("days_remaining", "days_remaining"),
        ("weak_cipher", "weak_cipher"),
        ("subject", "subject"),
        ("san", "san_domains"),
    ):
        if not tls.get(target_key) and tls_info.get(source_key):
            tls[target_key] = tls_info[source_key]
    http_surface["tls"] = tls


def _merge_technology_names(values: list[Any]) -> list[str]:
    merged: dict[str, str] = {}
    for value in values:
        name = str(value or "").strip()
        if not name:
            continue
        key = name.lower()
        if key not in merged:
            merged[key] = name
    return sorted(merged.values(), key=str.lower)


def _utc_compact_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _collect_dns(domain: str, errors: list[str], execution_log: list[dict[str, str]]) -> dict[str, list[str]]:
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA")
    with ThreadPoolExecutor(max_workers=len(record_types), thread_name_prefix="pamp-dns") as executor:
        values = executor.map(lambda record_type: _dns_query(domain, record_type, errors), record_types)
        records = dict(zip(record_types, values))
    execution_log.append({"stage": "dns", "status": f"{sum(len(values) for values in records.values())} records"})
    return records


def _dns_query(domain: str, record_type: str, errors: list[str]) -> list[str]:
    try:
        response = requests.get(
            DNS_ENDPOINT,
            params={"name": domain, "type": record_type},
            headers={"accept": "application/dns-json"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("Status") not in (0, 3):
            errors.append(f"DNS {record_type} {domain}: status {payload.get('Status')}")
        records = []
        expected_type = DNS_TYPE_CODES.get(record_type)
        for answer in payload.get("Answer") or []:
            if expected_type and answer.get("type") != expected_type:
                continue
            data = str(answer.get("data", "")).strip()
            if data:
                records.append(_clean_dns_value(record_type, data))
        return sorted(set(records))
    except Exception as exc:
        errors.append(f"DNS {record_type} {domain}: {exc}")
        return []


def _clean_dns_value(record_type: str, value: str) -> str:
    cleaned = value.strip().rstrip(".")
    if record_type in {"TXT", "CAA"}:
        cleaned = cleaned.replace('" "', "").strip('"')
    return cleaned


def _email_auth(domain: str, dns_records: dict[str, list[str]], errors: list[str]) -> dict[str, Any]:
    spf_records = [item for item in dns_records.get("TXT", []) if item.lower().strip('"').startswith("v=spf1")]
    dmarc_records = [
        item
        for item in _dns_query(f"_dmarc.{domain}", "TXT", errors)
        if "V=DMARC1" in item.upper()
    ]
    def selector_records(selector: str) -> list[dict[str, str]]:
        records = _dns_query(f"{selector}._domainkey.{domain}", "TXT", errors)
        return [
            {"selector": selector, "record": record[:300]}
            for record in records
            if record
        ]

    with ThreadPoolExecutor(max_workers=min(8, len(DKIM_SELECTORS)), thread_name_prefix="pamp-dkim") as executor:
        dkim_hints = [row for rows in executor.map(selector_records, DKIM_SELECTORS) for row in rows]
    return {
        "spf": spf_records,
        "dmarc": dmarc_records,
        "dkim_hints": dkim_hints,
    }


def _reverse_dns_for_ips(ips: list[str], errors: list[str]) -> list[dict[str, str]]:
    results = []
    for ip in ips:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results.append({"ip": ip, "hostname": hostname})
        except Exception as exc:
            errors.append(f"reverse_dns {ip}: {exc}")
    return results


def _domain_rdap(domain: str, errors: list[str], execution_log: list[dict[str, str]]) -> dict[str, Any]:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        entities = payload.get("entities") or []
        events = payload.get("events") or []
        parsed = {
            "handle": payload.get("handle") or "",
            "ldh_name": payload.get("ldhName") or "",
            "registrar": _entity_by_role(entities, "registrar"),
            "registrant_org": _entity_by_role(entities, "registrant"),
            "created": _event_date(events, ("registration", "created")),
            "updated": _event_date(events, ("last changed", "last update", "updated")),
            "expires": _event_date(events, ("expiration", "expiry", "expires")),
            "status": payload.get("status") or [],
            "nameservers": [
                ns.get("ldhName") or ns.get("unicodeName") or ""
                for ns in payload.get("nameservers") or []
                if ns.get("ldhName") or ns.get("unicodeName")
            ],
            "events": [
                {
                    "action": event.get("eventAction") or "",
                    "date": event.get("eventDate") or "",
                }
                for event in events
            ],
            "entities": _rdap_entities(entities),
        }
        execution_log.append({"stage": "rdap", "status": "registration data received"})
        return parsed
    except Exception as exc:
        errors.append(f"rdap.org domain: {exc}")
        status = "timeout" if isinstance(exc, requests.Timeout) else "failed"
        execution_log.append({"stage": "rdap", "status": status})
        return {}


def _rdap_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "handle": entity.get("handle") or "",
            "roles": entity.get("roles") or [],
            "name": _vcard_name(entity.get("vcardArray")),
        }
        for entity in entities[:12]
    ]


def _asn_bgp_for_ips(ips: list[str], errors: list[str]) -> list[dict[str, Any]]:
    results = []
    seen = set()
    for ip in ips[:12]:
        try:
            response = requests.get(f"https://rdap.org/ip/{ip}", timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            asn = str(payload.get("asn") or "")
            handle = str(payload.get("handle") or "")
            key = f"{ip}|{asn}|{handle}"
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "ip": ip,
                    "asn": asn,
                    "name": payload.get("name") or "",
                    "handle": handle,
                    "country": payload.get("country") or "",
                    "range": {
                        "start": payload.get("startAddress") or "",
                        "end": payload.get("endAddress") or "",
                    },
                    "bgp_prefix": _bgp_prefix_hint(payload),
                }
            )
        except Exception as exc:
            errors.append(f"asn_bgp {ip}: {exc}")
    return results


def _bgp_prefix_hint(payload: dict[str, Any]) -> str:
    start = payload.get("startAddress") or ""
    end = payload.get("endAddress") or ""
    if start and end and start == end:
        return str(start)
    if start and end:
        return f"{start} - {end}"
    return str(start or end or "")


def _certificate_transparency(domain: str, errors: list[str]) -> list[dict[str, str]]:
    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "Pamp/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        rows = response.json()
    except Exception as exc:
        errors.append(f"certificate transparency: {exc}")
        return []
    output = []
    seen = set()
    iter_rows = rows if isinstance(rows, list) else []
    for row in iter_rows:
        name = str(row.get("name_value") or "").strip().lower()
        if not name:
            continue
        names = [item.strip().strip("*.") for item in name.splitlines() if item.strip()]
        for item in names:
            if not item.endswith(domain) or item in seen:
                continue
            seen.add(item)
            output.append(
                {
                    "name": item,
                    "issuer": str(row.get("issuer_name") or ""),
                    "not_before": str(row.get("not_before") or ""),
                    "not_after": str(row.get("not_after") or ""),
                }
            )
            if len(output) >= 120:
                return output
    return output


def _merge_subdomains(
    domain: str,
    certificate_transparency: list[dict[str, str]],
    html_signals: dict[str, Any],
    devtools: dict[str, Any],
) -> list[str]:
    found = set()
    for item in certificate_transparency:
        name = item.get("name") or ""
        if name and name != domain:
            found.add(name)
    for group in (
        html_signals.get("external_links") or [],
        html_signals.get("script_links") or [],
        devtools.get("request_domains") or [],
        devtools.get("dom_links") or [],
        (devtools.get("javascript_intelligence") or {}).get("subdomains") or [],
    ):
        values = group if isinstance(group, list) else [group]
        for value in values:
            host = urlparse(str(value)).hostname or str(value)
            host = host.lower().strip(".")
            if host.endswith(f".{domain}"):
                found.add(host)
    return sorted(found)[:200]


def _entity_by_role(entities: list[dict[str, Any]], role: str) -> str:
    for entity in entities:
        if role in [str(item).lower() for item in entity.get("roles") or []]:
            name = _vcard_name(entity.get("vcardArray"))
            if name:
                return name
            if entity.get("handle"):
                return str(entity["handle"])
    return ""


def _vcard_name(vcard: Any) -> str:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] in {"fn", "org"}:
            value = item[3]
            if isinstance(value, list):
                return " ".join(str(part) for part in value if part)
            return str(value)
    return ""


def _event_date(events: list[dict[str, Any]], aliases: tuple[str, ...]) -> str:
    for event in events:
        action = str(event.get("eventAction") or "").lower()
        if any(alias in action for alias in aliases):
            return event.get("eventDate") or ""
    return ""


def _tls_certificate(domain: str, errors: list[str], execution_log: list[dict[str, str]]) -> dict[str, Any]:
    verification_error = ""
    last_error: Exception | None = None
    for verify in (True, False):
        try:
            context = ssl.create_default_context() if verify else ssl._create_unverified_context()
            with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert = tls_sock.getpeercert()
                    der = tls_sock.getpeercert(binary_form=True)
                    parsed = _parse_der_certificate(der) if der else {}
                    result = {
                        "subject": _cert_name(cert.get("subject") or []) or parsed.get("subject", ""),
                        "issuer": _cert_name(cert.get("issuer") or []) or parsed.get("issuer", ""),
                        "valid_from": cert.get("notBefore") or parsed.get("valid_from", ""),
                        "valid_to": cert.get("notAfter") or parsed.get("valid_to", ""),
                        "not_before": cert.get("notBefore") or parsed.get("valid_from", ""),
                        "not_after": cert.get("notAfter") or parsed.get("valid_to", ""),
                        "san_domains": _cert_sans(cert) or parsed.get("san_domains", []),
                        "subject_alt_names": _cert_sans(cert) or parsed.get("san_domains", []),
                        "serial": cert.get("serialNumber") or parsed.get("serial", ""),
                        "serial_number": cert.get("serialNumber") or parsed.get("serial", ""),
                        "fingerprint_sha256": hashlib.sha256(der).hexdigest() if der else "",
                        "tls_version": tls_sock.version() or "",
                        "cipher_suite": (tls_sock.cipher() or ("", "", 0))[0],
                        "cipher_bits": (tls_sock.cipher() or ("", "", 0))[2],
                        "signature_algorithm": parsed.get("signature_algorithm", ""),
                        "days_remaining": parsed.get("days_remaining"),
                        "weak_cipher": _weak_cipher((tls_sock.cipher() or ("", "", 0))[0]),
                        "verification_error": verification_error,
                    }
            execution_log.append(
                {"stage": "tls", "status": f"certificate received; {result.get('tls_version') or 'TLS'}"}
            )
            return result
        except Exception as exc:
            last_error = exc
            if verify:
                verification_error = str(exc)
                continue
            errors.append(f"TLS certificate: {exc}")
    status = "timeout" if isinstance(last_error, (TimeoutError, socket.timeout)) else "failed"
    execution_log.append({"stage": "tls", "status": status})
    return {}


def _parse_der_certificate(der: bytes) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
    except ModuleNotFoundError:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        san_domains: list[str] = []
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            san_domains = san.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_to": cert.not_valid_after_utc.isoformat(),
            "serial": format(cert.serial_number, "x"),
            "san_domains": san_domains,
            "signature_algorithm": getattr(cert.signature_hash_algorithm, "name", "") or "",
            "days_remaining": max(
                0,
                (cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
            ),
        }
    except Exception:
        return {}


def _cert_name(parts: list[Any]) -> str:
    values = []
    for part in parts:
        for key, value in part:
            if key in {"commonName", "organizationName"} and value:
                values.append(str(value))
    return ", ".join(values)


def _cert_sans(cert: dict[str, Any]) -> list[str]:
    return [
        value
        for key, value in cert.get("subjectAltName") or []
        if str(key).lower() == "dns"
    ]


def _weak_cipher(cipher_name: str) -> bool:
    lowered = str(cipher_name or "").lower()
    return any(marker in lowered for marker in ("rc4", "3des", "des-", "null", "export", "md5"))


def _http_lookup(domain: str, errors: list[str], execution_log: list[dict[str, str]]) -> dict[str, Any]:
    headers = {"User-Agent": "Pamp/1.0"}
    last_error = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            cookie_names = _response_cookie_names(response)
            response_headers = _sanitize_response_headers(dict(response.headers), cookie_names)
            content_type = response_headers.get("Content-Type", "")
            text = ""
            if "text/html" in content_type.lower() or "<html" in response.text[:500].lower():
                text = response.text[:350_000]
            execution_log.append({"stage": "http", "status": str(response.status_code)})
            return {
                "url": url,
                "final_url": response.url,
                "redirect_chain": [
                    {"status": item.status_code, "url": item.url}
                    for item in response.history
                ],
                "status_code": response.status_code,
                "server": response_headers.get("Server", ""),
                "x_powered_by": response_headers.get("X-Powered-By", ""),
                "content_type": content_type,
                "content_length": response_headers.get("Content-Length", ""),
                "headers": response_headers,
                "cookie_names": cookie_names,
                "_html": text,
            }
        except Exception as exc:
            last_error = f"{scheme}: {exc}"
    errors.append(f"HTTP lookup: {last_error}")
    execution_log.append({"stage": "http", "status": "failed"})
    return {
        "url": "",
        "final_url": "",
        "redirect_chain": [],
        "status_code": None,
        "server": "",
        "x_powered_by": "",
        "content_type": "",
        "content_length": "",
        "headers": {},
        "cookie_names": [],
        "_html": "",
    }


def _response_cookie_names(response: requests.Response) -> list[str]:
    names = {cookie.name for cookie in response.cookies}
    raw_headers = getattr(response.raw, "headers", None)
    get_all = getattr(raw_headers, "get_all", None)
    if callable(get_all):
        for header in get_all("Set-Cookie") or []:
            first = str(header).split(";", 1)[0]
            if "=" in first:
                names.add(first.split("=", 1)[0].strip())
    return sorted(name for name in names if name)


def _sanitize_response_headers(headers: dict[str, str], cookie_names: list[str]) -> dict[str, str]:
    sanitized = {}
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            sanitized[key] = f"redacted; cookie_names={','.join(cookie_names)}"
        else:
            sanitized[key] = value
    return sanitized


def _security_headers(headers: dict[str, str]) -> dict[str, str]:
    lower = {key.lower(): value for key, value in headers.items()}
    return {
        header: lower.get(header.lower(), "missing")
        for header in SECURITY_HEADERS
    }


def _social_links_from_collected_data(
    html_signals: dict[str, Any],
    devtools: dict[str, Any],
) -> tuple[list[str], dict[str, str]]:
    rows: list[tuple[str, str]] = []
    rows.extend((str(url), "HTML") for url in (html_signals.get("social_links") or []))
    rows.extend((str(url), "rendered DOM") for url in (devtools.get("dom_links") or []))
    for request in devtools.get("network_requests") or []:
        if not isinstance(request, dict):
            continue
        resource_type = str(request.get("resource_type") or request.get("type") or "").lower()
        if resource_type in {"document", "navigation"}:
            rows.append((str(request.get("url") or ""), "browser network request"))

    output: list[str] = []
    sources: dict[str, str] = {}
    seen: set[str] = set()
    for value, source in rows:
        clean = sanitize_url(value.strip())
        if not clean or clean in seen or not _host_matches(clean, SOCIAL_HOSTS):
            continue
        seen.add(clean)
        output.append(clean)
        sources[clean] = source
    return output[:120], sources


def _parse_html(domain: str, base_url: str, html: str, errors: list[str]) -> dict[str, Any]:
    empty = {
        "title": "",
        "meta_description": "",
        "meta_keywords": "",
        "canonical": "",
        "robots_meta": "",
        "favicon_url": "",
        "forms": [],
        "input_names": [],
        "hidden_input_names": [],
        "external_links": [],
        "internal_links_count": 0,
        "script_links": [],
        "external_js": [],
        "external_css": [],
        "images_count": 0,
        "comments_count": 0,
        "html_comments": [],
        "meta_tags": [],
        "inline_scripts": [],
        "hreflang": [],
        "source_map_links": [],
        "api_endpoint_candidates": [],
        "emails": [],
        "phones": [],
        "telegram_links": [],
        "social_links": [],
        "login_admin_paths": [],
        "mixed_content_links": [],
        "directory_listing_hint": False,
    }
    if not html:
        return empty
    try:
        from bs4 import BeautifulSoup, Comment

        soup = BeautifulSoup(html, "html.parser")
        links = [_absolute(base_url, tag.get("href")) for tag in soup.find_all("a", href=True)]
        script_links = [_absolute(base_url, tag.get("src")) for tag in soup.find_all("script", src=True)]
        css_links = [
            _absolute(base_url, tag.get("href"))
            for tag in soup.find_all("link", href=True)
            if "stylesheet" in " ".join(tag.get("rel") or []).lower()
        ]
        images = soup.find_all("img")
        external_links = [link for link in links if _is_external(link, domain)]
        telegram_links = [link for link in links if _host_matches(link, ("t.me", "telegram.me"))]
        social_links = [link for link in links if _host_matches(link, SOCIAL_HOSTS)]
        forms = []
        input_names: set[str] = set()
        hidden_names: set[str] = set()
        for form in soup.find_all("form"):
            names = []
            hidden = []
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name") or element.get("id") or element.get("type") or ""
                if name:
                    names.append(name)
                    input_names.add(name)
                if element.name == "input" and str(element.get("type") or "").lower() == "hidden" and name:
                    hidden.append(name)
                    hidden_names.add(name)
            forms.append(
                {
                    "method": str(form.get("method") or "GET").upper(),
                    "action": _absolute(base_url, form.get("action") or ""),
                    "input_names": sorted(set(names)),
                    "hidden_input_names": sorted(set(hidden)),
                }
            )
        text = soup.get_text("\n", strip=True)
        combined = f"{html}\n{text}"
        comments = [str(item).strip() for item in soup.find_all(string=lambda text_item: isinstance(text_item, Comment))]
        meta_tags = _meta_tag_rows(soup, base_url)
        inline_scripts = []
        for index, script in enumerate(soup.find_all("script")):
            if script.get("src"):
                continue
            script_text = script.string or script.get_text("\n", strip=False) or ""
            if not script_text.strip():
                continue
            markers = scan_javascript_text(script_text, f"inline script #{index + 1}")
            inline_scripts.append(
                {
                    "index": index + 1,
                    "size": len(script_text),
                    "type": str(script.get("type") or "text/javascript"),
                    "markers": ", ".join(row.get("name") or "" for row in markers),
                }
            )
        api_endpoints = _extract_api_endpoints(combined, base_url, "html")
        source_maps = sorted(
            set(
                [link for link in script_links + css_links if link.endswith(".map")]
                + re.findall(r"sourceMappingURL=([^\s*]+)", html)
            )
        )
        mixed = _mixed_content_links(base_url, links + script_links + css_links + [_absolute(base_url, img.get("src")) for img in images])
        login_paths = sorted({link for link in links + script_links if LOGIN_ADMIN_PATTERN.search(urlparse(link).path)})
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        return {
            "title": title,
            "meta_description": _meta_content(soup, "description"),
            "meta_keywords": _meta_content(soup, "keywords"),
            "canonical": _link_href(soup, "canonical", base_url),
            "robots_meta": _meta_content(soup, "robots"),
            "favicon_url": _favicon(soup, base_url),
            "forms": forms[:80],
            "input_names": sorted(input_names)[:200],
            "hidden_input_names": sorted(hidden_names)[:200],
            "external_links": sorted(set(external_links))[:300],
            "internal_links_count": len([link for link in links if link and not _is_external(link, domain)]),
            "script_links": sorted(set(script_links))[:300],
            "external_js": sorted({link for link in script_links if _is_external(link, domain)})[:200],
            "external_css": sorted({link for link in css_links if _is_external(link, domain)})[:200],
            "images_count": len(images),
            "comments_count": len(comments),
            "html_comments": _html_comment_rows(comments),
            "meta_tags": meta_tags,
            "inline_scripts": inline_scripts[:120],
            "hreflang": [
                {
                    "language": str(tag.get("hreflang") or ""),
                    "url": _absolute(base_url, tag.get("href")),
                }
                for tag in soup.find_all("link", href=True, hreflang=True)
            ][:120],
            "source_map_links": source_maps[:100],
            "api_endpoints": api_endpoints[:250],
            "api_endpoint_candidates": [item["endpoint"] for item in api_endpoints][:200],
            "emails": sorted(set(EMAIL_PATTERN.findall(combined)))[:250],
            "phones": _extract_phones(combined)[:250],
            "telegram_links": sorted(set(telegram_links))[:100],
            "social_links": sorted(set(social_links))[:200],
            "login_admin_paths": login_paths[:120],
            "mixed_content_links": sorted(set(mixed))[:150],
            "directory_listing_hint": bool(re.search(r"<title>\s*Index of\s*/|<h1>\s*Index of\s*/", html, re.I)),
        }
    except Exception as exc:
        errors.append(f"HTML parsing: {exc}")
        return empty


def _collect_js_intel(script_links: list[str], base_url: str, errors: list[str]) -> dict[str, Any]:
    chunks = []
    api_endpoints = []
    js_findings = []
    decoder_inputs = []
    scripts = []
    markers = []
    for script_url in script_links[:12]:
        try:
            text = _fetch_text_preview(script_url, limit=220_000)
            if text:
                chunks.append(text)
                scripts.append(
                    {
                        "url": script_url,
                        "source": "HTML script tag",
                        "size": len(text),
                        "status": "fetched",
                    }
                )
                markers.extend(scan_javascript_text(text, script_url))
                api_endpoints.extend(_extract_api_endpoints(text, base_url, script_url))
                js_findings.extend(_extract_js_route_findings(text, base_url, script_url))
                decoder_inputs.append({"value": text[:120_000], "source": f"js {script_url}"})
        except Exception as exc:
            errors.append(f"JS fetch {script_url}: {exc}")
            scripts.append(
                {
                    "url": script_url,
                    "source": "HTML script tag",
                    "size": 0,
                    "status": "fetch failed",
                }
            )
    combined = "\n".join(chunks)
    api_endpoints = _merge_api_endpoints(api_endpoints)
    js_findings = _dedupe_js_findings(js_findings)
    return {
        "api_endpoints": api_endpoints[:250],
        "api_endpoint_candidates": [item["endpoint"] for item in api_endpoints][:250],
        "js_findings": js_findings[:250],
        "scripts": scripts[:120],
        "markers": _dedupe_dicts(markers, ("name", "source"))[:220],
        "source_map_links": sorted(set(re.findall(r"sourceMappingURL=([^\s*]+)", combined)))[:100],
        "emails": sorted(set(EMAIL_PATTERN.findall(combined)))[:250],
        "phones": _extract_phones(combined)[:250],
        "decoded_classified_artifacts": decode_items(decoder_inputs, limit=100),
    }


def _meta_tag_rows(soup: Any, base_url: str) -> list[dict[str, str]]:
    rows = []
    interesting_prefixes = (
        "generator",
        "robots",
        "author",
        "description",
        "keywords",
        "theme-color",
        "application-name",
        "apple-",
        "twitter:",
        "og:",
    )
    for tag in soup.find_all("meta"):
        name = str(tag.get("name") or tag.get("property") or tag.get("http-equiv") or "").strip()
        content = re.sub(r"\s+", " ", str(tag.get("content") or "")).strip()
        if not name or not content:
            continue
        lowered = name.lower()
        if lowered in interesting_prefixes or any(lowered.startswith(prefix) for prefix in interesting_prefixes):
            rows.append({"name": name, "value": content[:500], "source": "HTML meta"})
    canonical = _link_href(soup, "canonical", base_url)
    if canonical:
        rows.append({"name": "canonical", "value": canonical, "source": "HTML link"})
    for tag in soup.find_all("link", href=True, hreflang=True):
        rows.append(
            {
                "name": f"hreflang:{tag.get('hreflang')}",
                "value": _absolute(base_url, tag.get("href")),
                "source": "HTML link",
            }
        )
    return _dedupe_dicts(rows, ("name", "value"))[:180]


def _html_comment_rows(comments: list[str]) -> list[dict[str, str]]:
    marker_pattern = re.compile(
        r"\b(TODO|FIXME|DEBUG|API|password|username|email|internal host|version|server|database)\b",
        re.I,
    )
    rows = []
    for comment in comments:
        compact = re.sub(r"\s+", " ", comment).strip()
        match = marker_pattern.search(compact)
        if not match:
            continue
        excerpt = compact[:320]
        if match.group(1).lower() == "password":
            excerpt = re.sub(r"(?i)(password\s*[:=]\s*)\S+", r"\1[masked]", excerpt)
        rows.append(
            {
                "marker": match.group(1).upper(),
                "excerpt": excerpt,
                "source": "HTML comment",
            }
        )
    return _dedupe_dicts(rows, ("marker", "excerpt"))[:120]


def _dedupe_dicts(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows:
        key = tuple(str(row.get(item) or "") for item in keys)
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _extract_js_route_findings(text: str, base_url: str, source_file: str) -> list[dict[str, Any]]:
    findings = []
    seen = set()
    for match in JS_ROUTE_PATTERN.finditer(text or ""):
        raw = match.group(1)
        endpoint = _absolute(base_url, raw)
        if not endpoint or not _is_reportable_endpoint(endpoint):
            continue
        key = f"{source_file}|{endpoint}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "url": endpoint,
                "source_js": source_file,
                "fragment": _js_fragment(text, match.start(), match.end()),
                "type": _js_route_type(raw, endpoint),
                "confidence": _js_route_confidence(raw, endpoint),
            }
        )
    return findings[:350]


def _js_fragment(text: str, start: int, end: int) -> str:
    fragment = re.sub(r"\s+", " ", (text or "")[max(0, start - 80) : min(len(text or ""), end + 80)]).strip()
    return fragment[:220]


def _js_route_type(raw: str, endpoint: str) -> str:
    lowered = f"{raw} {endpoint}".lower()
    if lowered.startswith(("ws://", "wss://")):
        return "websocket"
    if "graphql" in lowered:
        return "graphql"
    if "swagger" in lowered or "openapi" in lowered or "api-docs" in lowered:
        return "docs"
    if any(item in lowered for item in ("admin", "login", "auth", "oauth", "signin")):
        return "auth"
    if any(item in lowered for item in ("webhook", "callback")):
        return "integration"
    if any(item in lowered for item in ("upload", "download")):
        return "file-flow"
    return "api-route"


def _js_route_confidence(raw: str, endpoint: str) -> int:
    lowered = f"{raw} {endpoint}".lower()
    score = 55
    if raw.startswith(("http://", "https://", "ws://", "wss://", "/")):
        score += 20
    if any(item in lowered for item in ("api", "graphql", "auth", "admin", "login", "webhook", "upload", "download")):
        score += 20
    if "{" in raw or "${" in raw:
        score -= 20
    return max(10, min(score, 100))


def _dedupe_js_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows:
        key = f"{row.get('source_js')}|{row.get('url')}"
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _extract_api_endpoints(text: str, base_url: str, source_file: str, method: str = "") -> list[dict[str, str]]:
    endpoints = []
    seen = set()
    base_host = (urlparse(base_url).hostname or "").lower()
    source_host = (urlparse(source_file).hostname or "").lower()
    for match in API_ENDPOINT_PATTERN.finditer(text or ""):
        raw = match.group(1)
        if raw.startswith("/") and source_host and base_host and source_host != base_host:
            continue
        if raw.endswith("$") and "${" in (text[max(0, match.start() - 80) : match.end() + 100]):
            raw = raw[:-1]
        endpoint = normalize_endpoint(raw, base_url)
        if not endpoint or not is_probable_endpoint(endpoint):
            continue
        key = f"{method}|{endpoint}|{source_file}"
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(
            {
                "endpoint": endpoint,
                "source_file": source_file,
                "method": method,
                "risk": _endpoint_risk(endpoint),
                "notes": _endpoint_notes(endpoint),
            }
        )
    return endpoints[:300]


def _merge_api_endpoints(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    merged = []
    seen = set()
    for group in groups:
        for item in group or []:
            endpoint = normalize_endpoint(
                sanitize_url(item.get("endpoint") or item.get("value") or ""),
                "",
            )
            if not endpoint or not _is_reportable_endpoint(endpoint):
                continue
            method = item.get("method") or ""
            key = f"{method}|{endpoint}"
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                {
                    "endpoint": endpoint,
                    "source_file": item.get("source_file") or item.get("source") or "",
                    "method": method,
                    "risk": item.get("risk") or _endpoint_risk(endpoint),
                    "notes": item.get("notes") or _endpoint_notes(endpoint),
                }
            )
    return merged[:300]


def _is_reportable_endpoint(value: str) -> bool:
    return is_probable_endpoint(str(value or ""))


def _looks_static_asset(value: str) -> bool:
    return bool(STATIC_ASSET_PATTERN.search(str(value or "")))


def _endpoint_segment_match(segment: str) -> bool:
    if segment == "api" or re.fullmatch(r"api\d*", segment):
        return True
    return segment in {keyword for keyword in REPORT_ENDPOINT_KEYWORDS if keyword != "api"}


def _decoded_artifacts(
    html: str,
    http_info: dict[str, Any],
    html_signals: dict[str, Any],
    js_intel: dict[str, Any],
    devtools: dict[str, Any],
    cookie_names: list[str],
) -> list[dict[str, str]]:
    inputs: list[dict[str, str]] = []
    if html:
        inputs.append({"value": html[:140_000], "source": "html"})
    for key, value in (http_info.get("headers") or {}).items():
        inputs.append({"value": key, "source": "http header name"})
        inputs.append({"value": str(value), "source": f"http header:{key}"})
    for key in ("external_links", "script_links", "external_js", "external_css", "api_endpoint_candidates", "telegram_links", "social_links"):
        for value in html_signals.get(key) or []:
            inputs.append({"value": value, "source": f"html {key}"})
            inputs.extend(extract_query_values(value, f"html {key}"))
    for form in html_signals.get("forms") or []:
        if form.get("action"):
            inputs.append({"value": form["action"], "source": "html form action"})
        for name in form.get("input_names") or []:
            inputs.append({"value": name, "source": "html form input"})
    for key in ("input_names", "hidden_input_names"):
        for value in html_signals.get(key) or []:
            inputs.append({"value": value, "source": f"html {key}"})
    for item in js_intel.get("api_endpoint_candidates") or []:
        inputs.append({"value": item, "source": "js api endpoint"})
        inputs.extend(extract_query_values(item, "js api endpoint"))
    for item in devtools.get("api_endpoint_candidates") or []:
        inputs.append({"value": item, "source": "devtools api endpoint"})
        inputs.extend(extract_query_values(item, "devtools api endpoint"))
    for item in devtools.get("network_requests") or []:
        url = item.get("url") or ""
        inputs.append({"value": url, "source": "devtools network url"})
        inputs.extend(extract_query_values(url, "devtools network url"))
        for headers_key in ("request_headers", "response_headers"):
            for header_key, header_value in (item.get(headers_key) or {}).items():
                inputs.append({"value": header_key, "source": f"devtools {headers_key}"})
                inputs.append({"value": str(header_value), "source": f"devtools {headers_key}:{header_key}"})
    for name in cookie_names:
        inputs.append({"value": name, "source": "cookie name"})
    for key in devtools.get("localStorage_keys") or []:
        inputs.append({"value": key, "source": "localStorage key"})
    for key in devtools.get("sessionStorage_keys") or []:
        inputs.append({"value": key, "source": "sessionStorage key"})

    decoded = decode_items(inputs, limit=250)
    decoded.extend(js_intel.get("decoded_classified_artifacts") or [])
    decoded.extend(devtools.get("decoded_classified_artifacts") or [])
    return _dedupe_decoded(decoded)[:300]


def _dedupe_decoded(items: list[dict[str, str]]) -> list[dict[str, str]]:
    output = []
    seen = set()
    for item in items:
        key = f"{item.get('type')}|{item.get('value_masked')}|{item.get('source')}"
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _endpoint_risk(value: str) -> str:
    lowered = str(value).lower()
    return "Medium" if any(item in lowered for item in ("/auth", "/login", "/admin", "/token", "/oauth", "/callback", "/webhook", "token=", "key=")) else "Low"


def _endpoint_notes(value: str) -> str:
    lowered = str(value).lower()
    if lowered.startswith(("http://", "https://", "ws://", "wss://")) and not any(item in lowered for item in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/")):
        return "URL candidate"
    if any(item in lowered for item in ("/auth", "/login", "/admin", "/token", "/oauth", "/callback", "/webhook")):
        return "exposed endpoint"
    return "endpoint candidate"


def _fetch_text_preview(url: str, limit: int) -> str:
    response = requests.get(
        url,
        headers={"User-Agent": "Pamp/1.0"},
        timeout=REQUEST_TIMEOUT,
        stream=True,
        allow_redirects=True,
    )
    response.raise_for_status()
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
        if not chunk:
            continue
        text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)
        chunks.append(text)
        total += len(text)
        if total >= limit:
            break
    response.close()
    return "".join(chunks)[:limit]


def _combined_detection_text(
    http_info: dict[str, Any],
    html: str,
    html_signals: dict[str, Any],
    js_intel: dict[str, Any],
    devtools: dict[str, Any],
) -> str:
    parts = [
        html,
        "\n".join(f"{key}: {value}" for key, value in (http_info.get("headers") or {}).items()),
        "\n".join(http_info.get("cookie_names") or []),
        "\n".join(html_signals.get("script_links") or []),
        "\n".join(html_signals.get("external_css") or []),
        "\n".join(js_intel.get("api_endpoint_candidates") or []),
        "\n".join(devtools.get("loaded_js") or []),
        "\n".join(devtools.get("loaded_css") or []),
        "\n".join(devtools.get("request_domains") or []),
        "\n".join(devtools.get("cookies_names") or []),
    ]
    return "\n".join(str(part) for part in parts if part)


def _security_findings(
    base_url: str,
    security_headers: dict[str, str],
    html_signals: dict[str, Any],
    js_intel: dict[str, Any],
    sensitive_files: dict[str, Any],
    devtools: dict[str, Any],
    html: str,
) -> list[dict[str, str]]:
    findings = []
    for header in SECURITY_HEADERS:
        if security_headers.get(header) == "missing":
            findings.append({"type": "missing_header", "detail": header, "evidence": "HTTP response"})
    if html_signals.get("source_map_links") or js_intel.get("source_map_links"):
        findings.append({"type": "exposed_source_maps", "detail": "source map reference found", "evidence": "HTML/JS"})
    for link in html_signals.get("mixed_content_links") or []:
        findings.append({"type": "mixed_content", "detail": link, "evidence": base_url})
    for form in html_signals.get("forms") or []:
        action = form.get("action") or ""
        if action.startswith("http://"):
            findings.append({"type": "form_over_http", "detail": action, "evidence": form.get("method") or ""})
    if html_signals.get("login_admin_paths"):
        findings.append(
            {
                "type": "login_admin_paths",
                "detail": ", ".join(html_signals["login_admin_paths"][:8]),
                "evidence": "DOM links",
            }
        )
    if html_signals.get("directory_listing_hint"):
        findings.append({"type": "directory_listing_hint", "detail": "Index of marker", "evidence": "HTML title/body"})
    for item in sensitive_files.get("findings") or []:
        findings.append(
            {
                "type": "sensitive_public_file",
                "detail": item.get("url", ""),
                "evidence": str(item.get("status", "")),
            }
        )
    if devtools.get("cloudflare_page"):
        findings.append({"type": "cloudflare_challenge", "detail": "challenge page marker", "evidence": devtools.get("final_url", "")})
    if re.search(r"\bIndex of /", html, re.I):
        findings.append({"type": "directory_listing_hint", "detail": "Index of text", "evidence": "HTML"})
    return findings[:300]


def _detect_patterns(patterns: dict[str, tuple[str, ...]], text: str) -> list[str]:
    lowered = text.lower()
    return sorted(
        name
        for name, hints in patterns.items()
        if any(hint.lower() in lowered for hint in hints)
    )


def _meta_content(soup: BeautifulSoup, name: str) -> str:
    tag = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.I)})
    return str(tag.get("content") or "") if tag else ""


def _link_href(soup: BeautifulSoup, rel: str, base_url: str) -> str:
    tag = soup.find("link", rel=lambda value: value and rel.lower() in " ".join(value if isinstance(value, list) else [value]).lower())
    return _absolute(base_url, tag.get("href")) if tag and tag.get("href") else ""


def _favicon(soup: BeautifulSoup, base_url: str) -> str:
    for rel in ("icon", "shortcut icon", "apple-touch-icon"):
        href = _link_href(soup, rel, base_url)
        if href:
            return href
    return urljoin(base_url, "/favicon.ico")


def _absolute(base_url: str, value: str | None) -> str:
    if not value:
        return ""
    return sanitize_url(urljoin(base_url, str(value).strip()))


def _is_external(url: str, domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower().strip(".")
    domain = domain.lower().strip(".")
    return bool(host and host != domain and not host.endswith(f".{domain}"))


def _host_matches(url: str, hosts: tuple[str, ...]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == item or host.endswith(f".{item}") for item in hosts)


def _mixed_content_links(base_url: str, links: list[str]) -> list[str]:
    if not base_url.startswith("https://"):
        return []
    return [link for link in links if link.startswith("http://")]


def _clean_phone(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _extract_phones(text: str) -> list[str]:
    phones = []
    seen = set()
    for value in PHONE_PATTERN.findall(text or ""):
        cleaned = _clean_phone(value)
        if not _valid_phone(cleaned) or cleaned in seen:
            continue
        seen.add(cleaned)
        phones.append(cleaned)
    return sorted(phones)


def _valid_phone(value: str) -> bool:
    raw = str(value or "").strip()
    if "." in raw:
        return False
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 10 or len(digits) > 15:
        return False
    if len(set(digits)) < 4:
        return False
    if digits.startswith("000"):
        return False
    return True
