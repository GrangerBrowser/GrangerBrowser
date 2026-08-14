from __future__ import annotations

import base64
from collections import Counter
from copy import deepcopy
import mimetypes
from pathlib import Path
import re
import shutil
from typing import Any
from urllib.parse import parse_qsl, quote, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..core.application_blueprint import build_application_blueprint
from ..core.application_route_intelligence import build_application_route_intelligence
from ..core.endpoint_utils import is_probable_endpoint
from ..core.models import ArtifactRecord, utc_now
from ..i18n import load_all_locales, load_locale, normalize_language


TRACKER_GROUPS = {
    "Google": ("google", "gtag", "gtm", "analytics", "recaptcha"),
    "Meta": ("meta", "facebook", "fbp", "fbevents"),
    "Yandex": ("yandex", "metrika", "ym_"),
    "Cloudflare": ("cloudflare", "cf-"),
    "TikTok": ("tiktok", "ttq", "ttclid"),
    "Microsoft": ("microsoft", "clarity", "msclkid"),
}
TRACKER_GROUP_ORDER = ["Google", "Meta", "Yandex", "Cloudflare", "TikTok", "Microsoft", "Other"]
NETWORK_GROUP_ORDER = ["main document", "scripts", "api", "images", "css", "fonts", "other"]
ENDPOINT_KEYWORDS = (
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
VERSION_PATTERNS = {
    "Nginx": re.compile(r"nginx/(\d+(?:\.\d+){1,2})", re.I),
    "Apache": re.compile(r"apache/?(\d+(?:\.\d+){1,2})", re.I),
    "PHP": re.compile(r"php/?(\d+(?:\.\d+){1,2})", re.I),
    "jQuery": re.compile(r"jquery[-.]?(\d+(?:\.\d+){1,2})", re.I),
    "Bootstrap": re.compile(r"bootstrap[- ]?(\d+(?:\.\d+){1,2})", re.I),
}
BRANDING_INLINE_LIMIT = 2 * 1024 * 1024
LOGO_CANDIDATES = (
    "brand-logo.png",
    "brand-logo.jpg",
    "brand-logo.jpeg",
    "brand-logo.webp",
    "brand-logo.mp4",
    "brand-logo.webm",
    "logo.png",
    "logo.jpg",
    "logo.jpeg",
    "logo.webp",
    "logo.mp4",
    "logo.webm",
    "logo.gif",
)
BACKGROUND_CANDIDATES = (
    "background.webp",
    "background.png",
    "background.jpg",
    "background.jpeg",
)
REPORT_LOGO_CANDIDATES = (
    "brand-logo.png",
    "brand-logo.jpg",
    "brand-logo.jpeg",
    "brand-logo.webp",
    "brand-logo.mp4",
    "brand-logo.webm",
    "brand-logo.gif",
)
REPORT_BACKGROUND_CANDIDATES = (
    "custom-background.webp",
    "custom-background.png",
    "custom-background.jpg",
    "custom-background.jpeg",
)
CHAIN_ICON_NAMES = ("browser", "ddos", "tls", "firewall", "edge", "origin")
CHAIN_ICON_CANDIDATES = ("{name}.webp", "{name}.png", "{name}.jpg", "{name}.jpeg", "{name}.gif")


def export_html_report(
    artifacts: list[ArtifactRecord | dict[str, Any]],
    _unused_context: dict[str, Any] | None,
    output_path: str | Path,
    language: str = "en",
) -> dict[str, Any]:
    lang = normalize_language(language)
    report_path = Path(output_path).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_dir = Path(__file__).resolve().parent
    template_dir = report_dir / "templates"
    static_dir = report_dir / "static"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    normalized_artifacts = [
        ArtifactRecord.from_dict(artifact).to_dict() if isinstance(artifact, dict) else artifact.to_dict()
        for artifact in artifacts
    ]
    generated_at = utc_now()
    report = build_report_model(normalized_artifacts, _unused_context, language=lang)
    _remove_missing_local_screenshots(report, report_path.parent)
    report["generated_at"] = generated_at
    branding = _branding_assets(report_path)
    report_css = (static_dir / "report.css").read_text(encoding="utf-8")
    report_js = env.from_string((static_dir / "report.js").read_text(encoding="utf-8")).render(
        generated_at=generated_at,
        language=lang,
        locale=load_locale(lang),
        locales=load_all_locales(),
        report=report,
        branding={"chain_icons": branding.get("chain_icons") or {}},
    )
    html = template.render(
        generated_at=generated_at,
        language=lang,
        locale=load_locale(lang),
        locales=load_all_locales(),
        report_css=report_css,
        report_js=report_js,
        branding=branding,
        report=report,
    )
    report_path.write_text(html, encoding="utf-8")
    return {"report": report_path, "report_data": report}


def _remove_missing_local_screenshots(report: dict[str, Any], report_dir: Path) -> None:
    for domain in report.get("domains") or []:
        screenshot = domain.get("screenshot") or {}
        if not screenshot.get("available"):
            continue
        for key in ("png", "preview", "thumbnail"):
            value = str(screenshot.get(key) or "").strip()
            if value and not _report_media_exists(value, report_dir):
                screenshot[key] = ""
        screenshot["available"] = bool(
            screenshot.get("png") or screenshot.get("preview") or screenshot.get("thumbnail")
        )


def _report_media_exists(value: str, report_dir: Path) -> bool:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https", "data", "blob"}:
        return True
    if parsed.scheme == "file":
        local_path = Path(parsed.path.lstrip("/") if re.match(r"^/[A-Za-z]:", parsed.path) else parsed.path)
    else:
        local_path = Path(parsed.path)
        if not local_path.is_absolute():
            local_path = report_dir / local_path
    return local_path.is_file()


def _branding_assets(report_path: Path) -> dict[str, Any]:
    branding_dir = Path(__file__).resolve().parents[1] / "assets" / "branding"
    report_assets_dir = Path(__file__).resolve().parents[1] / "assets" / "report"
    output_assets = report_path.parent / "assets"
    logo = _asset_payload(report_assets_dir, output_assets, report_path.parent, REPORT_LOGO_CANDIDATES, "report_logo")
    if not logo:
        logo = _asset_payload(branding_dir, output_assets, report_path.parent, LOGO_CANDIDATES, "logo")
    background = _asset_payload(branding_dir, output_assets, report_path.parent, BACKGROUND_CANDIDATES, "background")
    if not background:
        background = _asset_payload(report_assets_dir, output_assets, report_path.parent, REPORT_BACKGROUND_CANDIDATES, "report_background")
    chain_icons = {
        name: payload
        for name in CHAIN_ICON_NAMES
        if (payload := _asset_payload(
            report_assets_dir / "chain-node-icons",
            output_assets,
            report_path.parent,
            tuple(pattern.format(name=name) for pattern in CHAIN_ICON_CANDIDATES),
            f"chain_{name}",
        ))
    }
    return {
        "logo": logo,
        "background": background,
        "background_css": background.get("src", "") if background else "",
        "chain_icons": chain_icons,
    }


def _asset_payload(
    branding_dir: Path,
    output_assets: Path,
    report_dir: Path,
    candidates: tuple[str, ...],
    prefix: str,
) -> dict[str, str]:
    for name in candidates:
        source = branding_dir / name
        if not source.is_file():
            continue
        suffix = source.suffix.lower()
        mime = mimetypes.guess_type(source.name)[0] or _fallback_mime(suffix)
        if source.stat().st_size <= BRANDING_INLINE_LIMIT:
            raw = base64.b64encode(source.read_bytes()).decode("ascii")
            return {
                "src": f"data:{mime};base64,{raw}",
                "kind": "video" if suffix in {".mp4", ".webm"} else "image",
                "mime": mime,
                "name": source.name,
            }
        output_assets.mkdir(parents=True, exist_ok=True)
        target = output_assets / f"branding_{prefix}{suffix}"
        if source.resolve() != target.resolve():
            shutil.copy2(source, target)
        return {
            "src": _relative_url(target, report_dir),
            "kind": "video" if suffix in {".mp4", ".webm"} else "image",
            "mime": mime,
            "name": source.name,
        }
    return {}


def _fallback_mime(suffix: str) -> str:
    return {
        ".mp4": "video/mp4",
        ".webm": "video/webm",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
    }.get(suffix.lower(), "application/octet-stream")


def _relative_url(path: Path, base_dir: Path) -> str:
    try:
        relative = path.resolve().relative_to(base_dir.resolve())
    except ValueError:
        relative = path.resolve()
    return "/".join(quote(part) for part in relative.parts)


def build_report_model(
    artifacts: list[dict[str, Any]],
    _unused_context: dict[str, Any] | None = None,
    language: str = "en",
) -> dict[str, Any]:
    domain_reports = [_domain_report(artifact) for artifact in artifacts if artifact.get("type") == "domain"]
    ip_reports = [_ip_report(artifact) for artifact in artifacts if artifact.get("type") == "ip"]
    mention_reports = [
        _mention_report(artifact)
        for artifact in artifacts
        if artifact.get("type") in {"mentions", "mention_hunter", "mention_search"}
    ]
    artifact_counts = Counter(artifact.get("type", "unknown") for artifact in artifacts)
    latest_artifact = artifacts[-1] if artifacts else {}
    target_type = latest_artifact.get("type") or ("domain" if domain_reports else "ip" if ip_reports else "")
    target = latest_artifact.get("label") or ""
    if target_type == "domain" and domain_reports:
        target = domain_reports[-1].get("domain") or target
    if target_type == "ip" and ip_reports:
        target = ip_reports[-1].get("ip") or target
    if target_type in {"mentions", "mention_hunter", "mention_search"} and mention_reports:
        target = mention_reports[-1].get("target") or target
    return {
        "language": normalize_language(language),
        "target_type": target_type,
        "target": target,
        "artifact_counts": dict(sorted(artifact_counts.items())),
        "domains": domain_reports,
        "ip_intelligence": ip_reports[-1] if ip_reports else {},
        "mention_hunter": mention_reports[-1] if mention_reports else {},
        "overview": _overview(domain_reports, ip_reports[-1] if ip_reports else {}),
        "raw_artifacts": [_raw_artifact_for_html(artifact) for artifact in artifacts],
    }


def _mention_report(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    matches = [_mention_match_row(row) for row in (data.get("matches") or [])[:2500]]
    top_matches = [_mention_match_row(row) for row in (data.get("top_matches") or [])[:30]]
    source_counts = (data.get("summary") or {}).get("source_types") or {}
    risk_counts = (data.get("summary") or {}).get("risk_counts") or {}
    variants = []
    for row in data.get("variants") or []:
        variants.append(
            {
                "keyword": str(row.get("keyword") or ""),
                "variants": row.get("values") or [],
                "count": len(row.get("values") or []),
            }
        )
    coverage = [
        {"source": str(key), "count": value}
        for key, value in (data.get("source_coverage") or {}).items()
    ]
    return {
        "artifact": artifact,
        "target": str(data.get("target") or artifact.get("label") or ""),
        "primary_url": str(data.get("primary_url") or ""),
        "keywords": data.get("keywords") or [],
        "search_modes": data.get("search_modes") or [],
        "summary": data.get("summary") or {},
        "matches": matches,
        "top_matches": top_matches,
        "variants": variants,
        "source_coverage": coverage,
        "source_distribution": [
            {"label": str(key), "value": value}
            for key, value in source_counts.items()
        ],
        "risk_distribution": [
            {"label": str(key), "value": value}
            for key, value in risk_counts.items()
        ],
        "limits": data.get("limits") or {},
        "errors": _unique_strings(data.get("errors") or [], limit=120),
        "timestamp": str(data.get("timestamp") or artifact.get("created_at") or ""),
    }


def _mention_match_row(row: dict[str, Any]) -> dict[str, Any]:
    source_url = str(row.get("source_url") or "")
    return {
        "keyword": str(row.get("keyword") or ""),
        "matched_text": str(row.get("matched_text") or ""),
        "variant": str(row.get("variant") or ""),
        "risk": str(row.get("risk") or "info"),
        "source_type": str(row.get("source_type") or ""),
        "location": str(row.get("location") or ""),
        "source_url": source_url,
        "href": source_url if source_url.startswith(("http://", "https://")) else "",
        "line": row.get("line") or 0,
        "context": {
            "before": str(row.get("context_before") or ""),
            "match": str(row.get("matched_text") or ""),
            "after": str(row.get("context_after") or ""),
        },
        "count": row.get("count") or 1,
        "confidence": str(row.get("confidence") or "low"),
        "notes": str(row.get("notes") or ""),
    }


def _ip_report(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    intelligence = data.get("ip_intelligence") if isinstance(data.get("ip_intelligence"), dict) else {}
    summary = intelligence.get("summary") if isinstance(intelligence.get("summary"), dict) else {}
    geo = intelligence.get("geo") if isinstance(intelligence.get("geo"), dict) else {}
    asn_data = intelligence.get("asn") if isinstance(intelligence.get("asn"), dict) else {}
    provider_data = intelligence.get("provider") if isinstance(intelligence.get("provider"), dict) else {}
    registry = intelligence.get("registry") if isinstance(intelligence.get("registry"), dict) else {}
    provider = data.get("provider") or data.get("isp") or ""
    hosting = data.get("hosting_datacenter")
    if hosting is None:
        hosting = data.get("hosting_or_datacenter")
    country_code = str(geo.get("country_code") or data.get("country_code") or "").upper()
    visual_assets = _ip_visual_assets(country_code)
    return {
        "artifact": artifact,
        "status": intelligence.get("status") or "completed",
        "ip": summary.get("ip") or data.get("ip") or artifact.get("label") or "",
        "version": data.get("version"),
        "is_private": data.get("is_private"),
        "summary": summary,
        "country": geo.get("country") or data.get("country") or "",
        "country_code": country_code,
        "region": geo.get("region") or data.get("region") or "",
        "city": geo.get("city") or data.get("city") or "",
        "latitude": geo.get("latitude", data.get("latitude")),
        "longitude": geo.get("longitude", data.get("longitude")),
        "timezone": geo.get("timezone") or data.get("timezone") or "",
        "geo": geo,
        "asn": asn_data.get("number") or data.get("asn") or "",
        "as_name": asn_data.get("name") or data.get("as_name") or "",
        "as_label": asn_data.get("label") or data.get("as_label") or "",
        "asn_intelligence": asn_data,
        "organization": provider_data.get("organization") or data.get("organization") or "",
        "isp": data.get("isp") or provider,
        "provider": provider_data.get("provider") or provider,
        "provider_intelligence": provider_data,
        "registry": registry,
        "classification": intelligence.get("classification") or {},
        "reverse_dns": provider_data.get("reverse_dns") or data.get("reverse_dns") or "",
        "hosting_datacenter": bool(hosting),
        "hosting_or_datacenter": bool(hosting),
        "hosting_signals": _unique_strings(data.get("hosting_signals") or [], limit=40),
        "vpn_proxy_tor": bool(data.get("vpn_proxy_tor")),
        "vpn_proxy_tor_signals": _unique_strings(data.get("vpn_proxy_tor_signals") or [], limit=40),
        "risk_flags": _unique_strings(data.get("risk_flags") or [], limit=40),
        "source": data.get("source") or ", ".join(data.get("sources") or []),
        "sources": _unique_strings(data.get("sources") or [], limit=40),
        "checked_at": data.get("checked_at") or artifact.get("created_at") or "",
        "rdap": data.get("rdap") or {},
        "ports": [row for row in (intelligence.get("ports") or []) if isinstance(row, dict)],
        "services": [row for row in (intelligence.get("services") or []) if isinstance(row, dict)],
        "technologies": [row for row in (intelligence.get("technologies") or []) if isinstance(row, dict)],
        "relationships": intelligence.get("relationships") or {},
        "blueprint": intelligence.get("blueprint") or {},
        "timeline": [row for row in (intelligence.get("timeline") or []) if isinstance(row, dict)],
        "risk_signals": [row for row in (intelligence.get("risk_signals") or []) if isinstance(row, dict)],
        "evidence": [row for row in (intelligence.get("evidence") or []) if isinstance(row, dict)],
        "insights": [row for row in (intelligence.get("insights") or []) if isinstance(row, dict)],
        "http_observations": [row for row in (intelligence.get("http_observations") or []) if isinstance(row, dict)],
        "tls_observations": [row for row in (intelligence.get("tls_observations") or []) if isinstance(row, dict)],
        "scan": intelligence.get("scan") or data.get("port_surface") or {},
        "assets": visual_assets,
        "reputation": data.get("reputation") or {},
        "errors": _unique_strings(data.get("errors") or [], limit=80),
    }


def _ip_visual_assets(country_code: str) -> dict[str, str]:
    assets_dir = Path(__file__).resolve().parents[1] / "assets" / "ip"
    world_path = assets_dir / "world" / "world.svg"
    flag_path = assets_dir / "flags" / f"{country_code.lower()}.svg" if country_code else Path()
    world_svg = world_path.read_text(encoding="utf-8") if world_path.is_file() else ""
    flag_data_uri = ""
    if country_code and flag_path.is_file():
        encoded = base64.b64encode(flag_path.read_bytes()).decode("ascii")
        flag_data_uri = f"data:image/svg+xml;base64,{encoded}"
    return {
        "world_svg": world_svg,
        "flag_data_uri": flag_data_uri,
        "country_code": country_code.lower(),
    }


def _domain_report(artifact: dict[str, Any]) -> dict[str, Any]:
    data = artifact.get("data") or {}
    devtools = data.get("devtools") or {}
    html = data.get("html") or {}
    http = data.get("http") or {}
    http_surface = data.get("http_surface") or {}
    sensitive = data.get("sensitive_public_files") or {}
    endpoints = _filter_endpoints(data.get("api_endpoints") or [])
    tracker_groups = _group_trackers(data.get("analytics_tracker_hints") or [])
    technologies = _technology_rows(data)
    security_findings = (data.get("security_findings") or [])[:160]
    discovery = _discovery_report(data.get("discovery") or {})
    sqli_analysis = _sqli_report(data.get("sqli_analysis") or {})
    agent_workflow = _agent_workflow_rows(data.get("agent_workflow") or [])
    admin_panels = _admin_panels(html, endpoints)
    public_resources = _sensitive_file_rows(sensitive.get("findings") or [])
    source_maps = _source_map_rows(html, data)
    score = _security_score(data, endpoints, admin_panels, public_resources, technologies)
    attack_surface = _attack_surface(data, endpoints, admin_panels, public_resources, source_maps)
    historical = _historical_report(data.get("historical_intelligence") or {})
    reputation = _reputation_report(data.get("reputation_intelligence") or {})
    js_intelligence = _js_intelligence_report(data.get("js_intelligence") or {})
    favicon_intelligence = _favicon_intelligence_report(
        data.get("favicon_intelligence") or {},
        http_surface.get("favicon") or {},
    )
    cloud_buckets = _cloud_bucket_report(data.get("cloud_buckets") or {})
    oauth_intelligence = _oauth_intelligence_report(data.get("oauth_intelligence") or {})
    traffic_chain = _traffic_chain_report(data.get("traffic_chain") or {})
    port_surface = _port_surface_report(data.get("port_surface") or {})
    social_intelligence = _social_intelligence_report(data)
    application_route_intelligence = _application_route_intelligence_report(data)
    application_blueprint = _application_blueprint_report(data)
    return {
        "artifact": artifact,
        "domain": data.get("domain") or artifact.get("label") or "",
        "domain_link": _domain_link(data.get("domain") or artifact.get("label") or ""),
        "ips": [_link_item(ip, f"http://ip-api.com/#/{quote(ip)}") for ip in _unique_strings(data.get("linked_ip_addresses") or [], limit=80)],
        "dns": _filtered_dns(data.get("dns") or {}),
        "reverse_dns": _dedupe_dict_rows(data.get("reverse_dns") or [], ("ip", "hostname"), limit=80),
        "email_auth": data.get("email_auth") or {},
        "rdap": data.get("rdap") or {},
        "asn_bgp": data.get("asn_bgp") or [],
        "tls": data.get("tls_certificate") or {},
        "tls_intelligence": _tls_intelligence(data.get("tls_certificate") or {}),
        "certificate_transparency": _ct_rows(data.get("certificate_transparency") or []),
        "subdomains": [_domain_link(item) for item in _unique_strings(data.get("subdomains") or [], limit=200)],
        "http": http,
        "http_surface": _http_surface_report(http_surface),
        "response_comparison": _response_comparison_rows(http_surface.get("response_comparison") or []),
        "screenshot": _screenshot_report(data.get("screenshot") or (data.get("devtools") or {}).get("screenshot") or {}),
        "favicon_intelligence": favicon_intelligence,
        "domain_summary": _domain_summary_rows(data),
        "security_headers": data.get("security_headers") or {},
        "security_audit": _security_audit_rows(data),
        "http_cookies": _http_cookie_rows(data),
        "security_signals": _security_signal_rows(data.get("security_signals") or []),
        "interesting_paths": _interesting_path_rows(data.get("interesting_paths") or http_surface.get("interesting_paths") or []),
        "analyst_notes": _unique_strings(data.get("analyst_notes") or http_surface.get("analyst_notes") or [], limit=80),
        "analyst_timeline": _analyst_timeline_rows(data.get("analyst_timeline") or []),
        "raw_headers": _raw_header_rows(http_surface.get("headers") or http.get("headers") or {}),
        "technology_fingerprints": _technology_fingerprint_rows(data),
        "javascript_intelligence": _javascript_report(data.get("javascript_intelligence") or {}),
        "js_intelligence": js_intelligence,
        "cloud_buckets": cloud_buckets,
        "oauth_intelligence": oauth_intelligence,
        "port_surface": port_surface,
        "executive_summary": _executive_summary(
            js_intelligence,
            favicon_intelligence,
            cloud_buckets,
            oauth_intelligence,
            traffic_chain,
        ),
        "html_comment_intelligence": _html_comment_rows(data.get("html_comment_intelligence") or (data.get("html") or {}).get("html_comments") or []),
        "meta_tag_intelligence": _meta_tag_rows(data.get("meta_tag_intelligence") or (data.get("html") or {}).get("meta_tags") or []),
        "cdn_detection": _cdn_rows(data.get("cdn_detection") or []),
        "html": html,
        "devtools": devtools,
        "devtools_intelligence": _devtools_intelligence_report(data),
        "traffic_chain": traffic_chain,
        "sources": _unique_strings(data.get("sources") or [], limit=80),
        "execution_log": _module_status_rows(data.get("execution_log") or [], limit=120),
        "network_summary": _network_summary(devtools.get("network_requests") or []),
        "websocket_urls": [_link_item(item, item) for item in _unique_strings(devtools.get("websocket_urls") or [], limit=80)],
        "trackers": tracker_groups,
        "tracker_total": sum(len(group["items"]) for group in tracker_groups),
        "technologies": technologies,
        "emails": [_email_link(item) for item in _unique_strings(data.get("emails") or [], limit=120)],
        "phones": [_phone_link(item) for item in _unique_strings(data.get("phones") or [], limit=120)],
        "social_links": [_link_item(item, item) for item in _unique_strings(data.get("social_links") or [], limit=160)],
        "social_profiles": social_intelligence.get("profiles") or [],
        "social_intelligence": social_intelligence,
        "application_route_intelligence": application_route_intelligence,
        "application_blueprint": application_blueprint,
        "endpoints": endpoints,
        "admin_panels": admin_panels,
        "public_resources": public_resources,
        "source_maps": source_maps,
        "discovery": discovery,
        "sqli_analysis": sqli_analysis,
        "agent_workflow": agent_workflow,
        "resource_links": _resource_links(data),
        "sensitive_checked_count": len(sensitive.get("checked_paths") or []),
        "security_findings": security_findings,
        "decoded_artifacts": _decoded_rows(data.get("decoded_classified_artifacts") or []),
        "errors": _unique_strings(data.get("errors") or [], limit=120),
        "attack_surface": attack_surface,
        "risk_distribution": _risk_distribution(data),
        "technology_distribution": _technology_distribution(technologies),
        "security_score": score,
        "historical": historical,
        "reputation": reputation,
        "summary": {
            "ips": len(data.get("linked_ip_addresses") or []),
            "trackers": sum(len(group["items"]) for group in tracker_groups),
            "technologies": len(technologies),
            "findings": len(security_findings),
            "security_signals": len(data.get("security_signals") or []),
            "interesting_paths": len(data.get("interesting_paths") or http_surface.get("interesting_paths") or []),
            "endpoints": len(endpoints),
            "risks": len(security_findings),
            "public_resources": len(public_resources),
            "subdomains": len(data.get("subdomains") or []),
            "historical_urls": len(historical.get("historical_urls") or []),
            "reputation_hits": len(reputation.get("matched_indicators") or []),
            "discovery_findings": len(discovery.get("interesting_paths") or []),
            "sqli_findings": len(sqli_analysis.get("confirmed_findings") or []),
            "sqli_tested_parameters": sqli_analysis.get("tested_parameters_count") or 0,
            "devtools_requests": len((devtools.get("network_intelligence") or {}).get("requests") or devtools.get("network_requests") or []),
            "devtools_findings": len(devtools.get("interesting_findings") or []),
            "js_files": len(js_intelligence.get("files") or []),
            "js_api_endpoints": len(js_intelligence.get("api_endpoints") or []),
            "graphql_operations": len(js_intelligence.get("graphql") or []),
            "websocket_endpoints": len(js_intelligence.get("websockets") or []),
            "secret_like_values": len(js_intelligence.get("secret_like_values") or []),
            "favicon_matches": len(favicon_intelligence.get("matches") or []),
            "cloud_buckets": len(cloud_buckets.get("candidates") or []),
            "oauth_providers": len(oauth_intelligence.get("providers") or []),
            "auth_routes": len(oauth_intelligence.get("auth_routes") or []),
            "traffic_requests": (traffic_chain.get("summary") or {}).get("total_requests") or 0,
            "traffic_api_requests": (traffic_chain.get("summary") or {}).get("api_requests") or 0,
            "traffic_third_party": (traffic_chain.get("summary") or {}).get("third_party_requests") or 0,
            "traffic_failed": (traffic_chain.get("summary") or {}).get("failed_requests") or 0,
            "open_ports": (port_surface.get("summary") or {}).get("open_ports") or 0,
            "detected_services": (port_surface.get("summary") or {}).get("services_identified") or 0,
            "social_profiles": (social_intelligence.get("summary") or {}).get("profiles_analyzed") or 0,
            "social_platforms": (social_intelligence.get("summary") or {}).get("platforms_found") or 0,
            "application_routes": (application_route_intelligence.get("summary") or {}).get("total_routes") or 0,
            "route_high_interest": (application_route_intelligence.get("summary") or {}).get("high_interest") or 0,
            "route_dynamic_imports": (application_route_intelligence.get("summary") or {}).get("dynamic_imports") or 0,
            "blueprint_nodes": (application_blueprint.get("summary") or {}).get("nodes") or 0,
            "blueprint_edges": (application_blueprint.get("summary") or {}).get("edges") or 0,
        },
    }


def _application_route_intelligence_report(data: dict[str, Any]) -> dict[str, Any]:
    payload = data.get("application_route_intelligence")
    if not isinstance(payload, dict) or not isinstance(payload.get("katana_level_2"), dict):
        payload = build_application_route_intelligence(data)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "status": str(payload.get("status") or "completed"),
        "summary": {
            "total_routes": summary.get("total_routes") or 0,
            "observed_routes": summary.get("observed_routes") or 0,
            "recovered_routes": summary.get("recovered_routes") or 0,
            "api_routes": summary.get("api_routes") or 0,
            "admin_routes": summary.get("admin_routes") or 0,
            "auth_routes": summary.get("auth_routes") or 0,
            "graphql_routes": summary.get("graphql_routes") or 0,
            "websocket_routes": summary.get("websocket_routes") or 0,
            "hidden_routes": summary.get("hidden_routes") or 0,
            "dynamic_imports": summary.get("dynamic_imports") or 0,
            "js_recovered_routes": summary.get("js_recovered_routes") or 0,
            "high_interest": summary.get("high_interest") or 0,
            "endpoints": summary.get("endpoints") or 0,
        },
        "routes": [row for row in (payload.get("routes") or []) if isinstance(row, dict)],
        "route_tree": [row for row in (payload.get("route_tree") or []) if isinstance(row, dict)],
        "endpoints": [row for row in (payload.get("endpoints") or []) if isinstance(row, dict)],
        "javascript_routes": [row for row in (payload.get("javascript_routes") or []) if isinstance(row, dict)],
        "dynamic_imports": [row for row in (payload.get("dynamic_imports") or []) if isinstance(row, dict)],
        "high_interest_routes": [row for row in (payload.get("high_interest_routes") or []) if isinstance(row, dict)],
        "katana_level_2": _katana_level_2_report(payload.get("katana_level_2") or {}),
        "insights": payload.get("insights") or [],
    }


def _katana_level_2_report(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "status": str(payload.get("status") or "completed"),
        "summary": {
            "parameters": summary.get("parameters") or 0,
            "interesting_parameters": summary.get("interesting_parameters") or 0,
            "hidden_api_hosts": summary.get("hidden_api_hosts") or 0,
            "permission_mappings": summary.get("permission_mappings") or 0,
            "correlation_chains": summary.get("correlation_chains") or 0,
            "route_risk_candidates": summary.get("route_risk_candidates") or 0,
        },
        "parameters": [row for row in (payload.get("parameters") or []) if isinstance(row, dict)],
        "hidden_api_hosts": [row for row in (payload.get("hidden_api_hosts") or []) if isinstance(row, dict)],
        "permission_mappings": [row for row in (payload.get("permission_mappings") or []) if isinstance(row, dict)],
        "correlation_chains": [row for row in (payload.get("correlation_chains") or []) if isinstance(row, dict)],
        "route_risk_candidates": [row for row in (payload.get("route_risk_candidates") or []) if isinstance(row, dict)],
        "insights": [row for row in (payload.get("insights") or []) if isinstance(row, dict)],
    }


def _application_blueprint_report(data: dict[str, Any]) -> dict[str, Any]:
    payload = data.get("application_blueprint")
    if not isinstance(payload, dict):
        payload = build_application_blueprint(data)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "status": str(payload.get("status") or "completed"),
        "summary": {
            "nodes": summary.get("nodes") or 0,
            "edges": summary.get("edges") or 0,
            "domains": summary.get("domains") or 0,
            "technologies": summary.get("technologies") or 0,
            "apis": summary.get("apis") or 0,
            "external_services": summary.get("external_services") or 0,
            "routes": summary.get("routes") or 0,
            "risks": summary.get("risks") or 0,
        },
        "nodes": [node for node in (payload.get("nodes") or []) if isinstance(node, dict)],
        "edges": [edge for edge in (payload.get("edges") or []) if isinstance(edge, dict)],
        "insights": payload.get("insights") or [],
    }


def _overview(
    domain_reports: list[dict[str, Any]],
    ip_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    latest = domain_reports[-1] if domain_reports else {}
    ip_report = ip_report or {}
    latest_summary = latest.get("summary") or {}
    latest_score = (latest.get("security_score") or {}).get("total", 0)
    return {
        "target": latest.get("domain", "") or ip_report.get("ip", ""),
        "target_type": "domain" if latest else "ip" if ip_report else "",
        "ip": ip_report.get("ip", ""),
        "country": ip_report.get("country", ""),
        "city": ip_report.get("city", ""),
        "asn": ip_report.get("asn", ""),
        "organization": ip_report.get("organization", ""),
        "provider": ip_report.get("provider", ""),
        "vpn_proxy_tor": ip_report.get("vpn_proxy_tor", False),
        "ips": latest_summary.get("ips", 0),
        "trackers": latest_summary.get("trackers", 0),
        "technologies": latest_summary.get("technologies", 0),
        "findings": latest_summary.get("findings", 0),
        "risks": latest_summary.get("risks", 0),
        "endpoints": latest_summary.get("endpoints", 0),
        "public_resources": latest_summary.get("public_resources", 0),
        "subdomains": latest_summary.get("subdomains", 0),
        "historical_urls": latest_summary.get("historical_urls", 0),
        "reputation_hits": latest_summary.get("reputation_hits", 0),
        "discovery_findings": latest_summary.get("discovery_findings", 0),
        "sqli_findings": latest_summary.get("sqli_findings", 0),
        "js_files": latest_summary.get("js_files", 0),
        "js_api_endpoints": latest_summary.get("js_api_endpoints", 0),
        "graphql_operations": latest_summary.get("graphql_operations", 0),
        "websocket_endpoints": latest_summary.get("websocket_endpoints", 0),
        "secret_like_values": latest_summary.get("secret_like_values", 0),
        "favicon_matches": latest_summary.get("favicon_matches", 0),
        "cloud_buckets": latest_summary.get("cloud_buckets", 0),
        "oauth_providers": latest_summary.get("oauth_providers", 0),
        "auth_routes": latest_summary.get("auth_routes", 0),
        "traffic_requests": latest_summary.get("traffic_requests", 0),
        "traffic_api_requests": latest_summary.get("traffic_api_requests", 0),
        "traffic_third_party": latest_summary.get("traffic_third_party", 0),
        "traffic_failed": latest_summary.get("traffic_failed", 0),
        "open_ports": latest_summary.get("open_ports", 0),
        "detected_services": latest_summary.get("detected_services", 0),
        "score": latest_score,
        "nodes": 1 if latest or ip_report else 0,
        "edges": 0,
    }


def _discovery_report(payload: dict[str, Any]) -> dict[str, Any]:
    findings = [_discovery_row(row) for row in (payload.get("findings") or [])[:300]]
    all_results = [_discovery_row(row) for row in (payload.get("all_results") or [])[:500]]
    by_category: dict[str, list[dict[str, Any]]] = {}
    for row in findings:
        category = row.get("category") or "unknown"
        by_category.setdefault(category, []).append(row)
    return {
        "summary": payload.get("summary") or {},
        "config": payload.get("config") or {},
        "wordlists": payload.get("wordlists") or [],
        "wildcard_detection": payload.get("wildcard_detection") or {},
        "js_findings": [_js_finding_row(row) for row in (payload.get("js_findings") or [])[:160]],
        "interesting_paths": findings,
        "admin_paths": by_category.get("admin") or [],
        "auth_paths": by_category.get("auth") or [],
        "api_endpoints": (by_category.get("api") or []) + (by_category.get("graphql") or []) + (by_category.get("swagger") or []),
        "graphql": by_category.get("graphql") or [],
        "swagger": by_category.get("swagger") or [],
        "docs": by_category.get("docs") or [],
        "backup_config": (by_category.get("backup") or []) + (by_category.get("config") or []),
        "source_maps": by_category.get("sourcemap") or [],
        "public_resources": by_category.get("public") or [],
        "all_results": all_results,
    }


def _discovery_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or "")
    status_code = row.get("status_code", row.get("status", ""))
    content_length = row.get("content_length", row.get("size", 0))
    redirect_location = str(row.get("redirect_location") or row.get("redirect") or "")
    page_title = str(row.get("page_title") or row.get("title") or "")
    server_header = str(row.get("server_header") or row.get("server") or "")
    return {
        "url": url,
        "href": url,
        "path": str(row.get("path") or ""),
        "status_code": str(status_code or ""),
        "status": str(status_code or ""),
        "content_length": content_length or 0,
        "size": content_length or 0,
        "words": row.get("words") or 0,
        "lines": row.get("lines") or 0,
        "content_type": str(row.get("content_type") or ""),
        "redirect_location": redirect_location,
        "redirect": redirect_location,
        "page_title": page_title,
        "title": page_title,
        "server_header": server_header,
        "server": server_header,
        "category": str(row.get("category") or "unknown"),
        "source_wordlist": str(row.get("source_wordlist") or ""),
        "interesting_score": row.get("interesting_score") or 0,
        "notes": str(row.get("notes") or ""),
        "is_soft_404": bool(row.get("is_soft_404", row.get("soft_404", False))),
        "is_duplicate": bool(row.get("is_duplicate", False)),
    }


def _js_finding_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or row.get("endpoint") or "")
    return {
        "url": url,
        "href": url,
        "source_js": str(row.get("source_js") or row.get("source_file") or ""),
        "fragment": str(row.get("fragment") or ""),
        "type": str(row.get("type") or ""),
        "confidence": row.get("confidence") or 0,
    }


def _agent_workflow_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in rows[:40]:
        summary = row.get("summary") or {}
        output.append(
            {
                "agent": str(row.get("agent") or ""),
                "status": str(row.get("status") or ""),
                "summary": ", ".join(f"{key}: {value}" for key, value in summary.items()),
            }
        )
    return output


def _sqli_report(payload: dict[str, Any]) -> dict[str, Any]:
    findings = [_sqli_finding_row(row) for row in (payload.get("findings") or []) if row.get("confidence") != "Low"]
    interesting_parameters = [_sqli_parameter_row(row) for row in (payload.get("interesting_parameters") or [])[:160]]
    debug = payload.get("debug") or {}
    return {
        "summary": payload.get("summary") or {},
        "config": payload.get("config") or {},
        "confirmed_findings": findings,
        "tested_parameters_count": (payload.get("summary") or {}).get("tested_parameters") or 0,
        "interesting_parameters": interesting_parameters,
        "low_confidence_count": len(debug.get("low_confidence_signals") or []),
        "request_count": (payload.get("summary") or {}).get("requests_used") or 0,
    }


def _sqli_finding_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or "")
    evidence = row.get("evidence") or []
    if isinstance(evidence, list):
        evidence_text = "; ".join(str(item) for item in evidence if item)
    else:
        evidence_text = str(evidence)
    return {
        "url": url,
        "href": url,
        "method": str(row.get("method") or ""),
        "parameter": str(row.get("parameter") or ""),
        "parameter_type": str(row.get("parameter_type") or ""),
        "baseline_status": str(row.get("baseline_status") or ""),
        "test_status": str(row.get("test_status") or ""),
        "baseline_length": row.get("baseline_length") or 0,
        "test_length": row.get("test_length") or 0,
        "difference_percent": row.get("difference_percent") or 0,
        "detected_error": str(row.get("detected_error") or ""),
        "dbms_hint": str(row.get("dbms_hint") or ""),
        "payload_type": str(row.get("payload_type") or ""),
        "confidence": str(row.get("confidence") or ""),
        "evidence": evidence_text,
        "notes": str(row.get("notes") or ""),
    }


def _sqli_parameter_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": str(row.get("url") or ""),
        "href": str(row.get("url") or ""),
        "method": str(row.get("method") or ""),
        "parameter": str(row.get("parameter") or ""),
        "parameter_type": str(row.get("parameter_type") or ""),
        "source": str(row.get("source") or ""),
        "source_detail": str(row.get("source_detail") or ""),
        "score": row.get("score") or 0,
        "reason": str(row.get("reason") or ""),
    }


def _filtered_dns(records: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"):
        values = _unique_strings(records.get(record_type) or [], limit=140)
        if values:
            rows.append({"type": record_type, "records": values})
    return rows


def _http_surface_report(surface: dict[str, Any]) -> dict[str, Any]:
    output = deepcopy(surface or {})
    for key in list(output):
        if str(key).startswith("_"):
            output.pop(key, None)
    output["probes"] = _dedupe_dict_rows(output.get("probes") or [], ("scheme", "url", "status_code", "final_url"), limit=8)
    output["redirect_chain"] = _dedupe_dict_rows(output.get("redirect_chain") or [], ("from", "to", "status"), limit=20)
    output["cookies"] = _dedupe_dict_rows(output.get("cookies") or [], ("name", "domain", "path"), limit=80)
    output["interesting_paths"] = _interesting_path_rows(output.get("interesting_paths") or [])
    output["security_signals"] = _security_signal_rows(output.get("security_signals") or [])
    output["analyst_notes"] = _unique_strings(output.get("analyst_notes") or [], limit=80)
    output["headers"] = {str(key): str(value) for key, value in (output.get("headers") or {}).items()}
    return output


def _port_surface_report(surface: dict[str, Any]) -> dict[str, Any]:
    output = deepcopy(surface or {})
    rows = []
    for row in output.get("open_ports") or []:
        rows.append(
            {
                "port": row.get("port") or 0,
                "protocol": str(row.get("protocol") or "tcp"),
                "service": str(row.get("service") or "unknown"),
                "product": str(row.get("product") or ""),
                "version": str(row.get("version") or ""),
                "state": str(row.get("state") or ""),
                "extra_info": str(row.get("extra_info") or ""),
                "risk": str(row.get("risk") or "info"),
                "risk_label": str(row.get("risk_label") or ""),
                "risk_reason": str(row.get("risk_reason") or ""),
                "sensitive": bool(row.get("sensitive")),
            }
        )
    output["open_ports"] = rows[:1000]
    output["summary"] = {
        "open_ports": len(rows),
        "services_identified": int((output.get("summary") or {}).get("services_identified") or 0),
        "sensitive_services": int((output.get("summary") or {}).get("sensitive_services") or 0),
        "web_services": int((output.get("summary") or {}).get("web_services") or 0),
        "non_web_services": int((output.get("summary") or {}).get("non_web_services") or 0),
        "service_names": _unique_strings((output.get("summary") or {}).get("service_names") or [], limit=120),
        "scan_timed_out": bool((output.get("summary") or {}).get("scan_timed_out")),
    }
    output["errors"] = _unique_strings(output.get("errors") or [], limit=40)
    return output


def _response_comparison_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "field": str(row.get("field") or ""),
            "http": str(row.get("http") or ""),
            "https": str(row.get("https") or ""),
            "changed": str(row.get("changed") or ""),
        }
        for row in rows[:40]
    ]


def _screenshot_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": bool(payload.get("available")),
        "url": str(payload.get("url") or ""),
        "png": str(payload.get("png") or ""),
        "preview": str(payload.get("preview") or ""),
        "thumbnail": str(payload.get("thumbnail") or ""),
        "captured_at": str(payload.get("captured_at") or ""),
        "viewport": str(payload.get("viewport") or ""),
        "error": str(payload.get("error") or ""),
    }


def _favicon_report(payload: dict[str, Any]) -> dict[str, Any]:
    match = payload.get("match") or {}
    return {
        "url": str(payload.get("url") or ""),
        "hash": str(payload.get("hash") or ""),
        "hash_type": str(payload.get("hash_type") or ""),
        "mime_type": str(payload.get("mime_type") or ""),
        "size": payload.get("size") or 0,
        "match": str(match.get("name") or ""),
        "match_confidence": str(match.get("confidence") or ""),
        "match_source": str(match.get("source") or ""),
    }


def _favicon_intelligence_report(
    payload: dict[str, Any],
    legacy_payload: dict[str, Any],
) -> dict[str, Any]:
    if not payload.get("icons") and not payload.get("matches"):
        legacy = _favicon_report(legacy_payload)
        if not legacy.get("url") or not legacy.get("hash"):
            return {"icons": [], "primary_icon": {}, "hashes": {}, "matches": [], "summary": {}}
        icon = {
            "name": "Favicon",
            "type": "favicon",
            "value": legacy["url"],
            "href": legacy["url"],
            "source": "HTTP Surface favicon",
            "confidence": "medium",
            "evidence": legacy.get("hash") or "",
            "risk": "low",
            "notes": "",
            "final_url": legacy["url"],
            "content_type": legacy.get("mime_type") or "",
            "size": legacy.get("size") or 0,
            legacy.get("hash_type") or "hash": legacy.get("hash") or "",
        }
        return {
            "icons": [icon],
            "primary_icon": icon,
            "hashes": {legacy.get("hash_type") or "hash": legacy.get("hash") or ""},
            "matches": [],
            "summary": {"icons": 1, "matches": 0},
        }
    icons = [_finding_row(row) for row in (payload.get("icons") or [])[:40]]
    matches = [_finding_row(row) for row in (payload.get("matches") or [])[:80]]
    primary = _finding_row(payload.get("primary_icon") or {}) if payload.get("primary_icon") else {}
    return {
        "icons": icons,
        "primary_icon": primary,
        "hashes": payload.get("hashes") or {},
        "matches": matches,
        "summary": payload.get("summary") or {},
    }


def _js_intelligence_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "files": [_finding_row(row) for row in (payload.get("files") or [])[:240]],
        "api_endpoints": [_finding_row(row) for row in (payload.get("api_endpoints") or [])[:500]],
        "graphql": [_finding_row(row) for row in (payload.get("graphql") or [])[:180]],
        "websockets": [_finding_row(row) for row in (payload.get("websockets") or [])[:120]],
        "third_party_sdks": [_finding_row(row) for row in (payload.get("third_party_sdks") or [])[:160]],
        "secret_like_values": [_finding_row(row) for row in (payload.get("secret_like_values") or [])[:180]],
        "config_objects": [_finding_row(row) for row in (payload.get("config_objects") or [])[:120]],
        "suspicious_strings": [_finding_row(row) for row in (payload.get("suspicious_strings") or [])[:160]],
        "summary": payload.get("summary") or {},
    }


def _cloud_bucket_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidates": [_finding_row(row) for row in (payload.get("candidates") or [])[:100]],
        "verified": [_finding_row(row) for row in (payload.get("verified") or [])[:100]],
        "public_objects": [_finding_row(row) for row in (payload.get("public_objects") or [])[:100]],
        "summary": payload.get("summary") or {},
    }


def _oauth_intelligence_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "providers": [_finding_row(row) for row in (payload.get("providers") or [])[:80]],
        "auth_routes": [_finding_row(row) for row in (payload.get("auth_routes") or [])[:240]],
        "callback_urls": [_finding_row(row) for row in (payload.get("callback_urls") or [])[:120]],
        "client_ids": [_finding_row(row) for row in (payload.get("client_ids") or [])[:120]],
        "scopes": [_finding_row(row) for row in (payload.get("scopes") or [])[:120]],
        "oidc_metadata": [_finding_row(row) for row in (payload.get("oidc_metadata") or [])[:40]],
        "session_indicators": [_finding_row(row) for row in (payload.get("session_indicators") or [])[:160]],
        "summary": payload.get("summary") or {},
    }


def _finding_row(row: dict[str, Any]) -> dict[str, Any]:
    output = dict(row or {})
    value = str(output.get("value") or "")
    url = str(output.get("url") or output.get("final_url") or "")
    output.update(
        {
            "name": str(output.get("name") or ""),
            "type": str(output.get("type") or ""),
            "value": value,
            "source": str(output.get("source") or ""),
            "confidence": str(output.get("confidence") or "low"),
            "evidence": str(output.get("evidence") or ""),
            "risk": str(output.get("risk") or "low"),
            "notes": str(output.get("notes") or ""),
            "href": url or _value_href(value),
        }
    )
    return output


def _executive_summary(
    js_intelligence: dict[str, Any],
    favicon: dict[str, Any],
    cloud: dict[str, Any],
    oauth: dict[str, Any],
    traffic: dict[str, Any],
) -> list[str]:
    notes = []
    endpoint_count = len(js_intelligence.get("api_endpoints") or [])
    if endpoint_count:
        notes.append(f"Detected {endpoint_count} API endpoint(s) from JavaScript and browser network.")
    graphql_count = len(js_intelligence.get("graphql") or [])
    if graphql_count:
        notes.append(f"Detected {graphql_count} GraphQL operation or endpoint marker(s).")
    providers = [str(row.get("name") or "") for row in oauth.get("providers") or [] if row.get("name")]
    if providers:
        notes.append(f"Detected OAuth/OIDC provider flow: {', '.join(providers[:4])}.")
    traffic_summary = traffic.get("summary") or {}
    total_requests = int(traffic_summary.get("total_requests") or 0)
    if total_requests:
        notes.append(
            f"Captured {total_requests} browser traffic request(s), "
            f"{int(traffic_summary.get('api_requests') or 0)} API, "
            f"{int(traffic_summary.get('third_party_requests') or 0)} third-party, "
            f"{int(traffic_summary.get('failed_requests') or 0)} failed."
        )
    if cloud.get("candidates"):
        public_count = sum(1 for row in cloud.get("verified") or [] if row.get("status") == "public")
        notes.append(
            f"Detected {len(cloud.get('candidates') or [])} cloud storage reference(s); {public_count} publicly reachable."
        )
    else:
        notes.append("No exposed cloud bucket reference was found.")
    if favicon.get("matches"):
        notes.append(f"Favicon matched {len(favicon.get('matches') or [])} known service fingerprint(s).")
    elif favicon.get("icons"):
        notes.append("Favicon did not match the local known-service database.")
    return notes[:8]


def _tls_intelligence(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "cipher_suite": str(payload.get("cipher_suite") or ""),
        "cipher_bits": payload.get("cipher_bits") or 0,
        "issuer": str(payload.get("issuer") or ""),
        "subject": str(payload.get("subject") or ""),
        "san": payload.get("san_domains") or payload.get("subject_alt_names") or [],
        "signature_algorithm": str(payload.get("signature_algorithm") or ""),
        "tls_version": str(payload.get("tls_version") or ""),
        "expiration": str(payload.get("valid_to") or payload.get("not_after") or ""),
        "days_remaining": payload.get("days_remaining"),
        "weak_cipher": bool(payload.get("weak_cipher")),
        "verification_error": str(payload.get("verification_error") or ""),
    }


def _analyst_timeline_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "timestamp": str(row.get("timestamp") or ""),
            "event": str(row.get("event") or ""),
            "source": str(row.get("source") or ""),
            "detail": str(row.get("detail") or ""),
        }
        for row in rows[:180]
        if row.get("event")
    ]


def _javascript_report(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "scripts": _dedupe_dict_rows(payload.get("scripts") or [], ("url",), limit=220),
        "inline_scripts": _dedupe_dict_rows(payload.get("inline_scripts") or [], ("index",), limit=120),
        "frameworks": _dedupe_dict_rows(payload.get("frameworks") or [], ("name",), limit=80),
        "markers": _dedupe_dict_rows(payload.get("markers") or [], ("name", "source", "evidence"), limit=220),
        "endpoints": _dedupe_dict_rows(payload.get("endpoints") or [], ("url", "source"), limit=240),
        "source_maps": [_link_item(item, item) for item in _unique_strings(payload.get("source_maps") or [], 120)],
    }


def _html_comment_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "marker": str(row.get("marker") or ""),
            "excerpt": str(row.get("excerpt") or ""),
            "source": str(row.get("source") or "HTML comment"),
        }
        for row in rows[:120]
    ]


def _meta_tag_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "name": str(row.get("name") or ""),
            "value": str(row.get("value") or ""),
            "source": str(row.get("source") or "HTML"),
        }
        for row in rows[:180]
    ]


def _cdn_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "name": str(row.get("name") or ""),
            "confidence": str(row.get("confidence") or ""),
            "evidence": str(row.get("evidence") or ""),
            "source": str(row.get("source") or ""),
        }
        for row in rows[:80]
    ]


def _domain_summary_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    dns = data.get("dns") or {}
    rdap = data.get("rdap") or {}
    http_surface = data.get("http_surface") or {}
    asn = data.get("asn_bgp") or []
    return [
        {"name": "Input", "value": str(data.get("input") or data.get("domain") or "")},
        {"name": "Host", "value": str(data.get("host") or data.get("domain") or ""), "type": "domain"},
        {"name": "Primary URL", "value": str(http_surface.get("primary_url") or ""), "type": "url"},
        {"name": "DNS Records", "value": str(sum(len(values) for values in dns.values()))},
        {"name": "IPs", "value": ", ".join(str(item) for item in (data.get("linked_ip_addresses") or [])[:12])},
        {"name": "ASN", "value": ", ".join(str(row.get("asn") or row.get("name") or "") for row in asn[:6] if row.get("asn") or row.get("name"))},
        {"name": "Registrar", "value": str(rdap.get("registrar") or "")},
        {"name": "HTTP Status", "value": str(http_surface.get("status_code") or "")},
    ]


def _security_signal_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "level": str(row.get("level") or ""),
            "name": str(row.get("name") or ""),
            "evidence": str(row.get("evidence") or ""),
            "source": str(row.get("source") or ""),
        }
        for row in rows[:160]
    ]


def _interesting_path_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "path": str(row.get("path") or ""),
            "url": str(row.get("url") or ""),
            "href": str(row.get("url") or ""),
            "status": str(row.get("status") or row.get("status_code") or ""),
            "content_type": str(row.get("content_type") or ""),
            "reason": str(row.get("reason") or row.get("notes") or ""),
            "source": str(row.get("source") or row.get("source_wordlist") or ""),
            "entry_count": row.get("entry_count") or 0,
        }
        for row in rows[:160]
    ]


def _raw_header_rows(headers: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"name": str(key), "value": str(value)}
        for key, value in sorted((headers or {}).items(), key=lambda item: str(item[0]).lower())
    ][:200]


def _http_cookie_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    domain = data.get("domain") or ""
    surface_cookies = (data.get("http_surface") or {}).get("cookies") or []
    if surface_cookies:
        return [
            {
                "name": str(cookie.get("name") or ""),
                "domain": str(cookie.get("domain") or domain),
                "flags": _cookie_flags(cookie),
            }
            for cookie in surface_cookies[:140]
            if cookie.get("name")
        ]
    names = set(data.get("cookie_names") or [])
    names.update((data.get("devtools") or {}).get("cookies_names") or [])
    return [
        {
            "name": name,
            "domain": domain,
            "flags": "name only",
        }
        for name in sorted(name for name in names if name)
    ][:140]


def _cookie_flags(cookie: dict[str, Any]) -> str:
    flags = []
    flags.append("Secure" if cookie.get("secure") else "missing Secure")
    flags.append("HttpOnly" if cookie.get("httponly") else "missing HttpOnly")
    same_site = str(cookie.get("samesite") or "")
    flags.append(f"SameSite={same_site}" if same_site else "missing SameSite")
    return ", ".join(flags)


def _group_trackers(trackers: list[Any]) -> list[dict[str, Any]]:
    grouped = {group: [] for group in TRACKER_GROUP_ORDER}
    for tracker in _unique_strings(trackers, limit=240):
        lowered = tracker.lower()
        group_name = "Other"
        for group, hints in TRACKER_GROUPS.items():
            if any(hint in lowered for hint in hints):
                group_name = group
                break
        grouped[group_name].append(tracker)
    return [{"name": group, "items": grouped[group]} for group in TRACKER_GROUP_ORDER if grouped[group]]


def _network_summary(requests: list[dict[str, Any]]) -> dict[str, Any]:
    groups = {name: {"name": name, "count": 0, "samples": []} for name in NETWORK_GROUP_ORDER}
    for request in requests:
        category = _network_category(request)
        group = groups[category]
        group["count"] += 1
        url = str(request.get("url") or "")
        if category not in {"images", "css", "fonts"} and url and len(group["samples"]) < 10:
            group["samples"].append(_link_item(url, url))
    return {
        "total": len(requests),
        "groups": [groups[name] for name in NETWORK_GROUP_ORDER if groups[name]["count"]],
    }


def _devtools_intelligence_report(data: dict[str, Any]) -> dict[str, Any]:
    devtools = data.get("devtools") or {}
    intelligence = devtools.get("devtools_intelligence") or {}
    network = devtools.get("network_intelligence") or intelligence.get("network") or {}
    api = devtools.get("api_intelligence") or intelligence.get("api") or {}
    javascript = devtools.get("javascript_intelligence") or intelligence.get("javascript") or {}
    storage = devtools.get("storage_intelligence") or intelligence.get("storage") or {}
    requests = network.get("requests") or devtools.get("network_requests") or []
    api_endpoints = api.get("endpoints") or []
    graphql = devtools.get("graphql_intelligence") or intelligence.get("graphql") or api.get("graphql") or []
    websockets = devtools.get("websocket_intelligence") or intelligence.get("websockets") or []
    cookies = devtools.get("cookie_intelligence") or intelligence.get("cookies") or []
    security_headers = devtools.get("security_headers_intelligence") or intelligence.get("security_headers") or []
    third_party = devtools.get("third_party_services") or intelligence.get("third_party_services") or []
    findings = devtools.get("interesting_findings") or intelligence.get("interesting_findings") or []
    storage_rows = _devtools_storage_rows(storage)
    js_files = javascript.get("files") or []
    js_findings = javascript.get("findings") or []
    stats = devtools.get("statistics") or intelligence.get("statistics") or network.get("statistics") or {}
    summary = intelligence.get("summary") or {
        "network_requests": len(requests),
        "api_endpoints": len(api_endpoints),
        "graphql": len(graphql),
        "websockets": len(websockets),
        "storage_objects": len(storage_rows),
        "cookies": len(cookies),
        "javascript_files": len(js_files),
        "third_party_services": len(third_party),
        "top_findings": len(findings),
    }
    return {
        "summary": summary,
        "network_requests": [_devtools_network_row(row) for row in requests[:320]],
        "api_endpoints": [_devtools_api_row(row) for row in api_endpoints[:220]],
        "graphql": [_devtools_graphql_row(row) for row in graphql[:80]],
        "websockets": [_devtools_websocket_row(row) for row in websockets[:100]],
        "storage": storage_rows[:180],
        "cookies": [_devtools_cookie_row(row) for row in cookies[:180]],
        "javascript_files": [_devtools_js_file_row(row) for row in js_files[:160]],
        "javascript_findings": [_devtools_js_finding_row(row) for row in js_findings[:180]],
        "security_headers": [_devtools_security_header_row(row) for row in security_headers[:80]],
        "third_party_services": [_devtools_service_row(row) for row in third_party[:120]],
        "interesting_findings": [_devtools_finding_row(row) for row in findings[:20]],
        "statistics": stats,
    }


def _traffic_chain_report(payload: dict[str, Any]) -> dict[str, Any]:
    requests = [_traffic_request_row(row) for row in (payload.get("requests") or [])[:500]]
    critical_source = payload.get("critical_requests") or payload.get("critical_path") or []
    critical = [_traffic_request_row(row) for row in critical_source[:80]]
    api = [_traffic_request_row(row) for row in (payload.get("api_requests") or [])[:160]]
    failed = [_traffic_request_row(row) for row in (payload.get("failed_requests") or [])[:120]]
    return {
        "summary": payload.get("summary") or {},
        "target": str(payload.get("target") or ""),
        "final_url": str(payload.get("final_url") or ""),
        "requests": requests,
        "critical_requests": critical,
        "api_requests": api,
        "failed_requests": failed,
        "lifecycle": payload.get("lifecycle") or {},
        "errors": _unique_strings(payload.get("errors") or [], limit=80),
    }


def _traffic_request_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or "")
    duration_ms = row.get("duration_ms") or 0
    size_bytes = row.get("size_bytes") or 0
    return {
        "sequence": row.get("sequence") or row.get("id") or 0,
        "display_type": str(row.get("display_type") or row.get("resource_type") or ""),
        "resource_type": str(row.get("resource_type") or ""),
        "method": str(row.get("method") or ""),
        "status": row.get("status") if row.get("status") is not None else "",
        "status_text": str(row.get("status_text") or ""),
        "duration_ms": duration_ms,
        "duration_label": f"{duration_ms} ms",
        "size_bytes": size_bytes,
        "size_label": f"{size_bytes} B",
        "start_time": str(row.get("start_time") or ""),
        "domain": str(row.get("domain") or ""),
        "path": str(row.get("path") or ""),
        "url": url,
        "href": url,
        "initiator": str(row.get("initiator") or ""),
        "importance": str(row.get("importance") or "normal"),
        "category": str(row.get("category") or "other"),
        "is_third_party": bool(row.get("is_third_party")),
        "notes": str(row.get("notes") or row.get("failure_text") or ""),
    }


def _header_rows(headers: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"name": str(key), "value": str(value)}
        for key, value in sorted((headers or {}).items(), key=lambda item: str(item[0]).lower())
    ][:120]


def _devtools_network_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or "")
    return {
        "url": url,
        "href": url,
        "host": str(row.get("host") or ""),
        "path": str(row.get("path") or ""),
        "method": str(row.get("method") or ""),
        "status": row.get("status") or "",
        "content_type": str(row.get("content_type") or ""),
        "resource_type": str(row.get("resource_type") or ""),
        "response_size": row.get("response_size") or 0,
        "initiator": str(row.get("initiator") or ""),
        "referer": str(row.get("referer") or ""),
        "timestamp": str(row.get("timestamp") or ""),
        "source_page": str(row.get("source_page") or ""),
        "duration": row.get("duration") or 0,
        "times_seen": row.get("times_seen") or 1,
    }


def _devtools_api_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or row.get("endpoint") or "")
    return {
        "url": url,
        "href": url,
        "method": str(row.get("method") or ""),
        "content_type": str(row.get("content_type") or ""),
        "response_type": str(row.get("response_type") or ""),
        "source": str(row.get("source") or ""),
        "page": str(row.get("page") or ""),
        "first_seen": str(row.get("first_seen") or ""),
        "times_seen": row.get("times_seen") or 1,
        "status": row.get("status") or "",
        "response_size": row.get("response_size") or 0,
        "classification": str(row.get("classification") or ""),
    }


def _devtools_graphql_row(row: dict[str, Any]) -> dict[str, Any]:
    endpoint = str(row.get("endpoint") or "")
    return {
        "endpoint": endpoint,
        "href": endpoint,
        "source_page": str(row.get("source_page") or ""),
        "source_request": str(row.get("source_request") or ""),
        "operation_names": ", ".join(row.get("operation_names") or []),
        "query_names": ", ".join(row.get("query_names") or []),
        "mutation_names": ", ".join(row.get("mutation_names") or []),
    }


def _devtools_websocket_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or "")
    return {
        "url": url,
        "href": url,
        "protocol": str(row.get("protocol") or ""),
        "source_page": str(row.get("source_page") or ""),
        "messages_count": row.get("messages_count") or 0,
        "status": str(row.get("status") or ""),
    }


def _devtools_storage_rows(storage: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for storage_type in ("localStorage", "sessionStorage", "indexedDB", "cacheStorage"):
        for row in storage.get(storage_type) or []:
            rows.append(
                {
                    "key": str(row.get("key") or ""),
                    "value_preview": str(row.get("value_preview") or ""),
                    "type": str(row.get("type") or storage_type),
                    "source": str(row.get("source") or ""),
                    "size": row.get("size") or 0,
                    "risk_score": row.get("risk_score") or 0,
                }
            )
    rows.sort(key=lambda item: (-int(item.get("risk_score") or 0), item.get("type") or "", item.get("key") or ""))
    return rows


def _devtools_cookie_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(row.get("name") or ""),
        "domain": str(row.get("domain") or ""),
        "path": str(row.get("path") or ""),
        "expires": str(row.get("expires") or ""),
        "secure": "yes" if row.get("secure") else "no",
        "httponly": "yes" if row.get("httponly") else "no",
        "samesite": str(row.get("samesite") or ""),
        "size": row.get("size") or 0,
        "value_preview": str(row.get("value_preview") or ""),
    }


def _devtools_js_file_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or "")
    return {
        "url": url,
        "href": url,
        "size": row.get("size") or 0,
        "type": str(row.get("type") or ""),
        "source": str(row.get("source") or ""),
        "page": str(row.get("page") or ""),
    }


def _devtools_js_finding_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_file": str(row.get("source_file") or ""),
        "source_type": str(row.get("source_type") or ""),
        "value": str(row.get("value") or ""),
        "confidence": row.get("confidence") or 0,
    }


def _devtools_security_header_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "header": str(row.get("header") or ""),
        "value": str(row.get("value") or ""),
        "status": str(row.get("status") or ""),
        "interpretation": str(row.get("interpretation") or ""),
    }


def _devtools_service_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(row.get("name") or ""),
        "type": str(row.get("type") or ""),
        "source": str(row.get("source") or ""),
        "where_found": str(row.get("where_found") or ""),
    }


def _devtools_finding_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "score": row.get("score") or 0,
        "type": str(row.get("type") or ""),
        "value": str(row.get("value") or ""),
        "detail": str(row.get("detail") or ""),
        "source": str(row.get("source") or ""),
    }


def _network_category(request: dict[str, Any]) -> str:
    resource_type = str(request.get("resource_type") or "").lower()
    url = str(request.get("url") or "")
    path = urlparse(url).path.lower()
    if resource_type == "document":
        return "main document"
    if resource_type == "script":
        return "scripts"
    if resource_type in {"fetch", "xhr", "websocket"} or _is_interesting_endpoint(url):
        return "api"
    if resource_type == "image" or path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
        return "images"
    if resource_type == "stylesheet" or path.endswith(".css"):
        return "css"
    if resource_type == "font" or path.endswith((".woff", ".woff2", ".ttf", ".otf")):
        return "fonts"
    return "other"


def _filter_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, str]]:
    output = []
    seen = set()
    for item in endpoints:
        endpoint = str(item.get("endpoint") or "")
        if not _is_interesting_endpoint(endpoint):
            continue
        method = str(item.get("method") or "")
        key = f"{method}|{endpoint}"
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "endpoint": endpoint,
                "href": endpoint,
                "source_file": str(item.get("source_file") or item.get("source") or ""),
                "method": method,
                "risk": str(item.get("risk") or ""),
                "notes": str(item.get("notes") or ""),
            }
        )
        if len(output) >= 120:
            break
    return output


def _is_interesting_endpoint(value: str) -> bool:
    return is_probable_endpoint(str(value or ""))


def _looks_static_asset(value: str) -> bool:
    return bool(STATIC_ASSET_PATTERN.search(str(value or "")))


def _endpoint_segment_match(segment: str) -> bool:
    if segment == "api" or re.fullmatch(r"api\d*", segment):
        return True
    return segment in {keyword for keyword in ENDPOINT_KEYWORDS if keyword != "api"}


def _security_audit_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    headers = data.get("security_headers") or {}
    for header, value in headers.items():
        value_text = str(value or "")
        missing = not value_text or value_text.lower() == "missing"
        if missing:
            present = "No"
            risk = "Medium" if header.lower() not in {"server", "x-powered-by"} else "Low"
        elif header.lower() in {"server", "x-powered-by"} and value_text:
            present = "Yes"
            risk = "Low"
        else:
            present = "Yes"
            risk = "Low"
        description = _security_header_description(header, not missing)
        rows.append(
            {
                "name": header,
                "header": header,
                "present": present,
                "status": "present" if not missing else "missing",
                "value": value_text if not missing else "missing",
                "risk": risk,
                "description": description,
            }
        )
    return rows


def _security_header_description(header: str, present: bool) -> str:
    descriptions = {
        "content-security-policy": (
            "Content Security Policy is configured.",
            "Content Security Policy is not configured.",
        ),
        "strict-transport-security": (
            "HSTS is enabled.",
            "HSTS is not configured.",
        ),
        "x-frame-options": (
            "Clickjacking protection is enabled.",
            "Clickjacking protection is not configured.",
        ),
        "x-content-type-options": (
            "MIME sniffing protection is enabled.",
            "MIME sniffing protection is not configured.",
        ),
        "referrer-policy": (
            "Referrer leakage policy is configured.",
            "Referrer leakage policy is not configured.",
        ),
        "permissions-policy": (
            "Browser feature policy is configured.",
            "Browser feature policy is not configured.",
        ),
        "cross-origin-opener-policy": (
            "Cross-origin opener isolation is configured.",
            "Cross-origin opener isolation is not configured.",
        ),
        "cross-origin-embedder-policy": (
            "Cross-origin embedder isolation is configured.",
            "Cross-origin embedder isolation is not configured.",
        ),
        "cross-origin-resource-policy": (
            "Cross-origin resource policy is configured.",
            "Cross-origin resource policy is not configured.",
        ),
        "server": (
            "Server product information is exposed.",
            "Server product information is not exposed.",
        ),
        "x-powered-by": (
            "Backend technology information is exposed.",
            "Backend technology information is not exposed.",
        ),
    }
    yes, no = descriptions.get(
        header.lower(),
        ("Header is present.", "Header is not present."),
    )
    return yes if present else no


def _security_score(
    data: dict[str, Any],
    endpoints: list[dict[str, str]],
    admin_panels: list[dict[str, str]],
    public_resources: list[dict[str, str]],
    technologies: list[dict[str, str]],
) -> dict[str, Any]:
    headers = data.get("security_headers") or {}
    missing_headers = [key for key, value in headers.items() if value == "missing" and key not in {"Server", "X-Powered-By"}]
    exposed_headers = [key for key in ("Server", "X-Powered-By") if headers.get(key) not in {"", "missing", None}]
    surface = data.get("http_surface") or {}
    probes = surface.get("probes") or []
    https_live = any(row.get("live") and row.get("scheme") == "https" for row in probes)
    http_live = any(row.get("live") and row.get("scheme") == "http" for row in probes)
    redirects_to_https = any(
        str(item.get("from") or "").startswith("http://") and str(item.get("to") or "").startswith("https://")
        for probe in probes
        for item in (probe.get("redirect_chain") or [])
    )
    http_score = 35
    if surface.get("status_code") is not None:
        http_score += 25
    if https_live:
        http_score += 25
    if not http_live or redirects_to_https:
        http_score += 15
    http_score = _clamp(http_score)

    header_score = _clamp(100 - len(missing_headers) * 12 - len(exposed_headers) * 3)

    tls = data.get("tls_certificate") or {}
    tls_score = 90 if tls else 25
    if tls.get("verification_error"):
        tls_score -= 18
    if not tls.get("tls_version"):
        tls_score -= 10
    if tls.get("weak_cipher"):
        tls_score -= 35
    if tls.get("days_remaining") is not None and int(tls.get("days_remaining") or 0) < 30:
        tls_score -= 15
    tls_score = _clamp(tls_score)

    dns = data.get("dns") or {}
    dns_score = _clamp(
        45
        + (20 if dns.get("NS") else 0)
        + (15 if dns.get("CAA") else 0)
        + (10 if dns.get("A") or dns.get("AAAA") else 0)
        + (10 if dns.get("MX") else 0)
    )
    email_auth = data.get("email_auth") or {}
    email_score = _clamp(40 + (20 if email_auth.get("spf") else 0) + (25 if email_auth.get("dmarc") else 0) + (15 if email_auth.get("dkim_hints") else 0))

    high_signals = sum(1 for row in data.get("security_signals") or [] if row.get("level") == "high")
    warn_signals = sum(1 for row in data.get("security_signals") or [] if row.get("level") == "warn")
    exposure_score = _clamp(
        100
        - len(public_resources) * 9
        - min(len(endpoints), 15) * 2
        - len(admin_panels) * 6
        - high_signals * 16
        - warn_signals * 4
    )
    outdated = sum(1 for item in technologies if item.get("status") == "Outdated")
    possible = sum(1 for item in technologies if item.get("status") == "Possibly Outdated")
    tech_score = _clamp(100 - outdated * 22 - possible * 10)
    components = [
        {"name": "DNS Security", "score": dns_score, "weight": 10, "reason": f"{sum(len(values) for values in dns.values())} DNS record(s); CAA {'present' if dns.get('CAA') else 'missing'}"},
        {"name": "TLS Security", "score": tls_score, "weight": 20, "reason": f"{tls.get('tls_version') or 'TLS unavailable'}; cipher {tls.get('cipher_suite') or 'unknown'}"},
        {"name": "HTTP Security", "score": http_score, "weight": 15, "reason": f"HTTPS {'live' if https_live else 'unavailable'}; HTTP redirect {'present' if redirects_to_https else 'not observed'}"},
        {"name": "Security Headers", "score": header_score, "weight": 20, "reason": f"{len(missing_headers)} security header(s) missing"},
        {"name": "Technology Risk", "score": tech_score, "weight": 10, "reason": f"{outdated} outdated and {possible} possibly outdated technology version(s)"},
        {"name": "Exposure Level", "score": exposure_score, "weight": 15, "reason": f"{len(public_resources)} public resource(s), {high_signals} high signal(s), {len(admin_panels)} admin/login path(s)"},
        {"name": "Email Security", "score": email_score, "weight": 10, "reason": f"SPF {'present' if email_auth.get('spf') else 'missing'}, DMARC {'present' if email_auth.get('dmarc') else 'missing'}, DKIM {'hinted' if email_auth.get('dkim_hints') else 'not observed'}"},
    ]
    for component in components:
        component["contribution"] = round(component["score"] * component["weight"] / 100, 1)
    total = round(sum(component["contribution"] for component in components))
    return {
        "total": total,
        "category": _score_category(total),
        "components": components,
        "formula": "Sum(component score x component weight / 100)",
        "explanation": "Overall score calculated from seven independent modules.",
    }


def _score_category(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 55:
        return "Medium"
    if score >= 35:
        return "Poor"
    return "Critical"


def _clamp(value: int | float) -> int:
    return max(0, min(100, int(round(value))))


def _attack_surface(
    data: dict[str, Any],
    endpoints: list[dict[str, str]],
    admin_panels: list[dict[str, str]],
    public_resources: list[dict[str, str]],
    source_maps: list[dict[str, str]],
) -> list[dict[str, Any]]:
    return [
        {"name": "DNS", "count": sum(len(values) for values in (data.get("dns") or {}).values())},
        {"name": "ASN / BGP", "count": len(data.get("asn_bgp") or [])},
        {"name": "TLS", "count": 1 if data.get("tls_certificate") else 0},
        {"name": "Certificate Transparency", "count": len(data.get("certificate_transparency") or [])},
        {"name": "Subdomains", "count": len(data.get("subdomains") or [])},
        {"name": "Headers", "count": len(data.get("security_headers") or {})},
        {"name": "Cookies", "count": len(data.get("cookie_names") or [])},
        {"name": "Trackers", "count": len(data.get("analytics_tracker_hints") or [])},
        {"name": "Technologies", "count": len(data.get("detected_technologies") or [])},
        {"name": "HTTP Probes", "count": len((data.get("http_surface") or {}).get("probes") or [])},
        {"name": "Security Signals", "count": len(data.get("security_signals") or [])},
        {"name": "Interesting Paths", "count": len(data.get("interesting_paths") or [])},
        {"name": "Open TCP Ports", "count": len((data.get("port_surface") or {}).get("open_ports") or [])},
        {"name": "API Endpoints", "count": len(endpoints)},
        {"name": "Admin Panels", "count": len(admin_panels)},
        {"name": "Public Resources", "count": len(public_resources)},
        {"name": "Source Maps", "count": len(source_maps)},
        {
            "name": "Historical URLs",
            "count": len(((data.get("historical_intelligence") or {}).get("wayback") or {}).get("historical_urls") or []),
        },
        {
            "name": "Historical Subdomains",
            "count": len((data.get("historical_intelligence") or {}).get("historical_subdomains") or []),
        },
        {
            "name": "Reputation Hits",
            "count": len((data.get("reputation_intelligence") or {}).get("matched_indicators") or []),
        },
        {
            "name": "Discovery Findings",
            "count": len((data.get("discovery") or {}).get("findings") or []),
        },
        {
            "name": "SQLi Findings",
            "count": len((data.get("sqli_analysis") or {}).get("findings") or []),
        },
        {"name": "Social Links", "count": len(data.get("social_links") or [])},
        {"name": "Emails", "count": len(data.get("emails") or [])},
        {"name": "Phones", "count": len(data.get("phones") or [])},
    ]


def _risk_distribution(data: dict[str, Any]) -> list[dict[str, Any]]:
    counts = Counter({"High": 0, "Medium": 0, "Low / Info": 0})
    for row in data.get("security_signals") or []:
        level = str(row.get("level") or "").lower()
        if level == "high":
            counts["High"] += 1
        elif level in {"warn", "medium", "warning"}:
            counts["Medium"] += 1
        else:
            counts["Low / Info"] += 1
    for row in data.get("security_findings") or []:
        risk = str(row.get("risk") or "").lower()
        if risk == "high":
            counts["High"] += 1
        elif risk in {"medium", "warn", "warning"}:
            counts["Medium"] += 1
        else:
            counts["Low / Info"] += 1
    return [{"label": label, "value": value} for label, value in counts.items() if value]


def _technology_distribution(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(row.get("category") or "Other") for row in rows if row.get("name"))
    return [{"label": label, "value": value} for label, value in counts.most_common()]


def _technology_fingerprint_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    seen = set()
    for item in (data.get("technologies") or data.get("detected_technology_details") or [])[:180]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        rows.append(
            {
                "name": name,
                "category": str(item.get("category") or ""),
                "confidence": str(item.get("confidence") or ""),
                "evidence": str(item.get("evidence") or ""),
                "version": str(item.get("version") or "Unknown Version"),
                "source": str(item.get("source") or ""),
            }
        )
    return rows


def _technology_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    fingerprint_rows = _technology_fingerprint_rows(data)
    if fingerprint_rows:
        evidence_text = _technology_evidence_text(data)
        output = []
        for row in fingerprint_rows:
            technology = row["name"]
            version = row.get("version") or "Unknown Version"
            status = "Current"
            evidence = row.get("evidence") or "fingerprint"
            pattern = VERSION_PATTERNS.get(technology) or VERSION_PATTERNS.get(technology.title())
            if pattern and version == "Unknown Version":
                match = pattern.search(evidence_text)
                if match:
                    version = match.group(1)
                    status = _version_status(technology.title(), version)
                    evidence = match.group(0)
            elif version != "Unknown Version":
                status = _version_status(technology.title(), version)
            output.append({**row, "version": version, "status": status, "evidence": evidence})
        return output
    technologies = _unique_strings(data.get("detected_technologies") or [], limit=160)
    evidence_text = _technology_evidence_text(data)
    rows = []
    for technology in technologies:
        version = "Unknown Version"
        status = "Current"
        evidence = "fingerprint"
        pattern = VERSION_PATTERNS.get(technology)
        if pattern:
            match = pattern.search(evidence_text)
            if match:
                version = match.group(1)
                status = _version_status(technology, version)
                evidence = match.group(0)
        rows.append({"name": technology, "version": version, "status": status, "evidence": evidence, "source": "Fingerprint"})
    return rows


def _technology_evidence_text(data: dict[str, Any]) -> str:
    http = data.get("http") or {}
    html = data.get("html") or {}
    devtools = data.get("devtools") or {}
    parts = [
        " ".join(f"{key}: {value}" for key, value in (http.get("headers") or {}).items()),
        str(http.get("server") or ""),
        str(http.get("x_powered_by") or ""),
        " ".join(html.get("script_links") or []),
        " ".join(devtools.get("loaded_js") or []),
        " ".join(devtools.get("loaded_css") or []),
    ]
    return "\n".join(parts)


def _version_status(technology: str, version: str) -> str:
    parts = [int(part) for part in re.findall(r"\d+", version)[:3]]
    major = parts[0] if parts else 0
    minor = parts[1] if len(parts) > 1 else 0
    if technology == "PHP":
        if major < 7:
            return "Outdated"
        if major == 7:
            return "Possibly Outdated"
    if technology == "jQuery":
        if major < 3:
            return "Outdated"
        if major == 3 and minor < 5:
            return "Possibly Outdated"
    if technology == "Bootstrap":
        if major < 4:
            return "Outdated"
        if major == 4:
            return "Possibly Outdated"
    if technology == "Apache":
        if major < 2 or (major == 2 and minor < 4):
            return "Outdated"
    if technology == "Nginx":
        if major == 1 and minor < 20:
            return "Possibly Outdated"
    return "Current"


def _admin_panels(html: dict[str, Any], endpoints: list[dict[str, str]]) -> list[dict[str, str]]:
    rows = []
    seen = set()
    for value in html.get("login_admin_paths") or []:
        if value and value not in seen:
            seen.add(value)
            rows.append({"label": value, "href": value, "source": "HTML"})
    for endpoint in endpoints:
        value = endpoint.get("endpoint") or ""
        lowered = value.lower()
        if any(key in lowered for key in ("/admin", "/login", "/auth", "/oauth")) and value not in seen:
            seen.add(value)
            rows.append({"label": value, "href": value, "source": "endpoint"})
    return rows[:120]


def _sensitive_file_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    output = []
    for item in rows[:120]:
        url = str(item.get("url") or "")
        output.append(
            {
                "path": str(item.get("path") or ""),
                "url": url,
                "href": url,
                "status": str(item.get("status") or ""),
                "size": str(item.get("size") or ""),
                "content_type": str(item.get("content_type") or ""),
            }
        )
    return output


def _source_map_rows(html: dict[str, Any], data: dict[str, Any]) -> list[dict[str, str]]:
    found = []
    for value in html.get("source_map_links") or []:
        found.append(str(value))
    sensitive = data.get("sensitive_public_files") or {}
    for item in sensitive.get("findings") or []:
        url = str(item.get("url") or "")
        if url.endswith(".map"):
            found.append(url)
    return [_link_item(item, item) for item in _unique_strings(found, limit=100)]


def _resource_links(data: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    html = data.get("html") or {}
    devtools = data.get("devtools") or {}
    js = _unique_strings((html.get("external_js") or []) + (devtools.get("loaded_js") or []), limit=120)
    css = _unique_strings((html.get("external_css") or []) + (devtools.get("loaded_css") or []), limit=120)
    favicon = html.get("favicon_url") or ""
    return {
        "js": [_link_item(item, item) for item in js],
        "css": [_link_item(item, item) for item in css],
        "favicon": [_link_item(favicon, favicon)] if favicon else [],
    }


def _ct_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "name": str(row.get("name") or ""),
            "href": _domain_href(str(row.get("name") or "")),
            "issuer": str(row.get("issuer") or ""),
            "not_before": str(row.get("not_before") or ""),
            "not_after": str(row.get("not_after") or ""),
        }
        for row in rows[:160]
    ]


def _historical_report(payload: dict[str, Any]) -> dict[str, Any]:
    wayback = payload.get("wayback") or {}
    certs = payload.get("certificate_history") or []
    historical_urls = [_url_row(row) for row in wayback.get("historical_urls") or []]
    interesting_urls = [_url_row(row) for row in wayback.get("interesting_urls") or []]
    top_urls = [
        {"url": str(row.get("url") or ""), "href": str(row.get("href") or row.get("url") or ""), "count": row.get("count") or 0}
        for row in (wayback.get("top_urls") or [])[:50]
    ]
    return {
        "status": payload.get("status") or "partial",
        "sources": payload.get("sources") or [],
        "historical_ips": [_link_item(item, f"http://ip-api.com/#/{quote(str(item))}") for item in _unique_strings(payload.get("historical_ips") or [], 80)],
        "historical_nameservers": [_domain_link(item) for item in _unique_strings(payload.get("historical_nameservers") or [], 80)],
        "historical_mx": [_domain_link(item) for item in _unique_strings(payload.get("historical_mx") or [], 80)],
        "historical_technologies": _unique_strings(payload.get("historical_technologies") or [], 80),
        "historical_subdomains": [_domain_link(item) for item in _unique_strings(payload.get("historical_subdomains") or [], 220)],
        "wayback": {
            "sampled_snapshot_count": wayback.get("sampled_snapshot_count") or 0,
            "limit": wayback.get("limit") or 0,
            "first_snapshot": _url_row(wayback.get("first_snapshot") or {}),
            "last_snapshot": _url_row(wayback.get("last_snapshot") or {}),
            "top_urls": top_urls,
        },
        "historical_urls": historical_urls[:120],
        "interesting_urls": interesting_urls[:80],
        "certificate_history": [_cert_history_row(row) for row in certs[:140]],
        "artifact_timeline": [_timeline_row(row) for row in (payload.get("artifact_timeline") or [])[:140]],
        "unavailable_sources": payload.get("unavailable_sources") or [],
        "errors": _unique_strings(payload.get("errors") or [], 120),
    }


def _reputation_report(payload: dict[str, Any]) -> dict[str, Any]:
    matched = [_reputation_hit(row) for row in (payload.get("matched_indicators") or [])[:140]]
    suspicious = [_reputation_hit(row) for row in (payload.get("suspicious_urls") or [])[:80]]
    groups = []
    for group in payload.get("threat_feed_hits") or []:
        groups.append(
            {
                "source": str(group.get("source") or ""),
                "count": group.get("count") or 0,
                "items": [_reputation_hit(row) for row in (group.get("items") or [])[:40]],
            }
        )
    return {
        "status": payload.get("status") or "partial",
        "summary": payload.get("summary") or {"hits": 0, "message": "No public reputation hits found"},
        "matched_indicators": matched,
        "suspicious_urls": suspicious,
        "threat_feed_hits": groups,
        "clean_sources": _unique_strings(payload.get("clean_sources") or [], 80),
        "unavailable_sources": payload.get("unavailable_sources") or [],
        "errors": _unique_strings(payload.get("errors") or [], 120),
    }


def _url_row(row: dict[str, Any]) -> dict[str, Any]:
    url = str(row.get("url") or row.get("href") or "")
    return {
        "url": url,
        "href": str(row.get("href") or url),
        "date": str(row.get("date") or ""),
        "timestamp": str(row.get("timestamp") or ""),
        "status": str(row.get("status") or ""),
        "mimetype": str(row.get("mimetype") or ""),
        "digest": str(row.get("digest") or ""),
        "tags": row.get("tags") or [],
    }


def _cert_history_row(row: dict[str, Any]) -> dict[str, Any]:
    names = _unique_strings(row.get("names") or [], 30)
    return {
        "cert_id": str(row.get("cert_id") or ""),
        "names": [_domain_link(item) for item in names],
        "issuer": str(row.get("issuer") or ""),
        "not_before": str(row.get("not_before") or ""),
        "not_after": str(row.get("not_after") or ""),
        "entry_timestamp": str(row.get("entry_timestamp") or ""),
        "reference_url": str(row.get("reference_url") or ""),
    }


def _timeline_row(row: dict[str, Any]) -> dict[str, Any]:
    value = str(row.get("value") or "")
    return {
        "type": str(row.get("type") or ""),
        "value": value,
        "href": _value_href(value),
        "first_seen": str(row.get("first_seen") or ""),
        "last_seen": str(row.get("last_seen") or ""),
        "source": str(row.get("source") or ""),
    }


def _reputation_hit(row: dict[str, Any]) -> dict[str, Any]:
    indicator = str(row.get("indicator") or "")
    reference_url = str(row.get("reference_url") or "")
    return {
        "source": str(row.get("source") or ""),
        "indicator": indicator,
        "href": reference_url or _value_href(indicator),
        "indicator_type": str(row.get("indicator_type") or ""),
        "status": str(row.get("status") or ""),
        "risk": str(row.get("risk") or "Medium"),
        "first_seen": str(row.get("first_seen") or ""),
        "last_seen": str(row.get("last_seen") or ""),
        "tags": _unique_strings(row.get("tags") or [], 16),
        "reference_url": reference_url,
    }


def _value_href(value: str) -> str:
    raw = str(value or "").strip()
    if raw.startswith(("http://", "https://")):
        return raw
    if "@" in raw and "." in raw:
        return f"mailto:{raw}"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
        return f"http://ip-api.com/#/{quote(raw)}"
    if "." in raw and " " not in raw:
        return _domain_href(raw)
    return ""


def _decoded_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    useful = []
    for item in rows:
        item_type = str(item.get("type") or "")
        notes = str(item.get("notes") or "")
        if item_type == "Endpoint":
            continue
        if item_type in {"Base64", "Base64URL"} and "binary payload" in notes:
            continue
        useful.append(item)
    return _dedupe_dict_rows(useful, ("type", "value_masked", "source"), limit=140)


def _raw_artifact_for_html(artifact: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(artifact)
    data = payload.get("data") or {}
    data.pop("cor" + "relation", None)
    if artifact.get("type") in {"mentions", "mention_hunter", "mention_search"}:
        if "matches" in data:
            data["matches"] = f"rendered in mention search section ({len(data.get('matches') or [])} matches)"
        if "top_matches" in data:
            data["top_matches"] = f"rendered in mention search section ({len(data.get('top_matches') or [])} matches)"
    if "api_endpoint_candidates" in data:
        data["api_endpoint_candidates"] = f"moved to output/debug.log ({len(data.get('api_endpoint_candidates') or [])} candidates)"
    if "decoded_classified_artifacts" in data:
        data["decoded_classified_artifacts"] = f"moved to output/debug.log ({len(data.get('decoded_classified_artifacts') or [])} items)"
    devtools = data.get("devtools")
    if isinstance(devtools, dict):
        request_count = len(devtools.get("network_requests") or [])
        devtools["network_requests"] = f"moved to output/debug.log ({request_count} captured requests)"
        if "traffic_requests" in devtools:
            devtools["traffic_requests"] = f"rendered in Traffic Chain ({len(devtools.get('traffic_requests') or [])} captured requests)"
        for key in (
            "api_endpoint_candidates",
            "dom_links",
            "loaded_css",
            "loaded_js",
            "devtools_intelligence",
            "network_intelligence",
            "api_intelligence",
            "graphql_intelligence",
            "websocket_intelligence",
            "storage_intelligence",
            "cookie_intelligence",
            "javascript_intelligence",
            "security_headers_intelligence",
            "third_party_services",
            "interesting_findings",
            "discovery_seeds",
        ):
            if key in devtools:
                devtools[key] = f"moved to output/debug.log ({len(devtools.get(key) or [])} items)"
    html = data.get("html")
    if isinstance(html, dict):
        for key in ("api_endpoint_candidates", "external_links", "script_links", "external_js", "external_css"):
            if key in html:
                html[key] = f"moved to output/debug.log ({len(html.get(key) or [])} items)"
    sensitive = data.get("sensitive_public_files")
    if isinstance(sensitive, dict):
        for item in sensitive.get("findings") or []:
            item.pop("preview", None)
    discovery = data.get("discovery")
    if isinstance(discovery, dict):
        debug = discovery.get("debug")
        if isinstance(debug, dict):
            for key in ("checked_paths", "all_statuses", "soft_404", "duplicates"):
                if key in debug:
                    debug[key] = f"moved to output/debug.log ({len(debug.get(key) or [])} items)"
    sqli = data.get("sqli_analysis")
    if isinstance(sqli, dict):
        debug = sqli.get("debug")
        if isinstance(debug, dict):
            for key in ("responses", "low_confidence_signals"):
                if key in debug:
                    debug[key] = f"moved to output/debug.log ({len(debug.get(key) or [])} items)"
    traffic = data.get("traffic_chain")
    if isinstance(traffic, dict):
        if "critical_path" in traffic and "critical_requests" not in traffic:
            traffic["critical_requests"] = traffic.get("critical_path")
        traffic.pop("critical_path", None)
        allowed_traffic_keys = {
            "type",
            "target",
            "final_url",
            "summary",
            "requests",
            "critical_requests",
            "api_requests",
            "failed_requests",
            "lifecycle",
            "errors",
            "timestamp",
        }
        for key in list(traffic):
            if key not in allowed_traffic_keys:
                traffic.pop(key, None)
        for key in ("requests", "critical_requests", "api_requests", "failed_requests"):
            if key in traffic:
                traffic[key] = f"rendered in Traffic Chain ({len(traffic.get(key) or [])} item(s))"
    return payload


def _link_item(label: str, href: str) -> dict[str, str]:
    return {"label": str(label), "href": str(href)}


def _domain_link(domain: str) -> dict[str, str]:
    return _link_item(domain, _domain_href(domain))


def _domain_href(domain: str) -> str:
    raw = str(domain or "").strip().strip(".")
    if not raw:
        return ""
    return raw if raw.startswith(("http://", "https://")) else f"https://{raw}"


def _email_link(email: str) -> dict[str, str]:
    return _link_item(email, f"mailto:{email}")


def _phone_link(phone: str) -> dict[str, str]:
    digits = re.sub(r"[^\d+]", "", str(phone))
    return _link_item(phone, f"tel:{digits}")


def _social_intelligence_report(data: dict[str, Any]) -> dict[str, Any]:
    payload = data.get("social_intelligence") or {}
    profiles = _social_profile_rows(data)
    summary = dict(payload.get("summary") or {})
    external_links = {
        str(link)
        for row in profiles
        for link in (row.get("external_links") or [])
        if str(link).strip()
    }
    summary.setdefault("platforms_found", len({row.get("platform") for row in profiles if row.get("platform")}))
    summary.setdefault("profiles_analyzed", len(profiles))
    summary.setdefault("verified_profiles", sum(1 for row in profiles if row.get("verified") is True))
    summary.setdefault("recent_posts_found", sum(len(row.get("recent_posts") or []) for row in profiles))
    summary.setdefault("external_links_found", len(external_links))
    summary.setdefault("reused_handles", len((payload.get("identity_map") or {}).get("reused_handles") or []))
    summary.setdefault(
        "fetch_warnings",
        sum(
            1
            for row in profiles
            if row.get("fetch_status") in {"blocked", "login_required", "unavailable", "rate_limited", "fetch_failed"}
        ),
    )
    identity_map = payload.get("identity_map") or {
        "name": data.get("domain") or "",
        "profiles": [
            {
                "platform": row.get("platform"),
                "handle": row.get("handle") or row.get("display_name"),
                "url": row.get("url"),
                "verified": row.get("verified"),
                "confidence": row.get("confidence"),
            }
            for row in profiles
        ],
        "reused_handles": [],
        "shared_external_domains": [],
    }
    return {
        "summary": summary,
        "profiles": profiles,
        "identity_map": identity_map,
        "signals": [row for row in (payload.get("signals") or []) if isinstance(row, dict)][:80],
        "errors": _unique_strings(payload.get("errors") or [], limit=80),
    }


def _social_profile_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    seen = set()
    seen_identities = set()
    profile_rows = (data.get("social_intelligence") or {}).get("profiles") or data.get("social_profiles") or []
    link_rows = [_link_item(item, item) for item in _unique_strings(data.get("social_links") or [], limit=160)]
    for profile in profile_rows:
        if not isinstance(profile, dict):
            continue
        url = str(profile.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        platform = str(profile.get("platform") or _social_platform(url))
        handle = str(profile.get("handle") or profile.get("username") or _social_handle(url, platform))
        original_url = str(profile.get("href") or "").strip()
        if original_url:
            seen.add(original_url)
        if handle:
            seen_identities.add((platform.lower(), handle.lower().lstrip("@")))
        rows.append(
            {
                "platform": platform,
                "url": url,
                "normalized_url": str(profile.get("normalized_url") or url),
                "href": url,
                "handle": handle,
                "username": str(profile.get("username") or handle),
                "display_name": str(profile.get("display_name") or handle or platform),
                "title": profile.get("title"),
                "description": profile.get("description") or profile.get("bio"),
                "avatar": profile.get("avatar") or profile.get("avatar_url"),
                "avatar_url": profile.get("avatar_url") or profile.get("avatar"),
                "banner": profile.get("banner") or profile.get("banner_url"),
                "banner_url": profile.get("banner_url") or profile.get("banner"),
                "bio": profile.get("bio"),
                "followers": profile.get("followers") if profile.get("followers") is not None else profile.get("subscribers"),
                "followers_count": profile.get("followers_count") if profile.get("followers_count") is not None else profile.get("followers"),
                "following": profile.get("following"),
                "following_count": profile.get("following_count") if profile.get("following_count") is not None else profile.get("following"),
                "posts": profile.get("posts") if profile.get("posts") is not None else profile.get("public_repos"),
                "posts_count": profile.get("posts_count") if profile.get("posts_count") is not None else profile.get("posts"),
                "verified": profile.get("verified"),
                "profile_type": str(profile.get("profile_type") or "public profile"),
                "profile_category": profile.get("profile_category"),
                "external_links": profile.get("external_links") or [],
                "website_links": profile.get("website_links") or profile.get("external_links") or [],
                "location": profile.get("location"),
                "joined_date": profile.get("joined_date"),
                "account_created_at": profile.get("account_created_at") or profile.get("joined_date"),
                "last_public_activity": profile.get("last_public_activity"),
                "language": profile.get("language"),
                "public_email": profile.get("public_email"),
                "public_phone": profile.get("public_phone"),
                "recent_posts": profile.get("recent_posts") or [],
                "redirect_chain": profile.get("redirect_chain") or [],
                "evidence": profile.get("evidence") or [],
                "sources": profile.get("sources") or [profile.get("source") or "public metadata"],
                "raw_metadata": profile.get("raw_metadata") or {},
                "official_likelihood": profile.get("official_likelihood"),
                "links_back_to_target": bool(profile.get("links_back_to_target")),
                "confidence": str(profile.get("confidence") or "medium"),
                "source": str(profile.get("source") or "public metadata"),
                "fetch_status": profile.get("fetch_status") or "ok",
                "error": profile.get("error"),
            }
        )
    for link in link_rows:
        url = str(link.get("href") or link.get("label") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        platform = _social_platform(url)
        handle = _social_handle(url, platform)
        if handle.lower().lstrip("@") in {"login", "signin", "share", "sharer", "intent", "search", "home"}:
            continue
        identity = (platform.lower(), handle.lower().lstrip("@"))
        if handle and identity in seen_identities:
            continue
        if handle:
            seen_identities.add(identity)
        rows.append(
            {
                "platform": platform,
                "url": url,
                "normalized_url": url,
                "href": url,
                "handle": handle,
                "username": handle,
                "display_name": handle or platform,
                "title": None,
                "description": None,
                "avatar": None,
                "avatar_url": None,
                "banner": None,
                "banner_url": None,
                "bio": None,
                "followers": None,
                "followers_count": None,
                "following": None,
                "following_count": None,
                "posts": None,
                "posts_count": None,
                "verified": None,
                "profile_type": "public link",
                "profile_category": None,
                "external_links": [],
                "website_links": [],
                "location": None,
                "joined_date": None,
                "account_created_at": None,
                "last_public_activity": None,
                "language": None,
                "public_email": None,
                "public_phone": None,
                "recent_posts": [],
                "redirect_chain": [],
                "evidence": ["Profile URL was linked from the analyzed website."],
                "sources": ["HTML social_links"],
                "raw_metadata": {},
                "official_likelihood": "medium",
                "links_back_to_target": False,
                "confidence": "medium" if platform != "Other social" else "low",
                "source": "html social_links",
                "fetch_status": "link_only",
                "error": None,
            }
        )
    return rows[:160]


def _social_platform(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    platform_hosts = {
        "Telegram": ("t.me", "telegram.me"),
        "VK": ("vk.com",),
        "Instagram": ("instagram.com",),
        "GitHub": ("github.com",),
        "YouTube": ("youtube.com", "youtu.be"),
        "LinkedIn": ("linkedin.com",),
        "X": ("twitter.com", "x.com"),
        "Facebook": ("facebook.com",),
        "TikTok": ("tiktok.com",),
        "Discord": ("discord.gg", "discord.com"),
        "Reddit": ("reddit.com",),
        "Pinterest": ("pinterest.com", "pin.it"),
        "Medium": ("medium.com",),
        "Spotify": ("spotify.com", "open.spotify.com"),
        "Steam": ("steamcommunity.com", "store.steampowered.com"),
        "Twitch": ("twitch.tv",),
        "OK": ("ok.ru",),
        "WhatsApp": ("wa.me",),
    }
    for platform, hosts in platform_hosts.items():
        if any(host == item or host.endswith(f".{item}") for item in hosts):
            return platform
    return "Other social"


def _social_handle(url: str, platform: str) -> str:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    query = dict(parse_qsl(parsed.query))
    if platform == "Facebook" and query.get("id"):
        return query["id"]
    if not parts:
        return parsed.hostname or ""
    if platform in {"Telegram", "Instagram", "X", "TikTok", "Twitch", "Medium"}:
        return f"@{parts[0].lstrip('@')}"
    if platform == "LinkedIn" and parts[0] in {"in", "company", "school"}:
        return "/".join(parts[:2])
    if platform == "YouTube":
        return parts[0] if parts[0].startswith("@") else "/".join(parts[:2])
    if platform in {"Spotify", "Steam"} and len(parts) > 1:
        return "/".join(parts[:2])
    if platform == "Discord":
        return parts[-1]
    return parts[0]


def _unique_strings(values: list[Any], limit: int) -> list[str]:
    output = []
    seen = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
        if len(output) >= limit:
            break
    return output


def _dedupe_dict_rows(rows: list[dict[str, Any]], keys: tuple[str, ...], limit: int) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = tuple(str(row.get(item) or "") for item in keys)
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
        if len(output) >= limit:
            break
    return output


def _module_status_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    by_stage: dict[str, dict[str, str]] = {}
    severity = {"Completed": 0, "Skipped": 1, "Partial": 2, "Failed": 3}
    for source in rows:
        if not isinstance(source, dict):
            continue
        stage = str(source.get("stage") or "module").strip() or "module"
        detail = str(source.get("status") or source.get("detail") or "").strip()
        outcome = _module_outcome(detail)
        reason = str(source.get("reason") or "").strip()
        if not reason and outcome != "Completed":
            reason = detail
        current = by_stage.get(stage)
        if current is None:
            current = {"stage": stage, "status": outcome, "details": detail, "reason": reason}
            by_stage[stage] = current
            output.append(current)
        else:
            details = [item for item in (current.get("details"), detail) if item]
            current["details"] = "; ".join(dict.fromkeys(details))
            if severity[outcome] > severity[current["status"]]:
                current["status"] = outcome
                current["reason"] = reason
            elif reason and not current.get("reason"):
                current["reason"] = reason
        if len(output) >= limit:
            break
    return output


def _module_outcome(detail: str) -> str:
    lowered = detail.casefold()
    if "skip" in lowered:
        return "Skipped"
    if any(marker in lowered for marker in ("partial", "no live", "not found", "without records")):
        return "Partial"
    if any(marker in lowered for marker in ("failed", "error", "exception", "timeout", "unavailable")):
        return "Failed"
    return "Completed"
