from __future__ import annotations

import re
from typing import Any


CONFIDENCE_WEIGHT = {"low": 1, "medium": 2, "high": 3}
VERSION_PATTERNS = {
    "nginx": re.compile(r"\bnginx/(\d+(?:\.\d+){1,3})", re.I),
    "Apache": re.compile(r"\bApache/?(\d+(?:\.\d+){1,3})", re.I),
    "LiteSpeed": re.compile(r"\bLiteSpeed/?(\d+(?:\.\d+){1,3})", re.I),
    "Microsoft IIS": re.compile(r"\bMicrosoft-IIS/(\d+(?:\.\d+){1,2})", re.I),
    "PHP": re.compile(r"\bPHP/?(\d+(?:\.\d+){1,3})", re.I),
    "jQuery": re.compile(r"\bjquery[-.]?(\d+(?:\.\d+){1,3})", re.I),
    "Bootstrap": re.compile(r"\bbootstrap[-.]?(\d+(?:\.\d+){1,3})", re.I),
    "Drupal": re.compile(r"\bDrupal\s+(\d+(?:\.\d+){0,2})", re.I),
    "Joomla": re.compile(r"\bJoomla!?\s+(\d+(?:\.\d+){0,2})", re.I),
}


def fingerprint_technologies(
    http_surface: dict[str, Any],
    html: str = "",
    html_signals: dict[str, Any] | None = None,
    js_intel: dict[str, Any] | None = None,
    devtools: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    html_signals = html_signals or {}
    js_intel = js_intel or {}
    devtools = devtools or {}
    headers = {str(key).lower(): str(value) for key, value in (http_surface.get("headers") or {}).items()}
    cookies = [str(item.get("name") or "") for item in http_surface.get("cookies") or [] if isinstance(item, dict)]
    cookie_text = "\n".join(cookies).lower()
    script_links = "\n".join(html_signals.get("script_links") or [])
    css_links = "\n".join((html_signals.get("external_css") or []) + (devtools.get("loaded_css") or []))
    path_text = "\n".join(
        [script_links, css_links]
        + [str(item.get("url") or "") for item in http_surface.get("interesting_paths") or []]
        + [str(item.get("endpoint") or "") for item in js_intel.get("api_endpoints") or []]
    ).lower()
    meta_generator = str(http_surface.get("meta_generator") or "").lower()
    body = (html or "").lower()
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
    combined = "\n".join([header_text, cookie_text, meta_generator, path_text, body])

    found: dict[str, dict[str, str]] = {}

    def add(name: str, category: str, confidence: str, evidence: str) -> None:
        if not evidence:
            return
        row = {
            "name": name,
            "category": category,
            "confidence": confidence,
            "evidence": evidence[:180],
        }
        current = found.get(name.lower())
        if not current or CONFIDENCE_WEIGHT[confidence] > CONFIDENCE_WEIGHT[current["confidence"]]:
            found[name.lower()] = row

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    via = headers.get("via", "")

    if "nginx" in server.lower():
        add("nginx", "Web server", "high", f"Server header: {server}")
    if "apache" in server.lower():
        add("Apache", "Web server", "high", f"Server header: {server}")
    if "litespeed" in server.lower():
        add("LiteSpeed", "Web server", "high", f"Server header: {server}")
    if "microsoft-iis" in server.lower() or "iis" in server.lower():
        add("Microsoft IIS", "Web server", "high", f"Server header: {server}")
    if "cloudflare" in server.lower() or "cf-ray" in headers:
        add("Cloudflare", "Infra / CDN / WAF", "high", "Cloudflare header found")

    if "php" in powered_by.lower() or "phpsessid" in cookie_text or re.search(r"\.php(?:[?#/]|$)", combined):
        add("PHP", "Language / backend", "high" if "php" in powered_by.lower() else "medium", "PHP marker found")
    if "asp.net" in powered_by.lower() or "asp.net_sessionid" in cookie_text or "x-aspnet-version" in headers:
        add("ASP.NET", "Language / backend", "high", "ASP.NET header or cookie found")
    if "express" in powered_by.lower():
        add("Express", "Language / backend", "high", f"X-Powered-By: {powered_by}")
    if "csrftoken" in cookie_text or "csrfmiddlewaretoken" in body:
        add("Django", "Language / backend", "medium", "Django CSRF marker found")
    if "flask" in powered_by.lower() or "werkzeug" in server.lower():
        add("Flask", "Language / backend", "medium", "Flask/Werkzeug marker found")
    if "laravel_session" in cookie_text or "x-csrf-token" in combined and "laravel" in combined:
        add("Laravel", "Language / backend", "high" if "laravel_session" in cookie_text else "medium", "Laravel marker found")
    if "_rails_session" in cookie_text or "csrf-param" in body and "csrf-token" in body:
        add("Ruby on Rails", "Language / backend", "medium", "Rails CSRF/session marker found")

    if "wp-content" in combined or "wp-includes" in combined or "/wp-login.php" in path_text:
        add("WordPress", "CMS", "high", "wp-content/wp-includes path found")
    if "joomla" in meta_generator or "/media/system/js/" in combined or "com_content" in combined:
        add("Joomla", "CMS", "high" if "joomla" in meta_generator else "medium", "Joomla marker found")
    if "drupal" in meta_generator or "drupal.settings" in combined or "/sites/default/" in combined:
        add("Drupal", "CMS", "high" if "drupal" in meta_generator else "medium", "Drupal marker found")
    if "/bitrix/" in combined or "bitrix" in meta_generator:
        add("Bitrix", "CMS", "high", "Bitrix path or generator found")
    if "opencart" in meta_generator or "catalog/view/theme" in combined or "route=common/home" in combined:
        add("OpenCart", "CMS", "high" if "opencart" in meta_generator else "medium", "OpenCart marker found")

    if "__next_data__" in combined or "_next/static" in combined:
        add("Next.js", "Frontend", "high", "_next/static or __NEXT_DATA__ marker found")
    if "data-reactroot" in combined or "react-dom" in combined or "react.production.min.js" in combined:
        add("React", "Frontend", "high", "React DOM marker found")
    elif re.search(r"\breact(?:\.|/|-)", path_text):
        add("React", "Frontend", "medium", "React asset path found")
    if "__nuxt" in combined or "_nuxt/" in combined:
        add("Nuxt", "Frontend", "high", "Nuxt marker found")
    if "vue.js" in combined or "__vue__" in combined or re.search(r"\bvue(?:\.|/|-)", path_text):
        add("Vue", "Frontend", "medium", "Vue marker found")
    if "ng-version" in combined or "angular" in combined and "zone.js" in combined:
        add("Angular", "Frontend", "high" if "ng-version" in combined else "medium", "Angular marker found")
    if "jquery" in combined:
        add("jQuery", "Frontend", "high", "jQuery asset or code marker found")
    if "bootstrap" in combined:
        add("Bootstrap", "Frontend", "high", "Bootstrap asset marker found")
    if "tailwind" in combined or "tailwindcss" in combined:
        add("Tailwind", "Frontend", "medium", "Tailwind marker found")

    if "akamai" in header_text or "akamai" in via.lower():
        add("Akamai", "Infra / CDN / WAF", "medium", "Akamai header marker found")
    if "fastly" in header_text or "x-served-by" in headers and "cache" in headers:
        add("Fastly", "Infra / CDN / WAF", "medium", "Fastly-style cache header found")
    if "x-vercel-id" in headers or "vercel" in header_text:
        add("Vercel", "Infra / CDN / WAF", "high", "Vercel header found")
    if "x-nf-request-id" in headers or "netlify" in header_text:
        add("Netlify", "Infra / CDN / WAF", "high", "Netlify header found")
    if "cloudfront" in header_text or "x-amz-cf-id" in headers:
        add("AWS CloudFront", "Infra / CDN / WAF", "high", "CloudFront header found")
    if "x-azure-ref" in headers or "azurefd.net" in combined or "azure front door" in combined:
        add("Azure Front Door", "Infra / CDN / WAF", "high", "Azure Front Door header or host found")
    if "bunnycdn" in combined or "b-cdn.net" in combined or "cdn-pullzone" in combined:
        add("BunnyCDN", "Infra / CDN / WAF", "medium", "BunnyCDN host or header marker found")
    if "googleusercontent.com" in combined or "gstatic.com" in combined and "via:" in header_text:
        add("Google CDN", "Infra / CDN / WAF", "medium", "Google CDN response marker found")

    for item in devtools.get("technologies") or []:
        name = str(item).strip()
        if name:
            add(name, "Browser-observed", "medium", "DevTools technology hint")

    rows = sorted(found.values(), key=lambda row: (row["category"], row["name"].lower()))
    for row in rows:
        row["source"] = _evidence_source(row.get("evidence") or "")
        row["version"] = _technology_version(row["name"], "\n".join([row.get("evidence") or "", combined]))
    return rows


def _evidence_source(evidence: str) -> str:
    lowered = evidence.lower()
    if "server header" in lowered:
        return "Server Header"
    if "x-powered-by" in lowered or "header" in lowered:
        return "Response Header"
    if "cookie" in lowered or "session" in lowered:
        return "Cookie"
    if "generator" in lowered:
        return "Meta Generator"
    if "asset" in lowered or "path" in lowered:
        return "JS Asset"
    if "devtools" in lowered:
        return "DevTools"
    return "HTML Marker"


def _technology_version(name: str, evidence: str) -> str:
    pattern = VERSION_PATTERNS.get(name)
    if not pattern:
        return "Unknown Version"
    match = pattern.search(evidence or "")
    return match.group(1) if match else "Unknown Version"
