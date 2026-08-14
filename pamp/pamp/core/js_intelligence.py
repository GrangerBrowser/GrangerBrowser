from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import html as html_lib
import json
import re
from typing import Any
from urllib.parse import unquote, urlparse

import requests

from .endpoint_utils import is_probable_endpoint, is_static_asset, normalize_endpoint
from .intelligence_common import (
    DebugLog,
    compact_text,
    dedupe_findings,
    finding,
    mask_secret,
    record_error,
)


JS_TIMEOUT = 8
MAX_JS_BYTES = 3 * 1024 * 1024
MAX_JS_FILES = 120
MAX_BEAUTIFY_BYTES = 16 * 1024
MAX_BEAUTIFY_FILES = 1
MAX_ANALYSIS_BYTES = 24 * 1024 * 1024
MAX_EXPENSIVE_SCAN_CHARS = 512 * 1024
MAX_URL_CANDIDATES_PER_FILE = 1600
USER_AGENT = "Pamp/Domain-Analyzer"
STRING_PATTERN = re.compile(r"""(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){2,600})\1""", re.S)
URL_PATTERN = re.compile(r"""(?:https?|wss?)://[^\s"'`<>\\]{3,240}|/(?:api|v\d+|auth|oauth2?|login|logout|session|users?|profile|admin|internal|debug|callback|webhook|payment|checkout|graphql|gql)(?:/[A-Za-z0-9_.~:@!$&'()*+,;=%-]*)*(?:\?[A-Za-z0-9_.~:@!$&'()*+,;=/%?-]*)?""", re.I)
GRAPHQL_PATTERN = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]{0,500}\))?\s*\{|operationName\s*[:=]\s*[\"']([A-Za-z_][A-Za-z0-9_]*)",
    re.I,
)
WEBSOCKET_PATTERN = re.compile(r"""(?:wss?://[^\s"'`<>\\]{3,180}|new\s+WebSocket\s*\(\s*["'`]([^"'`]+)|io\s*\(\s*["'`]([^"'`]+))""", re.I)
CLOUD_URL_PATTERN = re.compile(
    r"""https?://[^\s"'`<>\\]*(?:s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com|firebasestorage\.googleapis\.com|blob\.core\.windows\.net|r2\.cloudflarestorage\.com|digitaloceanspaces\.com|backblazeb2\.com|supabase\.co/storage/v1/object)[^\s"'`<>\\]{0,300}""",
    re.I,
)
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b"), "high"),
    ("Bearer token", re.compile(r"\bBearer\s+([A-Za-z0-9._~+/-]{16,})", re.I), "high"),
    ("Stripe key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{24,}\b"), "medium"),
    ("Sentry DSN", re.compile(r"https://[A-Za-z0-9]{12,}@[A-Za-z0-9.-]+/\d+"), "medium"),
    (
        "Assigned credential",
        re.compile(
            r"""(?i)\b(client_secret|private_key|access_token|refresh_token|api[_-]?key|public_key|client_id)\b\s*[:=]\s*["'`]([^"'`]{8,300})["'`]"""
        ),
        "high",
    ),
)
SDK_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Firebase", ("firebaseapp.com", "firebaseConfig", "firebasestorage.googleapis.com")),
    ("Supabase", ("supabase.co", "createClient(", "supabaseUrl")),
    ("Stripe", ("js.stripe.com", "Stripe(", "stripe.publishableKey")),
    ("Sentry", ("Sentry.init", "sentry.io", "__SENTRY__")),
    ("Google Maps", ("maps.googleapis.com", "google.maps.")),
    ("Google Analytics", ("google-analytics.com", "gtag(", "analytics.js")),
    ("Google Tag Manager", ("googletagmanager.com", "GTM-")),
    ("Telegram Login", ("oauth.telegram.org", "telegram-login", "TelegramLoginWidget")),
    ("Discord webhook", ("discord.com/api/webhooks", "discordapp.com/api/webhooks")),
    ("Cloudinary", ("cloudinary.com", "res.cloudinary.com")),
    ("Intercom", ("intercomSettings", "intercom.io")),
    ("Jivo", ("jivosite.com", "jivoSite")),
    ("GrowthBook", ("growthbook", "GrowthBook(")),
    ("Auth0", ("auth0.com", "createAuth0Client")),
    ("Keycloak", ("keycloak", "Keycloak(")),
    ("Okta", ("okta.com", "OktaAuth")),
    ("Clerk", ("clerk.com", "Clerk(")),
    ("NextAuth", ("next-auth", "/api/auth/session", "/api/auth/providers")),
)
SUSPICIOUS_PATTERN = re.compile(
    r"""(?i)(?:["'`])([^"'`\n]{0,50}(?:debug|internal|admin|staging|development|sandbox|private|secret|credential|service-account)[^"'`\n]{0,100})(?:["'`])"""
)
CLIENT_ID_PATTERN = re.compile(
    r"""(?i)\bclient[_-]?id\b\s*[:=]\s*["'`]([^"'`]{3,240})["'`]"""
)


def analyze_javascript(
    base_url: str,
    html_text: str,
    html_signals: dict[str, Any],
    devtools: dict[str, Any],
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    script_sources = _script_sources(html_signals, devtools)
    inline_sources = _inline_scripts(html_text)
    files: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    graphql: list[dict[str, Any]] = []
    websockets: list[dict[str, Any]] = []
    sdks: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    configs: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    beautify_remaining = MAX_BEAUTIFY_FILES
    analysis_bytes_remaining = MAX_ANALYSIS_BYTES

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {
            executor.submit(_download_js, row["url"]): row
            for row in script_sources[:MAX_JS_FILES]
        }
        for future in as_completed(futures):
            source_row = futures[future]
            try:
                downloaded = future.result()
            except Exception as exc:
                record_error(
                    errors,
                    debug_log,
                    "[DOMAIN][JS]",
                    f"url={source_row['url']} error={exc}",
                )
                continue
            if downloaded.get("error"):
                record_error(
                    errors,
                    debug_log,
                    "[DOMAIN][JS]",
                    f"url={source_row['url']} error={downloaded['error']}",
                )
            file_row = finding(
                name=urlparse(source_row["url"]).path.rsplit("/", 1)[-1] or "JavaScript file",
                item_type="js_file",
                value=source_row["url"],
                source=source_row["source"],
                confidence="high" if source_row["source"] == "DevTools network" else "medium",
                evidence=f"HTTP {downloaded.get('status') or 'error'}; sha256={downloaded.get('sha256') or 'none'}",
                risk="low",
                notes=downloaded.get("notes") or "",
                url=source_row["url"],
                final_url=downloaded.get("final_url") or source_row["url"],
                status=downloaded.get("status"),
                size=downloaded.get("size") or 0,
                sha256=downloaded.get("sha256") or "",
                content_type=downloaded.get("content_type") or "",
            )
            files.append(file_row)
            text = downloaded.get("text") or ""
            digest = downloaded.get("sha256") or ""
            if not text or digest in seen_hashes:
                if digest in seen_hashes:
                    file_row["notes"] = "Duplicate JavaScript content; static analysis skipped."
                continue
            seen_hashes.add(digest)
            text_size = len(text.encode("utf-8", errors="ignore"))
            if text_size > analysis_bytes_remaining:
                file_row["notes"] = (
                    f"{file_row.get('notes') or ''} Static analysis skipped after the "
                    f"{MAX_ANALYSIS_BYTES // (1024 * 1024)} MB run budget was exhausted."
                ).strip()
                continue
            analysis_bytes_remaining -= text_size
            allow_beautify = beautify_remaining > 0 and len(text.encode("utf-8", errors="ignore")) <= MAX_BEAUTIFY_BYTES
            if allow_beautify:
                beautify_remaining -= 1
            _analyze_text(
                _deobfuscate(text, allow_beautify=allow_beautify),
                source_row["url"],
                base_url,
                "high" if source_row["source"] == "DevTools network" else "medium",
                endpoints,
                graphql,
                websockets,
                sdks,
                secrets,
                configs,
                suspicious,
            )

    for index, inline_text in enumerate(inline_sources, start=1):
        sha256 = hashlib.sha256(inline_text.encode("utf-8", errors="ignore")).hexdigest()
        source = f"inline script #{index}"
        files.append(
            finding(
                name=source,
                item_type="inline_js",
                value=source,
                source="HTML inline script",
                confidence="medium",
                evidence=f"sha256={sha256}",
                risk="low",
                notes="Static inline script analysis; script was not executed.",
                url="",
                final_url="",
                status="inline",
                size=len(inline_text.encode("utf-8", errors="ignore")),
                sha256=sha256,
                content_type="text/javascript",
            )
        )
        if sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)
        allow_beautify = beautify_remaining > 0 and len(inline_text.encode("utf-8", errors="ignore")) <= MAX_BEAUTIFY_BYTES
        if allow_beautify:
            beautify_remaining -= 1
        _analyze_text(
            _deobfuscate(inline_text, allow_beautify=allow_beautify),
            source,
            base_url,
            "medium",
            endpoints,
            graphql,
            websockets,
            sdks,
            secrets,
            configs,
            suspicious,
        )

    _add_devtools_endpoints(devtools, base_url, endpoints, websockets)
    endpoints = dedupe_findings(endpoints, ("type", "value"), 500)
    graphql = dedupe_findings(graphql, ("type", "value", "source"), 180)
    websockets = dedupe_findings(websockets, ("type", "value"), 120)
    sdks = dedupe_findings(sdks, ("name", "value"), 120)
    secrets = dedupe_findings(secrets, ("type", "value", "source"), 180)
    configs = dedupe_findings(configs, ("type", "value", "source"), 120)
    suspicious = dedupe_findings(suspicious, ("value", "source"), 100)
    files = dedupe_findings(files, ("type", "value", "sha256"), 240)
    return {
        "files": files,
        "api_endpoints": endpoints,
        "graphql": graphql,
        "websockets": websockets,
        "third_party_sdks": sdks,
        "secret_like_values": secrets,
        "config_objects": configs,
        "suspicious_strings": suspicious,
        "summary": {
            "files": len(files),
            "api_endpoints": len(endpoints),
            "graphql": len(graphql),
            "websockets": len(websockets),
            "third_party_sdks": len(sdks),
            "secret_like_values": len(secrets),
            "config_objects": len(configs),
            "suspicious_strings": len(suspicious),
            "downloaded_bytes": sum(int(row.get("size") or 0) for row in files),
        },
        "errors": errors,
    }


def _script_sources(html_signals: dict[str, Any], devtools: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    rows.extend({"url": str(url), "source": "HTML script tag"} for url in html_signals.get("script_links") or [])
    rows.extend({"url": str(url), "source": "DevTools loaded JS"} for url in devtools.get("loaded_js") or [])
    for request in devtools.get("network_requests") or []:
        url = str(request.get("url") or "")
        resource_type = str(request.get("resource_type") or "").lower()
        content_type = str(request.get("content_type") or "").lower()
        if resource_type == "script" or "javascript" in content_type or re.search(r"\.m?js(?:[?#]|$)", url, re.I):
            rows.append({"url": url, "source": "DevTools network"})
    output = []
    seen = set()
    for row in rows:
        url = row["url"].strip()
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        output.append(row)
    return output


def _inline_scripts(html_text: str) -> list[str]:
    if not html_text:
        return []
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_text, "html.parser")
        return [
            str(tag.string or tag.get_text("", strip=False) or "")[:MAX_JS_BYTES]
            for tag in soup.find_all("script")
            if not tag.get("src") and str(tag.string or tag.get_text("", strip=False) or "").strip()
        ][:120]
    except Exception:
        return [
            match.group(1)[:MAX_JS_BYTES]
            for match in re.finditer(r"<script(?![^>]+\bsrc=)[^>]*>(.*?)</script>", html_text, re.I | re.S)
            if match.group(1).strip()
        ][:120]


def _download_js(url: str) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/javascript,text/javascript,*/*;q=0.5"},
            timeout=JS_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )
    except Exception as exc:
        return {"error": str(exc)}
    status = response.status_code
    if status >= 400:
        response.close()
        return {
            "status": status,
            "final_url": response.url,
            "content_type": response.headers.get("Content-Type", ""),
            "error": f"HTTP {status}",
        }
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=32_768):
        if not chunk:
            continue
        remaining = MAX_JS_BYTES - total
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if total >= MAX_JS_BYTES:
            break
    body = b"".join(chunks)
    response.close()
    encoding = response.encoding or "utf-8"
    text = body.decode(encoding, errors="replace")
    return {
        "status": status,
        "final_url": response.url,
        "content_type": response.headers.get("Content-Type", ""),
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest() if body else "",
        "text": text,
        "notes": "Truncated at 3 MB." if total >= MAX_JS_BYTES else "",
    }


def _deobfuscate(text: str, allow_beautify: bool = False) -> str:
    value = html_lib.unescape(text or "")
    if allow_beautify:
        try:
            import jsbeautifier

            value = jsbeautifier.beautify(value)
        except Exception:
            pass
    value = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        value,
    )
    value = re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda match: chr(int(match.group(1), 16)),
        value,
    )
    value = value.replace("\\/", "/")
    value = unquote(value)
    if len(value) <= MAX_EXPENSIVE_SCAN_CHARS:
        for _ in range(3):
            updated = re.sub(
                r"""(["'`])([^"'`\\]{1,160})\1\s*\+\s*(["'`])([^"'`\\]{1,160})\3""",
                lambda match: f'"{match.group(2)}{match.group(4)}"',
                value,
            )
            if updated == value:
                break
            value = updated
    decoded = []
    expensive_sample = _scan_sample(value)
    for candidate in re.findall(r"""["'`]([A-Za-z0-9+/_=-]{16,4096})["'`]""", expensive_sample):
        try:
            raw = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
        except Exception:
            continue
        if not raw or sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in raw) / len(raw) < 0.88:
            continue
        preview = raw.decode("utf-8", errors="replace")
        if any(marker in preview.lower() for marker in ("/api", "http", "graphql", "oauth", "client_id", "webhook")):
            decoded.append(preview[:8000])
    return f"{value}\n" + "\n".join(decoded)


def _analyze_text(
    text: str,
    source: str,
    base_url: str,
    default_confidence: str,
    endpoints: list[dict[str, Any]],
    graphql: list[dict[str, Any]],
    websockets: list[dict[str, Any]],
    sdks: list[dict[str, Any]],
    secrets: list[dict[str, Any]],
    configs: list[dict[str, Any]],
    suspicious: list[dict[str, Any]],
) -> None:
    candidates: dict[str, str] = {}
    for match in URL_PATTERN.finditer(text):
        raw = match.group(0)
        candidates.setdefault(
            raw,
            compact_text(
                text[max(0, match.start() - 70) : match.end() + 100],
                260,
            ),
        )
        if len(candidates) >= MAX_URL_CANDIDATES_PER_FILE:
            break
    expensive_sample = _scan_sample(text)
    source_host = (urlparse(source).hostname or "").lower()
    base_host = (urlparse(base_url).hostname or "").lower()
    for raw, evidence in candidates.items():
        normalized_raw = raw[:-1] if raw.endswith("$") and "${" in evidence else raw
        if (
            normalized_raw.startswith("/")
            and source_host
            and base_host
            and source_host != base_host
        ):
            continue
        endpoint = normalize_endpoint(normalized_raw, base_url)
        if not endpoint or not is_probable_endpoint(endpoint):
            continue
        endpoint_type = _endpoint_type(endpoint)
        risk = _endpoint_risk(endpoint, endpoint_type)
        confidence = "high" if raw.startswith(("http://", "https://", "ws://", "wss://", "/api/")) else default_confidence
        row = finding(
            name=urlparse(endpoint).path or endpoint,
            item_type=endpoint_type,
            value=endpoint,
            source=source,
            confidence=confidence,
            evidence=evidence,
            risk=risk,
            notes="Static JavaScript string extraction.",
            endpoint=endpoint,
            method=_detected_method(evidence),
            source_js=source,
        )
        if endpoint_type == "websocket":
            websockets.append(row)
        else:
            endpoints.append(row)
    for match in GRAPHQL_PATTERN.finditer(expensive_sample):
        operation_type = str(match.group(1) or "operationName").lower()
        operation_name = str(match.group(2) or match.group(3) or "anonymous")
        graphql.append(
            finding(
                name=operation_name,
                item_type=f"graphql_{operation_type}",
                value=operation_name,
                source=source,
                confidence=default_confidence,
                evidence=_context(text, match.group(0)),
                risk="high" if operation_type == "mutation" else "medium",
                notes="GraphQL operation name extracted statically.",
                operation=operation_name,
                operation_type=operation_type,
                source_js=source,
            )
        )
    for match in WEBSOCKET_PATTERN.finditer(expensive_sample):
        raw = match.group(0) if match.group(0).startswith(("ws://", "wss://")) else (match.group(1) or match.group(2) or "")
        endpoint = normalize_endpoint(raw, base_url)
        if endpoint and endpoint.startswith(("ws://", "wss://")):
            websockets.append(
                finding(
                    name="WebSocket endpoint",
                    item_type="websocket",
                    value=endpoint,
                    source=source,
                    confidence=default_confidence,
                    evidence=_context(text, match.group(0)),
                    risk="medium",
                    notes="WebSocket constructor or URL found in JavaScript.",
                    endpoint=endpoint,
                    method="CONNECT",
                    source_js=source,
                )
            )
    lowered = expensive_sample.lower()
    for name, markers in SDK_PATTERNS:
        matched = next((marker for marker in markers if marker.lower() in lowered), "")
        if matched:
            sdks.append(
                finding(
                    name=name,
                    item_type="third_party_sdk",
                    value=name,
                    source=source,
                    confidence="high" if "." in matched or "(" in matched else "medium",
                    evidence=f"Marker found: {matched}",
                    risk="medium" if name in {"Firebase", "Supabase", "Stripe", "Sentry"} else "low",
                    notes="Third-party SDK marker detected in static JavaScript.",
                    provider=name,
                    source_js=source,
                )
            )
    _extract_secrets(expensive_sample, source, secrets)
    _extract_configs(expensive_sample, source, configs)
    for match in CLIENT_ID_PATTERN.finditer(expensive_sample):
        value = compact_text(match.group(1), 240)
        suspicious.append(
            finding(
                name="OAuth client_id",
                item_type="oauth_client_id",
                value=value,
                source=source,
                confidence="high",
                evidence="client_id assignment found in static JavaScript",
                risk="medium",
                notes="Client IDs are generally public and were retained for OAuth analysis.",
                source_js=source,
            )
        )
    for match in CLOUD_URL_PATTERN.finditer(text):
        value = compact_text(match.group(0), 420)
        suspicious.append(
            finding(
                name="Cloud storage reference",
                item_type="cloud_storage_reference",
                value=value,
                source=source,
                confidence="high",
                evidence=_context(text, match.group(0)),
                risk="medium",
                notes="Storage URL passed to passive Cloud Bucket Intelligence.",
                source_js=source,
            )
        )
    for match in SUSPICIOUS_PATTERN.finditer(expensive_sample):
        value = compact_text(match.group(1), 180)
        if (
            len(value) < 4
            or is_static_asset(value)
            or (source_host and base_host and source_host != base_host)
            or _looks_like_code_fragment(value)
        ):
            continue
        suspicious.append(
            finding(
                name="Suspicious JavaScript string",
                item_type="suspicious_string",
                value=value,
                source=source,
                confidence="low",
                evidence=value,
                risk="medium" if any(marker in value.lower() for marker in ("internal", "debug", "admin")) else "low",
                notes="Keyword-bearing string; manual validation recommended.",
                source_js=source,
            )
        )


def _extract_secrets(text: str, source: str, output: list[dict[str, Any]]) -> None:
    for name, pattern, default_risk in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if name == "Assigned credential":
                secret_type = str(match.group(1))
                raw = str(match.group(2))
                risk = "medium" if secret_type.lower() in {"client_id", "public_key", "api_key"} else default_risk
            else:
                secret_type = name
                raw = str(match.group(1) if match.lastindex else match.group(0))
                risk = default_risk
            output.append(
                finding(
                    name=secret_type,
                    item_type="secret_like_value",
                    value=mask_secret(raw),
                    source=source,
                    confidence="high",
                    evidence=f"{secret_type} pattern found; raw value was not stored.",
                    risk=risk,
                    notes="Masked static match. Validate exposure and rotation requirements manually.",
                    masked_value=mask_secret(raw),
                    source_js=source,
                )
            )


def _extract_configs(text: str, source: str, output: list[dict[str, Any]]) -> None:
    pattern = re.compile(
        r"""(?is)\b(firebaseConfig|runtimeConfig|publicRuntimeConfig|config|environment)\b\s*[:=]\s*(\{.{20,1800}?\})"""
    )
    for match in pattern.finditer(text):
        raw = match.group(2)
        masked = re.sub(
            r"""(?i)(client_secret|private_key|access_token|refresh_token|api[_-]?key)(\s*[:=]\s*["'`])([^"'`]+)""",
            lambda item: f"{item.group(1)}{item.group(2)}{mask_secret(item.group(3))}",
            raw,
        )
        output.append(
            finding(
                name=match.group(1),
                item_type="config_object",
                value=compact_text(masked, 500),
                source=source,
                confidence="medium",
                evidence=f"{match.group(1)} object literal found",
                risk="medium",
                notes="Static config preview with credential-like values masked.",
                source_js=source,
            )
        )


def _add_devtools_endpoints(
    devtools: dict[str, Any],
    base_url: str,
    endpoints: list[dict[str, Any]],
    websockets: list[dict[str, Any]],
) -> None:
    for request in devtools.get("network_requests") or []:
        raw = str(request.get("url") or "")
        endpoint = normalize_endpoint(raw, base_url)
        if not endpoint or not is_probable_endpoint(endpoint):
            continue
        item_type = _endpoint_type(endpoint)
        row = finding(
            name=urlparse(endpoint).path or endpoint,
            item_type=item_type,
            value=endpoint,
            source="DevTools network",
            confidence="high",
            evidence=f"{request.get('method') or 'GET'} {request.get('status') or ''} {request.get('resource_type') or ''}",
            risk=_endpoint_risk(endpoint, item_type),
            notes="Observed browser network request.",
            endpoint=endpoint,
            method=str(request.get("method") or ""),
            source_js=str(request.get("initiator") or request.get("source_page") or "DevTools"),
        )
        if item_type == "websocket":
            websockets.append(row)
        else:
            endpoints.append(row)


def _endpoint_type(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("ws://", "wss://")):
        return "websocket"
    if "graphql" in lowered or "/gql" in lowered:
        return "graphql_endpoint"
    if any(marker in lowered for marker in ("/auth", "/oauth", "/login", "/logout", "/session", "/callback")):
        return "auth_endpoint"
    if any(marker in lowered for marker in ("/admin", "/internal", "/debug")):
        return "internal_endpoint"
    if "webhook" in lowered:
        return "webhook_endpoint"
    return "api_endpoint"


def _endpoint_risk(value: str, item_type: str) -> str:
    lowered = value.lower()
    if item_type in {"graphql_endpoint", "internal_endpoint", "webhook_endpoint"}:
        return "high"
    if any(marker in lowered for marker in ("/auth", "/login", "/logout", "/session", "/profile", "/user", "/callback")):
        return "medium"
    return "low"


def _detected_method(context: str) -> str:
    match = re.search(r"""(?i)\b(GET|POST|PUT|PATCH|DELETE|OPTIONS)\b""", context or "")
    return match.group(1).upper() if match else ""


def _context(text: str, needle: str) -> str:
    index = text.find(needle)
    if index < 0:
        return compact_text(needle, 220)
    return compact_text(text[max(0, index - 70) : index + len(needle) + 100], 260)


def _scan_sample(text: str) -> str:
    if len(text) <= MAX_EXPENSIVE_SCAN_CHARS:
        return text
    half = MAX_EXPENSIVE_SCAN_CHARS // 2
    return f"{text[:half]}\n{text[-half:]}"


def _looks_like_code_fragment(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in ("function", "return", "=>", ");", "&&", "||", "void 0")):
        return True
    if value[:1] in {",", ";", ")", "]", "}"}:
        return True
    return sum(not (char.isalnum() or char in " _./:@?&=+-") for char in value) > 8
