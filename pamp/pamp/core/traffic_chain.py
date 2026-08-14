from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from http import HTTPStatus
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .data_decoder import mask_text, sanitize_url
from .models import utc_now


MAX_REQUESTS = 500
SLOW_REQUEST_LIMIT = 30

ANALYTICS_HOST_HINTS = (
    "google-analytics.com",
    "googletagmanager.com",
    "mc.yandex",
    "metrika",
    "facebook.com",
    "connect.facebook.net",
    "clarity.ms",
    "hotjar.com",
    "analytics.tiktok.com",
)
CDN_HOST_HINTS = (
    "cloudflare.com",
    "cloudflare.net",
    "cloudfront.net",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "fastly.net",
    "akamai",
    "static",
    "cdn.",
)
CHAT_HOST_HINTS = (
    "jivosite",
    "intercom",
    "crisp.chat",
    "zendesk",
    "tawk.to",
)
SECURITY_HOST_HINTS = (
    "recaptcha",
    "hcaptcha",
    "turnstile",
    "captcha",
    "challenges.cloudflare.com",
)
API_PATH_PATTERN = re.compile(r"(/api/|/graphql\b|/rest/|/v\d+/|/rpc\b|/json\b)", re.I)
AUTH_PATH_PATTERN = re.compile(r"(auth|login|logout|signin|sign-in|session|oauth|oidc|callback|token|whoami)", re.I)
PAYMENT_PATH_PATTERN = re.compile(r"(checkout|payment|billing|invoice|crypto|card|topup|withdraw)", re.I)
TRACKING_PATH_PATTERN = re.compile(r"(beacon|pixel|collect|track|telemetry|metrics|events?)", re.I)
CONFIG_PATH_PATTERN = re.compile(r"(config|settings|manifest|service-worker|sw\.js|runtime)", re.I)
PROFILE_PATH_PATTERN = re.compile(r"(/profile|/me\b|/user|/account|/whoami|/session)", re.I)


def build_traffic_chain(
    *,
    target: str,
    final_url: str,
    devtools: dict[str, Any],
    debug_log: Any | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    base_host = _host(final_url or target)
    raw_requests = _request_source(devtools)
    requests: list[dict[str, Any]] = []
    for index, row in enumerate(_sort_requests(raw_requests)[:MAX_REQUESTS], start=1):
        try:
            requests.append(_request_row(index, row, base_host))
        except Exception as exc:
            errors.append(f"request normalize {index}: {exc}")
            if debug_log:
                try:
                    debug_log(f"[TRAFFIC][REQUEST] url={row.get('url') if isinstance(row, dict) else ''} error={exc}")
                except Exception:
                    pass

    summary = _summary(requests, devtools)
    critical_path = _critical_path(requests)
    domains = _domains(requests, base_host)
    api_requests = [row for row in requests if row.get("category") == "api" or row.get("resource_type") in {"xhr", "fetch"}]
    third_party = [row for row in requests if row.get("is_third_party")]
    failed_requests = [
        row
        for row in requests
        if row.get("failure_text") or _status_int(row.get("status")) >= 400
    ]
    slow_requests = sorted(
        [row for row in requests if int(row.get("duration_ms") or 0) > 0],
        key=lambda item: int(item.get("duration_ms") or 0),
        reverse=True,
    )[:SLOW_REQUEST_LIMIT]
    websocket_rows = _websockets(requests, devtools)
    console_messages = _console_messages(devtools)
    page_errors = [
        {"message": str(item)[:500], "source": "pageerror"}
        for item in devtools.get("page_errors") or []
    ][:80]
    errors.extend(devtools.get("traffic_errors") or [])

    return {
        "type": "traffic_chain",
        "target": target,
        "final_url": sanitize_url(final_url or target),
        "summary": summary,
        "requests": requests,
        "critical_path": critical_path,
        "critical_requests": critical_path,
        "domains": domains,
        "api_requests": api_requests[:160],
        "third_party": third_party[:180],
        "failed_requests": failed_requests[:120],
        "slow_requests": slow_requests,
        "websockets": websocket_rows,
        "console_messages": console_messages,
        "page_errors": page_errors,
        "lifecycle": devtools.get("lifecycle") or {},
        "limits": {
            "max_requests": MAX_REQUESTS,
            "max_response_preview_bytes": 100_000,
            "max_websocket_frames": 100,
            "timeout_ms": 30_000,
        },
        "errors": errors[:120],
        "timestamp": utc_now(),
    }


def traffic_note(chain: dict[str, Any]) -> str:
    summary = chain.get("summary") or {}
    total = int(summary.get("total_requests") or 0)
    if not total:
        return "No browser traffic was captured."
    api = int(summary.get("api_requests") or 0)
    third_party = int(summary.get("third_party_requests") or 0)
    failed = int(summary.get("failed_requests") or 0)
    return f"Traffic Chain captured {total} request(s), including {api} API request(s), {third_party} third-party request(s), and {failed} failed request(s)."


def _request_source(devtools: dict[str, Any]) -> list[dict[str, Any]]:
    rows = devtools.get("traffic_requests") or []
    if rows:
        return [row for row in rows if isinstance(row, dict)]
    intelligence = devtools.get("network_intelligence") or {}
    rows = intelligence.get("requests") or devtools.get("network_requests") or []
    return [row for row in rows if isinstance(row, dict)]


def _sort_requests(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=_request_sort_key)


def _request_sort_key(row: dict[str, Any]) -> tuple[int, str, int]:
    sequence = _int(row.get("sequence") or 999999)
    raw_time = str(row.get("start_time") or row.get("timestamp") or "")
    parsed = _iso_timestamp(raw_time)
    if parsed:
        return (0, parsed, sequence)
    return (1, "", sequence)


def _iso_timestamp(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()
    except Exception:
        return raw


def _request_row(index: int, row: dict[str, Any], base_host: str) -> dict[str, Any]:
    url = sanitize_url(str(row.get("url") or ""))
    parsed = urlparse(url)
    host = (parsed.hostname or row.get("host") or "").lower()
    resource_type = _resource_type(row)
    content_type = _content_type(row)
    status = row.get("status")
    category = _category(url, host, resource_type, content_type)
    importance = _importance(url, resource_type, category, status, index)
    duration = _int(row.get("duration_ms") or row.get("duration") or 0)
    response_headers = row.get("response_headers") or {}
    request_headers = row.get("request_headers") or {}
    query_parameters = [
        {"name": str(name), "value": mask_text(str(value))[:300]}
        for name, value in parse_qsl(parsed.query or "", keep_blank_values=True)[:40]
    ]
    cookie_names = _cookie_names(request_headers, response_headers)
    notes = _notes(url, category, importance, status, row)
    sequence = _int(row.get("sequence") or index) or index
    return {
        "id": sequence,
        "sequence": sequence,
        "url": url,
        "method": str(row.get("method") or "GET").upper(),
        "resource_type": resource_type,
        "display_type": _display_type(url, resource_type, category, content_type),
        "domain": host,
        "path": parsed.path or "/",
        "status": status,
        "status_text": _status_text(status),
        "mime_type": content_type,
        "size_bytes": _int(row.get("size_bytes") or row.get("response_size") or row.get("body_size") or 0),
        "request_headers": request_headers,
        "response_headers": response_headers,
        "query_parameters": query_parameters,
        "cookies": cookie_names,
        "response_preview": str(row.get("response_preview") or "")[:100_000],
        "post_data_preview": str(row.get("post_data_preview") or "")[:2_000],
        "start_time": str(row.get("start_time") or row.get("timestamp") or ""),
        "end_time": str(row.get("end_time") or ""),
        "duration_ms": duration,
        "from_cache": bool(row.get("from_cache") or False),
        "redirected_from": _redirected_from(row),
        "initiator": str(row.get("initiator") or row.get("referer") or row.get("source_page") or ""),
        "is_third_party": _third_party(host, base_host),
        "category": category,
        "importance": importance,
        "failure_text": str(row.get("failure_text") or ""),
        "notes": notes,
    }


def _summary(requests: list[dict[str, Any]], devtools: dict[str, Any]) -> dict[str, Any]:
    domains = {row.get("domain") for row in requests if row.get("domain")}
    status_failures = sum(1 for row in requests if row.get("failure_text") or _status_int(row.get("status")) >= 400)
    lifecycle = devtools.get("lifecycle") or {}
    counts = Counter(row.get("importance") or "normal" for row in requests)
    return {
        "total_requests": len(requests),
        "total_bytes": sum(_int(row.get("size_bytes") or 0) for row in requests),
        "load_time_ms": _int(devtools.get("duration_ms") or lifecycle.get("load_ms") or 0),
        "domcontentloaded_ms": _int(lifecycle.get("domcontentloaded_ms") or 0),
        "load_event_ms": _int(lifecycle.get("load_ms") or 0),
        "network_idle_ms": _int(lifecycle.get("network_idle_ms") or devtools.get("duration_ms") or 0),
        "domains": len(domains),
        "third_party_requests": sum(1 for row in requests if row.get("is_third_party")),
        "failed_requests": status_failures,
        "api_requests": sum(1 for row in requests if row.get("category") == "api" or row.get("resource_type") in {"xhr", "fetch"}),
        "websockets": sum(1 for row in requests if row.get("resource_type") == "websocket" or str(row.get("url") or "").startswith(("ws://", "wss://"))),
        "critical": counts.get("critical", 0),
        "important": counts.get("important", 0),
        "normal": counts.get("normal", 0),
        "noise": counts.get("noise", 0),
    }


def _critical_path(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen = set()

    def add(row: dict[str, Any]) -> None:
        key = row.get("url")
        if key and key not in seen:
            seen.add(key)
            selected.append(row)

    for row in requests:
        if row.get("resource_type") == "document":
            add(row)
            break
    for wanted in ("stylesheet", "script"):
        for row in requests:
            if row.get("resource_type") == wanted:
                add(row)
                break
    for row in requests:
        url = str(row.get("url") or "").lower()
        if (
            CONFIG_PATH_PATTERN.search(url)
            or AUTH_PATH_PATTERN.search(url)
            or PROFILE_PATH_PATTERN.search(url)
            or "graphql" in url
            or row.get("resource_type") == "websocket"
            or row.get("category") == "payment"
            or (row.get("category") == "api" and _status_int(row.get("status")) >= 400)
        ):
            add(row)
        if len(selected) >= 24:
            break
    return selected


def _domains(requests: list[dict[str, Any]], base_host: str) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    cats: dict[str, Counter[str]] = defaultdict(Counter)
    for row in requests:
        host = str(row.get("domain") or "")
        if not host:
            continue
        item = grouped.setdefault(
            host,
            {
                "domain": host,
                "requests": 0,
                "bytes": 0,
                "categories": [],
                "third_party": _third_party(host, base_host),
            },
        )
        item["requests"] += 1
        item["bytes"] += _int(row.get("size_bytes") or 0)
        cats[host][str(row.get("category") or "other")] += 1
    output = []
    for host, item in grouped.items():
        item["categories"] = [name for name, _count in cats[host].most_common(8)]
        output.append(item)
    return sorted(output, key=lambda item: (-int(item["requests"]), item["domain"]))[:120]


def _websockets(requests: list[dict[str, Any]], devtools: dict[str, Any]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in requests:
        url = str(row.get("url") or "")
        if row.get("resource_type") == "websocket" or url.startswith(("ws://", "wss://")):
            rows[url] = {
                "url": url,
                "opened_at": row.get("start_time") or "",
                "closed_at": "",
                "frames_count": 0,
                "status": row.get("failure_text") or "observed",
            }
    for item in devtools.get("_websocket_events") or []:
        url = str(item.get("url") or "")
        if not url:
            continue
        row = rows.setdefault(
            url,
            {"url": url, "opened_at": "", "closed_at": "", "frames_count": 0, "status": "observed"},
        )
        row["frames_count"] = max(_int(row.get("frames_count")), _int(item.get("messages_count")))
        row["status"] = str(item.get("status") or row.get("status") or "observed")
    return list(rows.values())[:120]


def _console_messages(devtools: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for value in devtools.get("console_messages") or []:
        if isinstance(value, dict):
            rows.append(
                {
                    "type": str(value.get("type") or "console"),
                    "message": str(value.get("text") or value.get("message") or "")[:500],
                    "location": str(value.get("location") or ""),
                }
            )
        else:
            text = str(value)
            msg_type = text.split(":", 1)[0].strip() if ":" in text else "console"
            rows.append({"type": msg_type, "message": text[:500], "location": ""})
    for value in devtools.get("console_errors") or []:
        text = str(value)
        rows.append({"type": text.split(":", 1)[0].strip() if ":" in text else "error", "message": text[:500], "location": ""})
    return rows[:120]


def _category(url: str, host: str, resource_type: str, content_type: str) -> str:
    lowered = f"{url} {host} {content_type}".lower()
    if resource_type == "websocket" or lowered.startswith(("ws://", "wss://")):
        return "websocket"
    if resource_type == "document":
        return "document"
    if any(hint in lowered for hint in SECURITY_HOST_HINTS):
        return "security"
    if AUTH_PATH_PATTERN.search(lowered):
        return "auth"
    if PAYMENT_PATH_PATTERN.search(lowered):
        return "payment"
    if resource_type in {"xhr", "fetch"} or "application/json" in lowered or API_PATH_PATTERN.search(lowered):
        return "api"
    if any(hint in lowered for hint in CHAT_HOST_HINTS):
        return "chat"
    if any(hint in lowered for hint in ANALYTICS_HOST_HINTS):
        return "analytics"
    if TRACKING_PATH_PATTERN.search(lowered):
        return "tracking"
    if any(hint in lowered for hint in CDN_HOST_HINTS):
        return "cdn"
    if resource_type in {"stylesheet", "script", "image", "font", "media", "manifest"}:
        return "asset"
    return "other"


def _importance(url: str, resource_type: str, category: str, status: Any, index: int) -> str:
    lowered = url.lower()
    if _status_int(status) >= 400:
        return "critical"
    if category in {"document", "auth", "api", "websocket", "payment"}:
        return "critical"
    if resource_type in {"script", "stylesheet"} and index <= 20:
        return "important"
    if CONFIG_PATH_PATTERN.search(lowered):
        return "important"
    if _status_int(status) >= 400 and category in {"api", "auth", "payment"}:
        return "critical"
    if category in {"analytics", "tracking"}:
        return "noise"
    if resource_type in {"image", "font"}:
        return "normal"
    return "normal"


def _display_type(url: str, resource_type: str, category: str, content_type: str) -> str:
    lowered = f"{url} {content_type}".lower()
    if category == "document":
        return "Document"
    if "graphql" in lowered:
        return "GraphQL"
    if category == "auth":
        return "API /auth"
    if PROFILE_PATH_PATTERN.search(lowered):
        return "API /profile"
    if category == "api":
        return "API request"
    if resource_type == "websocket" or lowered.startswith(("ws://", "wss://")):
        return "WebSocket"
    if "application/json" in lowered or CONFIG_PATH_PATTERN.search(lowered):
        return "Config JSON"
    if resource_type == "stylesheet":
        return "Main CSS"
    if resource_type == "script" and "/_next/static/chunks/" in lowered:
        return "Next.js Chunk"
    if resource_type == "script":
        return "Main JavaScript"
    if category in {"analytics", "tracking"}:
        return "Analytics"
    if resource_type == "image":
        return "Image"
    if resource_type == "font":
        return "Font"
    if resource_type == "media":
        return "Media"
    return resource_type.replace("_", " ").title() if resource_type else "Request"


def _notes(url: str, category: str, importance: str, status: Any, row: dict[str, Any]) -> str:
    notes = []
    lowered = url.lower()
    if row.get("failure_text"):
        notes.append(str(row.get("failure_text")))
    if _status_int(status) >= 400:
        notes.append("failed response")
    if "graphql" in lowered:
        notes.append("GraphQL traffic")
    if AUTH_PATH_PATTERN.search(lowered):
        notes.append("auth/session route")
    if PROFILE_PATH_PATTERN.search(lowered):
        notes.append("profile/session data")
    if category in {"analytics", "tracking"}:
        notes.append("tracking/noise candidate")
    if importance == "critical":
        notes.append("critical path candidate")
    return ", ".join(_dedupe(notes))[:300]


def _cookie_names(request_headers: dict[str, Any], response_headers: dict[str, Any]) -> list[str]:
    names = []
    for key, value in {**(request_headers or {}), **(response_headers or {})}.items():
        lowered = str(key).lower()
        raw = str(value or "")
        if lowered == "cookie":
            for part in raw.split(";"):
                name = part.split("=", 1)[0].strip()
                if name and name.lower() != "redacted":
                    names.append(name)
        if lowered == "set-cookie":
            name = raw.split("=", 1)[0].strip()
            if name and name.lower() != "redacted":
                names.append(name)
    return _dedupe(names)[:40]


def _redirected_from(row: dict[str, Any]) -> str:
    raw = row.get("redirected_from") or ""
    if isinstance(raw, dict):
        return sanitize_url(str(raw.get("url") or ""))
    return sanitize_url(str(raw or ""))


def _resource_type(row: dict[str, Any]) -> str:
    raw = str(row.get("resource_type") or "other").lower()
    if raw in {"document", "stylesheet", "script", "image", "font", "xhr", "fetch", "websocket", "media", "manifest", "other"}:
        return raw
    return "other"


def _content_type(row: dict[str, Any]) -> str:
    if row.get("content_type"):
        return str(row.get("content_type") or "").split(";", 1)[0].strip()
    headers = row.get("response_headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            return str(value or "").split(";", 1)[0].strip()
    return ""


def _status_text(status: Any) -> str:
    code = _status_int(status)
    if not code:
        return ""
    try:
        return HTTPStatus(code).phrase
    except Exception:
        return ""


def _status_int(status: Any) -> int:
    try:
        return int(status or 0)
    except Exception:
        return 0


def _int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except Exception:
        return 0


def _host(value: str) -> str:
    parsed = urlparse(str(value or ""))
    if parsed.hostname:
        return parsed.hostname.lower().strip(".")
    return str(value or "").split("/", 1)[0].lower().strip(".")


def _third_party(host: str, base_host: str) -> bool:
    host = (host or "").lower().strip(".")
    base_host = (base_host or "").lower().strip(".")
    if not host or not base_host:
        return False
    return host != base_host and not host.endswith(f".{base_host}")


def _dedupe(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
