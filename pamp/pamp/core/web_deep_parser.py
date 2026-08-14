from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .data_decoder import decode_items, extract_query_values, mask_text, sanitize_url
from .devtools_intelligence import build_devtools_intelligence
from .models import utc_now
from .storage_intelligence import collect_storage_snapshots, storage_keys


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
API_PATH_PATTERN = re.compile(
    r"(?P<endpoint>(?:https?|wss?)://[^\s\"'<>]+|/(?:api/|graphql\b|rest/|v1/|v2/|auth\b|login\b|admin\b|token\b|oauth\b|callback\b|webhook\b|upload\b|download\b)[A-Za-z0-9_./?=&%:+-]*)",
    re.I,
)
MAX_TRAFFIC_REQUESTS = 500
MAX_RESPONSE_PREVIEW_BYTES = 100_000


def parse_web_deep(
    target: str,
    timeout_ms: int = 30_000,
    output_dir: str | Path | None = None,
    traffic_callback: Any | None = None,
) -> dict[str, Any]:
    started_at = time.perf_counter()
    url = _target_url(target)
    errors: list[str] = []
    network: dict[int, dict[str, Any]] = {}
    console_errors: list[str] = []
    console_messages: list[dict[str, str]] = []
    page_errors: list[str] = []
    decoder_inputs: list[dict[str, str]] = []
    websocket_events: list[dict[str, Any]] = []
    current_page = {"url": url}
    counters = {"sequence": 0}
    lifecycle: dict[str, int] = {}

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        return {
            "available": False,
            "url": url,
            "errors": ["playwright is not installed"],
            "network_requests": [],
            "cookies_names": [],
            "console_errors": [],
        }

    def on_request(request: Any) -> None:
        if len(network) >= MAX_TRAFFIC_REQUESTS:
            return
        counters["sequence"] += 1
        safe_url = sanitize_url(request.url)
        headers = _sanitize_headers(request.headers)
        post_data = _safe_post_data(request)
        network[id(request)] = {
            "id": counters["sequence"],
            "sequence": counters["sequence"],
            "method": request.method,
            "url": safe_url,
            "status": None,
            "resource_type": request.resource_type,
            "request_headers": headers,
            "response_headers": {},
            "referer": headers.get("referer") or headers.get("Referer") or "",
            "initiator": _request_frame_url(request),
            "timestamp": utc_now(),
            "start_time": utc_now(),
            "end_time": "",
            "source_page": sanitize_url(current_page.get("url") or url),
            "post_data_preview": mask_text(post_data[:1000]) if post_data else "",
            "post_data_size": len(post_data),
            "redirected_from": _request_redirected_from(request),
            "from_cache": False,
            "_started_perf": time.perf_counter(),
        }
        decoder_inputs.append({"value": request.url, "source": "devtools network url"})
        decoder_inputs.extend(extract_query_values(request.url, "devtools network url"))

    def on_response(response: Any) -> None:
        request = response.request
        item = network.setdefault(
            id(request),
            {
                "method": request.method,
                "url": sanitize_url(request.url),
                "status": None,
                "resource_type": request.resource_type,
                "request_headers": _sanitize_headers(request.headers),
                "response_headers": {},
                "timestamp": utc_now(),
                "start_time": utc_now(),
                "end_time": "",
                "source_page": sanitize_url(current_page.get("url") or url),
                "_started_perf": time.perf_counter(),
            },
        )
        response_headers = _sanitize_headers(response.headers)
        item["status"] = response.status
        item["status_text"] = _safe_status_text(response)
        item["response_headers"] = response_headers
        item["content_type"] = _header_value(response_headers, "content-type").split(";", 1)[0].strip()
        item["response_size"] = _int_header(response_headers, "content-length")
        item["from_cache"] = _safe_from_cache(response)
        item["end_time"] = utc_now()
        started = item.get("_started_perf")
        if isinstance(started, (int, float)):
            item["duration"] = int((time.perf_counter() - started) * 1000)
            item["duration_ms"] = item["duration"]
        _capture_response_preview(response, item, errors)
        if not item.get("_traffic_emitted"):
            item["_traffic_emitted"] = True
            _emit_traffic_event(traffic_callback, _public_network_item(item), errors)

    def on_request_failed(request: Any) -> None:
        item = network.get(id(request))
        if item is None:
            return
        item["end_time"] = utc_now()
        item["failure_text"] = _request_failure_text(request)
        started = item.get("_started_perf")
        if isinstance(started, (int, float)):
            item["duration"] = int((time.perf_counter() - started) * 1000)
            item["duration_ms"] = item["duration"]
        if not item.get("_traffic_emitted"):
            item["_traffic_emitted"] = True
            _emit_traffic_event(traffic_callback, _public_network_item(item), errors)

    def on_console(message: Any) -> None:
        row = {
            "type": str(message.type or "console"),
            "text": str(message.text or "")[:500],
            "location": _console_location(message),
        }
        console_messages.append(row)
        if message.type in {"error", "warning"}:
            console_errors.append(f"{message.type}: {message.text}"[:500])

    def on_page_error(error: Any) -> None:
        page_errors.append(str(error)[:500])

    def on_frame_navigated(frame: Any) -> None:
        try:
            if frame == page.main_frame:
                current_page["url"] = sanitize_url(frame.url)
        except Exception:
            pass

    def on_websocket(websocket: Any) -> None:
        row = {
            "url": sanitize_url(websocket.url),
            "protocol": "wss" if str(websocket.url).startswith("wss://") else "ws",
            "source_page": sanitize_url(current_page.get("url") or url),
            "messages_count": 0,
            "status": "open",
        }
        websocket_events.append(row)
        try:
            websocket.on("framesent", lambda _frame: _increment_ws(row))
            websocket.on("framereceived", lambda _frame: _increment_ws(row))
            websocket.on("close", lambda *_args: row.update({"status": "closed"}))
        except Exception as exc:
            errors.append(f"websocket event hook: {exc}")

    browser = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Pamp/1.0",
                viewport={"width": 1366, "height": 768},
            )
            page = context.new_page()
            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfailed", on_request_failed)
            page.on("console", on_console)
            page.on("websocket", on_websocket)
            page.on("pageerror", on_page_error)
            page.on("framenavigated", on_frame_navigated)
            page.on("domcontentloaded", lambda: lifecycle.setdefault("domcontentloaded_ms", int((time.perf_counter() - started_at) * 1000)))
            page.on("load", lambda: lifecycle.setdefault("load_ms", int((time.perf_counter() - started_at) * 1000)))
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                current_page["url"] = page.url
                if response is not None and response.status >= 400:
                    errors.append(f"main document status {response.status}")
                try:
                    page.wait_for_load_state("networkidle", timeout=5_000)
                    lifecycle.setdefault("network_idle_ms", int((time.perf_counter() - started_at) * 1000))
                    page.wait_for_timeout(3_000)
                except PlaywrightTimeoutError:
                    errors.append("network idle timeout")
            except PlaywrightTimeoutError as exc:
                errors.append(f"timeout: {exc}")
            except PlaywrightError as exc:
                errors.append(f"navigation: {exc}")

            dom = _evaluate_dom(page, errors)
            cookies = context.cookies()
            storage = collect_storage_snapshots(page, sanitize_url(page.url), errors)
            html = ""
            try:
                html = page.content()[:250_000]
            except Exception:
                pass
            traffic_requests = sorted(
                [_public_network_item(item) for item in network.values()],
                key=lambda item: int(item.get("sequence") or 999999),
            )[:MAX_TRAFFIC_REQUESTS]
            requests = traffic_requests
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            lifecycle.setdefault("total_ms", duration_ms)
            intelligence = build_devtools_intelligence(
                base_url=url,
                final_url=sanitize_url(page.url),
                network_requests=requests,
                cookies=cookies,
                storage=storage,
                html=html,
                websocket_events=websocket_events,
                console_errors=console_errors,
                errors=errors,
                duration_ms=duration_ms,
            )
            normalized_requests = (intelligence.get("network") or {}).get("requests") or requests
            loaded_js = sorted({item["url"] for item in requests if item.get("resource_type") == "script"})
            loaded_css = sorted({item["url"] for item in requests if item.get("resource_type") == "stylesheet"})
            websocket_urls = sorted(
                {
                    item["url"]
                    for item in requests
                    if item.get("resource_type") == "websocket" or str(item.get("url") or "").startswith(("ws://", "wss://"))
                }
            )
            request_domains = sorted({_hostname(item.get("url", "")) for item in normalized_requests if _hostname(item.get("url", ""))})
            api_endpoints = intelligence.get("legacy_api_endpoints") or _network_api_endpoints(normalized_requests)
            api_candidates = sorted({item["endpoint"] for item in api_endpoints})
            local_storage_keys = storage_keys(storage.get("localStorage") or [])
            session_storage_keys = storage_keys(storage.get("sessionStorage") or [])
            combined = "\n".join(
                [html]
                + [item.get("url", "") for item in normalized_requests]
                + [str(item.get("response_headers", "")) for item in normalized_requests]
            )
            decoder_inputs.extend(_decoder_inputs_from_devtools(dom, cookies, normalized_requests))
            decoder_inputs.extend({"value": key, "source": "devtools localStorage key"} for key in local_storage_keys)
            decoder_inputs.extend({"value": key, "source": "devtools sessionStorage key"} for key in session_storage_keys)
            screenshot = _capture_screenshots(page, page.url, output_dir, errors)

            result = {
                "available": True,
                "url": url,
                "final_url": sanitize_url(page.url),
                "title": _safe_page_title(page),
                "duration_ms": duration_ms,
                "network_requests": normalized_requests[:500],
                "traffic_requests": traffic_requests[:MAX_TRAFFIC_REQUESTS],
                "lifecycle": lifecycle,
                "request_domains": request_domains[:250],
                "cookies_names": sorted({cookie.get("name", "") for cookie in cookies if cookie.get("name")}),
                "console_errors": console_errors[:100],
                "console_messages": console_messages[:120],
                "page_errors": page_errors[:80],
                "loaded_js": loaded_js[:200],
                "loaded_css": loaded_css[:200],
                "websocket_urls": websocket_urls[:100],
                "localStorage_keys": local_storage_keys,
                "sessionStorage_keys": session_storage_keys,
                "localStorage": storage.get("localStorage") or [],
                "sessionStorage": storage.get("sessionStorage") or [],
                "indexedDB": storage.get("indexedDB") or [],
                "cacheStorage": storage.get("cacheStorage") or [],
                "dom_links": dom.get("links", [])[:300],
                "forms": dom.get("forms", [])[:80],
                "inputs": dom.get("inputs", [])[:200],
                "meta_tags": dom.get("meta_tags", [])[:120],
                "technologies": _detect(TECH_PATTERNS, combined),
                "trackers": _detect(TRACKER_PATTERNS, combined),
                "api_endpoint_candidates": api_candidates[:200],
                "api_endpoints": api_endpoints[:250],
                "decoded_classified_artifacts": decode_items(decoder_inputs, limit=150),
                "cloudflare_page": _cloudflare_page(combined, page.url),
                "screenshot": screenshot,
                "errors": errors,
            }
            _merge_intelligence(result, intelligence)
            return result
    except Exception as exc:
        errors.append(str(exc))
        return {
            "available": False,
            "url": url,
            "errors": errors,
            "network_requests": list(network.values())[:400],
            "traffic_requests": sorted(
                [_public_network_item(item) for item in network.values()],
                key=lambda item: int(item.get("sequence") or 999999),
            )[:MAX_TRAFFIC_REQUESTS],
            "cookies_names": [],
            "console_errors": console_errors[:100],
            "console_messages": console_messages[:120],
            "page_errors": page_errors[:80],
        }
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


def _target_url(target: str) -> str:
    raw = target.strip()
    return raw if "://" in raw else f"https://{raw}"


def _capture_screenshots(
    page: Any,
    page_url: str,
    output_dir: str | Path | None,
    errors: list[str],
) -> dict[str, Any]:
    if not output_dir:
        return {}
    root = Path(output_dir).expanduser().resolve()
    screenshot_dir = root / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    host = (urlparse(page_url).hostname or "target").lower()
    safe_host = re.sub(r"[^a-z0-9._-]+", "_", host).strip("._") or "target"
    full_name = f"{safe_host}_full.png"
    preview_name = f"{safe_host}_preview.jpg"
    thumbnail_name = f"{safe_host}_thumb.jpg"
    full_path = screenshot_dir / full_name
    preview_path = screenshot_dir / preview_name
    thumbnail_path = screenshot_dir / thumbnail_name
    try:
        page.screenshot(path=str(full_path), full_page=True, type="png")
        page.screenshot(path=str(preview_path), full_page=False, type="jpeg", quality=82)
        page.set_viewport_size({"width": 480, "height": 300})
        page.screenshot(path=str(thumbnail_path), full_page=False, type="jpeg", quality=76)
        return {
            "available": True,
            "url": sanitize_url(page_url),
            "png": f"screenshots/{full_name}",
            "preview": f"screenshots/{preview_name}",
            "thumbnail": f"screenshots/{thumbnail_name}",
            "captured_at": utc_now(),
            "viewport": "1366x768",
        }
    except Exception as exc:
        errors.append(f"screenshot: {exc}")
        return {"available": False, "url": sanitize_url(page_url), "error": str(exc)}


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    blocked = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
    return {
        key: ("redacted" if key.lower() in blocked else mask_text(value))
        for key, value in headers.items()
    }


def _merge_intelligence(result: dict[str, Any], intelligence: dict[str, Any]) -> None:
    result["devtools_intelligence"] = intelligence
    result["network_intelligence"] = intelligence.get("network") or {}
    result["api_intelligence"] = intelligence.get("api") or {}
    result["graphql_intelligence"] = intelligence.get("graphql") or []
    result["websocket_intelligence"] = intelligence.get("websockets") or []
    result["storage_intelligence"] = intelligence.get("storage") or {}
    result["cookie_intelligence"] = intelligence.get("cookies") or []
    result["javascript_intelligence"] = intelligence.get("javascript") or {}
    result["security_headers_intelligence"] = intelligence.get("security_headers") or []
    result["third_party_services"] = intelligence.get("third_party_services") or []
    result["interesting_findings"] = intelligence.get("interesting_findings") or []
    result["statistics"] = intelligence.get("statistics") or {}
    result["discovery_seeds"] = intelligence.get("discovery_seeds") or []


def _public_network_item(item: dict[str, Any]) -> dict[str, Any]:
    output = dict(item)
    output.pop("_started_perf", None)
    return output


def _safe_post_data(request: Any) -> str:
    try:
        return request.post_data or ""
    except Exception:
        return ""


def _request_redirected_from(request: Any) -> str:
    try:
        previous = request.redirected_from
        return sanitize_url(previous.url) if previous is not None else ""
    except Exception:
        return ""


def _request_failure_text(request: Any) -> str:
    try:
        failure = request.failure
        if callable(failure):
            failure = failure()
        if isinstance(failure, dict):
            return str(failure.get("errorText") or failure.get("error_text") or "")[:300]
        return str(failure or "")[:300]
    except Exception:
        return ""


def _safe_status_text(response: Any) -> str:
    try:
        return str(response.status_text or "")
    except Exception:
        return ""


def _safe_from_cache(response: Any) -> bool:
    try:
        return bool(response.from_service_worker)
    except Exception:
        return False


def _capture_response_preview(response: Any, item: dict[str, Any], errors: list[str]) -> None:
    content_type = str(item.get("content_type") or "").lower()
    resource_type = str(item.get("resource_type") or "")
    if not (
        "json" in content_type
        or content_type.startswith("text/")
        or resource_type in {"document", "xhr", "fetch", "manifest"}
    ):
        return
    size = int(item.get("response_size") or 0)
    if size > MAX_RESPONSE_PREVIEW_BYTES:
        return
    try:
        text = response.text()
    except Exception as exc:
        errors.append(f"response preview {item.get('url')}: {exc}")
        return
    if text:
        item["response_preview"] = mask_text(text[:MAX_RESPONSE_PREVIEW_BYTES])


def _emit_traffic_event(callback: Any | None, item: dict[str, Any], errors: list[str]) -> None:
    if callback is None:
        return
    try:
        callback(item)
    except Exception as exc:
        errors.append(f"traffic callback: {exc}")


def _console_location(message: Any) -> str:
    try:
        location = message.location or {}
        return ":".join(str(location.get(key) or "") for key in ("url", "lineNumber", "columnNumber")).strip(":")
    except Exception:
        return ""


def _request_frame_url(request: Any) -> str:
    try:
        return sanitize_url(request.frame.url)
    except Exception:
        return ""


def _header_value(headers: dict[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value or "")
    return ""


def _int_header(headers: dict[str, Any], name: str) -> int:
    try:
        return int(_header_value(headers, name))
    except Exception:
        return 0


def _increment_ws(row: dict[str, Any]) -> None:
    row["messages_count"] = int(row.get("messages_count") or 0) + 1


def _evaluate_dom(page: Any, errors: list[str]) -> dict[str, Any]:
    script = """
    () => ({
      links: Array.from(document.links).map(a => a.href).filter(Boolean),
      forms: Array.from(document.forms).map(form => ({
        action: form.action || "",
        method: (form.method || "get").toUpperCase(),
        input_names: Array.from(form.querySelectorAll("input, textarea, select")).map(el => el.name || el.id || el.type || "").filter(Boolean),
        hidden_input_names: Array.from(form.querySelectorAll("input[type=hidden]")).map(el => el.name || el.id || "").filter(Boolean)
      })),
      inputs: Array.from(document.querySelectorAll("input, textarea, select")).map(el => ({
        name: el.name || "",
        id: el.id || "",
        type: el.type || el.tagName.toLowerCase()
      })),
      meta_tags: Array.from(document.querySelectorAll("meta")).map(el => ({
        name: el.getAttribute("name") || el.getAttribute("property") || "",
        content: el.getAttribute("content") || ""
      }))
    })
    """
    try:
        return page.evaluate(script)
    except Exception as exc:
        errors.append(f"dom evaluation: {exc}")
        return {"links": [], "forms": [], "inputs": [], "meta_tags": []}


def _storage_keys(page: Any, storage_name: str, errors: list[str]) -> list[str]:
    try:
        return page.evaluate(f"() => Object.keys(window.{storage_name})")
    except Exception as exc:
        errors.append(f"{storage_name}: {exc}")
        return []


def _safe_page_title(page: Any) -> str:
    try:
        return page.title()
    except Exception:
        return ""


def _detect(patterns: dict[str, tuple[str, ...]], text: str) -> list[str]:
    lowered = text.lower()
    return sorted(
        name
        for name, hints in patterns.items()
        if any(hint.lower() in lowered for hint in hints)
    )


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _cloudflare_page(text: str, final_url: str) -> bool:
    lowered = f"{text}\n{final_url}".lower()
    return any(
        hint in lowered
        for hint in (
            "checking your browser",
            "just a moment",
            "cf-chl",
            "cloudflare ray id",
            "verify you are human",
        )
    )


def _network_api_endpoints(requests: list[dict[str, Any]]) -> list[dict[str, str]]:
    endpoints = []
    seen = set()
    for item in requests:
        url = item.get("url") or ""
        method = item.get("method") or ""
        resource_type = item.get("resource_type") or ""
        if resource_type in {"fetch", "xhr"} or API_PATH_PATTERN.search(url):
            endpoint = sanitize_url(url)
            key = f"{method}|{endpoint}"
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(
                {
                    "endpoint": endpoint,
                    "source_file": "devtools network",
                    "method": method,
                    "risk": _endpoint_risk(endpoint),
                    "notes": "network request" if resource_type in {"fetch", "xhr"} else "endpoint pattern",
                }
            )
    return endpoints


def _decoder_inputs_from_devtools(
    dom: dict[str, Any],
    cookies: list[dict[str, Any]],
    requests: list[dict[str, Any]],
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for cookie in cookies:
        if cookie.get("name"):
            items.append({"value": cookie["name"], "source": "devtools cookie name"})
    for key in ("links",):
        for value in dom.get(key, []) or []:
            items.append({"value": value, "source": f"devtools dom {key}"})
            items.extend(extract_query_values(value, f"devtools dom {key}"))
    for form in dom.get("forms", []) or []:
        if form.get("action"):
            items.append({"value": form["action"], "source": "devtools form action"})
    for item in dom.get("inputs", []) or []:
        for key in ("name", "id", "type"):
            if item.get(key):
                items.append({"value": item[key], "source": f"devtools input {key}"})
    for request in requests:
        items.append({"value": request.get("url", ""), "source": "devtools network url"})
        for headers_key in ("request_headers", "response_headers"):
            for header_key, header_value in (request.get(headers_key) or {}).items():
                items.append({"value": header_key, "source": f"devtools {headers_key}"})
                items.append({"value": header_value, "source": f"devtools {headers_key}:{header_key}"})
    return items


def _endpoint_risk(value: str) -> str:
    lowered = value.lower()
    return "Medium" if any(item in lowered for item in ("/auth", "/login", "/admin", "/token", "/oauth", "/callback", "/webhook", "token=", "key=")) else "Low"
