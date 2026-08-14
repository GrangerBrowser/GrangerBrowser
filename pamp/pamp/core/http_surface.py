from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import requests

from .report_intelligence import build_response_comparison


HTTP_TIMEOUT = 8
MAIN_REDIRECTS = 3
PATH_REDIRECTS = 2
MAX_BODY_BYTES = 520_000
USER_AGENT = "Pamp/Domain-Analyzer"
INTERESTING_STATUSES = {200, 301, 302, 401, 403}
INTERESTING_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/admin",
    "/login",
    "/wp-login.php",
    "/phpinfo.php",
)
MISSING_SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS",
    "content-security-policy": "Missing CSP",
    "x-frame-options": "Missing X-Frame-Options",
    "x-content-type-options": "Missing X-Content-Type-Options",
    "referrer-policy": "Missing Referrer-Policy",
    "permissions-policy": "Missing Permissions-Policy",
}


try:
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


DebugLog = Callable[[str], None]


def analyze_http_surface(
    host: str,
    original_input: str = "",
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    errors: list[str] = []
    probes = [_probe_scheme(session, host, scheme, debug_log, errors) for scheme in ("https", "http")]
    primary = _choose_primary_probe(probes)
    tls_info = _tls_info(host, debug_log, errors)

    html = primary.get("_body_text") or ""
    primary_url = primary.get("final_url") or primary.get("url") or ""
    favicon_url = _favicon_url(html, primary_url) if primary_url else ""
    favicon = _fetch_favicon(session, favicon_url, primary.get("_verify", True), debug_log, errors) if favicon_url else {"url": "", "hash": None}
    interesting_paths = _check_interesting_paths(session, primary_url, primary.get("_verify", True), debug_log, errors)

    surface = {
        "primary_url": primary_url,
        "probes": [_public_probe(probe) for probe in probes],
        "status_code": primary.get("status_code"),
        "final_url": primary.get("final_url") or "",
        "scheme": primary.get("scheme") or "",
        "title": _extract_title(html),
        "meta_generator": _extract_meta_generator(html),
        "headers": primary.get("headers") or {},
        "cookies": primary.get("cookies") or [],
        "cookie_names": sorted({item.get("name") for item in primary.get("cookies") or [] if item.get("name")}),
        "redirect_chain": primary.get("redirect_chain") or [],
        "response_time_ms": primary.get("response_time_ms"),
        "content_length": primary.get("content_length"),
        "content_type": primary.get("content_type") or "",
        "server": (primary.get("headers") or {}).get("Server") or (primary.get("headers") or {}).get("server") or "",
        "x_powered_by": (primary.get("headers") or {}).get("X-Powered-By") or (primary.get("headers") or {}).get("x-powered-by") or "",
        "favicon": favicon,
        "body_hash": primary.get("body_hash"),
        "tls_enabled": bool(tls_info or primary.get("scheme") == "https" or _any_https_live(probes)),
        "tls_issuer": tls_info.get("issuer") or "",
        "tls_expires": tls_info.get("expires") or "",
        "tls": tls_info,
        "interesting_paths": interesting_paths,
        "response_comparison": build_response_comparison([_public_probe(probe) for probe in probes]),
        "errors": errors,
        "_html": html if _looks_html(primary.get("content_type") or "", html) else "",
        "_body_text": html,
    }
    surface["security_signals"] = detect_security_signals(surface, html, interesting_paths)
    surface["analyst_notes"] = analyst_notes(surface)
    session.close()
    return surface


def detect_security_signals(
    http_surface: dict[str, Any],
    body_text: str = "",
    interesting_paths: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    headers = {str(key).lower(): str(value) for key, value in (http_surface.get("headers") or {}).items()}

    def add(level: str, name: str, evidence: str, source: str) -> None:
        key = (level, name, evidence, source)
        if key in seen:
            return
        seen.add(key)
        signals.append({"level": level, "name": name, "evidence": evidence[:220], "source": source})

    seen: set[tuple[str, str, str, str]] = set()
    if http_surface.get("status_code") is not None:
        for header, name in MISSING_SECURITY_HEADERS.items():
            if header not in headers:
                add("warn", name, f"{header} header not present", "headers")
    if headers.get("access-control-allow-origin", "").strip() == "*":
        add("warn", "Wildcard CORS", "Access-Control-Allow-Origin is *", "headers")

    for cookie in http_surface.get("cookies") or []:
        name = str(cookie.get("name") or "cookie")
        if not cookie.get("httponly"):
            add("warn", "Cookie without HttpOnly", f"{name} missing HttpOnly", "cookies")
        if http_surface.get("scheme") == "https" and not cookie.get("secure"):
            add("warn", "Cookie without Secure", f"{name} missing Secure", "cookies")
        if not cookie.get("samesite"):
            add("warn", "Cookie without SameSite", f"{name} missing SameSite", "cookies")

    lowered = (body_text or "").lower()
    if re.search(r"(traceback \(most recent call last\)|stack trace|fatal error|uncaught exception|exception in thread|warning: mysql|postgresql error)", lowered, re.I):
        add("high", "Stack trace marker", "Error or stack trace marker found in response body", "content")
    if re.search(r"(xdebug|var_dump\(|debug mode|django debug|development mode|app_debug\s*=\s*true)", lowered, re.I):
        add("warn", "Debug marker", "Debug/development marker found in response body", "content")
    if re.search(r"(welcome to nginx|apache2 ubuntu default page|iis windows server|litespeed web server)", lowered, re.I):
        add("info", "Default server page", "Default web server page marker found", "content")
    if re.search(r"<title>\s*index of\s*/|<h1>\s*index of\s*/|\bindex of /", lowered, re.I):
        add("high", "Directory listing", "Index of / marker found", "content")
    if re.search(r"(login|sign in|wp-login|user/login)", lowered, re.I):
        add("info", "Login panel hint", "Login marker found in response body", "content")
    if re.search(r"(/admin\b|admin panel|administrator)", lowered, re.I):
        add("warn", "Admin panel hint", "Admin marker found in response body", "content")
    if re.search(r"(swagger-ui|swagger.json|openapi.json|openapi:)", lowered, re.I):
        add("warn", "Swagger/OpenAPI hint", "Swagger/OpenAPI marker found in response body", "content")
    if "graphql" in lowered:
        add("warn", "GraphQL hint", "GraphQL marker found in response body", "content")
    if re.search(r"(db_password|database_url|app_key|aws_secret_access_key)\s*=", lowered, re.I):
        add("high", "Exposed environment hint", "Environment-style secret key marker found", "content")
    if "phpinfo()" in lowered or "php version" in lowered and "_server" in lowered:
        add("high", "phpinfo hint", "phpinfo marker found in response body", "content")

    for row in interesting_paths or []:
        path = str(row.get("path") or "")
        status = str(row.get("status") or "")
        if path in {"/swagger", "/swagger-ui", "/api-docs", "/openapi.json"}:
            add("warn", "Reachable API docs", f"{path} returned {status}", "interesting_paths")
        elif path == "/graphql":
            add("warn", "Reachable GraphQL path", f"{path} returned {status}", "interesting_paths")
        elif path in {"/admin", "/login", "/wp-login.php"}:
            add("info", "Reachable login/admin path", f"{path} returned {status}", "interesting_paths")
        elif path == "/phpinfo.php" and status == "200":
            add("high", "Reachable phpinfo", "/phpinfo.php returned 200", "interesting_paths")
    return signals[:120]


def analyst_notes(http_surface: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    primary = str(http_surface.get("primary_url") or "")
    if not primary:
        return ["No live HTTP service detected, DNS data only."]
    if primary.startswith("https://"):
        notes.append("HTTPS is available and selected as primary surface.")
    if _has_http_to_https_redirect(http_surface.get("redirect_chain") or [], http_surface.get("probes") or []):
        notes.append("Domain redirects from HTTP to HTTPS.")

    high_tech = [
        item.get("name")
        for item in http_surface.get("technologies") or []
        if item.get("confidence") == "high" and item.get("name")
    ]
    if high_tech:
        notes.append(f"{high_tech[0]} markers detected with high confidence.")
    if any(item.get("name") == "Missing CSP" for item in http_surface.get("security_signals") or []):
        notes.append("Missing CSP header increases clickjacking/XSS exposure context.")
    if any((item.get("path") or "") in {"/swagger", "/swagger-ui", "/api-docs", "/openapi.json"} for item in http_surface.get("interesting_paths") or []):
        notes.append("Swagger/OpenAPI path is reachable and should be reviewed manually.")
    if any((item.get("path") or "") in {"/admin", "/login", "/wp-login.php"} for item in http_surface.get("interesting_paths") or []):
        notes.append("Login panel detected, manual access control review recommended.")
    high_count = sum(1 for item in http_surface.get("security_signals") or [] if item.get("level") == "high")
    if high_count:
        notes.append(f"{high_count} high-level passive security signal(s) need manual validation.")
    return _unique(notes)[:12]


def _probe_scheme(
    session: requests.Session,
    host: str,
    scheme: str,
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any]:
    url = f"{scheme}://{host}"
    verify = True
    try:
        head = _request_with_redirects(session, "HEAD", url, MAIN_REDIRECTS, verify=verify, read_body=False)
    except requests.exceptions.SSLError as exc:
        _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={exc}")
        verify = False
        try:
            head = _request_with_redirects(session, "HEAD", url, MAIN_REDIRECTS, verify=verify, read_body=False)
        except Exception as retry_exc:
            _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={retry_exc}")
            return _dead_probe(scheme, url, str(retry_exc))
    except Exception as exc:
        _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={exc}")
        head = None

    head_status = _result_status(head)
    get_needed = head is None or int(head_status or 0) in {400, 403, 405, 501} or _head_suggests_html(head)
    if get_needed:
        try:
            get = _request_with_redirects(session, "GET", url, MAIN_REDIRECTS, verify=verify, read_body=True)
            return _build_probe(scheme, url, get, verify, head)
        except requests.exceptions.SSLError as exc:
            _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={exc}")
            try:
                get = _request_with_redirects(session, "GET", url, MAIN_REDIRECTS, verify=False, read_body=True)
                return _build_probe(scheme, url, get, False, head)
            except Exception as retry_exc:
                _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={retry_exc}")
        except Exception as exc:
            _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={exc}")
    if head is not None:
        return _build_probe(scheme, url, head, verify, head)
    return _dead_probe(scheme, url, "no response")


def _request_with_redirects(
    session: requests.Session,
    method: str,
    url: str,
    max_redirects: int,
    *,
    verify: bool,
    read_body: bool,
) -> dict[str, Any]:
    chain: list[dict[str, Any]] = []
    current_url = url
    started = time.perf_counter()
    response: requests.Response | None = None
    body = b""
    for _ in range(max_redirects + 1):
        response = session.request(
            method,
            current_url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=verify,
        )
        location = response.headers.get("Location")
        if response.is_redirect and location and len(chain) < max_redirects:
            next_url = urljoin(current_url, location)
            chain.append({"from": current_url, "to": next_url, "status": response.status_code})
            response.close()
            current_url = next_url
            continue
        if read_body and method.upper() != "HEAD":
            body = _read_limited(response)
        response.close()
        break
    if response is None:
        raise requests.RequestException("empty response")
    elapsed_ms = int(round((time.perf_counter() - started) * 1000))
    return {
        "response": response,
        "body": body,
        "redirect_chain": chain,
        "elapsed_ms": elapsed_ms,
        "final_url": response.url or current_url,
        "method": method.upper(),
    }


def _read_limited(response: requests.Response) -> bytes:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:MAX_BODY_BYTES]


def _build_probe(
    scheme: str,
    url: str,
    result: dict[str, Any],
    verify: bool,
    head: dict[str, Any] | None,
) -> dict[str, Any]:
    response: requests.Response = result["response"]
    body = result.get("body") or b""
    headers = _sanitize_headers(dict(response.headers), _cookie_names_from_headers(response))
    text = _decode_body(body, response)
    content_length = headers.get("Content-Length") or str(len(body) if body else "")
    cookies = _extract_cookies(response)
    return {
        "scheme": scheme,
        "url": url,
        "live": True,
        "method": result.get("method") or "",
        "head_status_code": _result_status(head),
        "status_code": response.status_code,
        "final_url": result.get("final_url") or response.url,
        "redirect_chain": result.get("redirect_chain") or [],
        "response_time_ms": result.get("elapsed_ms"),
        "content_length": _int_or_text(content_length),
        "content_type": headers.get("Content-Type") or "",
        "headers": headers,
        "cookies": cookies,
        "cookie_names": sorted({item.get("name") for item in cookies if item.get("name")}),
        "title": _extract_title(text),
        "body_hash": hashlib.sha256(body).hexdigest() if body else None,
        "_body_text": text,
        "_verify": verify,
    }


def _dead_probe(scheme: str, url: str, error: str) -> dict[str, Any]:
    return {
        "scheme": scheme,
        "url": url,
        "live": False,
        "method": "",
        "status_code": None,
        "final_url": "",
        "redirect_chain": [],
        "response_time_ms": None,
        "content_length": None,
        "content_type": "",
        "headers": {},
        "cookies": [],
        "body_hash": None,
        "error": error,
    }


def _choose_primary_probe(probes: list[dict[str, Any]]) -> dict[str, Any]:
    https = next((probe for probe in probes if probe.get("scheme") == "https" and probe.get("live")), None)
    if https:
        return https
    http = next((probe for probe in probes if probe.get("scheme") == "http" and probe.get("live")), None)
    return http or {}


def _public_probe(probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "scheme": probe.get("scheme") or "",
        "url": probe.get("url") or "",
        "live": bool(probe.get("live")),
        "method": probe.get("method") or "",
        "head_status_code": probe.get("head_status_code"),
        "status_code": probe.get("status_code"),
        "final_url": probe.get("final_url") or "",
        "redirect_chain": probe.get("redirect_chain") or [],
        "response_time_ms": probe.get("response_time_ms"),
        "content_length": probe.get("content_length"),
        "content_type": probe.get("content_type") or "",
        "server": (probe.get("headers") or {}).get("Server") or "",
        "headers": probe.get("headers") or {},
        "cookies": probe.get("cookies") or [],
        "cookie_names": probe.get("cookie_names") or [],
        "title": probe.get("title"),
        "error": probe.get("error") or "",
    }


def _head_suggests_html(result: dict[str, Any]) -> bool:
    if not result:
        return True
    response: requests.Response = result["response"]
    content_type = response.headers.get("Content-Type", "").lower()
    return "text/html" in content_type or not content_type


def _result_status(result: dict[str, Any] | None) -> int | None:
    if not result:
        return None
    response = result.get("response")
    return getattr(response, "status_code", None)


def _decode_body(body: bytes, response: requests.Response) -> str:
    if not body:
        return ""
    encoding = response.encoding or requests.utils.get_encoding_from_headers(response.headers) or "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _looks_html(content_type: str, body_text: str) -> bool:
    lowered = (content_type or "").lower()
    return "text/html" in lowered or "<html" in (body_text or "")[:1000].lower()


def _extract_title(body_text: str) -> str | None:
    if not body_text:
        return None
    match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
    if not match:
        return None
    title = re.sub(r"\s+", " ", _strip_tags(match.group(1))).strip()
    return title[:120] if title else None


def _extract_meta_generator(body_text: str) -> str | None:
    if not body_text:
        return None
    match = re.search(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
        body_text,
        re.I,
    ) or re.search(
        r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']",
        body_text,
        re.I,
    )
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160] if match else None


def _strip_tags(value: str) -> str:
    return re.sub(r"<[^>]+>", "", value or "")


def _favicon_url(body_text: str, base_url: str) -> str:
    if body_text and base_url:
        for match in re.finditer(r"<link\b[^>]*>", body_text, re.I):
            tag = match.group(0)
            rel_match = re.search(r"\brel=[\"']([^\"']+)[\"']", tag, re.I)
            if not rel_match:
                continue
            rel = rel_match.group(1).lower()
            if "icon" not in rel:
                continue
            href_match = re.search(r"\bhref=[\"']([^\"']+)[\"']", tag, re.I)
            if href_match:
                return urljoin(base_url, href_match.group(1).strip())
    return urljoin(base_url, "/favicon.ico") if base_url else ""


def _fetch_favicon(
    session: requests.Session,
    url: str,
    verify: bool,
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any]:
    try:
        result = _request_with_redirects(session, "GET", url, PATH_REDIRECTS, verify=verify, read_body=True)
        response: requests.Response = result["response"]
        body = result.get("body") or b""
        if response.status_code >= 400 or not body:
            return {"url": url, "hash": None}
        return {
            "url": result.get("final_url") or url,
            "hash": hashlib.sha256(body).hexdigest(),
            "hash_type": "sha256",
            "mime_type": response.headers.get("Content-Type", "").split(";", 1)[0],
            "size": len(body),
            "match": _favicon_catalog_match(url),
        }
    except Exception as exc:
        _record_error(errors, debug_log, "[DOMAIN][HTTP]", f"target={url} error={exc}")
        return {"url": url, "hash": None}


def _check_interesting_paths(
    session: requests.Session,
    primary_url: str,
    verify: bool,
    debug_log: DebugLog | None,
    errors: list[str],
) -> list[dict[str, Any]]:
    if not primary_url:
        return []
    base = f"{urlparse(primary_url).scheme}://{urlparse(primary_url).netloc}"
    worker_count = min(6, len(INTERESTING_PATHS))
    chunks = [INTERESTING_PATHS[index::worker_count] for index in range(worker_count)]
    headers = dict(session.headers)
    cookies = requests.utils.dict_from_cookiejar(session.cookies)

    def check_chunk(paths: tuple[str, ...]) -> list[dict[str, Any]]:
        worker_session = requests.Session()
        worker_session.headers.update(headers)
        worker_session.cookies.update(cookies)
        try:
            return [
                row
                for path in paths
                if (row := _check_interesting_path(worker_session, base, path, verify, debug_log, errors))
            ]
        finally:
            worker_session.close()

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="pamp-http-path") as executor:
        rows = [row for chunk_rows in executor.map(check_chunk, chunks) for row in chunk_rows]
    order = {path: index for index, path in enumerate(INTERESTING_PATHS)}
    rows.sort(key=lambda row: order.get(str(row.get("path") or ""), len(order)))
    return rows


def _check_interesting_path(
    session: requests.Session,
    base: str,
    path: str,
    verify: bool,
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any] | None:
    url = urljoin(base, path)
    try:
        result = _request_with_redirects(session, "GET", url, PATH_REDIRECTS, verify=verify, read_body=True)
        response: requests.Response = result["response"]
        if response.status_code in INTERESTING_STATUSES:
            return {
                "path": path,
                "url": result.get("final_url") or url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "reason": _path_reason(path, response.status_code),
                "source": _path_source(path),
                "entry_count": _path_entry_count(path, result.get("body") or b""),
            }
    except Exception as exc:
        _record_error(errors, debug_log, "[DOMAIN][PATH]", f"url={url} error={exc}")
    return None


def _path_reason(path: str, status: int) -> str:
    reasons = {
        "/robots.txt": "robots.txt found",
        "/sitemap.xml": "sitemap.xml found",
        "/.well-known/security.txt": "security.txt found",
        "/swagger": "Swagger path reachable",
        "/swagger-ui": "Swagger UI path reachable",
        "/api-docs": "API docs path reachable",
        "/openapi.json": "OpenAPI descriptor reachable",
        "/graphql": "GraphQL path reachable",
        "/admin": "admin path reachable",
        "/login": "login path reachable",
        "/wp-login.php": "WordPress login path reachable",
        "/phpinfo.php": "phpinfo path reachable",
    }
    suffix = "access controlled" if status in {401, 403} else "found"
    return reasons.get(path, suffix)


def _path_source(path: str) -> str:
    if path in {"/admin", "/login", "/wp-login.php"}:
        return "admin_paths.txt"
    if path in {"/swagger", "/swagger-ui", "/api-docs", "/openapi.json"}:
        return "swagger_paths.txt"
    if path == "/graphql":
        return "graphql_paths.txt"
    if path in {"/phpinfo.php", "/.well-known/security.txt"}:
        return "config_paths.txt"
    return "common_paths.txt"


def _path_entry_count(path: str, body: bytes) -> int:
    if path != "/robots.txt" or not body:
        return 0
    text = body.decode("utf-8", errors="replace")
    return sum(
        1
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and ":" in line
    )


def _favicon_catalog_match(url: str) -> dict[str, str] | None:
    lowered = str(url or "").lower()
    catalog = (
        ("WordPress", ("wp-content", "wp-includes")),
        ("Drupal", ("/core/misc/favicon", "/misc/favicon")),
        ("Joomla", ("joomla", "/media/system/images/")),
    )
    for name, markers in catalog:
        if any(marker in lowered for marker in markers):
            return {
                "name": name,
                "confidence": "medium",
                "source": "internal favicon catalog",
            }
    return None


def _tls_info(host: str, debug_log: DebugLog | None, errors: list[str]) -> dict[str, str]:
    try:
        context = ssl._create_unverified_context()
        server_hostname = None if _is_ip(host) else host
        with socket.create_connection((host, 443), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                der = tls_sock.getpeercert(binary_form=True)
                parsed = _parse_der_certificate(der) if der else {}
                issuer = _cert_name(cert.get("issuer") or []) or parsed.get("issuer", "")
                expires = cert.get("notAfter") or parsed.get("expires", "")
                return {
                    "issuer": issuer,
                    "expires": expires,
                    "tls_version": tls_sock.version() or "",
                    "fingerprint_sha256": hashlib.sha256(der).hexdigest() if der else "",
                }
    except Exception as exc:
        _record_error(errors, debug_log, "[DOMAIN][TLS]", f"target={host} error={exc}")
        return {}


def _parse_der_certificate(der: bytes) -> dict[str, str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ModuleNotFoundError:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        return {
            "issuer": cert.issuer.rfc4514_string(),
            "expires": _datetime_to_text(cert.not_valid_after_utc),
        }
    except Exception:
        return {}


def _datetime_to_text(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _cert_name(parts: list[Any]) -> str:
    values = []
    for part in parts:
        for key, value in part:
            if key in {"commonName", "organizationName"} and value:
                values.append(str(value))
    return ", ".join(values)


def _extract_cookies(response: requests.Response) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for header in _set_cookie_headers(response):
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue
        for name, morsel in cookie.items():
            if name in seen:
                continue
            seen.add(name)
            rows.append(
                {
                    "name": name,
                    "domain": morsel["domain"] or "",
                    "path": morsel["path"] or "",
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or "",
                }
            )
    for cookie in response.cookies:
        if cookie.name in seen:
            continue
        seen.add(cookie.name)
        rows.append(
            {
                "name": cookie.name,
                "domain": cookie.domain or "",
                "path": cookie.path or "",
                "secure": bool(cookie.secure),
                "httponly": False,
                "samesite": "",
            }
        )
    return rows


def _set_cookie_headers(response: requests.Response) -> list[str]:
    raw_headers = getattr(response.raw, "headers", None)
    get_all = getattr(raw_headers, "get_all", None)
    if callable(get_all):
        values = [str(item) for item in get_all("Set-Cookie") or []]
        if values:
            return values
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _cookie_names_from_headers(response: requests.Response) -> list[str]:
    names = []
    for header in _set_cookie_headers(response):
        first = str(header).split(";", 1)[0]
        if "=" in first:
            names.append(first.split("=", 1)[0].strip())
    return sorted({name for name in names if name})


def _sanitize_headers(headers: dict[str, str], cookie_names: list[str]) -> dict[str, str]:
    sanitized = {}
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            sanitized[key] = f"redacted; cookie_names={','.join(cookie_names)}"
        else:
            sanitized[key] = str(value)
    return sanitized


def _int_or_text(value: Any) -> int | str | None:
    if value in {"", None}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


def _any_https_live(probes: list[dict[str, Any]]) -> bool:
    return any(probe.get("live") and str(probe.get("final_url") or "").startswith("https://") for probe in probes)


def _has_http_to_https_redirect(chain: list[dict[str, Any]], probes: list[dict[str, Any]]) -> bool:
    for row in chain:
        if str(row.get("from") or "").startswith("http://") and str(row.get("to") or "").startswith("https://"):
            return True
    for probe in probes:
        for row in probe.get("redirect_chain") or []:
            if str(row.get("from") or "").startswith("http://") and str(row.get("to") or "").startswith("https://"):
                return True
    return False


def _unique(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _record_error(errors: list[str], debug_log: DebugLog | None, prefix: str, detail: str) -> None:
    message = f"{prefix} {detail}"
    errors.append(message)
    if debug_log:
        try:
            debug_log(message)
        except Exception:
            pass
