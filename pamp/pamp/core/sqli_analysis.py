from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from html import unescape
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from .ffuf_discovery import normalize_base_url
from .models import utc_now


MAX_BODY_BYTES = 700_000
INTERESTING_NAMES = {
    "id",
    "user",
    "uid",
    "pid",
    "page",
    "cat",
    "category",
    "product",
    "item",
    "search",
    "query",
    "q",
    "sort",
    "filter",
    "order",
    "name",
    "email",
    "login",
    "username",
    "account",
    "role",
    "type",
    "lang",
    "locale",
    "file",
    "filename",
    "path",
    "url",
    "redirect",
    "next",
    "callback",
    "return",
}
SENSITIVE_OR_NOISY_NAMES = {
    "csrf",
    "xsrf",
    "token",
    "authenticity_token",
    "password",
    "passwd",
    "pass",
    "secret",
    "key",
    "api_key",
    "apikey",
    "session",
}
ID_LIKE = {"id", "uid", "pid", "product", "item", "page", "cat", "category"}
SEARCH_LIKE = {"search", "query", "q", "filter", "sort", "order", "name", "email", "login", "user"}
AUTH_LIKE = {"login", "user", "username", "email", "account", "role"}
FILE_LIKE = {"file", "filename", "path", "upload", "download"}
FLOW_LIKE = {"url", "redirect", "next", "callback", "return"}
ERROR_PATTERNS = {
    "MySQL": (
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQL server version",
        r"You have an error in your SQL syntax",
    ),
    "MariaDB": (
        r"MariaDB server version",
        r"You have an error in your SQL syntax.*MariaDB",
    ),
    "PostgreSQL": (
        r"PostgreSQL.*ERROR",
        r"pg_query\(",
        r"pg_exec\(",
        r"unterminated quoted string",
        r"syntax error at or near",
    ),
    "MSSQL": (
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Unclosed quotation mark after the character string",
    ),
    "Oracle": (
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
    ),
    "SQLite": (
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"sqlite3\.OperationalError",
        r"near \".*\": syntax error",
    ),
    "ODBC": (
        r"ODBC Driver",
        r"ODBC SQL",
        r"SQLSTATE",
    ),
    "PDO": (
        r"PDOException",
        r"PDOStatement",
    ),
    "JDBC": (
        r"JDBC Driver",
        r"java\.sql\.SQLException",
    ),
}


@dataclass
class SQLiConfig:
    timeout: float = 10
    delay: float = 0.2
    max_parameters: int = 30
    max_requests: int = 240
    user_agent: str = "Pamp/1.0"
    follow_redirects: bool = False
    repeat_confirmations: bool = True
    tested_parameter_names: set[str] | None = None
    exclude_parameter_names: set[str] = field(default_factory=set)

    @classmethod
    def from_mapping(cls, payload: dict[str, Any] | None = None) -> "SQLiConfig":
        payload = payload or {}
        config = cls()
        for key in (
            "timeout",
            "delay",
            "max_parameters",
            "max_requests",
            "user_agent",
            "follow_redirects",
            "repeat_confirmations",
        ):
            if key in payload and payload[key] is not None:
                setattr(config, key, payload[key])
        if payload.get("tested_parameter_names"):
            config.tested_parameter_names = {str(item).lower() for item in payload["tested_parameter_names"]}
        if payload.get("exclude_parameter_names"):
            config.exclude_parameter_names = {str(item).lower() for item in payload["exclude_parameter_names"]}
        config.timeout = max(1.0, float(config.timeout))
        config.delay = max(0.0, float(config.delay))
        config.max_parameters = max(1, min(int(config.max_parameters), 100))
        config.max_requests = max(1, int(config.max_requests))
        return config

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["tested_parameter_names"] = sorted(self.tested_parameter_names or [])
        payload["exclude_parameter_names"] = sorted(self.exclude_parameter_names)
        return payload


def analyze_sqli(
    target: str,
    domain_data: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    config: SQLiConfig | dict[str, Any] | None = None,
) -> dict[str, Any]:
    started_at = time.perf_counter()
    settings = config if isinstance(config, SQLiConfig) else SQLiConfig.from_mapping(config)
    domain_data = domain_data or {}
    discovery = discovery or {}
    base_url = _best_base_url(target, domain_data)
    candidates = collect_parameter_candidates(base_url, domain_data, discovery, settings)
    findings = []
    low_confidence = []
    response_summaries = []
    errors: list[str] = []
    request_budget = settings.max_requests

    for candidate in candidates[: settings.max_parameters]:
        if request_budget <= 0:
            break
        try:
            result, used = _analyze_candidate(candidate, settings, request_budget)
            request_budget -= used
            response_summaries.extend(result.get("responses") or [])
            if result.get("finding"):
                findings.append(result["finding"])
            low_confidence.extend(result.get("low_confidence") or [])
        except Exception as exc:
            errors.append(f"{candidate.get('method')} {candidate.get('url')} {candidate.get('parameter')}: {exc}")

    visible_findings = [item for item in findings if item.get("confidence") != "Low"]
    return {
        "target": target,
        "base_url": base_url,
        "generated_at": utc_now(),
        "config": settings.public_dict(),
        "summary": {
            "candidate_parameters": len(candidates),
            "tested_parameters": min(len(candidates), settings.max_parameters),
            "confirmed_findings": len(visible_findings),
            "low_confidence_signals": len(low_confidence),
            "requests_used": settings.max_requests - request_budget,
        },
        "interesting_parameters": candidates[: settings.max_parameters],
        "findings": visible_findings,
        "debug": {
            "execution_time_ms": int((time.perf_counter() - started_at) * 1000),
            "tested_parameters": candidates[: settings.max_parameters],
            "responses": response_summaries,
            "low_confidence_signals": low_confidence,
            "errors": errors,
        },
    }


def collect_parameter_candidates(
    base_url: str,
    domain_data: dict[str, Any],
    discovery: dict[str, Any],
    config: SQLiConfig | None = None,
) -> list[dict[str, Any]]:
    config = config or SQLiConfig()
    candidates: list[dict[str, Any]] = []

    http = domain_data.get("http") or {}
    for url in [http.get("url"), http.get("final_url"), base_url]:
        candidates.extend(_url_param_candidates(url, "GET", "http", "main document"))

    html = domain_data.get("html") or {}
    for form in html.get("forms") or []:
        candidates.extend(_form_candidates(form, base_url, "html form"))
    for url in html.get("external_links") or []:
        candidates.extend(_url_param_candidates(url, "GET", "html link", "crawler"))

    devtools = domain_data.get("devtools") or {}
    for form in devtools.get("forms") or []:
        candidates.extend(_form_candidates(form, base_url, "devtools form"))
    for request in devtools.get("network_requests") or []:
        method = str(request.get("method") or "GET").upper()
        url = request.get("url") or ""
        candidates.extend(_url_param_candidates(url, method, "devtools network", "devtools"))

    for endpoint in domain_data.get("api_endpoints") or []:
        method = str(endpoint.get("method") or "GET").upper() or "GET"
        candidates.extend(_url_param_candidates(endpoint.get("endpoint"), method, "api endpoint", endpoint.get("source_file") or "api"))

    discovery_rows = (discovery.get("findings") or []) + (discovery.get("all_results") or [])
    for row in discovery_rows:
        category = str(row.get("category") or "")
        if category not in {"api", "admin", "docs", "unknown"} and not row.get("url"):
            continue
        candidates.extend(_url_param_candidates(row.get("url"), "GET", "ffuf discovery", row.get("path") or "discovery"))

    ranked = []
    seen = {}
    for candidate in candidates:
        name = str(candidate.get("parameter") or "").lower()
        if not _allowed_parameter(name, config):
            continue
        score, parameter_type, reason = _classify_parameter(name, candidate.get("source") or "")
        if score <= 0:
            continue
        candidate["score"] = score
        candidate["parameter_type"] = parameter_type
        candidate["reason"] = reason
        candidate["baseline_value"] = candidate.get("baseline_value") or _default_value(name, parameter_type)
        key = _candidate_key(candidate)
        previous = seen.get(key)
        if not previous or score > previous.get("score", 0):
            seen[key] = candidate
    ranked = sorted(seen.values(), key=lambda item: (-int(item.get("score") or 0), str(item.get("parameter") or "")))
    return ranked


def _analyze_candidate(candidate: dict[str, Any], config: SQLiConfig, request_budget: int) -> tuple[dict[str, Any], int]:
    used = 0
    low_confidence = []
    responses = []
    baseline = _send(candidate, candidate["baseline_value"], "baseline", config)
    used += 1
    responses.append(_response_debug(candidate, baseline))

    tests = _payloads(candidate)
    test_results: dict[str, dict[str, Any]] = {}
    for payload_type, value in tests:
        if used >= request_budget:
            break
        response = _send(candidate, value, payload_type, config)
        used += 1
        test_results[payload_type] = response
        responses.append(_response_debug(candidate, response))

    signals = []
    evidence = []
    dbms_hint = ""
    detected_error = ""
    error_payload = ""
    for payload_type, response in test_results.items():
        error = _detect_sql_error(response.get("_text", ""))
        if error:
            dbms_hint = dbms_hint or error["dbms"]
            detected_error = detected_error or error["match"]
            error_payload = error_payload or payload_type
            signals.append("SQL error fingerprint found")
            evidence.append(f"{payload_type}: {error['dbms']} fingerprint")
            if baseline.get("status") != response.get("status"):
                signals.append("status code changed with SQL error")
            if _different_response(baseline, response):
                signals.append("response structure changed with SQL error")
            break

    if error_payload and config.repeat_confirmations and used < request_budget:
        repeat = _send(candidate, dict(tests)[error_payload], f"{error_payload}_repeat", config)
        used += 1
        responses.append(_response_debug(candidate, repeat))
        repeat_error = _detect_sql_error(repeat.get("_text", ""))
        if repeat_error and repeat_error.get("dbms") == dbms_hint:
            signals.append("same SQL error repeated")
            evidence.append(f"{error_payload} repeat: {repeat_error['dbms']} fingerprint")

    boolean_signal = _boolean_signal(baseline, test_results.get("boolean_true"), test_results.get("boolean_false"))
    if boolean_signal:
        signals.append("boolean true/false gave stable difference")
        evidence.append(boolean_signal)
        if config.repeat_confirmations and used + 2 <= request_budget:
            repeat_true = _send(candidate, dict(tests)["boolean_true"], "boolean_true_repeat", config)
            repeat_false = _send(candidate, dict(tests)["boolean_false"], "boolean_false_repeat", config)
            used += 2
            responses.append(_response_debug(candidate, repeat_true))
            responses.append(_response_debug(candidate, repeat_false))
            repeat_signal = _boolean_signal(baseline, repeat_true, repeat_false)
            if repeat_signal:
                signals.append("boolean comparison repeated with same result")
                evidence.append(repeat_signal)

    unique_signals = _unique(signals)
    finding = None
    if len(unique_signals) >= 2:
        confidence = _confidence(unique_signals)
        strongest = _strongest_response(test_results)
        finding = {
            "url": candidate.get("url", ""),
            "method": candidate.get("method", "GET"),
            "parameter": candidate.get("parameter", ""),
            "parameter_type": candidate.get("parameter_type", ""),
            "baseline_status": baseline.get("status"),
            "test_status": strongest.get("status"),
            "baseline_length": baseline.get("length"),
            "test_length": strongest.get("length"),
            "difference_percent": _max_difference_percent(baseline, test_results),
            "detected_error": detected_error,
            "dbms_hint": dbms_hint,
            "payload_type": strongest.get("payload_type", ""),
            "confidence": confidence,
            "evidence": evidence,
            "notes": "; ".join(unique_signals),
        }
    else:
        for payload_type, response in test_results.items():
            if _different_response(baseline, response):
                low_confidence.append(
                    {
                        "url": candidate.get("url", ""),
                        "method": candidate.get("method", "GET"),
                        "parameter": candidate.get("parameter", ""),
                        "payload_type": payload_type,
                        "baseline_status": baseline.get("status"),
                        "test_status": response.get("status"),
                        "difference_percent": _difference_percent(baseline.get("length"), response.get("length")),
                        "reason": "response changed without enough independent SQLi evidence",
                    }
                )

    return {"finding": finding, "low_confidence": low_confidence, "responses": responses}, used


def _url_param_candidates(url: Any, method: str, source: str, detail: str) -> list[dict[str, Any]]:
    raw = str(url or "").strip()
    if not raw:
        return []
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return []
    params = parse_qsl(parsed.query, keep_blank_values=True)
    output = []
    for name, value in params:
        if not name:
            continue
        output.append(
            {
                "url": _strip_fragment(raw),
                "method": method if method in {"GET", "POST"} else "GET",
                "parameter": name,
                "parameter_type": "",
                "source": source,
                "source_detail": str(detail or ""),
                "baseline_value": value or "",
                "fields": {},
            }
        )
    return output


def _form_candidates(form: dict[str, Any], base_url: str, source: str) -> list[dict[str, Any]]:
    action = str(form.get("action") or "").strip()
    url = urljoin(f"{base_url.rstrip('/')}/", action) if action else base_url
    method = str(form.get("method") or "GET").upper()
    if method not in {"GET", "POST"}:
        method = "GET"
    names = _unique([str(item) for item in (form.get("input_names") or []) if str(item).strip()])
    hidden = {str(item).lower() for item in (form.get("hidden_input_names") or [])}
    output = []
    defaults = {name: _default_value(name.lower(), "") for name in names}
    for name in names:
        lowered = name.lower()
        if lowered in hidden and lowered not in INTERESTING_NAMES:
            continue
        output.append(
            {
                "url": _strip_fragment(url),
                "method": method,
                "parameter": name,
                "parameter_type": "",
                "source": source,
                "source_detail": "form",
                "baseline_value": defaults.get(name, ""),
                "fields": defaults,
            }
        )
    return output


def _classify_parameter(name: str, source: str) -> tuple[int, str, str]:
    lowered = name.lower()
    score = 0
    parameter_type = "generic"
    reasons = []
    if lowered in INTERESTING_NAMES:
        score += 50
        reasons.append("interesting parameter name")
    if lowered in ID_LIKE or lowered.endswith("_id") or lowered.endswith("id"):
        score += 30
        parameter_type = "id-like"
        reasons.append("id-like")
    if lowered in SEARCH_LIKE or any(token in lowered for token in ("search", "query", "filter", "sort", "order")):
        score += 24
        parameter_type = "search/filter"
        reasons.append("search/filter")
    if lowered in AUTH_LIKE or any(token in lowered for token in ("login", "user", "account", "role", "email")):
        score += 18
        parameter_type = "auth"
        reasons.append("auth-like")
    if lowered in FILE_LIKE or any(token in lowered for token in ("file", "filename", "path", "upload", "download")):
        score += 16
        parameter_type = "file/path"
        reasons.append("file-like")
    if lowered in FLOW_LIKE or any(token in lowered for token in ("redirect", "callback", "return", "next")):
        score += 14
        parameter_type = "flow"
        reasons.append("flow-like")
    if lowered in {"type", "lang", "locale"}:
        score += 12
        parameter_type = "selector"
        reasons.append("selector-like")
    if "form" in source:
        score += 8
    if "devtools" in source or "api" in source or "ffuf" in source:
        score += 6
    return min(score, 100), parameter_type, ", ".join(reasons) or "classified interesting"


def _allowed_parameter(name: str, config: SQLiConfig) -> bool:
    if not name:
        return False
    lowered = name.lower()
    if config.tested_parameter_names is not None and lowered not in config.tested_parameter_names:
        return False
    if lowered in config.exclude_parameter_names:
        return False
    if lowered in SENSITIVE_OR_NOISY_NAMES:
        return False
    if any(token in lowered for token in ("csrf", "xsrf", "token", "password", "passwd", "secret", "session")):
        return False
    allowed_tokens = set(SEARCH_LIKE) | set(AUTH_LIKE) | set(FILE_LIKE) | set(FLOW_LIKE) | {"type", "lang", "locale"}
    return lowered in INTERESTING_NAMES or lowered.endswith("id") or any(token in lowered for token in allowed_tokens)


def _candidate_key(candidate: dict[str, Any]) -> str:
    parsed = urlparse(str(candidate.get("url") or ""))
    url_without_query = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    return "|".join(
        [
            str(candidate.get("method") or "GET").upper(),
            url_without_query,
            str(candidate.get("parameter") or "").lower(),
        ]
    )


def _payloads(candidate: dict[str, Any]) -> list[tuple[str, str]]:
    base = str(candidate.get("baseline_value") or _default_value(candidate.get("parameter", ""), candidate.get("parameter_type", "")))
    if not base:
        base = _default_value(candidate.get("parameter", ""), candidate.get("parameter_type", ""))
    parameter_type = str(candidate.get("parameter_type") or "")
    numeric = parameter_type == "id-like" or re.fullmatch(r"-?\d+", base or "") is not None
    if numeric:
        true_payload = f"{base} AND 1=1"
        false_payload = f"{base} AND 1=2"
        numeric_break = f"{base}'"
    else:
        true_payload = f"{base}' AND '1'='1"
        false_payload = f"{base}' AND '1'='2"
        numeric_break = f"{base})"
    return [
        ("quote", f"{base}'"),
        ("double_quote", f'{base}"'),
        ("numeric_break", numeric_break),
        ("boolean_true", true_payload),
        ("boolean_false", false_payload),
    ]


def _send(candidate: dict[str, Any], value: str, payload_type: str, config: SQLiConfig) -> dict[str, Any]:
    if config.delay:
        time.sleep(config.delay)
    method = str(candidate.get("method") or "GET").upper()
    url = str(candidate.get("url") or "")
    parameter = str(candidate.get("parameter") or "")
    headers = {
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
    }
    started = time.perf_counter()
    request_kwargs: dict[str, Any] = {
        "headers": headers,
        "timeout": config.timeout,
        "allow_redirects": config.follow_redirects,
        "stream": True,
    }
    if method == "POST":
        data = dict(candidate.get("fields") or {})
        data[parameter] = value
        response = requests.post(url, data=data, **request_kwargs)
    else:
        response = requests.get(_url_with_param(url, parameter, value), **request_kwargs)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    try:
        body = _read_limited(response, MAX_BODY_BYTES)
    finally:
        response.close()
    text = _decode_body(body, response)
    redirect = response.headers.get("Location", "")
    if config.follow_redirects and response.url != url:
        redirect = response.url
    return {
        "payload_type": payload_type,
        "status": int(response.status_code),
        "length": len(body),
        "words": len(re.findall(r"\S+", text)),
        "lines": len(text.splitlines()),
        "title": _extract_title(text),
        "hash": _normalized_hash(text),
        "response_time_ms": elapsed_ms,
        "redirect": redirect,
        "content_type": response.headers.get("Content-Type", ""),
        "_text": text,
    }


def _url_with_param(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output = []
    for key, old_value in pairs:
        if key == parameter:
            output.append((key, value))
            replaced = True
        else:
            output.append((key, old_value))
    if not replaced:
        output.append((parameter, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(output, doseq=True), ""))


def _read_limited(response: requests.Response, limit: int) -> bytes:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return b"".join(chunks)[:limit]


def _decode_body(body: bytes, response: requests.Response) -> str:
    encoding = response.encoding or "utf-8"
    return body.decode(encoding, errors="replace").replace("\x00", "")


def _extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", unescape(match.group(1))).strip()[:160]


def _normalized_hash(text: str) -> str:
    sample = (text or "")[:200_000].lower()
    sample = re.sub(r"\b[a-f0-9]{12,}\b", "HEX", sample)
    sample = re.sub(r"\b\d{4,}\b", "NUM", sample)
    sample = re.sub(r"\s+", " ", sample)
    return hashlib.sha256(sample.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _detect_sql_error(text: str) -> dict[str, str] | None:
    for dbms, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text or "", re.I)
            if match:
                return {"dbms": dbms, "match": match.group(0)[:180]}
    return None


def _boolean_signal(
    baseline: dict[str, Any],
    true_response: dict[str, Any] | None,
    false_response: dict[str, Any] | None,
) -> str:
    if not true_response or not false_response:
        return ""
    if _similar_response(baseline, true_response) and _different_response(baseline, false_response) and _different_response(true_response, false_response):
        return "true response stayed close to baseline while false response changed"
    return ""


def _similar_response(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("status") != right.get("status"):
        return False
    if left.get("hash") == right.get("hash"):
        return True
    if left.get("title") and left.get("title") == right.get("title") and _delta(left.get("length"), right.get("length")) <= 0.12:
        return True
    return _delta(left.get("length"), right.get("length")) <= 0.08 and _delta(left.get("words"), right.get("words")) <= 0.10


def _different_response(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if not right:
        return False
    if left.get("status") != right.get("status"):
        return True
    if left.get("redirect") != right.get("redirect") and (left.get("redirect") or right.get("redirect")):
        return True
    if left.get("hash") != right.get("hash") and (
        _delta(left.get("length"), right.get("length")) >= 0.20
        or _delta(left.get("words"), right.get("words")) >= 0.20
        or _delta(left.get("lines"), right.get("lines")) >= 0.20
    ):
        return True
    return False


def _delta(left: Any, right: Any) -> float:
    try:
        a = float(left or 0)
        b = float(right or 0)
    except (TypeError, ValueError):
        return 0.0
    if a == b:
        return 0.0
    return abs(a - b) / max(a, b, 1.0)


def _difference_percent(left: Any, right: Any) -> int:
    return int(round(_delta(left, right) * 100))


def _max_difference_percent(baseline: dict[str, Any], responses: dict[str, dict[str, Any]]) -> int:
    if not responses:
        return 0
    return max(_difference_percent(baseline.get("length"), response.get("length")) for response in responses.values())


def _confidence(signals: list[str]) -> str:
    signal_text = " | ".join(signals).lower()
    if "boolean true/false" in signal_text and "repeated" in signal_text:
        return "High"
    if "sql error fingerprint" in signal_text and ("response structure" in signal_text or "status code" in signal_text or "repeated" in signal_text):
        return "High"
    return "Medium"


def _strongest_response(responses: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not responses:
        return {}
    for payload_type in ("quote", "double_quote", "numeric_break", "boolean_true", "boolean_false"):
        response = responses.get(payload_type)
        if response and _detect_sql_error(response.get("_text", "")):
            return response
    for payload_type in ("boolean_false", "boolean_true", "numeric_break", "quote", "double_quote"):
        if payload_type in responses:
            return responses[payload_type]
    return next(iter(responses.values()))


def _response_debug(candidate: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": candidate.get("url", ""),
        "method": candidate.get("method", "GET"),
        "parameter": candidate.get("parameter", ""),
        "payload_type": response.get("payload_type", ""),
        "status": response.get("status"),
        "length": response.get("length"),
        "words": response.get("words"),
        "lines": response.get("lines"),
        "title": response.get("title"),
        "hash": response.get("hash"),
        "response_time_ms": response.get("response_time_ms"),
        "redirect": response.get("redirect"),
        "sql_error": _detect_sql_error(response.get("_text", "")) or {},
    }


def _default_value(name: str, parameter_type: str) -> str:
    lowered = str(name or "").lower()
    if parameter_type == "id-like" or lowered in ID_LIKE or lowered.endswith("id"):
        return "1"
    if "email" in lowered:
        return "test@example.com"
    if "sort" in lowered or "order" in lowered:
        return "name"
    if "page" in lowered:
        return "1"
    return "test"


def _best_base_url(target: str, domain_data: dict[str, Any]) -> str:
    http = domain_data.get("http") or {}
    return normalize_base_url(http.get("final_url") or http.get("url") or target)


def _strip_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))


def _unique(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
