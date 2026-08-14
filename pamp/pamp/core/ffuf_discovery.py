from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import hashlib
from html import unescape
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from .models import utc_now
from .path_classifier import classify_path
from .response_fingerprint import fingerprint_row, normalized_body_hash, response_signature


PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_WORDLIST_DIR = PROJECT_DIR / "wordlists"
MAX_BODY_BYTES = 1_000_000
WORDLIST_SPECS = (
    ("common_paths.txt", "unknown"),
    ("admin_paths.txt", "admin"),
    ("api_paths.txt", "api"),
    ("docs_paths.txt", "docs"),
    ("backup_paths.txt", "backup"),
    ("config_paths.txt", "config"),
    ("sourcemap_paths.txt", "sourcemap"),
)
STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
)
CONFIG_NAMES = (
    ".env",
    "config",
    "settings",
    "web.config",
    "appsettings",
    "application.yml",
    "application.yaml",
)
INTERESTING_STATUSES = {200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403}


@dataclass
class DiscoveryConfig:
    threads: int = 3
    timeout: float = 10
    delay: float = 0.3
    max_requests: int = 500
    user_agent: str = "Pamp/1.0"
    follow_redirects: bool = False
    status_codes: set[int] | None = None
    exclude_status_codes: set[int] = field(default_factory=set)
    size: int | None = None
    words: int | None = None
    lines: int | None = None
    content_type: str = ""
    redirect: bool | None = None
    interesting_only: bool = False
    hide_soft_404: bool = True
    hide_duplicates: bool = True
    hide_not_found: bool = True
    seed_urls: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, payload: dict[str, Any] | None = None) -> "DiscoveryConfig":
        payload = payload or {}
        config = cls()
        for key in (
            "threads",
            "timeout",
            "delay",
            "max_requests",
            "user_agent",
            "follow_redirects",
            "size",
            "words",
            "lines",
            "content_type",
            "redirect",
            "interesting_only",
            "hide_soft_404",
            "hide_duplicates",
            "hide_not_found",
        ):
            if key in payload and payload[key] is not None:
                setattr(config, key, payload[key])
        if payload.get("seed_urls"):
            config.seed_urls = [str(item) for item in payload.get("seed_urls") or [] if str(item).strip()]
        if payload.get("status_codes"):
            config.status_codes = {int(item) for item in payload["status_codes"]}
        if payload.get("exclude_status_codes"):
            config.exclude_status_codes = {int(item) for item in payload["exclude_status_codes"]}
        config.threads = max(1, min(int(config.threads), 20))
        config.timeout = max(1.0, float(config.timeout))
        config.delay = max(0.0, float(config.delay))
        config.max_requests = max(1, int(config.max_requests))
        return config

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status_codes"] = sorted(self.status_codes or [])
        payload["exclude_status_codes"] = sorted(self.exclude_status_codes)
        return payload


def run_discovery(
    target: str,
    config: DiscoveryConfig | dict[str, Any] | None = None,
    wordlist_dir: str | Path | None = None,
) -> dict[str, Any]:
    started_at = time.perf_counter()
    settings = config if isinstance(config, DiscoveryConfig) else DiscoveryConfig.from_mapping(config)
    base_url = normalize_base_url(target)
    wordlists = load_wordlists(Path(wordlist_dir) if wordlist_dir else DEFAULT_WORDLIST_DIR)
    candidates = _candidate_paths(wordlists, settings.max_requests, base_url=base_url, seed_urls=settings.seed_urls)
    errors: list[str] = []

    wildcard_responses = _wildcard_baselines(base_url, settings, errors)
    wildcard_enabled = any(_looks_discoverable(item.get("status_code", item.get("status", 0))) for item in wildcard_responses)

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=settings.threads) as executor:
        futures = {
            executor.submit(_probe_path, base_url, path, source_wordlist, category_hint, settings): (
                path,
                source_wordlist,
            )
            for path, source_wordlist, category_hint in candidates
        }
        for future in as_completed(futures):
            path, source_wordlist = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                errors.append(f"{source_wordlist}:{path}: {exc}")
                continue
            result["is_soft_404"] = _is_soft_404(result, wildcard_responses)
            result["soft_404"] = result["is_soft_404"]
            result["wildcard_match"] = _wildcard_match_reason(result, wildcard_responses)
            result["interesting_score"] = _interesting_score(result)
            result["notes"] = _notes(result)
            if _passes_filters(result, settings):
                results.append(result)

    _mark_duplicates(results)
    for row in results:
        row["notes"] = _notes(row)
    results.sort(key=lambda row: (-int(row.get("interesting_score") or 0), str(row.get("path") or "")))
    visible_results = [row for row in results if _show_in_main_output(row, settings)]
    findings = [row for row in visible_results if row.get("interesting_score", 0) > 0]
    debug_statuses = [
        {
            "path": row.get("path", ""),
            "url": row.get("url", ""),
            "status_code": row.get("status_code", row.get("status", 0)),
            "content_length": row.get("content_length", row.get("size", 0)),
            "words": row.get("words", 0),
            "lines": row.get("lines", 0),
            "content_type": row.get("content_type", ""),
            "is_soft_404": row.get("is_soft_404", False),
            "is_duplicate": row.get("is_duplicate", False),
            "wildcard_match": row.get("wildcard_match", ""),
        }
        for row in sorted(results, key=lambda item: str(item.get("path") or ""))
    ]
    category_counts: dict[str, int] = {}
    for row in findings:
        category = str(row.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "target": target,
        "base_url": base_url,
        "generated_at": utc_now(),
        "config": settings.public_dict(),
        "summary": {
            "checked": len(candidates),
            "returned": len(visible_results),
            "interesting": len(findings),
            "soft_404": sum(1 for row in results if row.get("is_soft_404")),
            "duplicates": sum(1 for row in results if row.get("is_duplicate")),
            "wildcard_detected": wildcard_enabled,
            "categories": dict(sorted(category_counts.items())),
        },
        "wordlists": [
            {
                "name": name,
                "category": category,
                "count": len(paths),
            }
            for name, category, paths in wordlists
        ],
        "wildcard_detection": {
            "enabled": wildcard_enabled,
            "baselines": wildcard_responses,
        },
        "findings": findings[:300],
        "all_results": visible_results[: settings.max_requests],
        "debug": {
            "execution_time_ms": int((time.perf_counter() - started_at) * 1000),
            "checked_paths": [
                {"path": path, "source_wordlist": source_wordlist}
                for path, source_wordlist, _ in candidates
            ],
            "all_statuses": debug_statuses,
            "soft_404": [row for row in debug_statuses if row.get("is_soft_404")],
            "duplicates": [row for row in debug_statuses if row.get("is_duplicate")],
            "wildcard_responses": wildcard_responses,
            "wildcard_signatures": [
                {
                    "path": item.get("path", ""),
                    "status_code": item.get("status_code", item.get("status", 0)),
                    "content_length": item.get("content_length", item.get("size", 0)),
                    "words": item.get("words", 0),
                    "lines": item.get("lines", 0),
                    "normalized_hash": item.get("normalized_hash", ""),
                }
                for item in wildcard_responses
            ],
            "errors": errors,
        },
    }


def normalize_base_url(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("Target is empty")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""
    return f"{scheme}://{netloc.strip('/')}{path.rstrip('/')}"


def load_wordlists(wordlist_dir: Path = DEFAULT_WORDLIST_DIR) -> list[tuple[str, str, list[str]]]:
    loaded = []
    for filename, category in WORDLIST_SPECS:
        path = wordlist_dir / filename
        rows = []
        if path.exists():
            rows = [
                _clean_path(line)
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if _clean_path(line)
            ]
        elif filename == "backup_paths.txt":
            legacy_path = wordlist_dir / "backup_files.txt"
            if legacy_path.exists():
                rows = [
                    _clean_path(line)
                    for line in legacy_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if _clean_path(line)
                ]
        loaded.append((filename, category, _dedupe(rows)))
    return loaded


def _candidate_paths(
    wordlists: list[tuple[str, str, list[str]]],
    max_requests: int,
    base_url: str = "",
    seed_urls: list[str] | None = None,
) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen = set()
    for path in _seed_paths(base_url, seed_urls or []):
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        candidates.append((path, "runtime_artifacts", "unknown"))
        if len(candidates) >= max_requests:
            return candidates
    for filename, category, paths in wordlists:
        for path in paths:
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            candidates.append((path, filename, category))
            if len(candidates) >= max_requests:
                return candidates
    return candidates


def _seed_paths(base_url: str, values: list[str]) -> list[str]:
    parsed_base = urlparse(base_url)
    base_host = (parsed_base.hostname or "").lower()
    output = []
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            host = (parsed.hostname or "").lower()
            if base_host and host and host != base_host and not host.endswith(f".{base_host}"):
                continue
            path = parsed.path.lstrip("/")
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            path = raw.lstrip("/")
        if path:
            output.append(path)
    return _dedupe(output)


def _clean_path(value: str) -> str:
    raw = value.strip()
    if not raw or raw.startswith("#"):
        return ""
    return raw.lstrip("/")


def _dedupe(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output


def _wildcard_baselines(base_url: str, config: DiscoveryConfig, errors: list[str]) -> list[dict[str, Any]]:
    token = secrets.token_hex(8)
    paths = [
        f"pamp-random-404-{token}",
        f"not-found-pamp-{token}",
        f"unknown-path-{token}",
    ]
    baselines = []
    for path in paths:
        try:
            result = _probe_path(base_url, path, "wildcard", "unknown", config)
            baselines.append(
                {
                    "path": result.get("path", ""),
                    "url": result.get("url", ""),
                    "status_code": result.get("status_code", result.get("status", 0)),
                    "status": result.get("status_code", result.get("status", 0)),
                    "content_length": result.get("content_length", result.get("size", 0)),
                    "size": result.get("content_length", result.get("size", 0)),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "content_type": result.get("content_type", ""),
                    "page_title": result.get("page_title", result.get("title", "")),
                    "body_hash": result.get("body_hash", ""),
                    "normalized_hash": result.get("normalized_hash", ""),
                }
            )
        except Exception as exc:
            errors.append(f"wildcard {path}: {exc}")
    return baselines


def _probe_path(
    base_url: str,
    path: str,
    source_wordlist: str,
    category_hint: str,
    config: DiscoveryConfig,
) -> dict[str, Any]:
    if config.delay:
        time.sleep(config.delay)
    url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
    started = time.perf_counter()
    response = requests.get(
        url,
        headers={
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
        },
        timeout=config.timeout,
        allow_redirects=config.follow_redirects,
        stream=True,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    try:
        body = _read_limited(response, MAX_BODY_BYTES)
    finally:
        response.close()
    text = _decode_body(body, response)
    title = _extract_title(text)
    redirect = response.headers.get("Location", "")
    if config.follow_redirects and response.url != url:
        redirect = response.url
    fingerprint = fingerprint_row(
        response.status_code,
        body,
        text,
        response.headers.get("Content-Type", ""),
        redirect,
    )
    return {
        "url": url,
        "path": path,
        "status_code": fingerprint["status_code"],
        "status": int(response.status_code),
        "content_length": fingerprint["content_length"],
        "size": fingerprint["content_length"],
        "words": fingerprint["words"],
        "lines": fingerprint["lines"],
        "content_type": fingerprint["content_type"],
        "redirect_location": redirect,
        "redirect": redirect,
        "page_title": title,
        "title": title,
        "server_header": response.headers.get("Server", ""),
        "server": response.headers.get("Server", ""),
        "category": _category(path, category_hint, response.headers.get("Content-Type", "")),
        "source": source_wordlist,
        "wordlist": source_wordlist,
        "source_wordlist": source_wordlist,
        "interesting_score": 0,
        "is_soft_404": False,
        "is_duplicate": False,
        "notes": "",
        "elapsed_ms": elapsed_ms,
        "body_hash": fingerprint["body_hash"],
        "fingerprint_hash": fingerprint["fingerprint_hash"],
        "normalized_hash": fingerprint["normalized_hash"],
        "response_signature": "",
        "has_form": _contains_form(text),
    }


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
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:160]


def _normalized_hash(text: str) -> str:
    return normalized_body_hash(text)


def _category(path: str, category_hint: str, content_type: str) -> str:
    return classify_path(path, category_hint, content_type)


def _interesting_score(result: dict[str, Any]) -> int:
    status = int(result.get("status_code") or result.get("status") or 0)
    category = str(result.get("category") or "unknown")
    path = str(result.get("path") or "").lower()
    content_type = str(result.get("content_type") or "").lower()
    score = 0
    if status in {200, 201, 202, 204, 206}:
        score += 35
    elif status in {401, 403}:
        score += 30
    elif status in {301, 302, 307, 308}:
        score += 12
    if category in {"admin", "api", "auth", "graphql", "swagger"}:
        score += 25
    elif category in {"docs", "backup", "config", "sourcemap"}:
        score += 22
    elif category == "public":
        score += 8
    if any(item in path for item in ("swagger", "openapi", "graphql", "wp-admin", ".env", ".git", ".sql", ".bak", ".map")):
        score += 15
    if "json" in content_type or "xml" in content_type:
        score += 5
    if result.get("page_title"):
        score += 4
    if result.get("has_form"):
        score += 10
    if result.get("source_wordlist") == "runtime_artifacts":
        score += 8
    if 0 < int(result.get("content_length") or 0) < 24:
        score -= 12
    if category == "static" and not any(item in path for item in (".map", "manifest", "asset-manifest")):
        score -= 12
    if result.get("is_soft_404") or result.get("soft_404"):
        score = 0
    if result.get("is_duplicate"):
        score = 0
    if status == 404:
        score = 0
    return min(score, 100)


def _notes(result: dict[str, Any]) -> str:
    notes = []
    status = int(result.get("status_code") or result.get("status") or 0)
    if result.get("is_soft_404") or result.get("soft_404"):
        notes.append("soft 404")
    if result.get("is_duplicate"):
        notes.append("duplicate response")
    if status in {401, 403}:
        notes.append("protected resource")
    if result.get("redirect_location") or result.get("redirect"):
        notes.append("redirect")
    category = result.get("category")
    if category and category != "unknown":
        notes.append(str(category))
    return ", ".join(notes)


def _passes_filters(result: dict[str, Any], config: DiscoveryConfig) -> bool:
    status = int(result.get("status_code") or result.get("status") or 0)
    if config.status_codes is not None and status not in config.status_codes:
        return False
    if status in config.exclude_status_codes:
        return False
    if config.size is not None and int(result.get("content_length") or result.get("size") or 0) != int(config.size):
        return False
    if config.words is not None and int(result.get("words") or 0) != int(config.words):
        return False
    if config.lines is not None and int(result.get("lines") or 0) != int(config.lines):
        return False
    if config.content_type and config.content_type.lower() not in str(result.get("content_type") or "").lower():
        return False
    if config.redirect is not None and bool(result.get("redirect_location") or result.get("redirect")) is not bool(config.redirect):
        return False
    if config.interesting_only and int(result.get("interesting_score") or 0) <= 0:
        return False
    return True


def _looks_discoverable(status: int) -> bool:
    return int(status or 0) in INTERESTING_STATUSES


def _is_soft_404(result: dict[str, Any], baselines: list[dict[str, Any]]) -> bool:
    status = int(result.get("status_code") or result.get("status") or 0)
    if status in {0, 404}:
        return False
    for baseline in baselines:
        if status != int(baseline.get("status_code") or baseline.get("status") or 0):
            continue
        if result.get("normalized_hash") and result.get("normalized_hash") == baseline.get("normalized_hash"):
            return True
        title = str(result.get("page_title") or result.get("title") or "")
        if title and title == str(baseline.get("page_title") or baseline.get("title") or "") and _close_number(result.get("content_length") or result.get("size"), baseline.get("content_length") or baseline.get("size"), 0.08):
            return True
        if (
            _close_number(result.get("content_length") or result.get("size"), baseline.get("content_length") or baseline.get("size"), 0.03)
            and _close_number(result.get("words"), baseline.get("words"), 0.05)
            and _close_number(result.get("lines"), baseline.get("lines"), 0.05)
        ):
            return True
    return False


def _wildcard_match_reason(result: dict[str, Any], baselines: list[dict[str, Any]]) -> str:
    if not _is_soft_404(result, baselines):
        return ""
    status = int(result.get("status_code") or result.get("status") or 0)
    for baseline in baselines:
        if status == int(baseline.get("status_code") or baseline.get("status") or 0):
            return f"status {status} resembles {baseline.get('path')}"
    return "wildcard-like response"


def _mark_duplicates(results: list[dict[str, Any]]) -> None:
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in sorted(results, key=lambda item: (-int(item.get("interesting_score") or 0), str(item.get("path") or ""))):
        status = int(row.get("status_code") or row.get("status") or 0)
        signature = response_signature(row)
        row["response_signature"] = "|".join(str(item) for item in signature)
        if status in {401, 403} and row.get("category") in {"admin", "auth"}:
            continue
        if signature in seen:
            row["is_duplicate"] = True
            row["duplicate_of"] = seen[signature].get("path") or ""
        else:
            seen[signature] = row


def _show_in_main_output(result: dict[str, Any], config: DiscoveryConfig) -> bool:
    status = int(result.get("status_code") or result.get("status") or 0)
    if config.hide_not_found and status in {0, 404, 410}:
        return False
    if config.hide_soft_404 and (result.get("is_soft_404") or result.get("soft_404")):
        return False
    if config.hide_duplicates and result.get("is_duplicate"):
        return False
    return int(result.get("interesting_score") or 0) > 0


def _contains_form(text: str) -> bool:
    return bool(re.search(r"<form\b|<input\b|<select\b|<textarea\b", text or "", re.I))


def _close_number(left: Any, right: Any, tolerance: float) -> bool:
    try:
        a = float(left or 0)
        b = float(right or 0)
    except (TypeError, ValueError):
        return False
    if a == b:
        return True
    return abs(a - b) / max(a, b, 1.0) <= tolerance
