from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import requests


REQUEST_TIMEOUT = 7
PREVIEW_LIMIT = 300
SENSITIVE_PATHS = [
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    "ads.txt",
    "humans.txt",
    "manifest.json",
    "openapi.json",
    "swagger.json",
    "swagger-ui",
    "swagger-ui/",
    "graphql",
    "api-docs",
    "api/docs",
    "redoc",
    "asset-manifest.json",
    "manifest.webmanifest",
    "runtime.js.map",
    "main.js.map",
    "bundle.js.map",
    "webpack.json",
    "webpack-stats.json",
    "runtime-manifest.json",
    ".env",
    ".git/config",
    ".git/HEAD",
    "backup.zip",
    "backup.sql",
    "db.sql",
    "dump.sql",
    "config.php.bak",
    "wp-config.php.bak",
    "phpinfo.php",
    "server-status",
]


def check_sensitive_files(
    target: str,
    known_paths: list[dict[str, Any]] | None = None,
    skip_paths: tuple[str, ...] | list[str] | set[str] | None = None,
) -> dict[str, Any]:
    base = _base_url(target)
    known_by_path = {
        str(row.get("path") or "").lstrip("/"): row
        for row in known_paths or []
        if row.get("path") and _looks_found(int(row.get("status") or 0))
    }
    skipped = {str(path).lstrip("/") for path in skip_paths or []}
    pending = [path for path in SENSITIVE_PATHS if path not in skipped]

    worker_count = min(10, max(1, len(pending)))
    chunk_size = max(1, (len(pending) + worker_count - 1) // worker_count)
    chunks = [pending[index:index + chunk_size] for index in range(0, len(pending), chunk_size)]

    def check_chunk(paths: list[str]) -> list[tuple[dict[str, Any] | None, str]]:
        session = requests.Session()
        try:
            return [_check_path(base, path, session) for path in paths]
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        checked = [row for chunk_rows in executor.map(check_chunk, chunks) for row in chunk_rows]

    findings = [_known_finding(base, path, known_by_path[path]) for path in SENSITIVE_PATHS if path in known_by_path]
    findings.extend(row for row, _error in checked if row)
    errors = [error for _row, error in checked if error]
    order = {path: index for index, path in enumerate(SENSITIVE_PATHS)}
    findings.sort(key=lambda row: order.get(str(row.get("path") or ""), len(order)))

    return {
        "base_url": base,
        "checked_paths": SENSITIVE_PATHS,
        "findings": findings,
        "errors": errors,
    }


def _check_path(
    base: str,
    path: str,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, str]:
    url = f"{base}/{path}"
    try:
        response = (session or requests).get(
            url,
            headers={
                "User-Agent": "Pamp/1.0",
                "Accept": "text/plain,text/html,application/json,application/xml,*/*",
                "Range": f"bytes=0-{PREVIEW_LIMIT - 1}",
            },
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        try:
            if not _looks_found(response.status_code):
                return None, ""
            return {
                "path": path,
                "url": url,
                "status": response.status_code,
                "size": response.headers.get("Content-Length", ""),
                "content_type": response.headers.get("Content-Type", ""),
                "preview": _read_preview(response),
            }, ""
        finally:
            response.close()
    except Exception as exc:
        return None, f"{path}: {exc}"


def _known_finding(base: str, path: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": path,
        "url": str(row.get("url") or f"{base}/{path}"),
        "status": row.get("status"),
        "size": row.get("size") or "",
        "content_type": row.get("content_type") or "",
        "preview": row.get("preview") or "",
    }


def _base_url(target: str) -> str:
    raw = target.strip()
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    return f"{scheme}://{netloc.strip('/')}"


def _looks_found(status_code: int) -> bool:
    return 200 <= status_code < 300 or status_code in {401, 403}


def _read_preview(response: requests.Response) -> str:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=128):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= PREVIEW_LIMIT:
            break
    data = b"".join(chunks)[:PREVIEW_LIMIT]
    return data.decode("utf-8", errors="replace").replace("\x00", "")
