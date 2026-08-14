from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse


RESOURCE_ORDER = (
    "document",
    "xhr",
    "fetch",
    "script",
    "stylesheet",
    "image",
    "font",
    "media",
    "websocket",
    "manifest",
    "other",
)


def normalize_network_requests(rows: list[dict[str, Any]], source_page: str = "") -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        method = str(row.get("method") or "GET").upper()
        status = row.get("status")
        resource_type = normalize_resource_type(row.get("resource_type"))
        key = f"{method}|{url}|{resource_type}|{status}"
        parsed = urlparse(url)
        item = merged.get(key)
        if item is None:
            item = {
                "url": url,
                "host": parsed.hostname or "",
                "path": parsed.path or "/",
                "method": method,
                "status": status,
                "content_type": _content_type(row),
                "resource_type": resource_type,
                "response_size": _response_size(row),
                "initiator": str(row.get("initiator") or ""),
                "referer": str(row.get("referer") or ""),
                "timestamp": str(row.get("timestamp") or ""),
                "source_page": str(row.get("source_page") or source_page or ""),
                "duration": _duration(row),
                "times_seen": 0,
                "request_headers": row.get("request_headers") or {},
                "response_headers": row.get("response_headers") or {},
                "post_data_preview": str(row.get("post_data_preview") or ""),
            }
            merged[key] = item
        item["times_seen"] = int(item.get("times_seen") or 0) + 1
        item["response_size"] = max(int(item.get("response_size") or 0), _response_size(row))
        if not item.get("content_type"):
            item["content_type"] = _content_type(row)
        if not item.get("duration"):
            item["duration"] = _duration(row)
    output = list(merged.values())
    output.sort(key=lambda item: (_resource_sort(item.get("resource_type")), item.get("host") or "", item.get("path") or ""))
    return output[:700]


def network_statistics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    resource_counts = Counter(str(row.get("resource_type") or "other") for row in rows)
    host_counts = Counter(str(row.get("host") or "") for row in rows if row.get("host"))
    status_counts = Counter(str(row.get("status") or "unknown") for row in rows)
    total_size = sum(int(row.get("response_size") or 0) for row in rows)
    return {
        "total_requests": len(rows),
        "unique_hosts": len(host_counts),
        "total_response_size": total_size,
        "resource_types": dict(sorted(resource_counts.items())),
        "statuses": dict(sorted(status_counts.items())),
        "top_hosts": [{"host": host, "count": count} for host, count in host_counts.most_common(20)],
    }


def normalize_resource_type(value: Any) -> str:
    raw = str(value or "other").lower()
    if raw in {"xhr", "fetch", "document", "script", "stylesheet", "image", "font", "media", "websocket", "manifest"}:
        return raw
    return "other"


def _resource_sort(resource_type: Any) -> int:
    try:
        return RESOURCE_ORDER.index(str(resource_type or "other"))
    except ValueError:
        return len(RESOURCE_ORDER)


def _content_type(row: dict[str, Any]) -> str:
    if row.get("content_type"):
        return str(row.get("content_type") or "")
    headers = row.get("response_headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "content-type":
            return str(value).split(";", 1)[0].strip()
    return ""


def _response_size(row: dict[str, Any]) -> int:
    for key in ("response_size", "encoded_body_size", "body_size"):
        try:
            value = int(row.get(key) or 0)
            if value > 0:
                return value
        except Exception:
            pass
    headers = row.get("response_headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "content-length":
            try:
                return int(value)
            except Exception:
                return 0
    return 0


def _duration(row: dict[str, Any]) -> int:
    try:
        return int(float(row.get("duration") or row.get("duration_ms") or 0))
    except Exception:
        return 0
