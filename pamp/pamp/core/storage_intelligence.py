from __future__ import annotations

import json
from typing import Any

from .models import SENSITIVE_NAME_PATTERN, digest_value, mask_value


PREVIEW_LIMIT = 120


def collect_storage_snapshots(page: Any, source_page: str, errors: list[str]) -> dict[str, Any]:
    return {
        "localStorage": _evaluate_storage(page, "localStorage", source_page, errors),
        "sessionStorage": _evaluate_storage(page, "sessionStorage", source_page, errors),
        "indexedDB": _evaluate_indexeddb(page, source_page, errors),
        "cacheStorage": _evaluate_cache_storage(page, source_page, errors),
    }


def storage_keys(storage_rows: list[dict[str, Any]]) -> list[str]:
    return sorted({str(row.get("key") or "") for row in storage_rows if row.get("key")})


def storage_summary(storage: dict[str, Any]) -> dict[str, int]:
    return {
        "localStorage": len(storage.get("localStorage") or []),
        "sessionStorage": len(storage.get("sessionStorage") or []),
        "indexedDB": len(storage.get("indexedDB") or []),
        "cacheStorage": len(storage.get("cacheStorage") or []),
    }


def _evaluate_storage(page: Any, storage_name: str, source_page: str, errors: list[str]) -> list[dict[str, Any]]:
    script = f"""
    () => Object.keys(window.{storage_name} || {{}}).map(key => {{
      const value = window.{storage_name}.getItem(key) || "";
      return {{ key, value, type: "{storage_name}", source: location.href, size: value.length }};
    }})
    """
    try:
        rows = page.evaluate(script)
    except Exception as exc:
        errors.append(f"{storage_name}: {exc}")
        return []
    return sanitize_storage_rows(rows, storage_name, source_page)


def _evaluate_indexeddb(page: Any, source_page: str, errors: list[str]) -> list[dict[str, Any]]:
    script = """
    async () => {
      if (!("indexedDB" in window) || !indexedDB.databases) return [];
      const dbs = await indexedDB.databases();
      return dbs.map(db => ({
        key: db.name || "",
        value: db.version ? `version ${db.version}` : "",
        type: "IndexedDB",
        source: location.href,
        size: 0
      }));
    }
    """
    try:
        rows = page.evaluate(script)
    except Exception as exc:
        errors.append(f"IndexedDB: {exc}")
        return []
    return sanitize_storage_rows(rows, "IndexedDB", source_page)


def _evaluate_cache_storage(page: Any, source_page: str, errors: list[str]) -> list[dict[str, Any]]:
    script = """
    async () => {
      if (!("caches" in window)) return [];
      const names = await caches.keys();
      return names.map(name => ({
        key: name,
        value: "",
        type: "Cache Storage",
        source: location.href,
        size: 0
      }));
    }
    """
    try:
        rows = page.evaluate(script)
    except Exception as exc:
        errors.append(f"Cache Storage: {exc}")
        return []
    return sanitize_storage_rows(rows, "Cache Storage", source_page)


def sanitize_storage_rows(rows: list[Any], storage_type: str, source_page: str) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("key") or "")
        if not key:
            continue
        value = row.get("value", "")
        source = str(row.get("source") or source_page or "")
        dedupe_key = f"{storage_type}|{source}|{key}"
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        size = _size(value, row.get("size"))
        output.append(
            {
                "key": key,
                "value_preview": _preview(key, value),
                "value_digest": digest_value(value),
                "type": str(row.get("type") or storage_type),
                "source": source,
                "size": size,
                "risk_score": _risk_score(key, value, size),
            }
        )
    output.sort(key=lambda item: (-int(item.get("risk_score") or 0), item.get("type") or "", item.get("key") or ""))
    return output[:240]


def _preview(key: str, value: Any) -> str:
    raw = "" if value is None else str(value)
    if SENSITIVE_NAME_PATTERN.search(key):
        return mask_value(raw)
    if len(raw) <= PREVIEW_LIMIT:
        return raw
    return f"{raw[:PREVIEW_LIMIT]}..."


def _risk_score(key: str, value: Any, size: int) -> int:
    raw = "" if value is None else str(value)
    score = 5
    if SENSITIVE_NAME_PATTERN.search(key):
        score += 45
    lowered = f"{key} {raw[:500]}".lower()
    if any(marker in lowered for marker in ("token", "jwt", "bearer", "secret", "apikey", "api_key")):
        score += 30
    if raw.count(".") >= 2 and len(raw) > 80:
        score += 15
    if size > 4096:
        score += 8
    return min(score, 100)


def _size(value: Any, fallback: Any = None) -> int:
    if isinstance(fallback, int):
        return fallback
    try:
        if isinstance(value, (dict, list)):
            return len(json.dumps(value, ensure_ascii=False))
        return len(str(value or ""))
    except Exception:
        return 0
