from __future__ import annotations

import re
from typing import Any, Callable


DebugLog = Callable[[str], None]


def finding(
    name: str,
    item_type: str,
    value: Any,
    source: str,
    confidence: str,
    evidence: str,
    risk: str,
    notes: str = "",
    **extra: Any,
) -> dict[str, Any]:
    row = {
        "name": str(name or ""),
        "type": str(item_type or ""),
        "value": str(value or ""),
        "source": str(source or ""),
        "confidence": str(confidence or "low").lower(),
        "evidence": compact_text(evidence, 320),
        "risk": str(risk or "low").lower(),
        "notes": compact_text(notes, 320),
    }
    row.update(extra)
    return row


def compact_text(value: Any, limit: int = 320) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def mask_secret(value: Any, keep_start: int = 10, keep_end: int = 2) -> str:
    raw = str(value or "")
    if not raw:
        return ""
    if len(raw) <= keep_start + keep_end + 4:
        return f"{raw[:2]}****{raw[-2:]}" if len(raw) > 4 else "****"
    hidden = max(8, min(32, len(raw) - keep_start - keep_end))
    return f"{raw[:keep_start]}{'*' * hidden}{raw[-keep_end:]}"


def record_error(
    errors: list[str],
    debug_log: DebugLog | None,
    prefix: str,
    detail: str,
) -> None:
    message = f"{prefix} {detail}"
    errors.append(message)
    if debug_log:
        try:
            debug_log(message)
        except Exception:
            pass


def dedupe_findings(
    rows: list[dict[str, Any]],
    keys: tuple[str, ...] = ("type", "value", "source"),
    limit: int = 500,
) -> list[dict[str, Any]]:
    output = []
    seen = set()
    confidence_rank = {"low": 1, "medium": 2, "high": 3}
    risk_rank = {"low": 1, "medium": 2, "high": 3}
    for row in rows:
        key = tuple(str(row.get(item) or "").lower() for item in keys)
        if not any(key) or key in seen:
            continue
        seen.add(key)
        output.append(row)
    output.sort(
        key=lambda row: (
            -risk_rank.get(str(row.get("risk") or "").lower(), 0),
            -confidence_rank.get(str(row.get("confidence") or "").lower(), 0),
            str(row.get("name") or "").lower(),
        )
    )
    return output[:limit]
