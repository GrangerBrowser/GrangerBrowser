from __future__ import annotations

import hashlib
import re
from typing import Any


def normalized_body_hash(text: str) -> str:
    sample = (text or "")[:200_000].lower()
    sample = re.sub(r"pamp-(?:random-404|not-found|unknown-path)-[a-f0-9-]+", "pamp-random", sample)
    sample = re.sub(r"__pamp_wildcard_[a-f0-9]+", "__pamp_wildcard_", sample)
    sample = re.sub(r"\b[a-f0-9]{12,}\b", "HEX", sample)
    sample = re.sub(r"\b\d{4,}\b", "NUM", sample)
    sample = re.sub(r"\s+", " ", sample)
    return hashlib.sha256(sample.encode("utf-8", errors="ignore")).hexdigest()[:16]


def response_signature(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(row.get("status_code") or row.get("status") or 0),
        row.get("normalized_hash") or row.get("fingerprint_hash") or row.get("body_hash") or "",
        row.get("content_length") or row.get("size") or 0,
        row.get("content_type") or "",
        row.get("redirect_location") or row.get("redirect") or "",
    )


def fingerprint_row(
    status_code: int,
    body: bytes,
    text: str,
    content_type: str,
    redirect_location: str = "",
) -> dict[str, Any]:
    normalized_hash = normalized_body_hash(text)
    body_hash = hashlib.sha256(body).hexdigest()[:16]
    return {
        "status_code": int(status_code),
        "content_length": len(body),
        "words": len(re.findall(r"\S+", text or "")),
        "lines": len((text or "").splitlines()),
        "content_type": content_type,
        "redirect_location": redirect_location,
        "body_hash": body_hash,
        "fingerprint_hash": normalized_hash,
        "normalized_hash": normalized_hash,
    }
