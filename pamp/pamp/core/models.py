from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import re
from typing import Any
from uuid import uuid4


SENSITIVE_NAME_PATTERN = re.compile(
    r"(token|secret|password|passwd|session|auth|jwt|bearer|refresh|access|id_token|credential|key)",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value.strip())
    return cleaned[:80] or "artifact"


def digest_value(value: Any) -> str:
    raw = "" if value is None else str(value)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def mask_value(value: Any, keep_start: int = 3, keep_end: int = 3) -> str:
    if value is None:
        return ""
    raw = str(value)
    if not raw:
        return ""
    if len(raw) <= keep_start + keep_end + 3:
        return "***"
    return f"{raw[:keep_start]}...{raw[-keep_end:]}"


def mask_by_name(name: str, value: Any) -> Any:
    if value is None:
        return None
    if SENSITIVE_NAME_PATTERN.search(name or ""):
        return mask_value(value)
    return value


def mask_jwt(value: str) -> str:
    parts = value.split(".")
    if len(parts) != 3:
        return mask_value(value)
    return ".".join(mask_value(part, 4, 4) for part in parts)


@dataclass
class ArtifactRecord:
    type: str
    label: str
    data: dict[str, Any]
    source: str
    id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ArtifactRecord":
        return cls(
            id=payload.get("id") or uuid4().hex,
            type=payload["type"],
            label=payload["label"],
            data=payload.get("data") or {},
            source=payload.get("source") or "imported",
            created_at=payload.get("created_at") or utc_now(),
        )

