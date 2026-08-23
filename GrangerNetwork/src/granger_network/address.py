from __future__ import annotations

import base64
import hashlib
import re

from .errors import AddressError


NAMESPACE = ".granger"
SERVICE_ID_DOMAIN = b"granger-network-v0.1/service-id\x00"
_ALIAS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CANONICAL_LABEL = re.compile(r"^[a-z2-7]{52}$")


def service_id_from_public_key(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise AddressError("an Ed25519 public key must contain exactly 32 bytes")
    digest = hashlib.sha256(SERVICE_ID_DOMAIN + public_key).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=").lower()


def canonical_address(public_key: bytes) -> str:
    return f"{service_id_from_public_key(public_key)}{NAMESPACE}"


def normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise AddressError("a .granger name must be text")
    normalized = name.strip().lower()
    if normalized != name.lower() or not normalized.endswith(NAMESPACE):
        raise AddressError("only a single ASCII label ending in .granger is accepted")
    label = normalized[: -len(NAMESPACE)]
    if not label or "." in label or not _ALIAS_LABEL.fullmatch(label):
        raise AddressError("invalid .granger label")
    return normalized


def is_canonical_name(name: str) -> bool:
    try:
        label = normalize_name(name)[: -len(NAMESPACE)]
    except AddressError:
        return False
    return _CANONICAL_LABEL.fullmatch(label) is not None


def service_id_from_name(name: str) -> str:
    normalized = normalize_name(name)
    label = normalized[: -len(NAMESPACE)]
    if not _CANONICAL_LABEL.fullmatch(label):
        raise AddressError("the name is a local alias, not a canonical service address")
    return label
