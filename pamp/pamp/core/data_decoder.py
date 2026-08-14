from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import re
import string
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .models import digest_value, mask_value


JWT_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
UUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
HEX_PATTERN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
HASH_PATTERN = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
GA_PATTERN = re.compile(r"\b(?:GA\d+\.\d+\.[0-9.]+|G-[A-Z0-9]{4,}|UA-\d+-\d+)\b")
YANDEX_PATTERN = re.compile(r"\b(?:ym_uid|ym_d|_ym_uid|_ym_d|yaCounter\d+|mc\.yandex)\b", re.I)
META_PIXEL_PATTERN = re.compile(r"\b(?:_fbp|fbp|fbclid|fbevents\.js|connect\.facebook\.net)\b", re.I)
TIKTOK_PIXEL_PATTERN = re.compile(r"\b(?:ttclid|ttq|analytics\.tiktok\.com|tiktok pixel)\b", re.I)
MICROSOFT_ANALYTICS_PATTERN = re.compile(r"\b(?:clarity\.ms|Microsoft Clarity|msclkid)\b", re.I)
CLOUDFLARE_COOKIE_PATTERN = re.compile(r"\b(?:cf_clearance|__cf_bm|cf_chl_|cf_ob_info|cf_use_ob)\b", re.I)
TELEGRAM_PATTERN = re.compile(r"https?://(?:t\.me|telegram\.me)/[A-Za-z0-9_+/.-]+", re.I)
BEARER_PATTERN = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})\b", re.I)
API_KEY_PATTERN = re.compile(
    r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|authorization|auth)\b[=:]\s*([A-Za-z0-9._~+/=-]{12,})",
    re.I,
)
BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=")
BASE64URL_CHARS = set(string.ascii_letters + string.digits + "-_=")
SENSITIVE_PARAM_NAMES = re.compile(
    r"(token|secret|password|passwd|session|auth|jwt|bearer|refresh|access|id_token|credential|key|code|signature|sig)",
    re.I,
)
ENDPOINT_KEYWORDS = (
    "/api/",
    "/graphql",
    "/rest/",
    "/v1/",
    "/v2/",
    "/auth",
    "/login",
    "/admin",
    "/token",
    "/oauth",
    "/callback",
    "/webhook",
    "/upload",
    "/download",
)


def decode_items(items: list[dict[str, str]], limit: int = 300) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        value = str(item.get("value") or "").strip()
        source = str(item.get("source") or "")
        if not value:
            continue
        for result in inspect_value(value, source):
            key = f"{result['type']}|{result['value_masked']}|{result['source']}"
            if key in seen:
                continue
            seen.add(key)
            results.append(result)
            if len(results) >= limit:
                return results
    return results


def inspect_value(value: str, source: str = "") -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    text = str(value).strip()
    if not text:
        return results

    for token in JWT_PATTERN.findall(text):
        results.append(_jwt_result(token, source))
    for token in BEARER_PATTERN.findall(text):
        results.append(_basic_result(token, "Token-like string", source, "High", "bearer token-like string detected"))
    for token in API_KEY_PATTERN.findall(text):
        results.append(_basic_result(token, "Token-like string", source, "High", "key/token-like string detected"))
    for token in UUID_PATTERN.findall(text):
        results.append(_basic_result(token, "UUID", source, "Low", "identifier format"))
    for token in HASH_PATTERN.findall(text):
        results.append(_hash_result(token, source))
    for token in EMAIL_PATTERN.findall(text):
        results.append(_basic_result(token, "email-like", source, "Low", "email pattern"))
    for token in GA_PATTERN.findall(text):
        results.append(_basic_result(token, "Analytics ID", source, "Low", "Google analytics ID"))
    for token in TELEGRAM_PATTERN.findall(text):
        results.append(_basic_result(token, "Telegram link", source, "Low", "public link"))

    for match in CLOUDFLARE_COOKIE_PATTERN.finditer(text):
        results.append(_basic_result(match.group(0), "Cloudflare cookie name", source, "Low", "cookie name only"))
    for match in YANDEX_PATTERN.finditer(text):
        results.append(_basic_result(match.group(0), "Analytics ID", source, "Low", "Yandex analytics ID"))
    for match in META_PIXEL_PATTERN.finditer(text):
        results.append(_basic_result(match.group(0), "Pixel ID", source, "Low", "Meta pixel ID"))
    for match in TIKTOK_PIXEL_PATTERN.finditer(text):
        results.append(_basic_result(match.group(0), "Pixel ID", source, "Low", "TikTok pixel ID"))
    for match in MICROSOFT_ANALYTICS_PATTERN.finditer(text):
        results.append(_basic_result(match.group(0), "Analytics ID", source, "Low", "Microsoft analytics ID"))
    if _looks_endpoint(text):
        results.append(_basic_result(text, "Endpoint", source, _endpoint_risk(text), _endpoint_notes(text)))

    if not results:
        base_result = _base_decode_result(text, source)
        if base_result:
            results.append(base_result)
        hex_result = _hex_decode_result(text, source)
        if hex_result:
            results.append(hex_result)

    return _dedupe_results(results)


def sanitize_url(url: str) -> str:
    raw = str(url or "")
    if not raw:
        return ""
    parsed = urlparse(raw)
    if not parsed.query:
        return _mask_embedded_secrets(raw)
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if SENSITIVE_PARAM_NAMES.search(key) or _looks_sensitive_value(value):
            query.append((key, mask_value(value, 4, 4)))
        else:
            query.append((key, value))
    sanitized = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    return _mask_embedded_secrets(sanitized)


def extract_query_values(url: str, source: str) -> list[dict[str, str]]:
    parsed = urlparse(str(url or ""))
    if not parsed.query:
        return []
    items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not value:
            continue
        items.append({"value": value, "source": f"{source} query:{key}"})
    return items


def mask_text(text: str) -> str:
    masked = JWT_PATTERN.sub(lambda match: mask_value(match.group(0), 4, 4), str(text))
    masked = BEARER_PATTERN.sub(lambda match: f"Bearer {mask_value(match.group(1), 4, 4)}", masked)
    masked = API_KEY_PATTERN.sub(lambda match: match.group(0).replace(match.group(1), mask_value(match.group(1), 4, 4)), masked)
    return masked


def _jwt_result(token: str, source: str) -> dict[str, str]:
    header: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    notes = "JWT header/payload decoded; signature not inspected"
    try:
        header = _decode_jwt_part(token.split(".")[0])
        payload = _decode_jwt_part(token.split(".")[1])
    except Exception as exc:
        notes = f"invalid JWT: {exc}"
    claims = {}
    for key in ("alg", "typ"):
        if key in header:
            claims[key] = header[key]
    for key in ("iss", "aud", "sub", "iat", "exp"):
        if key in payload:
            claims[key] = _format_claim(key, payload[key])
    return {
        "value_masked": mask_value(token, 4, 4),
        "type": "JWT",
        "source": source,
        "decoded_preview": _json_preview(claims),
        "risk": "High",
        "notes": notes,
    }


def _decode_jwt_part(value: str) -> dict[str, Any]:
    padded = value + "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    payload = json.loads(decoded.decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _format_claim(key: str, value: Any) -> Any:
    if key in {"iat", "exp"}:
        try:
            return f"{value} ({datetime.fromtimestamp(int(value), timezone.utc).isoformat()})"
        except Exception:
            return value
    return value


def _hash_result(token: str, source: str) -> dict[str, str]:
    size = len(token)
    hash_type = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(size, "Hash")
    return {
        "value_masked": mask_value(token, 4, 4),
        "type": hash_type,
        "source": source,
        "decoded_preview": "",
        "risk": "Low",
        "notes": "hash type guessed by length; no cracking attempted",
    }


def _base_decode_result(value: str, source: str) -> dict[str, str] | None:
    if len(value) < 12 or len(value) > 4096:
        return None
    candidate = value.strip()
    if set(candidate) <= BASE64URL_CHARS and any(char in candidate for char in "-_"):
        decoder = base64.urlsafe_b64decode
        kind = "Base64URL"
    elif set(candidate) <= BASE64_CHARS:
        decoder = base64.b64decode
        kind = "Base64"
    else:
        return None
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = decoder(padded.encode("ascii"))
    except Exception:
        return None
    if not decoded:
        return None
    if _is_text(decoded):
        preview = decoded.decode("utf-8", errors="replace")[:300]
        preview = mask_text(preview)
        notes = "text preview"
    else:
        preview = f"binary, {len(decoded)} bytes"
        notes = "binary payload"
    return {
        "value_masked": mask_value(value, 4, 4),
        "type": kind,
        "source": source,
        "decoded_preview": preview,
        "risk": "Medium" if _looks_sensitive_value(value) else "Low",
        "notes": notes,
    }


def _hex_decode_result(value: str, source: str) -> dict[str, str] | None:
    raw = value[2:] if value.lower().startswith("0x") else value
    if len(raw) < 16 or len(raw) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw):
        return None
    if len(raw) in {32, 40, 64}:
        return None
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        return None
    if _is_text(decoded):
        preview = decoded.decode("utf-8", errors="replace")[:300]
        notes = "hex text preview"
    else:
        preview = f"binary, {len(decoded)} bytes"
        notes = "hex binary payload"
    return {
        "value_masked": mask_value(value, 4, 4),
        "type": "hex",
        "source": source,
        "decoded_preview": mask_text(preview),
        "risk": "Low",
        "notes": notes,
    }


def _basic_result(value: str, item_type: str, source: str, risk: str, notes: str) -> dict[str, str]:
    return {
        "value_masked": mask_value(value, 4, 4),
        "type": item_type,
        "source": source,
        "decoded_preview": "",
        "risk": risk,
        "notes": notes,
    }


def _json_preview(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)[:300]


def _is_text(data: bytes) -> bool:
    if not data:
        return False
    text_chars = sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in data)
    return text_chars / len(data) > 0.85


def _looks_sensitive_value(value: str) -> bool:
    text = str(value or "")
    return bool(JWT_PATTERN.search(text) or BEARER_PATTERN.search(text) or len(text) >= 24 and re.search(r"[A-Za-z]", text) and re.search(r"\d", text))


def _looks_endpoint(value: str) -> bool:
    lowered = str(value).lower()
    return lowered.startswith(("http://", "https://", "ws://", "wss://")) or any(keyword in lowered for keyword in ENDPOINT_KEYWORDS)


def _endpoint_risk(value: str) -> str:
    lowered = str(value).lower()
    if any(keyword in lowered for keyword in ("/auth", "/login", "/admin", "/token", "/oauth", "/callback", "/webhook", "token=", "key=")):
        return "Medium"
    return "Medium" if _looks_endpoint(value) else "Low"


def _endpoint_notes(value: str) -> str:
    lowered = str(value).lower()
    if any(keyword in lowered for keyword in ("/auth", "/login", "/admin", "/token", "/oauth", "/callback", "/webhook")):
        return "exposed endpoint"
    return "endpoint candidate"


def _mask_embedded_secrets(value: str) -> str:
    return mask_text(value)


def _dedupe_results(items: list[dict[str, str]]) -> list[dict[str, str]]:
    output = []
    seen = set()
    for item in items:
        key = digest_value(f"{item.get('type')}|{item.get('value_masked')}|{item.get('source')}")
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output
