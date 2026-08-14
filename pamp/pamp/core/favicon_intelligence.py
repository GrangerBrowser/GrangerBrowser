from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from .intelligence_common import DebugLog, dedupe_findings, finding, record_error


FAVICON_TIMEOUT = 8
MAX_ICON_BYTES = 2 * 1024 * 1024
USER_AGENT = "Pamp/Domain-Analyzer"
FINGERPRINT_PATH = Path(__file__).resolve().parents[1] / "data" / "favicons" / "fingerprints.json"


def analyze_favicons(
    base_url: str,
    html_text: str,
    existing_favicon: dict[str, Any] | None = None,
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    candidates = _icon_candidates(base_url, html_text, existing_favicon or {}, debug_log, errors)
    selected = candidates[:16]
    with ThreadPoolExecutor(max_workers=min(6, max(1, len(selected)))) as executor:
        fetched = executor.map(lambda candidate: _fetch_icon(candidate, debug_log, errors), selected)
        icons = [row for row in fetched if row]
    icons = dedupe_findings(icons, ("value", "sha256"), 30)
    primary = next((row for row in icons if row.get("status_code") == 200 and row.get("sha256")), {})
    fingerprints = _load_fingerprints(debug_log, errors)
    matches = _match_fingerprints(icons, fingerprints)
    hashes = {
        key: primary.get(key) or ""
        for key in ("sha256", "md5", "mmh3")
        if primary.get(key) not in {None, ""}
    }
    return {
        "icons": icons,
        "primary_icon": primary,
        "hashes": hashes,
        "matches": matches,
        "summary": {
            "candidates": len(candidates),
            "icons": len(icons),
            "matches": len(matches),
            "database_entries": len(fingerprints),
        },
        "errors": errors,
    }


def _icon_candidates(
    base_url: str,
    html_text: str,
    existing: dict[str, Any],
    debug_log: DebugLog | None,
    errors: list[str],
) -> list[dict[str, str]]:
    rows = []
    if existing.get("url"):
        rows.append({"url": str(existing["url"]), "source": "HTTP Surface favicon"})
    manifest_urls = []
    if html_text and base_url:
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_text, "html.parser")
            for tag in soup.find_all("link", href=True):
                rel = " ".join(tag.get("rel") or []).lower()
                url = urljoin(base_url, str(tag.get("href") or ""))
                if "apple-touch-icon" in rel:
                    rows.append({"url": url, "source": "apple-touch-icon"})
                elif "shortcut icon" in rel:
                    rows.append({"url": url, "source": "shortcut icon"})
                elif "icon" in rel:
                    rows.append({"url": url, "source": "HTML link icon"})
                elif "manifest" in rel:
                    manifest_urls.append(url)
        except Exception as exc:
            record_error(errors, debug_log, "[DOMAIN][FAVICON]", f"parse error={exc}")
    for manifest_url in manifest_urls[:3]:
        try:
            response = requests.get(
                manifest_url,
                headers={"User-Agent": USER_AGENT},
                timeout=FAVICON_TIMEOUT,
            )
            if response.status_code < 400:
                payload = response.json()
                for icon in payload.get("icons") or []:
                    if icon.get("src"):
                        rows.append(
                            {
                                "url": urljoin(manifest_url, str(icon["src"])),
                                "source": "manifest icon",
                            }
                        )
        except Exception as exc:
            record_error(
                errors,
                debug_log,
                "[DOMAIN][FAVICON]",
                f"url={manifest_url} error={exc}",
            )
    if base_url:
        rows.append({"url": urljoin(base_url, "/favicon.ico"), "source": "/favicon.ico fallback"})
    output = []
    seen = set()
    for row in rows:
        url = row["url"].strip()
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        output.append(row)
    return output


def _fetch_icon(
    candidate: dict[str, str],
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any] | None:
    url = candidate["url"]
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "image/*,*/*;q=0.5"},
            timeout=FAVICON_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )
        body = response.raw.read(MAX_ICON_BYTES + 1, decode_content=True)
        response.close()
    except Exception as exc:
        record_error(errors, debug_log, "[DOMAIN][FAVICON]", f"url={url} error={exc}")
        return None
    if response.status_code >= 400 or not body:
        return None
    body = body[:MAX_ICON_BYTES]
    sha256 = hashlib.sha256(body).hexdigest()
    md5 = hashlib.md5(body, usedforsecurity=False).hexdigest()
    mmh3_hash = _mmh3_hash(body)
    width, height = _image_dimensions(body)
    return finding(
        name="Favicon",
        item_type="favicon",
        value=response.url or url,
        source=candidate["source"],
        confidence="high",
        evidence=f"HTTP {response.status_code}; sha256={sha256}",
        risk="low",
        notes="Public icon fetched for passive fingerprint comparison.",
        url=url,
        final_url=response.url or url,
        status_code=response.status_code,
        content_type=response.headers.get("Content-Type", "").split(";", 1)[0],
        size=len(body),
        sha256=sha256,
        md5=md5,
        mmh3=mmh3_hash,
        width=width,
        height=height,
        dimensions=f"{width}x{height}" if width and height else "",
    )


def _mmh3_hash(body: bytes) -> int | None:
    try:
        import mmh3

        encoded = base64.encodebytes(body)
        return int(mmh3.hash(encoded))
    except Exception:
        return None


def _image_dimensions(body: bytes) -> tuple[int, int]:
    try:
        from PIL import Image

        with Image.open(BytesIO(body)) as image:
            return int(image.width), int(image.height)
    except Exception:
        return 0, 0


def _load_fingerprints(
    debug_log: DebugLog | None,
    errors: list[str],
) -> list[dict[str, Any]]:
    try:
        payload = json.loads(FINGERPRINT_PATH.read_text(encoding="utf-8"))
        return payload if isinstance(payload, list) else []
    except FileNotFoundError:
        return []
    except Exception as exc:
        record_error(
            errors,
            debug_log,
            "[DOMAIN][FAVICON]",
            f"database={FINGERPRINT_PATH} error={exc}",
        )
        return []


def _match_fingerprints(
    icons: list[dict[str, Any]],
    fingerprints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for icon in icons:
        for fingerprint in fingerprints:
            hash_type = str(fingerprint.get("hash_type") or "").lower()
            expected = str(fingerprint.get("hash") or "")
            actual = str(icon.get(hash_type) if hash_type in {"sha256", "md5", "mmh3"} else "")
            if not expected or actual != expected:
                continue
            rows.append(
                finding(
                    name=str(fingerprint.get("name") or "Favicon match"),
                    item_type=str(fingerprint.get("type") or "service"),
                    value=str(fingerprint.get("name") or ""),
                    source="pamp/data/favicons/fingerprints.json",
                    confidence=str(fingerprint.get("confidence") or "medium"),
                    evidence=f"{hash_type} matched {expected}",
                    risk=str(fingerprint.get("risk") or "low"),
                    notes=str(fingerprint.get("notes") or "Local favicon fingerprint match."),
                    service=str(fingerprint.get("name") or ""),
                    hash_type=hash_type,
                    hash=expected,
                    icon_url=str(icon.get("final_url") or icon.get("value") or ""),
                )
            )
    return dedupe_findings(rows, ("name", "hash_type", "hash"), 80)
