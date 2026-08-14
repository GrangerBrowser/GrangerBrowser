from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

import requests

from .intelligence_common import DebugLog, dedupe_findings, finding, record_error


TIMEOUT = 8
MAX_CANDIDATES = 80
MAX_VERIFY = 40
USER_AGENT = "Pamp/Domain-Analyzer"
URL_PATTERN = re.compile(r"""https?://[^\s"'`<>\\]{5,500}""", re.I)
SENSITIVE_PATTERN = re.compile(
    r"""(?i)(?:^|[/_.-])(?:\.env|config|backup|dump|database|credentials?|service-account)(?:[/_.-]|$)|\.(?:sql|zip|tar|gz|key|pem)(?:[?#]|$)"""
)


def analyze_cloud_buckets(
    sources: list[dict[str, Any]],
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    candidates: list[dict[str, Any]] = []
    for source_row in sources:
        source = str(source_row.get("source") or "domain analysis")
        for value in _source_values(source_row.get("value")):
            for url in URL_PATTERN.findall(value):
                parsed = _parse_storage_url(url.rstrip(".,);]"))
                if not parsed:
                    continue
                risk = _candidate_risk(parsed)
                candidates.append(
                    finding(
                        name=parsed["bucket"] or parsed["provider"],
                        item_type="cloud_bucket",
                        value=parsed["url"],
                        source=source,
                        confidence="high",
                        evidence=f"{parsed['provider']} storage URL referenced in {source}",
                        risk=risk,
                        notes="Exact referenced storage URL; no bucket-name guessing was performed.",
                        provider=parsed["provider"],
                        bucket=parsed["bucket"],
                        region=parsed["region"],
                        url=parsed["url"],
                        object_path=parsed["object_path"],
                        status="unknown",
                    )
                )
    candidates = dedupe_findings(candidates, ("provider", "bucket", "url"), MAX_CANDIDATES)
    verified = []
    public_objects = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_verify_reference, candidate, debug_log, errors): candidate
            for candidate in candidates[:MAX_VERIFY]
        }
        for future in as_completed(futures):
            try:
                checked = future.result()
            except Exception as exc:
                candidate = futures[future]
                record_error(
                    errors,
                    debug_log,
                    "[DOMAIN][BUCKET]",
                    f"url={candidate.get('url') or ''} error={exc}",
                )
                continue
            verified.append(checked)
    for checked in verified:
        if checked.get("status") == "public" and checked.get("object_path"):
            public_objects.append(
                finding(
                    name=checked["object_path"].rsplit("/", 1)[-1] or checked["bucket"],
                    item_type="public_object",
                    value=checked["url"],
                    source=checked["source"],
                    confidence="high",
                    evidence=f"Referenced object returned HTTP {checked.get('status_code')}",
                    risk="high" if SENSITIVE_PATTERN.search(checked["url"]) else "medium",
                    notes="Only availability, content type, and size were checked.",
                    provider=checked["provider"],
                    bucket=checked["bucket"],
                    region=checked["region"],
                    url=checked["url"],
                    object_path=checked["object_path"],
                    status=checked["status"],
                    status_code=checked.get("status_code"),
                    content_type=checked.get("content_type") or "",
                    size=checked.get("size"),
                )
            )
    public_objects = dedupe_findings(public_objects, ("provider", "bucket", "url"), MAX_CANDIDATES)
    return {
        "candidates": candidates,
        "verified": verified,
        "public_objects": public_objects,
        "summary": {
            "candidates": len(candidates),
            "verified": len(verified),
            "public": sum(1 for row in verified if row.get("status") == "public"),
            "protected": sum(1 for row in verified if row.get("status") == "protected"),
            "public_objects": len(public_objects),
            "high_risk": sum(1 for row in verified + public_objects if row.get("risk") == "high"),
        },
        "errors": errors,
    }


def _source_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value[:2_000_000]]
    if isinstance(value, dict):
        return [str(item) for item in value.values() if item is not None][:500]
    if isinstance(value, (list, tuple, set)):
        rows = []
        for item in value:
            if isinstance(item, dict):
                rows.extend(str(value) for value in item.values() if value is not None)
            elif item is not None:
                rows.append(str(item))
            if len(rows) >= 1000:
                break
        return rows
    return [str(value)] if value is not None else []


def _parse_storage_url(url: str) -> dict[str, str] | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    path = parsed.path.lstrip("/")
    provider = bucket = region = object_path = ""

    if host == "s3.amazonaws.com" and path:
        provider = "Amazon S3"
        bucket, _, object_path = path.partition("/")
    elif re.fullmatch(r"[^.]+\.s3\.amazonaws\.com", host):
        provider = "Amazon S3"
        bucket = host.split(".s3.", 1)[0]
        object_path = path
    else:
        match = re.fullmatch(r"([^.]+)\.s3[.-]([a-z0-9-]+)\.amazonaws\.com", host)
        if match:
            provider = "Amazon S3"
            bucket, region = match.groups()
            object_path = path
        match = match or re.fullmatch(r"([^.]+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com", host)
        if match and not provider:
            provider = "Amazon S3"
            bucket, region = match.groups()
            object_path = path

    if host == "storage.googleapis.com" and path:
        provider = "Google Cloud Storage"
        bucket, _, object_path = path.partition("/")
    elif host.endswith(".storage.googleapis.com"):
        provider = "Google Cloud Storage"
        bucket = host[: -len(".storage.googleapis.com")]
        object_path = path
    elif host == "firebasestorage.googleapis.com":
        provider = "Firebase Storage"
        match = re.search(r"(?:^|/)b/([^/]+)/o(?:/(.*))?", parsed.path)
        bucket = match.group(1) if match else ""
        object_path = match.group(2) if match and match.group(2) else path
    elif host.endswith(".blob.core.windows.net"):
        provider = "Azure Blob Storage"
        bucket = host.split(".blob.core.windows.net", 1)[0]
        container, _, rest = path.partition("/")
        object_path = f"{container}/{rest}".rstrip("/") if container else ""
    elif host.endswith(".r2.cloudflarestorage.com"):
        provider = "Cloudflare R2"
        bucket = host.split(".r2.cloudflarestorage.com", 1)[0]
        object_path = path
    elif host.endswith(".digitaloceanspaces.com"):
        provider = "DigitalOcean Spaces"
        labels = host.split(".")
        bucket = labels[0]
        region = labels[1] if len(labels) > 3 else ""
        object_path = path
    elif host.endswith(".backblazeb2.com") or host == "f000.backblazeb2.com":
        provider = "Backblaze B2"
        match = re.search(r"(?:^|/)file/([^/]+)(?:/(.*))?", parsed.path)
        bucket = match.group(1) if match else host.split(".", 1)[0]
        object_path = match.group(2) if match and match.group(2) else path
    elif host.endswith(".supabase.co") and "/storage/v1/object/" in parsed.path:
        provider = "Supabase Storage"
        suffix = parsed.path.split("/storage/v1/object/", 1)[1].lstrip("/")
        if suffix.startswith(("public/", "sign/", "authenticated/")):
            suffix = suffix.split("/", 1)[1] if "/" in suffix else ""
        bucket, _, object_path = suffix.partition("/")

    if not provider:
        return None
    return {
        "provider": provider,
        "bucket": bucket,
        "region": region,
        "url": url,
        "object_path": object_path,
    }


def _candidate_risk(parsed: dict[str, str]) -> str:
    if SENSITIVE_PATTERN.search(parsed["url"]):
        return "high"
    return "medium" if parsed["object_path"] else "high"


def _verify_reference(
    candidate: dict[str, Any],
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any]:
    row = dict(candidate)
    url = str(candidate.get("url") or "")
    try:
        response = requests.head(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        if response.status_code == 405:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT, "Range": "bytes=0-65535"},
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
        status_code = response.status_code
        row.update(
            {
                "url": response.url or url,
                "value": response.url or url,
                "status_code": status_code,
                "status": _access_status(status_code),
                "content_type": response.headers.get("Content-Type", "").split(";", 1)[0],
                "size": _content_length(response.headers.get("Content-Length")),
                "evidence": f"Passive availability check returned HTTP {status_code}",
            }
        )
        if row["status"] == "public" and not row.get("object_path"):
            row["risk"] = "high"
            row["notes"] = "Bucket root or listing endpoint is publicly reachable; review manually."
        elif row["status"] == "protected":
            row["risk"] = "low"
            row["notes"] = "Referenced storage endpoint requires authorization."
        elif row["status"] == "not_found":
            row["risk"] = "low"
            row["notes"] = "Referenced storage endpoint was not found."
        response.close()
    except Exception as exc:
        record_error(errors, debug_log, "[DOMAIN][BUCKET]", f"url={url} error={exc}")
        row["status"] = "unknown"
        row["notes"] = "Availability check failed; see debug.log."
    return row


def _access_status(status_code: int) -> str:
    if status_code in {200, 206, 301, 302, 307, 308}:
        return "public"
    if status_code in {401, 403}:
        return "protected"
    if status_code == 404:
        return "not_found"
    return "unknown"


def _content_length(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
