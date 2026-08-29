from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import shutil
import socket
import stat
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote_to_bytes, urlsplit

from ._codec import atomic_write_text, parse_json_object
from .descriptor import ServiceDescriptor
from .errors import GrangerNetworkError, OverlayRoutingError, UpstreamPolicyError
from .http_bridge import HttpResult, LoopbackHttpBridge, LoopbackHttpTarget
from .identity import ServiceIdentity
from .introduction import IntroductionDescriptor
from .wan_config import (
    ensure_browser_wan_config,
    load_browser_wan_config,
    load_discovery_runtime,
)
from .wan_routing import WanRouteSelector
from .wan_service import WanServiceHost


HOSTING_VERSION = 2
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_SERVICE_ROUTE_STARTUP_SECONDS = 90.0
MAX_SERVICE_ROUTE_ATTEMPTS = 2
MAX_STATIC_FILES = 10_000
MAX_TEXT_SCAN_BYTES = 256 * 1024
CONFIG_FILE = "config.json"
IDENTITY_FILE = "identity/service-identity.json"
SERVICE_DESCRIPTOR_FILE = "metadata/service-descriptor.json"
INTRODUCTION_DESCRIPTOR_FILE = "metadata/introduction-descriptor.json"
INTRODUCTION_SEQUENCE_FILE = "metadata/introduction-sequence.txt"
STATUS_FILE = "metadata/status.json"
PUBLICATION_ROOT = "publication"
PUBLICATION_CURRENT = "publication/current"
PUBLICATION_CONTENT = "publication/current/content"
PUBLICATION_MANIFEST = "publication/current/manifest.json"
_SERVICE_ID = re.compile(r"^[a-f0-9]{32}$")
_TITLE = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".gif": "image/gif",
    ".htm": "text/html; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".otf": "font/otf",
    ".png": "image/png",
    ".svg": "image/svg+xml; charset=utf-8",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
    ".wasm": "application/wasm",
    ".webp": "image/webp",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".xml": "application/xml; charset=utf-8",
}
_EXCLUDED_DIRECTORIES = {
    ".cache",
    ".git",
    ".github",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".vs",
    ".vscode",
    "__pycache__",
}
_EXCLUDED_FILES = {".git", ".gitattributes", ".gitignore", ".gitmodules"}
_EXCLUDED_SUFFIXES = {".bak", ".ilk", ".log", ".obj", ".pdb", ".pyc", ".swo", ".swp", ".tmp"}
_SENSITIVE_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"}
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
_OPSEC_PATH_MARKERS = ("c:\\users\\", "/home/", "/users/")


@dataclass(frozen=True)
class PublicationFinding:
    path: str
    reason: str

    def to_document(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True)
class _PublicationFile:
    relative_path: str
    source: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class StaticSiteInspection:
    ok: bool
    root: str
    files: int
    htmlFiles: int
    cssFiles: int
    jsFiles: int
    jsonFiles: int
    assets: int
    totalBytes: int
    indexFound: bool
    entryPage: str
    entryCandidates: tuple[str, ...]
    requiresEntrySelection: bool
    includedFiles: tuple[str, ...]
    excludedFiles: tuple[PublicationFinding, ...]
    blockedFindings: tuple[PublicationFinding, ...]
    snapshotHash: str
    errors: tuple[str, ...]

    def to_document(self) -> dict[str, object]:
        document = asdict(self)
        document["errors"] = list(self.errors)
        document["entryCandidates"] = list(self.entryCandidates)
        document["includedFiles"] = list(self.includedFiles)
        document["excludedFiles"] = [item.to_document() for item in self.excludedFiles]
        document["blockedFindings"] = [item.to_document() for item in self.blockedFindings]
        document["totalFiles"] = self.files
        document["version"] = HOSTING_VERSION
        return document


@dataclass(frozen=True)
class HostedServiceConfig:
    service_id: str
    title: str
    kind: str
    source: str
    entry_page: str
    upstream: str
    auto_start: bool
    max_file_bytes: int
    created_at: int

    def to_document(self) -> dict[str, object]:
        return {
            "autoStart": self.auto_start,
            "createdAt": self.created_at,
            "entryPage": self.entry_page,
            "id": self.service_id,
            "maxFileBytes": self.max_file_bytes,
            "source": self.source,
            "title": self.title,
            "type": self.kind,
            "upstream": self.upstream,
            "version": HOSTING_VERSION,
        }


def _validate_service_id(value: str) -> str:
    if not isinstance(value, str) or not _SERVICE_ID.fullmatch(value):
        raise ValueError("hosted service identifier is invalid")
    return value


def _validate_title(value: str) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if not _TITLE.fullmatch(normalized):
        raise ValueError("hosted service title is invalid")
    return normalized


def _validate_max_file_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 64 * 1024 <= value <= 64 * 1024 * 1024:
        raise ValueError("static site file limit is invalid")
    return value


def _relative_to_root(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _is_unc_path(path: Path) -> bool:
    value = os.fspath(path)
    return value.startswith("\\\\") or value.startswith("//")


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    is_junction = bool(getattr(path, "is_junction", lambda: False)())
    return path.is_symlink() or is_junction or bool(attributes & reparse_flag)


def _excluded_reason(relative_path: str, *, directory: bool) -> str:
    name = PurePosixPath(relative_path).name.casefold()
    if directory:
        if name in _EXCLUDED_DIRECTORIES:
            return "development_metadata_directory"
        return ""
    if name in _EXCLUDED_FILES:
        return "development_metadata_file"
    suffix = PurePosixPath(name).suffix
    if suffix in _EXCLUDED_SUFFIXES or name.endswith("~"):
        return "temporary_artifact"
    if re.fullmatch(r"readme(?:[._-].*)?", name):
        return "project_documentation"
    if re.fullmatch(r"changelog(?:[._-].*)?", name):
        return "project_documentation"
    if re.fullmatch(r"contributing(?:[._-].*)?", name):
        return "project_documentation"
    if re.fullmatch(r"code[._-]of[._-]conduct(?:[._-].*)?", name):
        return "project_documentation"
    if name == "security.md":
        return "project_security_documentation"
    return ""


def _sensitive_name_reason(relative_path: str) -> str:
    name = PurePosixPath(relative_path).name.casefold()
    if name == ".env" or name.startswith(".env."):
        return "environment_secrets"
    if PurePosixPath(name).suffix in _SENSITIVE_SUFFIXES:
        return "private_credential_container"
    if name in {"id_rsa", "id_ed25519", "authorized_keys"}:
        return "ssh_credentials"
    if name.startswith("credentials") or name.startswith("secrets"):
        return "credential_filename"
    return ""


def _decode_text_probe(content: bytes) -> str | None:
    try:
        if content.startswith((b"\xff\xfe", b"\xfe\xff")):
            decoded = content.decode("utf-16")
        else:
            decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    if "\x00" in decoded:
        return None
    return decoded


def _content_block_reason(content: bytes) -> str:
    upper = content.upper()
    if any(marker in upper for marker in _PRIVATE_KEY_MARKERS):
        return "private_key_material"
    decoded = _decode_text_probe(content)
    if decoded is None:
        return ""
    lowered = decoded.casefold()
    if any(marker in lowered for marker in _OPSEC_PATH_MARKERS):
        return "local_path_disclosure"
    return ""


def _hash_and_probe(path: Path, expected_size: int) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    probe = bytearray()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
            raise OSError("source file changed during privacy scan")
        total = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if len(probe) < MAX_TEXT_SCAN_BYTES:
                probe.extend(chunk[: MAX_TEXT_SCAN_BYTES - len(probe)])
    if total != expected_size:
        raise OSError("source file changed during privacy scan")
    return digest.hexdigest().upper(), bytes(probe)


def _snapshot_hash(files: tuple[_PublicationFile, ...], entry_page: str) -> str:
    digest = hashlib.sha256(b"granger-publication-snapshot-v1\x00")
    encoded_entry = entry_page.encode("utf-8")
    digest.update(len(encoded_entry).to_bytes(4, "big"))
    digest.update(encoded_entry)
    for item in files:
        encoded_path = item.relative_path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(item.size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(item.sha256))
    return digest.hexdigest().upper()


def _normalize_entry_page(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("static site entry page is invalid")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ValueError("static site entry page is invalid")
    normalized = parsed.as_posix()
    if Path(normalized).suffix.lower() not in {".html", ".htm"}:
        raise ValueError("static site entry page must be HTML")
    return normalized


def _scan_static_site(
    source: Path,
    *,
    entry_page: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> tuple[StaticSiteInspection, tuple[_PublicationFile, ...]]:
    limit = _validate_max_file_bytes(max_file_bytes)
    errors: list[str] = []
    excluded: list[PublicationFinding] = []
    blocked: list[PublicationFinding] = []

    def record_error(message: str) -> None:
        if len(errors) < 64:
            errors.append(message)

    def empty(root_value: str, message: str) -> tuple[StaticSiteInspection, tuple[_PublicationFile, ...]]:
        return (
            StaticSiteInspection(
                ok=False,
                root=root_value,
                files=0,
                htmlFiles=0,
                cssFiles=0,
                jsFiles=0,
                jsonFiles=0,
                assets=0,
                totalBytes=0,
                indexFound=False,
                entryPage="",
                entryCandidates=(),
                requiresEntrySelection=False,
                includedFiles=(),
                excludedFiles=(),
                blockedFindings=(),
                snapshotHash="",
                errors=(message,),
            ),
            (),
        )

    raw = Path(source)
    if not raw.is_absolute():
        return empty(str(raw), "source path must be absolute")
    if _is_unc_path(raw):
        return empty(str(raw), "UNC source paths are not publishable")
    if _is_reparse_point(raw):
        return empty(str(raw), "source directory cannot be a link or reparse point")
    try:
        root = raw.resolve(strict=True)
    except OSError:
        return empty(str(raw), "source directory is unavailable")
    if not root.is_dir():
        return empty(str(root), "source path is not a directory")

    included: list[_PublicationFile] = []
    html_files: list[str] = []
    css_files = 0
    js_files = 0
    json_files = 0
    assets = 0
    total_bytes = 0
    index_found = False
    scanned_entries = 0
    scan_stopped = False
    try:
        pending = [root]
        while pending and not scan_stopped:
            current = pending.pop()
            entries = sorted(os.scandir(current), key=lambda item: (item.name.casefold(), item.name))
            for directory_entry in entries:
                scanned_entries += 1
                if scanned_entries > MAX_STATIC_FILES:
                    record_error("static site exceeds the file-count limit")
                    scan_stopped = True
                    break
                entry = Path(directory_entry.path)
                relative = entry.relative_to(root).as_posix()
                try:
                    metadata = entry.lstat()
                    if _is_reparse_point(entry):
                        blocked.append(PublicationFinding(relative, "link_or_reparse_point"))
                        continue
                    resolved = entry.resolve(strict=True)
                    if not _relative_to_root(resolved, root):
                        blocked.append(PublicationFinding(relative, "canonical_path_escape"))
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        reason = _excluded_reason(relative, directory=True)
                        if reason:
                            excluded.append(PublicationFinding(relative, reason))
                        else:
                            pending.append(resolved)
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        blocked.append(PublicationFinding(relative, "special_filesystem_entry"))
                        continue
                    sensitive_reason = _sensitive_name_reason(relative)
                    if sensitive_reason:
                        blocked.append(PublicationFinding(relative, sensitive_reason))
                        continue
                    excluded_reason = _excluded_reason(relative, directory=False)
                    if excluded_reason:
                        excluded.append(PublicationFinding(relative, excluded_reason))
                        continue
                    size = metadata.st_size
                    if size > limit:
                        record_error(f"file exceeds size limit: {relative}")
                        continue
                    sha256, probe = _hash_and_probe(resolved, size)
                    block_reason = _content_block_reason(probe)
                    if block_reason:
                        blocked.append(PublicationFinding(relative, block_reason))
                        continue
                except OSError:
                    record_error(f"file is not readable: {relative}")
                    continue
                suffix = resolved.suffix.lower()
                included.append(_PublicationFile(relative, resolved, size, sha256))
                total_bytes += size
                if suffix in {".html", ".htm"}:
                    html_files.append(relative)
                elif suffix == ".css":
                    css_files += 1
                elif suffix in {".js", ".mjs"}:
                    js_files += 1
                elif suffix == ".json":
                    json_files += 1
                else:
                    assets += 1
    except OSError:
        record_error("source directory could not be scanned")
    included.sort(key=lambda item: (item.relative_path.casefold(), item.relative_path))
    excluded.sort(key=lambda item: (item.path.casefold(), item.path, item.reason))
    blocked.sort(key=lambda item: (item.path.casefold(), item.path, item.reason))
    html_files.sort(key=lambda value: (value.casefold(), value))
    index_found = "index.html" in html_files
    selected_entry = ""
    requested_entry = entry_page.strip() if isinstance(entry_page, str) else ""
    if requested_entry:
        try:
            normalized_entry = _normalize_entry_page(requested_entry)
            matching_entry = next(
                (
                    candidate
                    for candidate in html_files
                    if candidate == normalized_entry
                    or (os.name == "nt" and candidate.casefold() == normalized_entry.casefold())
                ),
                "",
            )
            if not matching_entry:
                record_error("selected HTML entry page is unavailable")
            else:
                selected_entry = matching_entry
        except ValueError as error:
            record_error(str(error))
    elif index_found:
        selected_entry = "index.html"
    elif "index.htm" in html_files:
        selected_entry = "index.htm"
    elif os.name == "nt":
        selected_entry = next(
            (candidate for candidate in html_files if candidate.casefold() == "index.html"),
            "",
        ) or next(
            (candidate for candidate in html_files if candidate.casefold() == "index.htm"),
            "",
        )
    if not selected_entry and len(html_files) == 1:
        selected_entry = html_files[0]
    if not html_files:
        record_error("no HTML entry page found")
    requires_selection = len(html_files) > 1 and not selected_entry and not errors and not blocked
    publication_files = tuple(included)
    inspection = StaticSiteInspection(
        ok=not errors and not blocked,
        root=str(root),
        files=len(publication_files),
        htmlFiles=len(html_files),
        cssFiles=css_files,
        jsFiles=js_files,
        jsonFiles=json_files,
        assets=assets,
        totalBytes=total_bytes,
        indexFound=index_found,
        entryPage=selected_entry,
        entryCandidates=tuple(html_files),
        requiresEntrySelection=requires_selection,
        includedFiles=tuple(item.relative_path for item in publication_files),
        excludedFiles=tuple(excluded),
        blockedFindings=tuple(blocked),
        snapshotHash=_snapshot_hash(publication_files, selected_entry),
        errors=tuple(errors),
    )
    return inspection, publication_files


def inspect_static_site(
    source: Path,
    *,
    entry_page: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> StaticSiteInspection:
    inspection, _files = _scan_static_site(
        source,
        entry_page=entry_page,
        max_file_bytes=max_file_bytes,
    )
    return inspection


def _publication_manifest(inspection: StaticSiteInspection) -> dict[str, object]:
    return {
        "blockedFindings": [item.to_document() for item in inspection.blockedFindings],
        "entryPoint": inspection.entryPage,
        "excludedFiles": [item.to_document() for item in inspection.excludedFiles],
        "includedFiles": list(inspection.includedFiles),
        "snapshotHash": inspection.snapshotHash,
        "totalBytes": inspection.totalBytes,
        "totalFiles": inspection.files,
    }


def _validate_manifest_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise UpstreamPolicyError("publication manifest contains an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise UpstreamPolicyError("publication manifest contains an invalid relative path")
    return path.as_posix()


def _validate_publication_snapshot(
    root: Path,
    config: HostedServiceConfig,
) -> StaticSiteInspection:
    content = root / PUBLICATION_CONTENT
    manifest_path = root / PUBLICATION_MANIFEST
    try:
        document = parse_json_object(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise UpstreamPolicyError("publication snapshot manifest is invalid") from error
    expected_fields = {
        "blockedFindings",
        "entryPoint",
        "excludedFiles",
        "includedFiles",
        "snapshotHash",
        "totalBytes",
        "totalFiles",
    }
    if set(document) != expected_fields:
        raise UpstreamPolicyError("publication snapshot manifest schema is invalid")
    entry_point = _normalize_entry_page(document["entryPoint"])
    if entry_point != config.entry_page:
        raise UpstreamPolicyError("publication snapshot entry point does not match configuration")
    included_document = document["includedFiles"]
    if not isinstance(included_document, list):
        raise UpstreamPolicyError("publication snapshot file list is invalid")
    included = tuple(_validate_manifest_relative(item) for item in included_document)
    if len(set(included)) != len(included):
        raise UpstreamPolicyError("publication snapshot file list contains duplicates")
    for name in ("excludedFiles", "blockedFindings"):
        findings = document[name]
        if not isinstance(findings, list):
            raise UpstreamPolicyError("publication snapshot findings are invalid")
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != {"path", "reason"}:
                raise UpstreamPolicyError("publication snapshot finding is invalid")
            _validate_manifest_relative(finding["path"])
            if not isinstance(finding["reason"], str) or not re.fullmatch(
                r"[a-z][a-z0-9_]{0,63}", finding["reason"]
            ):
                raise UpstreamPolicyError("publication snapshot finding reason is invalid")
    if document["blockedFindings"]:
        raise UpstreamPolicyError("publication snapshot contains blocked privacy findings")
    total_files = document["totalFiles"]
    total_bytes = document["totalBytes"]
    snapshot_hash = document["snapshotHash"]
    if (
        isinstance(total_files, bool)
        or not isinstance(total_files, int)
        or total_files < 0
        or isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or total_bytes < 0
        or not isinstance(snapshot_hash, str)
        or not re.fullmatch(r"[A-F0-9]{64}", snapshot_hash)
    ):
        raise UpstreamPolicyError("publication snapshot integrity fields are invalid")
    inspection = inspect_static_site(
        content,
        entry_page=config.entry_page,
        max_file_bytes=config.max_file_bytes,
    )
    if not inspection.ok or inspection.requiresEntrySelection:
        raise UpstreamPolicyError("publication snapshot content failed privacy validation")
    if (
        inspection.includedFiles != included
        or inspection.files != total_files
        or inspection.totalBytes != total_bytes
        or inspection.snapshotHash != snapshot_hash
    ):
        raise UpstreamPolicyError("publication snapshot integrity check failed")
    return inspection


def _remove_internal_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_publication_file(item: _PublicationFile, content_root: Path) -> None:
    destination = content_root.joinpath(*PurePosixPath(item.relative_path).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied = 0
    with item.source.open("rb") as source, destination.open("xb") as target:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != item.size:
            raise OSError(f"source file changed before snapshot: {item.relative_path}")
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
            digest.update(chunk)
            copied += len(chunk)
    if copied != item.size or digest.hexdigest().upper() != item.sha256:
        raise OSError(f"source file changed during snapshot: {item.relative_path}")


def build_publication_snapshot(
    service_dir: Path,
    source: Path,
    *,
    entry_page: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> StaticSiteInspection:
    root = Path(service_dir).resolve()
    inspection, files = _scan_static_site(
        source,
        entry_page=entry_page,
        max_file_bytes=max_file_bytes,
    )
    if not inspection.ok:
        findings = [item.path for item in inspection.blockedFindings[:8]]
        details = list(inspection.errors) + (
            ["blocked privacy findings: " + ", ".join(findings)] if findings else []
        )
        raise UpstreamPolicyError("static site privacy check failed: " + "; ".join(details))
    if inspection.requiresEntrySelection or not inspection.entryPage:
        raise UpstreamPolicyError("static site entry page must be selected")

    publication_root = root / PUBLICATION_ROOT
    publication_root.mkdir(parents=True, exist_ok=True)
    token = f"{os.getpid()}.{time.time_ns()}"
    staging = publication_root / f".{token}.staging"
    backup = publication_root / f".{token}.backup"
    current = root / PUBLICATION_CURRENT
    if staging.exists() or backup.exists():
        raise FileExistsError("publication snapshot staging path already exists")
    installed = False
    try:
        content_root = staging / "content"
        content_root.mkdir(parents=True)
        for item in files:
            _copy_publication_file(item, content_root)
        atomic_write_text(
            staging / "manifest.json",
            json.dumps(
                _publication_manifest(inspection),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            ) + "\n",
            mode=0o600,
        )
        if current.exists():
            os.replace(current, backup)
        try:
            os.replace(staging, current)
        except Exception:
            if backup.exists() and not current.exists():
                os.replace(backup, current)
            raise
        installed = True
        _remove_internal_tree(backup)
        return inspection
    finally:
        _remove_internal_tree(staging)
        if installed:
            _remove_internal_tree(backup)


def _ensure_publication_snapshot(
    root: Path,
    config: HostedServiceConfig,
) -> StaticSiteInspection | None:
    if config.kind != "static":
        return None
    content = root / PUBLICATION_CONTENT
    manifest = root / PUBLICATION_MANIFEST
    if content.is_dir() and manifest.is_file():
        return _validate_publication_snapshot(root, config)
    inspection = build_publication_snapshot(
        root,
        Path(config.source),
        entry_page=config.entry_page,
        max_file_bytes=config.max_file_bytes,
    )
    _validate_publication_snapshot(root, config)
    return inspection


class StaticSiteBridge:
    def __init__(
        self,
        source: Path,
        *,
        entry_page: str = "",
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        inspection = inspect_static_site(
            source,
            entry_page=entry_page,
            max_file_bytes=max_file_bytes,
        )
        if not inspection.ok:
            raise UpstreamPolicyError("static site validation failed: " + "; ".join(inspection.errors))
        if inspection.requiresEntrySelection or not inspection.entryPage:
            raise UpstreamPolicyError("static site entry page must be selected")
        self.root = Path(inspection.root)
        self.entry_page = inspection.entryPage
        self.max_file_bytes = _validate_max_file_bytes(max_file_bytes)

    @staticmethod
    def _response(status: int, reason: str, body: bytes = b"") -> HttpResult:
        return HttpResult(
            status,
            reason,
            {
                "cache-control": "no-store",
                "content-type": "text/plain; charset=utf-8",
            },
            body,
        )

    def _resolve_request(self, path: str) -> Path:
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise UpstreamPolicyError("static request path is invalid")
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise UpstreamPolicyError("static request path is not origin-form")
        try:
            decoded = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise UpstreamPolicyError("static request path encoding is invalid") from error
        if "\x00" in decoded or "\\" in decoded:
            raise UpstreamPolicyError("static request path contains an unsafe character")
        parts = PurePosixPath(decoded).parts
        if any(part in {".", ".."} for part in parts):
            raise UpstreamPolicyError("static request path traversal is blocked")
        relative = decoded.lstrip("/") or self.entry_page
        candidate = self.root.joinpath(*PurePosixPath(relative).parts)
        try:
            if candidate.is_dir():
                html_index = candidate / "index.html"
                htm_index = candidate / "index.htm"
                candidate = html_index if html_index.is_file() else htm_index
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise FileNotFoundError(relative) from error
        if not _relative_to_root(resolved, self.root) or not resolved.is_file():
            raise UpstreamPolicyError("static request escaped the source directory")
        if resolved.stat().st_size > self.max_file_bytes:
            raise UpstreamPolicyError("static response exceeds the configured file limit")
        return resolved

    def fetch(
        self,
        method: str,
        path: str,
        _headers: dict[str, str] | None = None,
        body: bytes = b"",
        *,
        session_identity: str = "",
    ) -> HttpResult:
        del session_identity
        normalized = method.upper() if isinstance(method, str) else ""
        if normalized not in {"GET", "HEAD"} or body:
            return self._response(405, "Method Not Allowed", b"method not allowed")
        try:
            source = self._resolve_request(path)
            with source.open("rb") as stream:
                content = stream.read(self.max_file_bytes + 1)
            if len(content) > self.max_file_bytes:
                raise UpstreamPolicyError("static response exceeds the configured file limit")
        except FileNotFoundError:
            return self._response(404, "Not Found", b"not found")
        except (OSError, UpstreamPolicyError):
            return self._response(403, "Forbidden", b"forbidden")
        if normalized == "HEAD":
            content = b""
        content_type = _MIME_TYPES.get(source.suffix.lower())
        if content_type is None:
            guessed, _encoding = mimetypes.guess_type(source.name, strict=False)
            content_type = guessed or "application/octet-stream"
            if content_type.startswith("text/"):
                content_type += "; charset=utf-8"
        return HttpResult(
            200,
            "OK",
            {
                "cache-control": "no-store",
                "content-type": content_type,
            },
            content,
        )


def probe_loopback_application(upstream: str, *, timeout: float = 1.5) -> LoopbackHttpTarget:
    target = LoopbackHttpTarget.parse(upstream)
    connection = socket.socket(target.family, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(target.socket_address)
        authority = f"[{target.host}]" if target.family == socket.AF_INET6 else target.host
        connection.sendall(
            f"GET / HTTP/1.1\r\nHost: {authority}:{target.port}\r\n"
            "Connection: close\r\nUser-Agent: Granger-Hosting-Probe/1\r\n\r\n".encode("ascii")
        )
        response = bytearray()
        while b"\r\n" not in response and len(response) < 4096:
            chunk = connection.recv(512)
            if not chunk:
                break
            response.extend(chunk)
    except OSError as error:
        raise UpstreamPolicyError("local application is not reachable") from error
    finally:
        connection.close()
    status_line = bytes(response).partition(b"\r\n")[0]
    if not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?", status_line):
        raise UpstreamPolicyError("local application did not return a valid HTTP response")
    return target


def load_hosted_service(service_dir: Path) -> tuple[HostedServiceConfig, ServiceIdentity, ServiceDescriptor]:
    root = Path(service_dir).resolve()
    try:
        document = parse_json_object((root / CONFIG_FILE).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"hosted service configuration is invalid: {error}") from error
    version = document.get("version")
    expected_v1 = {"autoStart", "createdAt", "id", "maxFileBytes", "source", "title", "type", "upstream", "version"}
    expected_v2 = expected_v1 | {"entryPage"}
    if (version == 1 and set(document) == expected_v1):
        entry_page = "index.html" if document.get("type") == "static" else ""
    elif version == HOSTING_VERSION and set(document) == expected_v2:
        entry_page = document["entryPage"]
    else:
        raise ValueError("hosted service configuration schema is unsupported")
    if not isinstance(document["autoStart"], bool):
        raise ValueError("hosted service startup policy is invalid")
    created_at = document["createdAt"]
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at <= 0:
        raise ValueError("hosted service creation time is invalid")
    kind = document["type"]
    if kind not in {"static", "local-application"}:
        raise ValueError("hosted service type is invalid")
    source = document["source"]
    upstream = document["upstream"]
    if not isinstance(source, str) or not isinstance(upstream, str):
        raise ValueError("hosted service source is invalid")
    config = HostedServiceConfig(
        _validate_service_id(document["id"]),
        _validate_title(document["title"]),
        kind,
        source,
        _normalize_entry_page(entry_page) if kind == "static" else "",
        upstream,
        document["autoStart"],
        _validate_max_file_bytes(document["maxFileBytes"]),
        created_at,
    )
    identity = ServiceIdentity.load(root / IDENTITY_FILE)
    descriptor = ServiceDescriptor.from_json(
        (root / SERVICE_DESCRIPTOR_FILE).read_text(encoding="utf-8")
    )
    if descriptor.identity_public_key != identity.public_key_bytes:
        raise ValueError("hosted service descriptor does not match its identity")
    return config, identity, descriptor


def initialize_hosted_service(
    services_root: Path,
    service_id: str,
    title: str,
    kind: str,
    *,
    source: str = "",
    entry_page: str = "",
    upstream: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> tuple[HostedServiceConfig, ServiceDescriptor]:
    identifier = _validate_service_id(service_id)
    display_title = _validate_title(title)
    if kind not in {"static", "local-application"}:
        raise ValueError("hosted service type is invalid")
    root = Path(services_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / identifier
    if destination.exists():
        raise FileExistsError("hosted service already exists")
    temporary = root / f".{identifier}.{os.getpid()}.creating"
    if temporary.exists():
        raise FileExistsError("hosted service staging directory already exists")
    limit = _validate_max_file_bytes(max_file_bytes)
    normalized_source = ""
    normalized_entry_page = ""
    normalized_upstream = ""
    if kind == "static":
        inspection = inspect_static_site(
            Path(source),
            entry_page=entry_page,
            max_file_bytes=limit,
        )
        if not inspection.ok:
            blocked_paths = ", ".join(item.path for item in inspection.blockedFindings[:8])
            details = list(inspection.errors)
            if blocked_paths:
                details.append("blocked privacy findings: " + blocked_paths)
            raise UpstreamPolicyError("static site privacy check failed: " + "; ".join(details))
        if inspection.requiresEntrySelection or not inspection.entryPage:
            raise UpstreamPolicyError("static site entry page must be selected")
        normalized_source = inspection.root
        normalized_entry_page = inspection.entryPage
    else:
        target = probe_loopback_application(upstream)
        normalized_upstream = target.url
    config = HostedServiceConfig(
        identifier,
        display_title,
        kind,
        normalized_source,
        normalized_entry_page,
        normalized_upstream,
        True,
        limit,
        int(time.time()),
    )
    temporary.mkdir(mode=0o700)
    try:
        if kind == "static":
            snapshot = build_publication_snapshot(
                temporary,
                Path(normalized_source),
                entry_page=normalized_entry_page,
                max_file_bytes=limit,
            )
            normalized_entry_page = snapshot.entryPage
            config = HostedServiceConfig(
                identifier,
                display_title,
                kind,
                normalized_source,
                normalized_entry_page,
                normalized_upstream,
                True,
                limit,
                config.created_at,
            )
        identity = ServiceIdentity.generate()
        identity.save(temporary / IDENTITY_FILE)
        descriptor = ServiceDescriptor.create_remote(
            identity,
            "distributed-overlay",
            metadata={"contentType": "text/html", "title": display_title},
            lifetime=24 * 60 * 60,
        )
        atomic_write_text(temporary / SERVICE_DESCRIPTOR_FILE, descriptor.to_json(), mode=0o644)
        atomic_write_text(temporary / INTRODUCTION_SEQUENCE_FILE, "0\n", mode=0o600)
        atomic_write_text(
            temporary / CONFIG_FILE,
            json.dumps(config.to_document(), ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
        os.replace(temporary, destination)
        return config, descriptor
    except Exception:
        if temporary.exists():
            for path in sorted(temporary.rglob("*"), reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink(missing_ok=True)
                elif path.is_dir():
                    path.rmdir()
            temporary.rmdir()
        raise


def update_hosted_service(
    service_dir: Path,
    *,
    title: str,
    source: str = "",
    entry_page: str = "",
    upstream: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> tuple[HostedServiceConfig, ServiceDescriptor]:
    root = Path(service_dir).resolve()
    previous, identity, _descriptor = load_hosted_service(root)
    display_title = _validate_title(title)
    limit = _validate_max_file_bytes(max_file_bytes)
    normalized_source = previous.source
    normalized_entry_page = previous.entry_page
    normalized_upstream = previous.upstream
    if previous.kind == "static":
        inspection = inspect_static_site(
            Path(source or previous.source),
            entry_page=entry_page or previous.entry_page,
            max_file_bytes=limit,
        )
        if not inspection.ok:
            blocked_paths = ", ".join(item.path for item in inspection.blockedFindings[:8])
            details = list(inspection.errors)
            if blocked_paths:
                details.append("blocked privacy findings: " + blocked_paths)
            raise UpstreamPolicyError("static site privacy check failed: " + "; ".join(details))
        if inspection.requiresEntrySelection or not inspection.entryPage:
            raise UpstreamPolicyError("static site entry page must be selected")
        normalized_source = inspection.root
        normalized_entry_page = inspection.entryPage
        snapshot = build_publication_snapshot(
            root,
            Path(normalized_source),
            entry_page=normalized_entry_page,
            max_file_bytes=limit,
        )
        normalized_entry_page = snapshot.entryPage
    else:
        target = probe_loopback_application(upstream or previous.upstream)
        normalized_upstream = target.url
    config = HostedServiceConfig(
        previous.service_id,
        display_title,
        previous.kind,
        normalized_source,
        normalized_entry_page,
        normalized_upstream,
        previous.auto_start,
        limit,
        previous.created_at,
    )
    descriptor = ServiceDescriptor.create_remote(
        identity,
        "distributed-overlay",
        metadata={"contentType": "text/html", "title": display_title},
        lifetime=24 * 60 * 60,
    )
    atomic_write_text(root / SERVICE_DESCRIPTOR_FILE, descriptor.to_json(), mode=0o644)
    atomic_write_text(
        root / CONFIG_FILE,
        json.dumps(config.to_document(), ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )
    return config, descriptor


def _next_sequence(path: Path) -> int:
    try:
        previous = int(path.read_text(encoding="ascii").strip()) if path.exists() else 0
    except (OSError, ValueError) as error:
        raise ValueError("introduction sequence state is invalid") from error
    if not 0 <= previous < 2**64 - 1:
        raise ValueError("introduction sequence is exhausted")
    current = previous + 1
    atomic_write_text(path, f"{current}\n", mode=0o600)
    return current


def _target(service_id: str, purpose: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(
        b"granger-network-v0.4/host-selection\x00"
        + purpose
        + b"\x00"
        + service_id.encode("ascii")
    ).digest()


def _service_route_startup_timeout(network_timeout: float, route_count: int) -> float:
    return max(
        15.0,
        min(
            MAX_SERVICE_ROUTE_STARTUP_SECONDS,
            network_timeout * (route_count + 5),
        ),
    )


def _write_status(root: Path, state: str, descriptor: ServiceDescriptor, **details: object) -> None:
    document: dict[str, object] = {
        "canonicalName": descriptor.canonical_name,
        "pid": os.getpid(),
        "state": state,
        "updatedAt": int(time.time()),
        "version": HOSTING_VERSION,
    }
    document.update(details)
    atomic_write_text(
        root / STATUS_FILE,
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )


def serve_hosted_service(
    service_dir: Path,
    wan_config_path: Path,
    *,
    wan_trust_anchor: Path | None = None,
    wan_rollback_state: Path | None = None,
) -> int:
    root = Path(service_dir).resolve()
    config, identity, service = load_hosted_service(root)
    browser_config = load_browser_wan_config(
        wan_config_path,
        trust_anchor_path=wan_trust_anchor,
        rollback_state_path=wan_rollback_state,
        allow_legacy=wan_trust_anchor is None,
    )
    if config.kind == "static":
        _ensure_publication_snapshot(root, config)
        bridge: object = StaticSiteBridge(
            root / PUBLICATION_CONTENT,
            entry_page=config.entry_page,
            max_file_bytes=config.max_file_bytes,
        )
    else:
        bridge = LoopbackHttpBridge(probe_loopback_application(config.upstream))
    runtime = load_discovery_runtime(
        browser_config.bootstrap_path,
        browser_config.authority_pin_path,
        root / "metadata/peer-cache.json",
        root / "identity/network-identity.json",
        timeout=browser_config.timeout,
        replication_factor=browser_config.replication_factor,
        minimum_replicas=browser_config.minimum_replicas,
    )
    selector = WanRouteSelector(
        runtime.discovery,
        guard_seed=runtime.identity.public_key_bytes,
    )
    generation = 0
    recovery_cycles = 0
    _write_status(
        root,
        "starting",
        service,
        stage="network-bootstrap",
        networkHealth=runtime.discovery.health().to_document(),
    )
    while True:
        now = int(time.time())
        assert service.expires_at is not None
        if service.expires_at - now <= 60 * 60:
            service = ServiceDescriptor.create_remote(
                identity,
                "distributed-overlay",
                metadata=service.metadata,
                lifetime=24 * 60 * 60,
            )
            atomic_write_text(root / SERVICE_DESCRIPTOR_FILE, service.to_json(), mode=0o644)
        introductions = runtime.discovery.route_candidates(
            _target(service.service_id, b"introduction"), "introduction"
        )
        rendezvous_nodes = runtime.discovery.route_candidates(
            _target(service.service_id, b"rendezvous"), "rendezvous"
        )
        selected_introductions = introductions[:2]
        if len(selected_introductions) < 2 or not rendezvous_nodes:
            raise OverlayRoutingError("hosting infrastructure is unavailable")
        introduction_ids = {node.node_id for node in selected_introductions}
        rendezvous_node = next(
            (node for node in rendezvous_nodes if node.node_id not in introduction_ids), None
        )
        if rendezvous_node is None:
            raise OverlayRoutingError("independent hosting rendezvous is unavailable")
        _write_status(
            root,
            "starting",
            service,
            stage="publishing-service-record",
            networkHealth=runtime.discovery.health().to_document(),
        )
        introduction = IntroductionDescriptor.create(
            identity,
            service,
            [node.node_id for node in selected_introductions],
            sequence=_next_sequence(root / INTRODUCTION_SEQUENCE_FILE),
            lifetime=15 * 60,
        )
        atomic_write_text(root / INTRODUCTION_DESCRIPTOR_FILE, introduction.to_json(), mode=0o644)
        runtime.discovery.publish(service)
        _write_status(
            root,
            "starting",
            service,
            stage="building-private-routes",
            networkHealth=runtime.discovery.health().to_document(),
        )
        host: WanServiceHost | None = None
        failures: list[str] = []
        route_exclusions: set[str] = set()
        try:
            for attempt in range(MAX_SERVICE_ROUTE_ATTEMPTS):
                candidate: WanServiceHost | None = None
                try:
                    _write_status(
                        root,
                        "starting",
                        service,
                        stage="building-private-routes",
                        routeAttempt=attempt + 1,
                        routeAttempts=MAX_SERVICE_ROUTE_ATTEMPTS,
                        networkHealth=runtime.discovery.health().to_document(),
                    )
                    intro_routes = tuple(
                        selector.service_route(
                            service.service_id,
                            node,
                            "introduction",
                            excluded_ids=route_exclusions,
                        )
                        for node in selected_introductions
                    )
                    rendezvous_route = selector.service_route(
                        service.service_id,
                        rendezvous_node,
                        "rendezvous",
                        excluded_ids=route_exclusions,
                    )
                    candidate = WanServiceHost(
                        identity,
                        service,
                        introduction,
                        tuple(route.route for route in intro_routes),
                        rendezvous_route.route,
                        bridge,
                        timeout=browser_config.timeout,
                        rendezvous_lifetime=600,
                    )
                    candidate.start_background()
                    candidate.wait_ready(
                        _service_route_startup_timeout(
                            browser_config.timeout,
                            len(intro_routes) + 1,
                        )
                    )
                    host = candidate
                    break
                except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                    failures.append(f"{type(error).__name__}:{str(error)[:160]}")
                    if candidate is not None:
                        route_exclusions.update(candidate.startup_failed_route_ids)
                        candidate.stop()
                    if attempt + 1 < MAX_SERVICE_ROUTE_ATTEMPTS:
                        time.sleep(0.2 * (attempt + 1))
            if host is None:
                if generation == 0:
                    raise OverlayRoutingError(
                        "hosting route startup attempts were exhausted: "
                        + ";".join(failures)
                    )
                recovery_cycles += 1
                _write_status(
                    root,
                    "recovering",
                    service,
                    generation=generation,
                    networkHealth=runtime.discovery.health().to_document(),
                    recoveryReason="hosting route startup attempts were exhausted",
                    startupFailures=failures,
                )
                time.sleep(min(2.0, 0.25 * recovery_cycles))
                continue
            runtime.discovery.publish(introduction)
            recovery_cycles = 0
            generation += 1
            _write_status(
                root,
                "online",
                service,
                generation=generation,
                introductionNodeIds=[node.node_id for node in selected_introductions],
                networkHealth=runtime.discovery.health().to_document(),
                rendezvousNodeId=rendezvous_node.node_id,
                startupFailures=failures,
            )
            refresh_at = introduction.expires_at - 2 * 60
            while not host.wait(0.25):
                if int(time.time()) >= refresh_at:
                    break
            if host.recovery_requested:
                _write_status(
                    root,
                    "recovering",
                    service,
                    generation=generation,
                    networkHealth=runtime.discovery.health().to_document(),
                    recoveryReason=host.recovery_reason,
                )
                time.sleep(0.25)
            elif host.wait(0):
                if host.errors:
                    raise RuntimeError(host.errors[0])
                raise RuntimeError("hosted service stopped before descriptor refresh")
        finally:
            if host is not None:
                host.stop()


def _service_document(config: HostedServiceConfig, descriptor: ServiceDescriptor) -> dict[str, object]:
    return {
        "address": descriptor.canonical_name,
        "autoStart": config.auto_start,
        "createdAt": config.created_at,
        "entryPage": config.entry_page,
        "id": config.service_id,
        "maxFileBytes": config.max_file_bytes,
        "source": config.source,
        "title": config.title,
        "type": config.kind,
        "upstream": config.upstream,
        "version": HOSTING_VERSION,
    }


def _print(document: dict[str, object]) -> None:
    print(json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


def _error_document(command: str, error: Exception) -> dict[str, object]:
    message = str(error).strip() or type(error).__name__
    if isinstance(error, FileExistsError):
        code = "service_already_exists"
    elif isinstance(error, PermissionError):
        code = "permission_denied"
    elif isinstance(error, UpstreamPolicyError):
        if "local application" in message:
            code = "backend_unreachable"
        elif "static site validation" in message or "static site privacy check" in message:
            code = "folder_validation_failed"
        else:
            code = "upstream_policy_rejected"
    elif isinstance(error, ValueError):
        code = "invalid_input"
    elif isinstance(error, OSError):
        code = "filesystem_error"
    else:
        code = "runtime_error"
    return {
        "command": command,
        "error": {"code": code, "message": message},
        "ok": False,
        "version": HOSTING_VERSION,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network private service hosting runtime")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect-static")
    inspect.add_argument("--source", type=Path, required=True)
    inspect.add_argument("--entry-page", default="")
    inspect.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    create = commands.add_parser("create")
    create.add_argument("--services-root", type=Path, required=True)
    create.add_argument("--service-id", required=True)
    create.add_argument("--title", required=True)
    create.add_argument("--type", choices=("static", "local-application"), required=True)
    create.add_argument("--source", default="")
    create.add_argument("--entry-page", default="")
    create.add_argument("--upstream", default="")
    create.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    update = commands.add_parser("update")
    update.add_argument("--service-dir", type=Path, required=True)
    update.add_argument("--title", required=True)
    update.add_argument("--source", default="")
    update.add_argument("--entry-page", default="")
    update.add_argument("--upstream", default="")
    update.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    inspect_service = commands.add_parser("inspect-service")
    inspect_service.add_argument("--service-dir", type=Path, required=True)
    probe = commands.add_parser("probe-application")
    probe.add_argument("--upstream", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--service-dir", type=Path, required=True)
    serve.add_argument("--wan-config", type=Path)
    serve.add_argument("--wan-bundle", type=Path)
    serve.add_argument("--wan-trust-anchor", type=Path)
    serve.add_argument("--wan-install-root", type=Path)
    serve.add_argument("--wan-rollback-state", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    from .network_audit import install_from_environment

    install_from_environment("hosting")
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "inspect-static":
            _print(inspect_static_site(
                options.source,
                entry_page=options.entry_page,
                max_file_bytes=options.max_file_bytes,
            ).to_document())
            return 0
        if options.command == "create":
            config, descriptor = initialize_hosted_service(
                options.services_root,
                options.service_id,
                options.title,
                options.type,
                source=options.source,
                entry_page=options.entry_page,
                upstream=options.upstream,
                max_file_bytes=options.max_file_bytes,
            )
            _print(_service_document(config, descriptor))
            return 0
        if options.command == "update":
            config, descriptor = update_hosted_service(
                options.service_dir,
                title=options.title,
                source=options.source,
                entry_page=options.entry_page,
                upstream=options.upstream,
                max_file_bytes=options.max_file_bytes,
            )
            _print(_service_document(config, descriptor))
            return 0
        if options.command == "inspect-service":
            config, _identity, descriptor = load_hosted_service(options.service_dir)
            _print(_service_document(config, descriptor))
            return 0
        if options.command == "probe-application":
            target = probe_loopback_application(options.upstream)
            _print({"host": target.host, "ok": True, "port": target.port, "version": HOSTING_VERSION})
            return 0
        provision_values = (
            options.wan_bundle,
            options.wan_trust_anchor,
            options.wan_install_root,
            options.wan_rollback_state,
        )
        provision_requested = any(value is not None for value in provision_values)
        if provision_requested and not all(value is not None for value in provision_values):
            raise ValueError("signed WAN provisioning requires all bundle paths")
        if options.wan_config is not None and provision_requested:
            raise ValueError("explicit WAN config and signed provisioning are mutually exclusive")
        if options.wan_config is None and not provision_requested:
            raise ValueError("hosting requires a trusted WAN configuration")
        wan_config = options.wan_config
        wan_trust_anchor = None
        wan_rollback_state = None
        if provision_requested:
            wan_config = ensure_browser_wan_config(
                options.wan_bundle,
                options.wan_trust_anchor,
                options.wan_install_root,
                options.wan_rollback_state,
            )
            wan_trust_anchor = options.wan_trust_anchor
            wan_rollback_state = options.wan_rollback_state
        return serve_hosted_service(
            options.service_dir,
            wan_config,
            wan_trust_anchor=wan_trust_anchor,
            wan_rollback_state=wan_rollback_state,
        )
    except KeyboardInterrupt:
        return 130
    except (GrangerNetworkError, OSError, RuntimeError, TypeError, ValueError) as error:
        if options.command == "serve":
            try:
                _config, _identity, descriptor = load_hosted_service(options.service_dir)
                _write_status(
                    options.service_dir,
                    "error",
                    descriptor,
                    errorCode=type(error).__name__,
                    errorMessage=str(error)[:512],
                )
            except Exception:
                pass
        _print(_error_document(options.command, error))
        print(f"granger-hosting: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
