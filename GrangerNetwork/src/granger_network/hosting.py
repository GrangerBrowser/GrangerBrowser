from __future__ import annotations

import argparse
import json
import os
import re
import socket
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
MAX_STATIC_FILES = 10_000
CONFIG_FILE = "config.json"
IDENTITY_FILE = "identity/service-identity.json"
SERVICE_DESCRIPTOR_FILE = "metadata/service-descriptor.json"
INTRODUCTION_DESCRIPTOR_FILE = "metadata/introduction-descriptor.json"
INTRODUCTION_SEQUENCE_FILE = "metadata/introduction-sequence.txt"
STATUS_FILE = "metadata/status.json"
_SERVICE_ID = re.compile(r"^[a-f0-9]{32}$")
_TITLE = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_ALLOWED_SUFFIXES = {
    ".css",
    ".gif",
    ".htm",
    ".html",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".mjs",
    ".otf",
    ".png",
    ".svg",
    ".ttf",
    ".txt",
    ".wasm",
    ".webp",
    ".webmanifest",
    ".woff",
    ".woff2",
    ".xml",
}
_FORBIDDEN_SUFFIXES = {".bat", ".cmd", ".com", ".dll", ".exe", ".ps1", ".scr", ".sh"}
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
    errors: tuple[str, ...]

    def to_document(self) -> dict[str, object]:
        document = asdict(self)
        document["errors"] = list(self.errors)
        document["entryCandidates"] = list(self.entryCandidates)
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


def inspect_static_site(
    source: Path,
    *,
    entry_page: str = "",
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> StaticSiteInspection:
    limit = _validate_max_file_bytes(max_file_bytes)
    errors: list[str] = []

    def record_error(message: str) -> None:
        if len(errors) < 64:
            errors.append(message)

    raw = Path(source)
    if not raw.is_absolute():
        return StaticSiteInspection(
            False, str(raw), 0, 0, 0, 0, 0, 0, 0, False, "", (), False,
            ("source path must be absolute",),
        )
    try:
        root = raw.resolve(strict=True)
    except OSError:
        return StaticSiteInspection(
            False, str(raw), 0, 0, 0, 0, 0, 0, 0, False, "", (), False,
            ("source directory is unavailable",),
        )
    if not root.is_dir():
        return StaticSiteInspection(
            False, str(root), 0, 0, 0, 0, 0, 0, 0, False, "", (), False,
            ("source path is not a directory",),
        )

    files = 0
    html_files: list[str] = []
    css_files = 0
    js_files = 0
    json_files = 0
    assets = 0
    total_bytes = 0
    index_found = False
    scanned_files = 0
    file_limit_reached = False
    try:
        for directory, names, file_names in os.walk(root, followlinks=False):
            current = Path(directory)
            for name in tuple(names):
                entry = current / name
                is_link = entry.is_symlink()
                is_junction = bool(getattr(entry, "is_junction", lambda: False)())
                if is_link or is_junction:
                    try:
                        resolved = entry.resolve(strict=True)
                    except OSError:
                        record_error(f"broken linked directory: {entry.relative_to(root).as_posix()}")
                        names.remove(name)
                        continue
                    if not _relative_to_root(resolved, root):
                        record_error(f"linked directory escapes source: {entry.relative_to(root).as_posix()}")
                    names.remove(name)
            for name in file_names:
                scanned_files += 1
                if scanned_files > MAX_STATIC_FILES:
                    record_error("static site exceeds the file-count limit")
                    file_limit_reached = True
                    break
                entry = current / name
                relative = entry.relative_to(root).as_posix()
                try:
                    resolved = entry.resolve(strict=True)
                    if not _relative_to_root(resolved, root) or not resolved.is_file():
                        record_error(f"file escapes source: {relative}")
                        continue
                    suffix = resolved.suffix.lower()
                    if suffix in _FORBIDDEN_SUFFIXES:
                        record_error(f"forbidden executable file: {relative}")
                        continue
                    if suffix not in _ALLOWED_SUFFIXES:
                        record_error(f"unsupported file type: {relative}")
                        continue
                    size = resolved.stat().st_size
                    if size > limit:
                        record_error(f"file exceeds size limit: {relative}")
                        continue
                    with resolved.open("rb") as probe:
                        probe.read(1)
                except OSError:
                    record_error(f"file is not readable: {relative}")
                    continue
                files += 1
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
            if file_limit_reached:
                break
    except OSError:
        record_error("source directory could not be scanned")
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
    requires_selection = len(html_files) > 1 and not selected_entry and not errors
    return StaticSiteInspection(
        not errors,
        str(root),
        files,
        len(html_files),
        css_files,
        js_files,
        json_files,
        assets,
        total_bytes,
        index_found,
        selected_entry,
        tuple(html_files),
        requires_selection,
        tuple(errors),
    )


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
        if resolved.suffix.lower() not in _ALLOWED_SUFFIXES:
            raise UpstreamPolicyError("static request file type is blocked")
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
        return HttpResult(
            200,
            "OK",
            {
                "cache-control": "no-store",
                "content-type": _MIME_TYPES[source.suffix.lower()],
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
            raise UpstreamPolicyError("static site validation failed: " + "; ".join(inspection.errors))
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
            raise UpstreamPolicyError("static site validation failed: " + "; ".join(inspection.errors))
        if inspection.requiresEntrySelection or not inspection.entryPage:
            raise UpstreamPolicyError("static site entry page must be selected")
        normalized_source = inspection.root
        normalized_entry_page = inspection.entryPage
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
        bridge: object = StaticSiteBridge(
            Path(config.source),
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
    selector = WanRouteSelector(runtime.discovery)
    generation = 0
    _write_status(root, "starting", service)
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
        introductions = runtime.discovery.find_nodes(
            _target(service.service_id, b"introduction"), "introduction"
        )
        rendezvous_nodes = runtime.discovery.find_nodes(
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
        introduction = IntroductionDescriptor.create(
            identity,
            service,
            [node.node_id for node in selected_introductions],
            sequence=_next_sequence(root / INTRODUCTION_SEQUENCE_FILE),
            lifetime=15 * 60,
        )
        atomic_write_text(root / INTRODUCTION_DESCRIPTOR_FILE, introduction.to_json(), mode=0o644)
        runtime.discovery.publish(service)
        runtime.discovery.publish(introduction)
        host: WanServiceHost | None = None
        failures: list[str] = []
        try:
            for attempt in range(4):
                candidate: WanServiceHost | None = None
                try:
                    intro_routes = tuple(
                        selector.service_route(service.service_id, node, "introduction")
                        for node in selected_introductions
                    )
                    rendezvous_route = selector.service_route(
                        service.service_id, rendezvous_node, "rendezvous"
                    )
                    candidate = WanServiceHost(
                        identity,
                        service,
                        introduction,
                        tuple(route.route for route in intro_routes),
                        rendezvous_route.route,
                        bridge,
                        timeout=browser_config.timeout,
                        rendezvous_lifetime=180,
                    )
                    candidate.start_background()
                    candidate.wait_ready(15.0)
                    host = candidate
                    break
                except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                    failures.append(type(error).__name__)
                    if candidate is not None:
                        candidate.stop()
                    if attempt < 3:
                        time.sleep(0.2 * (attempt + 1))
            if host is None:
                raise OverlayRoutingError("hosting route startup attempts were exhausted")
            generation += 1
            _write_status(
                root,
                "online",
                service,
                generation=generation,
                introductionNodeIds=[node.node_id for node in selected_introductions],
                rendezvousNodeId=rendezvous_node.node_id,
                startupFailures=failures,
            )
            refresh_at = introduction.expires_at - 2 * 60
            while not host.wait(0.25):
                if int(time.time()) >= refresh_at:
                    break
            if host.wait(0):
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
        elif "static site validation" in message:
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
