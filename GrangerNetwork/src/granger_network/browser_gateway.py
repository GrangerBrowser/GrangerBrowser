from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import html
import json
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ._codec import parse_json_object
from .address import normalize_name
from .client import GrangerClient, GrangerResponse
from .cells import CoverTrafficProfile, cover_profile_from_environment
from .descriptor import ServiceDescriptor
from .errors import (
    DescriptorError,
    GrangerNetworkError,
    IdentityVerificationError,
    ProtocolError,
    RendezvousError,
    ReplayError,
    ResolutionError,
)
from .http_bridge import HttpResult
from .identity import ServiceIdentity
from .resolver import LocalResolver
from .service import GrangerServiceHost
from .transport import LoopbackEndpoint
from .wan_client import WanClientConnection, connect_service
from .wan_config import (
    ensure_browser_wan_config,
    load_browser_wan_config,
    load_discovery_runtime,
)
from .wan_discovery import WanDistributedResolver


PROTOCOL_VERSION = 2
MAX_REQUEST_BODY = 2 * 1024 * 1024
MAX_MESSAGE_BYTES = 3 * 1024 * 1024
MAX_PATH_LENGTH = 4096
MAX_HEADER_VALUE = 1024
MAX_RESPONSE_BODY = 2 * 1024 * 1024
_REQUEST_ID = re.compile(r"^[a-f0-9]{32}$")
_ALLOWED_REQUEST_HEADERS = {
    "accept",
    "accept-language",
    "content-type",
    "user-agent",
}
_dns_request_count = 0
_write_lock = threading.Lock()


class _LocalDemoBridge:
    def __init__(self, canonical_name: str) -> None:
        self.canonical_name = canonical_name

    def fetch(
        self,
        method: str,
        path: str,
        _headers: dict[str, str] | None = None,
    ) -> HttpResult:
        body = (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>Granger Network</title></head><body>"
            "<main><h1>test.granger works</h1>"
            "<p>Authenticated encrypted local Granger Network service.</p>"
            f"<code id=\"canonical\">{self.canonical_name}</code>"
            f"<p id=\"path\">{html.escape(path)}</p></main></body></html>"
        ).encode("utf-8")
        if method.upper() == "HEAD":
            body = b""
        return HttpResult(
            200,
            "OK",
            {
                "cache-control": "no-store",
                "content-type": "text/html; charset=utf-8",
            },
            body,
        )


class _LocalDemoResolver:
    def __init__(self, registry: Path, descriptor: ServiceDescriptor) -> None:
        self._persistent = LocalResolver(registry)
        self._descriptor = descriptor

    def resolve(self, name: str) -> ServiceDescriptor:
        normalized = normalize_name(name)
        if normalized in {"test.granger", self._descriptor.canonical_name}:
            return self._descriptor
        return self._persistent.resolve(normalized)

    def resolve_rendezvous(self, rendezvous_id: str):
        return self._persistent.resolve_rendezvous(rendezvous_id)


class _ReservedLoopbackTransport:
    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(32)
            self._listener.settimeout(0.25)
        except Exception:
            self._listener.close()
            raise
        self.endpoint = LoopbackEndpoint(
            "127.0.0.1", int(self._listener.getsockname()[1])
        )
        self._claimed = False

    def listen(self, endpoint: LoopbackEndpoint, _backlog: int = 32) -> socket.socket:
        if self._claimed or endpoint != self.endpoint:
            raise OSError("reserved local demo listener is unavailable")
        self._claimed = True
        return self._listener


class _LocalDemo:
    def __init__(self, registry: Path) -> None:
        transport = _ReservedLoopbackTransport()
        identity = ServiceIdentity.generate()
        self.descriptor = ServiceDescriptor.create(identity, transport.endpoint)
        self.resolver = _LocalDemoResolver(registry, self.descriptor)
        self.host = GrangerServiceHost(
            identity,
            self.descriptor,
            _LocalDemoBridge(self.descriptor.canonical_name),
            transport=transport,
        )

    def start(self) -> None:
        self.host.start_background()

    def stop(self) -> None:
        self.host.stop()


@dataclass(frozen=True)
class CircuitRotationPolicy:
    max_age_seconds: float = 10 * 60
    max_requests: int = 128
    max_transferred_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, (int, float))
            or not 1 <= self.max_age_seconds <= 24 * 60 * 60
            or isinstance(self.max_requests, bool)
            or not isinstance(self.max_requests, int)
            or not 1 <= self.max_requests <= 4096
            or isinstance(self.max_transferred_bytes, bool)
            or not isinstance(self.max_transferred_bytes, int)
            or not 64 * 1024 <= self.max_transferred_bytes <= 1024 * 1024 * 1024
        ):
            raise ValueError("circuit rotation policy is invalid")


@dataclass
class _GatewaySessionSlot:
    connected: WanClientConnection
    created_at: float
    active_requests: int = 0
    request_count: int = 0
    transferred_bytes: int = 0
    retired: bool = False


class _WanGateway:
    def __init__(
        self,
        config_path: Path,
        state_dir: Path,
        *,
        trust_anchor_path: Path | None = None,
        rollback_state_path: Path | None = None,
        rotation_policy: CircuitRotationPolicy | None = None,
    ) -> None:
        config = load_browser_wan_config(
            config_path,
            trust_anchor_path=trust_anchor_path,
            rollback_state_path=rollback_state_path,
            allow_legacy=trust_anchor_path is None,
        )
        self._runtime = load_discovery_runtime(
            config.bootstrap_path,
            config.authority_pin_path,
            Path(state_dir) / "peer-cache.json",
            Path(state_dir) / "client-identity.json",
            timeout=config.timeout,
            replication_factor=config.replication_factor,
            minimum_replicas=config.minimum_replicas,
        )
        self._resolver = WanDistributedResolver(self._runtime.discovery, config.alias_pins)
        self._route_attempts = config.route_attempts
        self._timeout = config.timeout
        self._sessions: dict[str, _GatewaySessionSlot] = {}
        self._session_locks = tuple(threading.Lock() for _ in range(32))
        self._rotation_policy = rotation_policy or CircuitRotationPolicy()
        self._cover_profile = cover_profile_from_environment()
        self._rotation_count = 0
        self._closed = False
        self._lock = threading.Lock()

    def network_health(self) -> dict[str, object]:
        result = self._runtime.discovery.health().to_document()
        with self._lock:
            result["activeServiceCircuits"] = len(self._sessions)
            result["circuitRotations"] = self._rotation_count
            result["coverActive"] = bool(self._sessions) and (
                self._cover_profile is not CoverTrafficProfile.OFF
            )
            result["coverProfile"] = self._cover_profile.value
        return result

    def _service_lock(self, name: str) -> threading.Lock:
        return self._session_locks[hash(name) % len(self._session_locks)]

    def _rotation_due(self, slot: _GatewaySessionSlot, now: float) -> bool:
        policy = self._rotation_policy
        return (
            now - slot.created_at >= policy.max_age_seconds
            or slot.request_count >= policy.max_requests
            or slot.transferred_bytes >= policy.max_transferred_bytes
            or slot.connected.session.application_mux.failed
        )

    def _acquire_session(
        self,
        name: str,
    ) -> tuple[_GatewaySessionSlot, _GatewaySessionSlot | None]:
        service_lock = self._service_lock(name)
        with service_lock:
            with self._lock:
                if self._closed:
                    raise RendezvousError("Granger WAN gateway is closed")
                slot = self._sessions.get(name)
                replace = slot is None or self._rotation_due(slot, time.monotonic())
            retired: _GatewaySessionSlot | None = None
            if replace:
                connected = connect_service(
                    self._runtime,
                    self._resolver,
                    name,
                    route_attempts=self._route_attempts,
                    timeout=self._timeout,
                )
                replacement = _GatewaySessionSlot(connected, time.monotonic())
                with self._lock:
                    if self._closed:
                        connected.session.close()
                        raise RendezvousError("Granger WAN gateway is closed")
                    previous = self._sessions.get(name)
                    self._sessions[name] = replacement
                    slot = replacement
                    if previous is not None:
                        previous.retired = True
                        self._rotation_count += 1
                        if previous.active_requests == 0:
                            retired = previous
            assert slot is not None
            with self._lock:
                slot.active_requests += 1
            return slot, retired

    def _release_session(
        self,
        name: str,
        slot: _GatewaySessionSlot,
        *,
        transferred_bytes: int,
        failed: bool,
    ) -> _GatewaySessionSlot | None:
        with self._lock:
            slot.active_requests -= 1
            if failed:
                if self._sessions.get(name) is slot:
                    self._sessions.pop(name, None)
                slot.retired = True
            else:
                slot.request_count += 1
                slot.transferred_bytes += transferred_bytes
            return slot if slot.retired and slot.active_requests == 0 else None

    def fetch_gateway(
        self,
        name: str,
        path: str,
        method: str,
        headers: dict[str, str],
        body: bytes,
    ) -> GrangerResponse:
        maximum_attempts = 2 if method.upper() in {"GET", "HEAD"} else 1
        for attempt in range(maximum_attempts):
            slot, retired = self._acquire_session(name)
            if retired is not None:
                retired.connected.session.close()
            failed = False
            retry_with_fresh_session = False
            transferred = 0
            try:
                response = slot.connected.session.fetch(
                    path,
                    method=method,
                    headers=headers,
                    body=body,
                )
                transferred = (
                    len(body)
                    + len(path.encode("utf-8"))
                    + len(response.body)
                    + sum(
                        len(key.encode("utf-8")) + len(value.encode("utf-8"))
                        for key, value in (*headers.items(), *response.headers.items())
                    )
                )
                return GrangerResponse(
                    response.status,
                    response.reason,
                    response.headers,
                    response.body,
                    slot.connected.service.canonical_name,
                )
            except (GrangerNetworkError, OSError, TimeoutError, ValueError):
                failed = True
                retry_with_fresh_session = (
                    attempt + 1 < maximum_attempts
                    and slot.connected.session.application_mux.failed
                )
                if not retry_with_fresh_session:
                    raise
            finally:
                ready_to_close = self._release_session(
                    name,
                    slot,
                    transferred_bytes=transferred,
                    failed=failed,
                )
                if ready_to_close is not None:
                    ready_to_close.connected.session.close()
            if retry_with_fresh_session:
                continue
        raise RendezvousError("idempotent service request retry was exhausted")

    def close(self) -> None:
        with self._lock:
            self._closed = True
            sessions = tuple(slot.connected for slot in self._sessions.values())
            self._sessions.clear()
        for connected in sessions:
            connected.session.close()


class _UnavailableGateway:
    def fetch_gateway(
        self,
        _name: str,
        _path: str,
        _method: str,
        _headers: dict[str, str],
        _body: bytes,
    ) -> GrangerResponse:
        raise RendezvousError("no Granger WAN configuration is installed")


def _deny_dns(*_args: object, **_kwargs: object) -> object:
    global _dns_request_count
    _dns_request_count += 1
    raise OSError("DNS is disabled for the Granger Network browser gateway")


def install_dns_guard() -> None:
    socket.getaddrinfo = _deny_dns
    socket.gethostbyname = _deny_dns
    socket.gethostbyname_ex = _deny_dns


def _safe_request_id(document: object) -> str:
    if isinstance(document, dict):
        value = document.get("requestId")
        if isinstance(value, str) and _REQUEST_ID.fullmatch(value):
            return value
    return ""


def _validate_path(path: object) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or len(path) > MAX_PATH_LENGTH
        or "#" in path
        or "\r" in path
        or "\n" in path
    ):
        raise ValueError("request path is invalid")
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("request path must be percent-encoded ASCII") from error
    if any(byte <= 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError("request path contains an unsafe character")
    return path


def _validate_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict) or len(headers) > 16:
        raise ValueError("request headers are invalid")
    result: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("request headers must contain text")
        normalized = name.lower()
        if normalized not in _ALLOWED_REQUEST_HEADERS:
            continue
        if "\r" in value or "\n" in value or len(value) > MAX_HEADER_VALUE:
            raise ValueError("request header value is invalid")
        result[normalized] = value
    return result


def parse_request(content: bytes) -> dict[str, object]:
    if not content or len(content) > MAX_MESSAGE_BYTES:
        raise ValueError("gateway request exceeds the message limit")
    try:
        document = parse_json_object(content.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("gateway request is not UTF-8") from error
    expected = {
        "body",
        "headers",
        "method",
        "name",
        "path",
        "requestId",
        "type",
        "version",
    }
    if set(document) != expected:
        raise ValueError("gateway request fields are invalid")
    if document["type"] != "fetch" or document["version"] != PROTOCOL_VERSION:
        raise ValueError("gateway request version is unsupported")
    request_id = document["requestId"]
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("gateway request identifier is invalid")
    method = document["method"]
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "POST"}:
        raise ValueError("gateway request method is unsupported")
    encoded_body = document["body"]
    if not isinstance(encoded_body, str):
        raise ValueError("gateway request body is invalid")
    try:
        body = base64.b64decode(encoded_body, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("gateway request body is not canonical base64") from error
    if len(body) > MAX_REQUEST_BODY or base64.b64encode(body).decode("ascii") != encoded_body:
        raise ValueError("gateway request body exceeds its limit")
    if method.upper() in {"GET", "HEAD"} and body:
        raise ValueError("GET and HEAD gateway requests cannot contain a body")
    try:
        name = normalize_name(document["name"])
    except GrangerNetworkError as error:
        raise ValueError("gateway destination is not a valid .granger name") from error
    return {
        "headers": _validate_headers(document["headers"]),
        "body": body,
        "method": method.upper(),
        "name": name,
        "path": _validate_path(document["path"]),
        "requestId": request_id,
    }


def _error_code(error: BaseException) -> str:
    if isinstance(error, ResolutionError):
        return "SERVICE_NOT_FOUND"
    if isinstance(error, (DescriptorError, IdentityVerificationError)):
        return "IDENTITY_VERIFICATION_FAILED"
    if isinstance(error, ReplayError):
        return "REPLAY_REJECTED"
    if isinstance(error, RendezvousError):
        return "NETWORK_UNAVAILABLE"
    if isinstance(error, ProtocolError):
        return "CONNECTION_FAILED"
    if isinstance(error, OSError):
        return "NETWORK_UNAVAILABLE"
    return "REQUEST_REJECTED"


def handle_request(resolver: object, timeout: float, content: bytes) -> dict[str, object]:
    request_id = ""
    try:
        document = parse_json_object(content.decode("utf-8"))
        request_id = _safe_request_id(document)
        request = parse_request(content)
        request_id = str(request["requestId"])
        if hasattr(resolver, "fetch_gateway"):
            response = resolver.fetch_gateway(
                str(request["name"]),
                str(request["path"]),
                str(request["method"]),
                request["headers"],
                request["body"],
            )
        else:
            if request["body"]:
                raise ProtocolError("compatibility gateway does not carry request bodies")
            response = GrangerClient(resolver, timeout=timeout).fetch(
                str(request["name"]),
                str(request["path"]),
                method=str(request["method"]),
                headers=request["headers"],
            )
        if len(response.body) > MAX_RESPONSE_BODY:
            raise ProtocolError("service response exceeds the browser gateway limit")
        result: dict[str, object] = {
            "body": base64.b64encode(response.body).decode("ascii"),
            "canonicalService": response.canonical_service,
            "dnsRequests": _dns_request_count,
            "headers": response.headers,
            "ok": True,
            "reason": response.reason,
            "requestId": request_id,
            "status": response.status,
            "type": "response",
            "version": PROTOCOL_VERSION,
        }
        if hasattr(resolver, "network_health"):
            result["networkHealth"] = resolver.network_health()
        return result
    except (GrangerNetworkError, OSError, TypeError, ValueError) as error:
        result = {
            "code": _error_code(error),
            "dnsRequests": _dns_request_count,
            "ok": False,
            "requestId": request_id,
            "type": "response",
            "version": PROTOCOL_VERSION,
        }
        if hasattr(resolver, "network_health"):
            result["networkHealth"] = resolver.network_health()
        return result


def _write(document: dict[str, object]) -> None:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    with _write_lock:
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()


def serve(
    registry: Path | None,
    timeout: float,
    *,
    local_demo: bool = False,
    wan_config: Path | None = None,
    state_dir: Path | None = None,
    wan_trust_anchor: Path | None = None,
    wan_rollback_state: Path | None = None,
) -> int:
    install_dns_guard()
    demo = _LocalDemo(registry) if local_demo and registry is not None else None
    if wan_config is not None:
        if state_dir is None:
            raise ValueError("WAN browser gateway requires a state directory")
        resolver: object = _WanGateway(
            wan_config,
            state_dir,
            trust_anchor_path=wan_trust_anchor,
            rollback_state_path=wan_rollback_state,
        )
        mode = "wan"
    elif demo is not None:
        resolver = demo.resolver
        mode = "local-demo"
    elif registry is not None:
        resolver = LocalResolver(registry)
        mode = "compatibility"
    else:
        resolver = _UnavailableGateway()
        mode = "unavailable"
    if demo is not None:
        demo.start()
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=16,
        thread_name_prefix="granger-browser-request",
    )
    pending_slots = threading.BoundedSemaphore(64)

    def dispatch(content: bytes) -> None:
        try:
            _write(handle_request(resolver, timeout, content))
        finally:
            pending_slots.release()

    try:
        ready: dict[str, object] = {
            "localDemo": demo is not None,
            "mode": mode,
            "pid": os.getpid(),
            "type": "ready",
            "version": PROTOCOL_VERSION,
        }
        if demo is not None:
            ready["localDemoCanonical"] = demo.descriptor.canonical_name
        if hasattr(resolver, "network_health"):
            ready["networkHealth"] = resolver.network_health()
        _write(ready)
        while True:
            content = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 2)
            if not content:
                return 0
            if len(content) > MAX_MESSAGE_BYTES + 1 or not content.endswith(b"\n"):
                _write(
                    {
                        "code": "REQUEST_REJECTED",
                        "ok": False,
                        "requestId": "",
                        "type": "response",
                        "version": PROTOCOL_VERSION,
                    }
                )
                return 2
            if not pending_slots.acquire(blocking=False):
                document = parse_json_object(content[:-1].decode("utf-8"))
                _write(
                    {
                        "code": "REQUEST_REJECTED",
                        "dnsRequests": _dns_request_count,
                        "ok": False,
                        "requestId": _safe_request_id(document),
                        "type": "response",
                        "version": PROTOCOL_VERSION,
                    }
                )
                continue
            try:
                executor.submit(dispatch, content[:-1])
            except Exception:
                pending_slots.release()
                raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        if hasattr(resolver, "close"):
            resolver.close()
        if demo is not None:
            demo.stop()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Browser private stdio gateway")
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--wan-config", type=Path)
    parser.add_argument("--wan-bundle", type=Path)
    parser.add_argument("--wan-trust-anchor", type=Path)
    parser.add_argument("--wan-install-root", type=Path)
    parser.add_argument("--wan-rollback-state", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--local-demo", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    from .network_audit import install_from_environment

    install_from_environment("browser-gateway")
    options = _build_parser().parse_args(argv)
    if not 0.5 <= options.timeout <= 30.0:
        print("granger-browser-gateway: timeout is outside the allowed range", file=sys.stderr)
        return 2
    try:
        if options.local_demo and options.registry is None:
            raise ValueError("local demo requires an explicit registry")
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
        if (options.wan_config is not None or provision_requested) and (
            options.local_demo or options.registry is not None
        ):
            raise ValueError("WAN, compatibility, and local demo modes are mutually exclusive")
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
        return serve(
            options.registry,
            options.timeout,
            local_demo=options.local_demo,
            wan_config=wan_config,
            state_dir=options.state_dir,
            wan_trust_anchor=wan_trust_anchor,
            wan_rollback_state=wan_rollback_state,
        )
    except (GrangerNetworkError, OSError, ValueError) as error:
        print(f"granger-browser-gateway: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
