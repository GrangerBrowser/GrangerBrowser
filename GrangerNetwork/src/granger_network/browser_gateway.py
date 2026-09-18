from __future__ import annotations

from .stage_trace import traced

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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ._codec import parse_json_object
from .address import normalize_name
from .browser_peer import BrowserPeerPolicy, BrowserPeerRuntime
from .client import GrangerClient, GrangerResponse
from .cells import CoverTrafficProfile, cover_profile_from_environment
from .descriptor import ServiceDescriptor
from .errors import (
    DescriptorError,
    DiscoveryError,
    GrangerNetworkError,
    IdentityVerificationError,
    IntroductionOfflineError,
    NetworkUnavailableError,
    OverlayRoutingError,
    ProtocolError,
    RecordQuorumError,
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
    load_browser_wan_config,
    load_discovery_runtime,
    load_or_create_identity,
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


def _browser_peer_policy_from_environment() -> BrowserPeerPolicy:
    raw_port = os.environ.get("GRANGER_BROWSER_RELAY_PORT", "").strip()
    if not raw_port:
        return BrowserPeerPolicy()
    try:
        port = int(raw_port, 10)
    except ValueError as error:
        raise ValueError("browser relay port is invalid") from error
    return BrowserPeerPolicy(public_listener_port=port)


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
    max_cached_services: int = 16

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
            or isinstance(self.max_cached_services, bool)
            or not isinstance(self.max_cached_services, int)
            or not 1 <= self.max_cached_services <= 256
        ):
            raise ValueError("circuit rotation policy is invalid")


def _load_browser_peer_identity(state_dir: Path) -> ServiceIdentity:
    return load_or_create_identity(
        Path(state_dir) / "browser-peer" / "relay-identity.json"
    )


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
        on_health_changed: Callable[[], None] | None = None,
    ) -> None:
        config = load_browser_wan_config(
            config_path,
            trust_anchor_path=trust_anchor_path,
            rollback_state_path=rollback_state_path,
            allow_legacy=trust_anchor_path is None,
        )
        self._config = config
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
        browser_peer_root = Path(state_dir) / "browser-peer"
        publisher = None
        if trust_anchor_path is not None:
            from .wan_config_recovery import WanConfigPublisher
            try:
                publisher = WanConfigPublisher(config_path, trust_anchor_path)
            except DiscoveryError:
                # A still-valid config may already rely on a newer cached
                # reseed. Never relay its expired embedded bootstrap snapshot.
                pass
        self._browser_peer = BrowserPeerRuntime(
            _load_browser_peer_identity(state_dir),
            self._runtime.discovery,
            browser_peer_root,
            lifecycle_policy=_browser_peer_policy_from_environment(),
            reseed_store=self._runtime.reseed,
            wan_config_publisher=publisher,
            on_state_changed=on_health_changed,
        )
        self._browser_peer.start()

    def network_health(self) -> dict[str, object]:
        result = self._runtime.discovery.health().to_document()
        with self._lock:
            result["activeServiceCircuits"] = len(self._sessions)
            result["circuitRotations"] = self._rotation_count
            result["coverActive"] = bool(self._sessions) and (
                self._cover_profile is not CoverTrafficProfile.OFF
            )
            result["coverProfile"] = self._cover_profile.value
        browser_peer = getattr(self, "_browser_peer", None)
        if browser_peer is not None:
            result["browserPeer"] = browser_peer.contribution_snapshot()
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

    @traced("client-session")
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
                capacity_error = False
                with self._lock:
                    if self._closed:
                        capacity_error = True
                    else:
                        previous = self._sessions.get(name)
                        if (
                            previous is None
                            and len(self._sessions)
                            >= self._rotation_policy.max_cached_services
                        ):
                            inactive = tuple(
                                (cached_name, cached_slot)
                                for cached_name, cached_slot in self._sessions.items()
                                if cached_slot.active_requests == 0
                            )
                            if not inactive:
                                capacity_error = True
                            else:
                                evicted_name, evicted = min(
                                    inactive,
                                    key=lambda item: item[1].created_at,
                                )
                                del self._sessions[evicted_name]
                                evicted.retired = True
                                retired = evicted
                                self._rotation_count += 1
                        if not capacity_error:
                            self._sessions[name] = replacement
                            slot = replacement
                            if previous is not None:
                                previous.retired = True
                                self._rotation_count += 1
                                if previous.active_requests == 0:
                                    retired = previous
                if capacity_error:
                    connected.session.close()
                    if self._closed:
                        raise RendezvousError("Granger WAN gateway is closed")
                    raise RendezvousError("service circuit cache limit is exhausted")
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
        config = getattr(self, "_config", None)
        if config is not None and config.version == 2 and (
            config.issued_at > int(time.time()) + 120 or config.expires_at <= int(time.time())
        ):
            raise DiscoveryError("signed browser WAN config is not currently valid")
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
            except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                request_timeout = (
                    isinstance(error, TimeoutError)
                    and not slot.connected.session.application_mux.failed
                )
                stream_protocol_failure = (
                    isinstance(error, ProtocolError)
                    and not slot.connected.session.application_mux.failed
                )
                failed = not request_timeout
                retry_with_fresh_session = (
                    attempt + 1 < maximum_attempts
                    and (
                        slot.connected.session.application_mux.failed
                        or stream_protocol_failure
                    )
                )
                retry_on_healthy_session = (
                    attempt + 1 < maximum_attempts and request_timeout
                )
                if not retry_with_fresh_session and not retry_on_healthy_session:
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
            if retry_with_fresh_session or retry_on_healthy_session:
                continue
        raise RendezvousError("idempotent service request retry was exhausted")

    def close(self) -> None:
        browser_peer = getattr(self, "_browser_peer", None)
        if browser_peer is not None:
            browser_peer.stop()
        with self._lock:
            self._closed = True
            sessions = tuple(slot.connected for slot in self._sessions.values())
            self._sessions.clear()
        for connected in sessions:
            connected.session.close()


class _ManagedWanGateway:
    """One gateway owner; installs control snapshots and swaps only when idle."""

    def __init__(self, recovery, state_dir: Path) -> None:
        self.recovery = recovery
        self.state_dir = Path(state_dir)
        self.identity = load_or_create_identity(self.state_dir / "client-identity.json")
        self._active = None
        self._users = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._available = threading.Event()
        self._retry_at = 0.0
        self._failures = 0
        self._generation = 0
        self._last_health = None
        self._thread = threading.Thread(target=self._supervise, name="granger-config-lifecycle", daemon=True)
        self._thread.start()

    def _supervise(self) -> None:
        from .bootstrap import PeerCache
        try:
            cache = PeerCache(self.state_dir / "peer-cache.json")
        except GrangerNetworkError:
            cache = None
        while not self._stop.is_set():
            if time.monotonic() < self._retry_at:
                self._wake.wait(max(0, self._retry_at - time.monotonic()))
                self._wake.clear()
                if self._stop.is_set():
                    break
                # Peer notifications publish state without triggering config IO/RPC retries.
                self._publish_health()
                if time.monotonic() < self._retry_at:
                    continue
            try:
                path = None
                try:
                    path = self.recovery.current()
                except DiscoveryError:
                    pass
                with self._lock:
                    active = self._active
                    expired = active is not None and (
                        active._config.expires_at <= int(time.time())
                        or active._config.issued_at > int(time.time()) + 120
                    )
                    if expired:
                        self._active = None
                        self._generation = 0
                        self._available.clear()
                if expired:
                    active.close()
                    active = None
                if path is None or self.recovery.expires_at - int(time.time()) <= self.recovery.renewal_margin:
                    replacement = self.recovery.refresh(
                        self.identity, cache=cache,
                        discovery=active._runtime.discovery if active is not None else None,
                        stop=self._stop,
                    )
                    path = replacement or path
                if path is not None and not self._stop.is_set():
                    config = load_browser_wan_config(
                        path, trust_anchor_path=self.recovery.trust_anchor,
                        rollback_state_path=self.recovery.rollback, allow_legacy=False,
                    )
                    with self._lock:
                        replace = self._users == 0 and self._generation != config.generation
                        old = self._active if replace else None
                        if replace:
                            self._active = None
                            self._generation = 0
                            self._available.clear()
                    if replace:
                        if old is not None:
                            old.close()
                        candidate = _WanGateway(
                            path, self.state_dir, trust_anchor_path=self.recovery.trust_anchor,
                            rollback_state_path=self.recovery.rollback,
                            on_health_changed=self._wake.set,
                        )
                        with self._lock:
                            if self._stop.is_set():
                                candidate.close()
                            else:
                                self._active = candidate
                                self._generation = config.generation
                                self._failures = 0
                                self.recovery.state = "CONFIG_VALID"
                                self._available.set()
                elif path is None:
                    self.recovery.state = "RECOVERING"
            except (GrangerNetworkError, OSError, ValueError):
                self.recovery.state = "RECOVERING"
                self._failures = min(6, self._failures + 1)
            self._publish_health()
            delay = max(5, min(300, 10 * 2 ** self._failures))
            if self.recovery.expires_at - int(time.time()) > self.recovery.renewal_margin:
                delay = min(300, max(10, self.recovery.expires_at - int(time.time()) - self.recovery.renewal_margin))
            until_expiry = self.recovery.expires_at - int(time.time())
            if until_expiry > 0:
                delay = min(delay, until_expiry)
            self._retry_at = time.monotonic() + delay

    def _publish_health(self) -> None:
        health = self.network_health()
        if health != self._last_health and not self._stop.is_set():
            _write({"type": "health", "version": PROTOCOL_VERSION, "networkHealth": health})
            self._last_health = health

    @traced("gateway-fetch")
    def fetch_gateway(self, *args, **kwargs):
        if not self._available.is_set() and not self._stop.is_set():
            self._available.wait(30)
        with self._lock:
            active = self._active
            if self._stop.is_set() or active is None or active._config.expires_at <= int(time.time()):
                self._wake.set()
                raise DiscoveryError("Granger Network configuration is recovering")
            self._users += 1
        try:
            return active.fetch_gateway(*args, **kwargs)
        finally:
            with self._lock:
                self._users -= 1

    def network_health(self) -> dict[str, object]:
        with self._lock:
            active = self._active
            result = active.network_health() if active is not None else {}
            valid = active is not None and (
                active._config.issued_at <= int(time.time()) + 120
                and active._config.expires_at > int(time.time())
            )
        if not valid:
            result.update(state="RECOVERING", dhtReady=False, failureReason="CONFIG_RECOVERY")
        result["configRecovery"] = self.recovery.snapshot()
        return result

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        self._available.set()
        self._thread.join(timeout=5)
        with self._lock:
            active = self._active
            self._active = None
        if active is not None:
            active.close()


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
    if isinstance(error, RecordQuorumError):
        return "QUORUM_UNAVAILABLE"
    if isinstance(error, NetworkUnavailableError):
        return "NETWORK_UNAVAILABLE"
    if isinstance(error, IntroductionOfflineError):
        return "INTRO_UNAVAILABLE"
    if isinstance(error, OverlayRoutingError):
        return "NO_ROUTE"
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


@traced("gateway-ipc-request")
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
    wan_recovery=None,
) -> int:
    install_dns_guard()
    demo = _LocalDemo(registry) if local_demo and registry is not None else None
    if wan_recovery is not None:
        if state_dir is None:
            raise ValueError("WAN browser gateway requires a state directory")
        resolver = _ManagedWanGateway(wan_recovery, state_dir)
        mode = "wan"
    elif wan_config is not None:
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
        wan_recovery = None
        if provision_requested:
            from .wan_config_recovery import WanConfigRecovery
            wan_recovery = WanConfigRecovery(
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
            wan_recovery=wan_recovery,
        )
    except (GrangerNetworkError, OSError, ValueError) as error:
        print(f"granger-browser-gateway: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
