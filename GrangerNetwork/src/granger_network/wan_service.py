from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass

from .cells import CellMultiplexer
from .circuit import BuiltCircuit, CircuitBuilder
from .descriptor import ServiceDescriptor
from .errors import GrangerNetworkError, OverlayRoutingError, ProtocolError
from .http_bridge import HttpResult, LoopbackHttpBridge
from .identity import ServiceIdentity
from .introduction import IntroductionDescriptor
from .peer import NodeDescriptor
from .peer_rpc import PeerRole, RpcType
from .protocol import VERSION_3, SecureChannel, client_handshake, server_handshake
from .wan_application import WanApplicationClient, WanApplicationServer
from .wan_control import (
    IntroductionRequest,
    RendezvousGrant,
    RendezvousJoin,
    RendezvousRegistration,
    decode_intro_request,
    encode_intro_registration,
    encode_intro_request,
)


_RENDEZVOUS_ROUTE_FAILURE_LIMIT = 3


class _RendezvousRouteUnavailable(OverlayRoutingError):
    pass


def rendezvous_session_id(cookie: bytes) -> bytes:
    if not isinstance(cookie, bytes) or len(cookie) != 32:
        raise ProtocolError("rendezvous cookie is invalid")
    return hashlib.sha256(
        b"granger-network-v0.4/rendezvous-session\x00" + cookie
    ).digest()[:16]


def application_circuit_id(cookie: bytes) -> bytes:
    if not isinstance(cookie, bytes) or len(cookie) != 32:
        raise ProtocolError("rendezvous cookie is invalid")
    return hashlib.sha256(
        b"granger-network-v0.4/application-circuit\x00" + cookie
    ).digest()[:16]


@dataclass
class WanServiceSession:
    service: ServiceDescriptor
    grant: RendezvousGrant
    circuit: BuiltCircuit
    rendezvous_mux: CellMultiplexer
    channel: SecureChannel
    application_mux: CellMultiplexer
    application: WanApplicationClient
    timings: dict[str, float]
    _closed: bool = False

    def fetch(
        self,
        path: str = "/",
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResult:
        if self._closed:
            raise ProtocolError("WAN service session is closed")
        return self.application.fetch(method, path, headers, body)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.application_mux.close()
        self.channel.destroy()
        self.rendezvous_mux.close()
        self.circuit.close()

    def __enter__(self) -> "WanServiceSession":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class WanServiceClient:
    def __init__(
        self,
        identity: ServiceIdentity,
        service: ServiceDescriptor,
        introduction: IntroductionDescriptor,
        client_route_prefix: list[tuple[NodeDescriptor, str]] | tuple[tuple[NodeDescriptor, str], ...],
        *,
        timeout: float = 10.0,
    ) -> None:
        service.verify()
        introduction.verify_for(service)
        if len(client_route_prefix) < 2:
            raise OverlayRoutingError("client WAN route prefix requires entry and middle relays")
        self.identity = identity
        self.service = service
        self.introduction = introduction
        self.route_prefix = tuple(client_route_prefix)
        self.timeout = timeout

    def connect(self, introduction_node: NodeDescriptor) -> WanServiceSession:
        point = next(
            (point for point in self.introduction.points if point.node_id == introduction_node.node_id),
            None,
        )
        if point is None:
            raise OverlayRoutingError("selected introduction node is not authorized by the service")
        builder = CircuitBuilder(self.identity, PeerRole.CLIENT, timeout=self.timeout)
        session_started = time.perf_counter_ns()
        introduction_started = session_started
        intro_circuit = builder.open((*self.route_prefix, (introduction_node, "introduction")))
        request_nonce = secrets.token_bytes(16)
        try:
            response = intro_circuit.endpoint.rpc.request(
                RpcType.INTRO_REQUEST,
                encode_intro_request(
                    IntroductionRequest(
                        self.service.service_id,
                        point.token,
                        request_nonce,
                    )
                ),
                expected=RpcType.INTRO_REQUEST,
            )
            grant = RendezvousGrant.decode(
                response.payload,
                self.service,
                request_nonce=request_nonce,
            )
        finally:
            intro_circuit.close()
        introduction_finished = time.perf_counter_ns()

        rendezvous_circuit: BuiltCircuit | None = None
        rendezvous_mux: CellMultiplexer | None = None
        channel: SecureChannel | None = None
        application_mux: CellMultiplexer | None = None
        try:
            rendezvous_started = time.perf_counter_ns()
            rendezvous_circuit = builder.open(
                (*self.route_prefix, (grant.rendezvous, "rendezvous"))
            )
            cell_circuit_id = secrets.token_bytes(16)
            rendezvous_circuit.endpoint.rpc.request(
                RpcType.RENDEZVOUS_JOIN,
                RendezvousJoin(
                    self.service.service_id,
                    grant.cookie,
                    secrets.token_bytes(16),
                    cell_circuit_id,
                ).encode(),
                expected=RpcType.RENDEZVOUS_JOIN,
            )
            rendezvous_mux = CellMultiplexer(
                rendezvous_circuit.endpoint.channel,
                cell_circuit_id,
                initiator=True,
            )
            stream = rendezvous_mux.open_stream(self.timeout)
            channel = client_handshake(
                stream,
                self.service.identity_public_key,
                session_id=rendezvous_session_id(grant.cookie),
                protocol_version=VERSION_3,
            )
            application_mux = CellMultiplexer(
                channel,
                application_circuit_id(grant.cookie),
                initiator=True,
            )
            application = WanApplicationClient(application_mux, timeout=self.timeout)
            rendezvous_finished = time.perf_counter_ns()
            return WanServiceSession(
                self.service,
                grant,
                rendezvous_circuit,
                rendezvous_mux,
                channel,
                application_mux,
                application,
                {
                    "introductionMs": (
                        introduction_finished - introduction_started
                    )
                    / 1_000_000,
                    "rendezvousMs": (rendezvous_finished - rendezvous_started)
                    / 1_000_000,
                    "sessionMs": (rendezvous_finished - session_started) / 1_000_000,
                },
            )
        except Exception:
            if application_mux is not None:
                application_mux.close()
            if channel is not None:
                channel.destroy()
            if rendezvous_mux is not None:
                rendezvous_mux.close()
            if rendezvous_circuit is not None:
                rendezvous_circuit.close()
            raise


class WanServiceHost:
    def __init__(
        self,
        identity: ServiceIdentity,
        service: ServiceDescriptor,
        introduction: IntroductionDescriptor,
        introduction_route: (
            list[tuple[NodeDescriptor, str]]
            | tuple[tuple[NodeDescriptor, str], ...]
            | list[list[tuple[NodeDescriptor, str]] | tuple[tuple[NodeDescriptor, str], ...]]
            | tuple[tuple[tuple[NodeDescriptor, str], ...], ...]
        ),
        rendezvous_route: list[tuple[NodeDescriptor, str]] | tuple[tuple[NodeDescriptor, str], ...],
        bridge: LoopbackHttpBridge,
        *,
        timeout: float = 10.0,
        rendezvous_lifetime: int = 180,
    ) -> None:
        service.verify()
        introduction.verify_for(service)
        if service.identity_public_key != identity.public_key_bytes:
            raise ProtocolError("WAN service host identity does not match its descriptor")
        raw_introduction_routes = tuple(introduction_route)
        if not raw_introduction_routes:
            raise OverlayRoutingError("service introduction route is invalid")
        first = raw_introduction_routes[0]
        if (
            isinstance(first, tuple)
            and len(first) == 2
            and isinstance(first[0], NodeDescriptor)
            and isinstance(first[1], str)
        ):
            introduction_routes = (raw_introduction_routes,)
        else:
            introduction_routes = tuple(tuple(route) for route in raw_introduction_routes)
        if any(
            len(route) < 3 or route[-1][1] != "introduction"
            for route in introduction_routes
        ):
            raise OverlayRoutingError("service introduction route is invalid")
        introduction_node_ids = {route[-1][0].node_id for route in introduction_routes}
        if (
            len(introduction_node_ids) != len(introduction_routes)
            or introduction_node_ids != {point.node_id for point in introduction.points}
        ):
            raise OverlayRoutingError(
                "service introduction routes do not match the signed descriptor"
            )
        if len(rendezvous_route) < 3 or rendezvous_route[-1][1] != "rendezvous":
            raise OverlayRoutingError("service rendezvous route is invalid")
        self.identity = identity
        self.service = service
        self.introduction = introduction
        self.introduction_routes = introduction_routes
        self.rendezvous_route = tuple(rendezvous_route)
        self.bridge = bridge
        self.timeout = timeout
        if not 30 <= rendezvous_lifetime <= 300:
            raise ProtocolError("WAN service rendezvous lifetime is invalid")
        self.rendezvous_lifetime = rendezvous_lifetime
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._recovery = threading.Event()
        self._recovery_lock = threading.Lock()
        self._recovery_reason = ""
        self._thread: threading.Thread | None = None
        self._intro_threads: list[threading.Thread] = []
        self._intro_circuits: list[BuiltCircuit] = []
        self._rendezvous_circuit: BuiltCircuit | None = None
        self._rendezvous_mux: CellMultiplexer | None = None
        self._channel: SecureChannel | None = None
        self._application_mux: CellMultiplexer | None = None
        self._application_server: WanApplicationServer | None = None
        self._grant_condition = threading.Condition()
        self._grant_slot: tuple[bytes, int] | None = None
        self._startup_failed_route: tuple[tuple[NodeDescriptor, str], ...] = ()
        self.errors: list[str] = []
        self.session_failures: list[str] = []

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def recovery_requested(self) -> bool:
        return self._recovery.is_set()

    @property
    def recovery_reason(self) -> str:
        with self._recovery_lock:
            return self._recovery_reason

    @property
    def startup_failed_middle_ids(self) -> frozenset[str]:
        return frozenset(
            descriptor.node_id
            for descriptor, role in self._startup_failed_route
            if role == "middle"
        )

    def start_background(self) -> None:
        if self._thread is not None:
            raise RuntimeError("WAN service host is already running")
        self._stop.clear()
        self._recovery.clear()
        with self._recovery_lock:
            self._recovery_reason = ""
        self._thread = threading.Thread(
            target=self._run,
            name="granger-wan-service-host",
            daemon=True,
        )
        self._thread.start()

    def wait_ready(self, timeout: float = 15.0) -> None:
        if not self._ready.wait(timeout):
            if self.errors:
                raise ProtocolError(f"WAN service host failed: {self.errors[0]}")
            raise TimeoutError("WAN service host did not become ready")
        if self.errors:
            raise ProtocolError(f"WAN service host failed: {self.errors[0]}")
        if self.recovery_requested:
            raise OverlayRoutingError(
                f"WAN service route requires recovery: {self.recovery_reason}"
            )

    def _request_recovery(self, reason: str) -> None:
        if self._stop.is_set():
            return
        with self._recovery_lock:
            if not self._recovery_reason:
                self._recovery_reason = reason
        self._recovery.set()
        with self._grant_condition:
            self._grant_slot = None
            self._grant_condition.notify_all()
        circuit = self._rendezvous_circuit
        if circuit is not None:
            circuit.close()

    def _run(self) -> None:
        try:
            builder = CircuitBuilder(self.identity, PeerRole.SERVICE, timeout=self.timeout)
            for route in self.introduction_routes:
                try:
                    circuit = builder.open(route)
                except (GrangerNetworkError, OSError, TimeoutError, ValueError):
                    self._startup_failed_route = route
                    raise
                try:
                    circuit.endpoint.rpc.request(
                        RpcType.INTRO_REGISTER,
                        encode_intro_registration(self.service, self.introduction),
                        expected=RpcType.INTRO_REGISTER,
                    )
                    circuit.endpoint.channel.connection.settimeout(None)
                except Exception:
                    circuit.close()
                    raise
                self._intro_circuits.append(circuit)
            for circuit in self._intro_circuits:
                thread = threading.Thread(
                    target=self._answer_introductions,
                    args=(circuit,),
                    daemon=True,
                )
                self._intro_threads.append(thread)
                thread.start()

            consecutive_route_failures = 0
            while (
                not self._stop.is_set()
                and not self._recovery.is_set()
                and int(time.time()) < self.introduction.expires_at
            ):
                try:
                    self._serve_rendezvous_session(builder)
                    consecutive_route_failures = 0
                except _RendezvousRouteUnavailable as error:
                    if self._stop.is_set() or self._recovery.is_set():
                        break
                    if not self._ready.is_set():
                        self._startup_failed_route = self.rendezvous_route
                        raise
                    consecutive_route_failures += 1
                    if len(self.session_failures) < 1024:
                        self.session_failures.append(
                            f"rendezvous-route:{type(error.__cause__).__name__}:{error}"
                        )
                    if consecutive_route_failures >= _RENDEZVOUS_ROUTE_FAILURE_LIMIT:
                        self._request_recovery(
                            f"rendezvous-route:{type(error.__cause__).__name__}"
                        )
                        break
                    self._stop.wait(0.1 * consecutive_route_failures)
                except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                    if self._stop.is_set() or self._recovery.is_set():
                        break
                    if not self._ready.is_set():
                        raise
                    consecutive_route_failures = 0
                    if len(self.session_failures) < 1024:
                        self.session_failures.append(f"{type(error).__name__}:{error}")
                    self._stop.wait(0.1)
            if (
                not self._stop.is_set()
                and not self._recovery.is_set()
                and int(time.time()) >= self.introduction.expires_at
            ):
                raise ProtocolError("service introduction descriptor expired")
        except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
            if not self._stop.is_set():
                self.errors.append(f"service-session:{type(error).__name__}:{error}")
        finally:
            self._ready.set()

    def _serve_rendezvous_session(self, builder: CircuitBuilder) -> None:
        cookie = secrets.token_bytes(32)
        expires_at = int(time.time()) + self.rendezvous_lifetime
        cell_circuit_id = secrets.token_bytes(16)
        route_ready = False
        try:
            self._rendezvous_circuit = builder.open(self.rendezvous_route)
            if self._recovery.is_set():
                raise OverlayRoutingError("service route recovery was requested")
            registration = RendezvousRegistration.create(
                self.identity,
                self.service.service_id,
                cookie,
                expires_at,
                cell_circuit_id,
            )
            self._rendezvous_circuit.endpoint.rpc.request(
                RpcType.RENDEZVOUS_REGISTER,
                registration.encode(),
                expected=RpcType.RENDEZVOUS_REGISTER,
            )
            self._rendezvous_mux = CellMultiplexer(
                self._rendezvous_circuit.endpoint.channel,
                cell_circuit_id,
                initiator=True,
            )
            rendezvous_stream = self._rendezvous_mux.open_stream(self.timeout)
            rendezvous_stream.settimeout(float(self.rendezvous_lifetime))
            route_ready = True
            with self._grant_condition:
                if self._recovery.is_set():
                    raise OverlayRoutingError("service route recovery was requested")
                self._grant_slot = (cookie, expires_at)
                self._grant_condition.notify_all()
            self._ready.set()

            self._channel = server_handshake(
                rendezvous_stream,
                self.identity,
                expected_session_id=rendezvous_session_id(cookie),
                protocol_version=VERSION_3,
            )
            with self._grant_condition:
                if self._grant_slot is not None and self._grant_slot[0] == cookie:
                    self._grant_slot = None
            self._application_mux = CellMultiplexer(
                self._channel,
                application_circuit_id(cookie),
                initiator=False,
            )
            self._application_server = WanApplicationServer(
                self._application_mux,
                self.bridge,
                timeout=self.timeout,
            )
            self._application_server.serve_forever()
        except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
            if not route_ready and not self._stop.is_set() and not self._recovery.is_set():
                raise _RendezvousRouteUnavailable(str(error)) from error
            raise
        finally:
            with self._grant_condition:
                if self._grant_slot is not None and self._grant_slot[0] == cookie:
                    self._grant_slot = None
                self._grant_condition.notify_all()
            self._close_rendezvous_session()

    def _answer_introductions(self, intro_circuit: BuiltCircuit) -> None:
        rendezvous = self.rendezvous_route[-1][0]
        while not self._stop.is_set() and int(time.time()) < self.introduction.expires_at:
            try:
                request = intro_circuit.endpoint.rpc.receive()
                if request.message_type is not RpcType.INTRO_DELIVER or request.is_response:
                    raise ProtocolError("service received an unexpected introduction message")
                introduced = decode_intro_request(request.payload)
                if introduced.service_id != self.service.service_id:
                    raise ProtocolError("introduction delivery service identity is invalid")
                deadline = time.monotonic() + self.timeout
                with self._grant_condition:
                    while self._grant_slot is None and not self._stop.is_set():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("service has no available rendezvous slot")
                        self._grant_condition.wait(min(0.25, remaining))
                    if self._grant_slot is None:
                        raise ProtocolError("service is stopping")
                    cookie, expires_at = self._grant_slot
                    self._grant_slot = None
                lifetime = max(1, min(120, expires_at - int(time.time())))
                grant = RendezvousGrant.create(
                    self.identity,
                    self.service,
                    introduced.nonce,
                    rendezvous,
                    cookie=cookie,
                    lifetime=lifetime,
                )
                intro_circuit.endpoint.rpc.send(
                    RpcType.INTRO_DELIVER,
                    grant.encode(),
                    request_id=request.request_id,
                    response=True,
                )
            except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                if not self._stop.is_set():
                    reason = f"introduction:{type(error).__name__}:{error}"
                    if len(self.session_failures) < 1024:
                        self.session_failures.append(reason)
                    self._request_recovery(reason)
                return

    def _close_rendezvous_session(self) -> None:
        if self._application_server is not None:
            self._application_server.stop()
            self._application_server = None
        if self._application_mux is not None:
            self._application_mux.close()
            self._application_mux = None
        if self._channel is not None:
            self._channel.destroy()
            self._channel = None
        if self._rendezvous_mux is not None:
            self._rendezvous_mux.close()
            self._rendezvous_mux = None
        if self._rendezvous_circuit is not None:
            self._rendezvous_circuit.close()
            self._rendezvous_circuit = None

    def stop(self) -> None:
        self._stop.set()
        with self._grant_condition:
            self._grant_slot = None
            self._grant_condition.notify_all()
        self._close_rendezvous_session()
        for circuit in self._intro_circuits:
            circuit.close()
        self._intro_circuits.clear()
        for thread in self._intro_threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2.0)
        self._intro_threads.clear()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=3.0)
            self._thread = None

    def wait(self, timeout: float | None = None) -> bool:
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()
