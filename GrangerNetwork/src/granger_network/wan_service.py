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

        rendezvous_circuit: BuiltCircuit | None = None
        rendezvous_mux: CellMultiplexer | None = None
        channel: SecureChannel | None = None
        application_mux: CellMultiplexer | None = None
        try:
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
            return WanServiceSession(
                self.service,
                grant,
                rendezvous_circuit,
                rendezvous_mux,
                channel,
                application_mux,
                application,
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
        introduction_route: list[tuple[NodeDescriptor, str]] | tuple[tuple[NodeDescriptor, str], ...],
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
        if len(introduction_route) < 3 or introduction_route[-1][1] != "introduction":
            raise OverlayRoutingError("service introduction route is invalid")
        if len(rendezvous_route) < 3 or rendezvous_route[-1][1] != "rendezvous":
            raise OverlayRoutingError("service rendezvous route is invalid")
        self.identity = identity
        self.service = service
        self.introduction = introduction
        self.introduction_route = tuple(introduction_route)
        self.rendezvous_route = tuple(rendezvous_route)
        self.bridge = bridge
        self.timeout = timeout
        if not 30 <= rendezvous_lifetime <= 300:
            raise ProtocolError("WAN service rendezvous lifetime is invalid")
        self.rendezvous_lifetime = rendezvous_lifetime
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._intro_thread: threading.Thread | None = None
        self._intro_circuit: BuiltCircuit | None = None
        self._rendezvous_circuit: BuiltCircuit | None = None
        self._rendezvous_mux: CellMultiplexer | None = None
        self._channel: SecureChannel | None = None
        self._application_mux: CellMultiplexer | None = None
        self._application_server: WanApplicationServer | None = None
        self._cookie: bytes | None = None
        self.errors: list[str] = []

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    def start_background(self) -> None:
        if self._thread is not None:
            raise RuntimeError("WAN service host is already running")
        self._stop.clear()
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

    def _run(self) -> None:
        try:
            builder = CircuitBuilder(self.identity, PeerRole.SERVICE, timeout=self.timeout)
            self._rendezvous_circuit = builder.open(self.rendezvous_route)
            self._cookie = secrets.token_bytes(32)
            expires_at = int(time.time()) + self.rendezvous_lifetime
            cell_circuit_id = secrets.token_bytes(16)
            registration = RendezvousRegistration.create(
                self.identity,
                self.service.service_id,
                self._cookie,
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

            self._intro_circuit = builder.open(self.introduction_route)
            self._intro_circuit.endpoint.rpc.request(
                RpcType.INTRO_REGISTER,
                encode_intro_registration(self.service, self.introduction),
                expected=RpcType.INTRO_REGISTER,
            )
            self._intro_circuit.endpoint.channel.connection.settimeout(None)
            self._intro_thread = threading.Thread(
                target=self._answer_introductions,
                args=(expires_at,),
                daemon=True,
            )
            self._intro_thread.start()
            self._ready.set()

            self._channel = server_handshake(
                rendezvous_stream,
                self.identity,
                expected_session_id=rendezvous_session_id(self._cookie),
                protocol_version=VERSION_3,
            )
            self._application_mux = CellMultiplexer(
                self._channel,
                application_circuit_id(self._cookie),
                initiator=False,
            )
            self._application_server = WanApplicationServer(
                self._application_mux,
                self.bridge,
                timeout=self.timeout,
            )
            self._application_server.serve_forever()
        except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
            if not self._stop.is_set():
                self.errors.append(f"service-session:{type(error).__name__}")
        finally:
            self._ready.set()

    def _answer_introductions(self, expires_at: int) -> None:
        assert self._intro_circuit is not None and self._cookie is not None
        rendezvous = self.rendezvous_route[-1][0]
        while not self._stop.is_set() and int(time.time()) < expires_at:
            try:
                request = self._intro_circuit.endpoint.rpc.receive()
                if request.message_type is not RpcType.INTRO_DELIVER or request.is_response:
                    raise ProtocolError("service received an unexpected introduction message")
                introduced = decode_intro_request(request.payload)
                if introduced.service_id != self.service.service_id:
                    raise ProtocolError("introduction delivery service identity is invalid")
                lifetime = max(1, min(120, expires_at - int(time.time())))
                grant = RendezvousGrant.create(
                    self.identity,
                    self.service,
                    introduced.nonce,
                    rendezvous,
                    cookie=self._cookie,
                    lifetime=lifetime,
                )
                self._intro_circuit.endpoint.rpc.send(
                    RpcType.INTRO_DELIVER,
                    grant.encode(),
                    request_id=request.request_id,
                    response=True,
                )
            except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                if not self._stop.is_set():
                    self.errors.append(f"introduction:{type(error).__name__}")
                return

    def stop(self) -> None:
        self._stop.set()
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
        if self._intro_circuit is not None:
            self._intro_circuit.close()
            self._intro_circuit = None
        if self._rendezvous_circuit is not None:
            self._rendezvous_circuit.close()
            self._rendezvous_circuit = None
        if self._intro_thread is not None and self._intro_thread is not threading.current_thread():
            self._intro_thread.join(timeout=2.0)
            self._intro_thread = None
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=3.0)
            self._thread = None
