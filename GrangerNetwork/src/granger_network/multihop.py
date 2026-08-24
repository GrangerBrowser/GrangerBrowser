from __future__ import annotations

import ipaddress
import queue
import secrets
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from .descriptor import ServiceDescriptor
from .distributed import DistributedResolver
from .errors import (
    DescriptorError,
    GrangerNetworkError,
    OverlayRoutingError,
    ProtocolError,
)
from .identity import ServiceIdentity
from .introduction import (
    IntroductionDescriptor,
    IntroductionPoint,
    IntroductionRegistry,
)
from .peer import GrangerNode, NodeDescriptor
from .protocol import VERSION_3, SecureChannel, client_handshake, server_handshake


class DuplexStream(Protocol):
    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def settimeout(self, value: float | None) -> None: ...


@dataclass(frozen=True)
class OverlayRoutePlan:
    service: ServiceDescriptor
    introductions: IntroductionDescriptor
    introduction_point: IntroductionPoint
    client_entry: NodeDescriptor
    client_middle: NodeDescriptor
    introduction: NodeDescriptor
    host_middle: NodeDescriptor
    service_relay: NodeDescriptor

    def __post_init__(self) -> None:
        self.service.verify()
        self.introductions.verify_for(self.service)
        roles = (
            (self.client_entry, "entry"),
            (self.client_middle, "middle"),
            (self.introduction, "introduction"),
            (self.host_middle, "middle"),
            (self.service_relay, "service-relay"),
        )
        node_ids: list[str] = []
        for descriptor, capability in roles:
            descriptor.verify()
            if capability not in descriptor.capabilities:
                raise OverlayRoutingError(
                    f"route node lacks required capability: {capability}"
                )
            node_ids.append(descriptor.node_id)
        if len(set(node_ids)) != len(node_ids):
            raise OverlayRoutingError("multi-hop route must use distinct node identities")
        if (
            self.service.endpoint is not None
            or self.service.protocol_version != VERSION_3
        ):
            raise OverlayRoutingError("multi-hop route requires a remote wire 3 service")
        if (
            self.introduction.node_id != self.introduction_point.node_id
            or self.introduction_point not in self.introductions.points
        ):
            raise OverlayRoutingError("route introduction is not service-authorized")

    @property
    def node_descriptors(self) -> tuple[NodeDescriptor, ...]:
        return (
            self.client_entry,
            self.client_middle,
            self.introduction,
            self.host_middle,
            self.service_relay,
        )


class OverlayRoutePlanner:
    def __init__(
        self,
        resolver: DistributedResolver,
        *,
        chooser: Callable[[Sequence[object]], object] = secrets.choice,
    ) -> None:
        if not isinstance(resolver, DistributedResolver):
            raise OverlayRoutingError("route planner requires distributed discovery")
        self.resolver = resolver
        self._chooser = chooser

    def _choose_node(
        self,
        capability: str,
        excluded: set[str],
        now: int | None,
    ) -> NodeDescriptor:
        candidates = tuple(
            node
            for node in self.resolver.network.known_nodes(capability, now=now)
            if node.node_id not in excluded
        )
        if not candidates:
            raise OverlayRoutingError(
                f"no distinct overlay node is available for role: {capability}"
            )
        selected = self._chooser(candidates)
        if not isinstance(selected, NodeDescriptor) or selected not in candidates:
            raise OverlayRoutingError("route chooser returned an invalid node")
        return selected

    def plan(self, name: str, now: int | None = None) -> OverlayRoutePlan:
        service = self.resolver.resolve(name)
        introductions = self.resolver.resolve_introduction(service, now=now)
        valid_points: list[tuple[IntroductionPoint, NodeDescriptor]] = []
        for point in introductions.points:
            try:
                node = self.resolver.resolve_node(point.node_id, now=now)
            except GrangerNetworkError:
                continue
            if "introduction" in node.capabilities:
                valid_points.append((point, node))
        if not valid_points:
            raise OverlayRoutingError("service has no valid distributed introduction point")
        selected_pair = self._chooser(valid_points)
        if (
            not isinstance(selected_pair, tuple)
            or len(selected_pair) != 2
            or selected_pair not in valid_points
        ):
            raise OverlayRoutingError("route chooser returned an invalid introduction")
        introduction_point, introduction = selected_pair
        excluded = {introduction.node_id}
        client_entry = self._choose_node("entry", excluded, now)
        excluded.add(client_entry.node_id)
        client_middle = self._choose_node("middle", excluded, now)
        excluded.add(client_middle.node_id)
        service_relay = self._choose_node("service-relay", excluded, now)
        excluded.add(service_relay.node_id)
        host_middle = self._choose_node("middle", excluded, now)
        return OverlayRoutePlan(
            service=service,
            introductions=introductions,
            introduction_point=introduction_point,
            client_entry=client_entry,
            client_middle=client_middle,
            introduction=introduction,
            host_middle=host_middle,
            service_relay=service_relay,
        )


class SecureChannelStream:
    """Adapts authenticated data frames to the socket API used by wire v3."""

    def __init__(self, channel: SecureChannel) -> None:
        if channel.protocol_version != VERSION_3:
            raise ProtocolError("telescoped streams require wire protocol 3")
        self.channel = channel
        self._buffer = bytearray()
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()
        self._closed = False

    def sendall(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise ProtocolError("telescoped stream accepts only bytes")
        if self._closed:
            raise ProtocolError("telescoped stream is closed")
        if not data:
            return
        with self._send_lock:
            for offset in range(0, len(data), self.channel.max_message_size):
                self.channel.send_bytes(
                    data[offset : offset + self.channel.max_message_size]
                )

    def recv(self, size: int) -> bytes:
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ProtocolError("telescoped stream receive size is invalid")
        if self._closed:
            return b""
        with self._receive_lock:
            while not self._buffer:
                payload = self.channel.receive_bytes()
                if payload:
                    self._buffer.extend(payload)
            result = bytes(self._buffer[:size])
            del self._buffer[:size]
            return result

    def settimeout(self, value: float | None) -> None:
        connection = self.channel.connection
        setter = getattr(connection, "settimeout", None)
        if setter is None:
            raise ProtocolError("telescoped stream has no timeout-capable transport")
        setter(value)

    def close(self) -> None:
        self._closed = True
        self.channel.destroy()


class RelayObservation:
    def __init__(
        self,
        node_id: str,
        capability: str,
        upstream_address: str,
        downstream_address: str,
        *,
        sample_limit: int = 2 * 1024 * 1024,
    ) -> None:
        self.node_id = node_id
        self.capability = capability
        self.upstream_address = upstream_address
        self.downstream_address = downstream_address
        self.sample_limit = sample_limit
        self.bytes_forwarded = 0
        self._sample = bytearray()
        self._lock = threading.Lock()

    def record(self, payload: bytes) -> None:
        with self._lock:
            self.bytes_forwarded += len(payload)
            remaining = self.sample_limit - len(self._sample)
            if remaining > 0:
                self._sample.extend(payload[:remaining])

    def contains(self, marker: bytes) -> bool:
        with self._lock:
            return marker in self._sample

    @property
    def adjacent_addresses(self) -> frozenset[str]:
        return frozenset({self.upstream_address, self.downstream_address})


class RelayForwarder:
    def __init__(
        self,
        left: DuplexStream,
        right: DuplexStream,
        node: GrangerNode,
        circuit_id: bytes,
        observation: RelayObservation,
    ) -> None:
        self.left = left
        self.right = right
        self.node = node
        self.circuit_id = circuit_id
        self.observation = observation
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for source, destination, label in (
            (self.left, self.right, "forward"),
            (self.right, self.left, "reverse"),
        ):
            thread = threading.Thread(
                target=self._pump,
                args=(source, destination, label),
                name=f"granger-overlay-{self.observation.capability}-{label}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def _pump(
        self,
        source: DuplexStream,
        destination: DuplexStream,
        label: str,
    ) -> None:
        try:
            while not self._stop.is_set():
                payload = source.recv(64 * 1024)
                if not payload:
                    raise ProtocolError("overlay relay stream closed unexpectedly")
                self.node.account_bytes(self.circuit_id, len(payload))
                self.observation.record(payload)
                destination.sendall(payload)
        except Exception as error:
            if not self._stop.is_set():
                self.errors.append(f"{label}: {type(error).__name__}: {error}")
                self._stop.set()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float = 2.0) -> None:
        for thread in self._threads:
            thread.join(timeout=timeout)


def _set_timeout(connection: DuplexStream, value: float | None) -> None:
    setter = getattr(connection, "settimeout", None)
    if setter is None:
        raise ProtocolError("overlay stream does not support bounded handshakes")
    setter(value)


def _establish_v3_session(
    client_connection: DuplexStream,
    server_connection: DuplexStream,
    server_identity: ServiceIdentity,
    *,
    timeout: float = 8.0,
) -> tuple[SecureChannel, SecureChannel]:
    session_id = secrets.token_bytes(16)
    results: queue.Queue[SecureChannel | BaseException] = queue.Queue()
    _set_timeout(client_connection, timeout)
    _set_timeout(server_connection, timeout)

    def accept() -> None:
        try:
            results.put(
                server_handshake(
                    server_connection,
                    server_identity,
                    expected_session_id=session_id,
                    protocol_version=VERSION_3,
                )
            )
        except BaseException as error:
            results.put(error)

    thread = threading.Thread(target=accept, name="granger-overlay-handshake", daemon=True)
    thread.start()
    try:
        client = client_handshake(
            client_connection,
            server_identity.public_key_bytes,
            session_id=session_id,
            protocol_version=VERSION_3,
        )
    except Exception:
        thread.join(timeout=timeout)
        raise
    thread.join(timeout=timeout)
    if thread.is_alive():
        client.destroy()
        raise ProtocolError("overlay server handshake timed out")
    server = results.get_nowait()
    if isinstance(server, BaseException):
        client.destroy()
        raise server
    _set_timeout(client_connection, None)
    _set_timeout(server_connection, None)
    return client, server


class MultiHopCircuit:
    def __init__(
        self,
        route: OverlayRoutePlan,
        circuit_id: bytes,
        client_channel: SecureChannel,
        service_channel: SecureChannel,
        channels: list[SecureChannel],
        raw_sockets: list[socket.socket],
        forwarders: list[RelayForwarder],
        observations: dict[str, RelayObservation],
        nodes: list[GrangerNode],
        session_count: int,
        client_address: str,
        host_address: str,
    ) -> None:
        self.route = route
        self.circuit_id = circuit_id
        self.client_channel = client_channel
        self.service_channel = service_channel
        self._channels = channels
        self._raw_sockets = raw_sockets
        self._forwarders = forwarders
        self.observations = observations
        self._nodes = nodes
        self.session_count = session_count
        self.client_address = client_address
        self.host_address = host_address
        self._closed = False

    @classmethod
    def open(
        cls,
        route: OverlayRoutePlan,
        node_runtimes: dict[str, GrangerNode],
        service_identity: ServiceIdentity,
        introduction_registry: IntroductionRegistry,
        *,
        client_address: str = "198.51.100.10",
        host_address: str = "198.51.100.20",
    ) -> "MultiHopCircuit":
        if not isinstance(route, OverlayRoutePlan):
            raise OverlayRoutingError("multi-hop circuit requires a validated route")
        if route.service.identity_public_key != service_identity.public_key_bytes:
            raise OverlayRoutingError("service identity does not match the route descriptor")
        if not isinstance(introduction_registry, IntroductionRegistry):
            raise OverlayRoutingError("multi-hop circuit requires introduction state")
        for address, label in (
            (client_address, "client"),
            (host_address, "host"),
        ):
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as error:
                raise OverlayRoutingError(f"{label} simulation address is invalid") from error
            if parsed.is_unspecified or parsed.is_multicast:
                raise OverlayRoutingError(f"{label} simulation address is not usable")
        if client_address == host_address:
            raise OverlayRoutingError("client and host simulation addresses must differ")

        nodes: list[GrangerNode] = []
        roles = (
            (route.client_entry, "entry"),
            (route.client_middle, "middle"),
            (route.introduction, "introduction"),
            (route.host_middle, "middle"),
            (route.service_relay, "service-relay"),
        )
        circuit_id = secrets.token_bytes(16)
        channels: list[SecureChannel] = []
        raw_sockets: list[socket.socket] = []
        forwarders: list[RelayForwarder] = []
        observations: dict[str, RelayObservation] = {}
        session_count = 0

        try:
            introduction_registry.install(route.introductions, route.service)
            introduction_registry.authorize(
                route.service.service_id,
                route.introduction.node_id,
                route.introduction_point.token,
                secrets.token_bytes(16),
            )
            for descriptor, capability in roles:
                node = node_runtimes.get(descriptor.node_id)
                if (
                    not isinstance(node, GrangerNode)
                    or node.descriptor != descriptor
                ):
                    raise OverlayRoutingError(
                        f"route has no matching runtime for {capability}"
                    )
                node.begin_circuit(circuit_id, capability)
                nodes.append(node)

            def establish(
                client_connection: DuplexStream,
                server_connection: DuplexStream,
                identity: ServiceIdentity,
            ) -> tuple[SecureChannelStream, SecureChannelStream]:
                nonlocal session_count
                client, server = _establish_v3_session(
                    client_connection,
                    server_connection,
                    identity,
                )
                channels.extend((client, server))
                session_count += 1
                return SecureChannelStream(client), SecureChannelStream(server)

            def physical_pair(
                identity: ServiceIdentity,
            ) -> tuple[SecureChannelStream, SecureChannelStream]:
                left, right = socket.socketpair()
                raw_sockets.extend((left, right))
                return establish(left, right, identity)

            def add_forwarder(
                descriptor: NodeDescriptor,
                capability: str,
                left: DuplexStream,
                right: DuplexStream,
                upstream: str,
                downstream: str,
            ) -> None:
                node = node_runtimes[descriptor.node_id]
                observation = RelayObservation(
                    descriptor.node_id,
                    capability,
                    upstream,
                    downstream,
                )
                observations[descriptor.node_id] = observation
                forwarder = RelayForwarder(
                    left,
                    right,
                    node,
                    circuit_id,
                    observation,
                )
                forwarders.append(forwarder)
                forwarder.start()

            client_to_entry, entry_from_client = physical_pair(
                node_runtimes[route.client_entry.node_id].identity
            )
            entry_to_middle, middle_from_entry = physical_pair(
                node_runtimes[route.client_middle.node_id].identity
            )
            add_forwarder(
                route.client_entry,
                "entry",
                entry_from_client,
                entry_to_middle,
                client_address,
                route.client_middle.endpoint.host,
            )
            client_to_middle, middle_from_client = establish(
                client_to_entry,
                middle_from_entry,
                node_runtimes[route.client_middle.node_id].identity,
            )

            middle_to_intro, intro_from_middle = physical_pair(
                node_runtimes[route.introduction.node_id].identity
            )
            add_forwarder(
                route.client_middle,
                "middle",
                middle_from_client,
                middle_to_intro,
                route.client_entry.endpoint.host,
                route.introduction.endpoint.host,
            )
            client_to_intro, intro_from_client = establish(
                client_to_middle,
                intro_from_middle,
                node_runtimes[route.introduction.node_id].identity,
            )

            host_to_service_relay, service_relay_from_host = physical_pair(
                node_runtimes[route.service_relay.node_id].identity
            )
            service_relay_to_middle, host_middle_from_relay = physical_pair(
                node_runtimes[route.host_middle.node_id].identity
            )
            add_forwarder(
                route.service_relay,
                "service-relay",
                service_relay_from_host,
                service_relay_to_middle,
                host_address,
                route.host_middle.endpoint.host,
            )
            host_to_middle, host_middle_from_host = establish(
                host_to_service_relay,
                host_middle_from_relay,
                node_runtimes[route.host_middle.node_id].identity,
            )

            host_middle_to_intro, intro_from_host_middle = physical_pair(
                node_runtimes[route.introduction.node_id].identity
            )
            add_forwarder(
                route.host_middle,
                "middle",
                host_middle_from_host,
                host_middle_to_intro,
                route.service_relay.endpoint.host,
                route.introduction.endpoint.host,
            )
            host_to_intro, intro_from_host = establish(
                host_to_middle,
                intro_from_host_middle,
                node_runtimes[route.introduction.node_id].identity,
            )

            add_forwarder(
                route.introduction,
                "introduction",
                intro_from_client,
                intro_from_host,
                route.client_middle.endpoint.host,
                route.host_middle.endpoint.host,
            )

            client_channel, service_channel = _establish_v3_session(
                client_to_intro,
                host_to_intro,
                service_identity,
            )
            channels.extend((client_channel, service_channel))
            session_count += 1
            return cls(
                route,
                circuit_id,
                client_channel,
                service_channel,
                channels,
                raw_sockets,
                forwarders,
                observations,
                nodes,
                session_count,
                client_address,
                host_address,
            )
        except Exception:
            for forwarder in forwarders:
                forwarder.stop()
            for connection in raw_sockets:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            for channel in channels:
                channel.destroy()
            for forwarder in forwarders:
                forwarder.join()
            for node in nodes:
                node.end_circuit(circuit_id)
            raise

    @property
    def hop_session_count(self) -> int:
        return self.session_count - 1

    @property
    def all_sessions_use_wire_v3(self) -> bool:
        return bool(self._channels) and all(
            channel.protocol_version == VERSION_3 for channel in self._channels
        )

    @property
    def unique_session_bindings(self) -> frozenset[bytes]:
        return frozenset(channel.channel_binding for channel in self._channels)

    @property
    def client_visible_addresses(self) -> frozenset[str]:
        return frozenset({self.route.client_entry.endpoint.host})

    @property
    def host_visible_addresses(self) -> frozenset[str]:
        return frozenset({self.route.service_relay.endpoint.host})

    @property
    def topology_edges(self) -> tuple[frozenset[str], ...]:
        return (
            frozenset({self.client_address, self.route.client_entry.endpoint.host}),
            frozenset(
                {
                    self.route.client_entry.endpoint.host,
                    self.route.client_middle.endpoint.host,
                }
            ),
            frozenset(
                {
                    self.route.client_middle.endpoint.host,
                    self.route.introduction.endpoint.host,
                }
            ),
            frozenset(
                {
                    self.route.introduction.endpoint.host,
                    self.route.host_middle.endpoint.host,
                }
            ),
            frozenset(
                {
                    self.route.host_middle.endpoint.host,
                    self.route.service_relay.endpoint.host,
                }
            ),
            frozenset({self.route.service_relay.endpoint.host, self.host_address}),
        )

    @property
    def direct_client_host_connections(self) -> int:
        endpoint_pair = frozenset({self.client_address, self.host_address})
        return sum(edge == endpoint_pair for edge in self.topology_edges)

    def plaintext_observed(self, marker: bytes) -> bool:
        return any(
            observation.contains(marker) for observation in self.observations.values()
        )

    def single_relay_sees_both_endpoints(self) -> bool:
        endpoint_pair = {self.client_address, self.host_address}
        return any(
            endpoint_pair.issubset(observation.adjacent_addresses)
            for observation in self.observations.values()
        )

    def assert_healthy(self) -> None:
        errors = [
            error
            for forwarder in self._forwarders
            for error in forwarder.errors
        ]
        if errors:
            raise OverlayRoutingError(f"overlay relay failed closed: {errors[0]}")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for forwarder in self._forwarders:
            forwarder.stop()
        for connection in self._raw_sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for channel in self._channels:
            channel.destroy()
        for forwarder in self._forwarders:
            forwarder.join()
        for node in self._nodes:
            node.end_circuit(self.circuit_id)

    def __enter__(self) -> "MultiHopCircuit":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
