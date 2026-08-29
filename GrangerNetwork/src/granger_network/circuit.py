from __future__ import annotations

import secrets
from dataclasses import dataclass

from .binary import BinaryReader, BinaryWriter
from .cells import (
    CellMultiplexer,
    CoverTrafficProfile,
    MuxStream,
    cover_profile_from_environment,
)
from .errors import OverlayRoutingError, ProtocolError
from .identity import ServiceIdentity
from .peer import CIRCUIT_CAPABILITIES, NodeDescriptor
from .peer_rpc import (
    AuthenticatedPeer,
    PeerRole,
    RpcType,
    authenticate_client_stream,
    connect_authenticated_peer,
)


MAX_CIRCUIT_CONTROL = 66 * 1024


@dataclass(frozen=True)
class CircuitOpenRequest:
    circuit_id: bytes
    role: str


@dataclass(frozen=True)
class CircuitExtendRequest:
    incoming_circuit_id: bytes
    outgoing_circuit_id: bytes
    current_role: str
    next_role: str
    next_node: NodeDescriptor


def _validate_role(role: str) -> str:
    if not isinstance(role, str) or role not in CIRCUIT_CAPABILITIES:
        raise ProtocolError("circuit relay role is invalid")
    return role


def encode_open_circuit(circuit_id: bytes, role: str) -> bytes:
    return (
        BinaryWriter(128)
        .fixed(circuit_id, 16)
        .text_u16(_validate_role(role), 32)
        .build()
    )


def decode_open_circuit(content: bytes) -> CircuitOpenRequest:
    reader = BinaryReader(content, 128)
    result = CircuitOpenRequest(reader.fixed(16), _validate_role(reader.text_u16(32)))
    reader.finish()
    return result


def encode_extend_circuit(request: CircuitExtendRequest) -> bytes:
    if not isinstance(request, CircuitExtendRequest):
        raise ProtocolError("circuit extension request is invalid")
    request.next_node.verify()
    descriptor = request.next_node.to_json().encode("ascii")
    return (
        BinaryWriter(MAX_CIRCUIT_CONTROL)
        .fixed(request.incoming_circuit_id, 16)
        .fixed(request.outgoing_circuit_id, 16)
        .text_u16(_validate_role(request.current_role), 32)
        .text_u16(_validate_role(request.next_role), 32)
        .bytes_u32(descriptor, 64 * 1024)
        .build()
    )


def decode_extend_circuit(content: bytes) -> CircuitExtendRequest:
    reader = BinaryReader(content, MAX_CIRCUIT_CONTROL)
    incoming = reader.fixed(16)
    outgoing = reader.fixed(16)
    current_role = _validate_role(reader.text_u16(32))
    next_role = _validate_role(reader.text_u16(32))
    try:
        descriptor = NodeDescriptor.from_json(reader.bytes_u32(64 * 1024).decode("ascii"))
    except UnicodeDecodeError as error:
        raise ProtocolError("circuit node descriptor is not ASCII") from error
    reader.finish()
    if next_role not in descriptor.capabilities or descriptor.reachability != "reachable":
        raise OverlayRoutingError("next circuit node did not advertise the requested role")
    if incoming == outgoing:
        raise OverlayRoutingError("adjacent circuit identifiers must be independent")
    return CircuitExtendRequest(incoming, outgoing, current_role, next_role, descriptor)


@dataclass
class BuiltCircuit:
    route: tuple[tuple[NodeDescriptor, str], ...]
    endpoint: AuthenticatedPeer
    multiplexers: list[CellMultiplexer]
    streams: list[MuxStream]
    circuit_ids: tuple[bytes, ...]
    hop_authentication_keys: tuple[bytes, ...]
    _closed: bool = False

    @property
    def hop_count(self) -> int:
        return len(self.route)

    @property
    def unique_node_ids(self) -> frozenset[str]:
        return frozenset(descriptor.node_id for descriptor, _role in self.route)

    @property
    def all_cells_fixed_size(self) -> bool:
        return bool(self.multiplexers)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.endpoint.close()
        for stream in reversed(self.streams):
            stream.close()
        for multiplexer in reversed(self.multiplexers):
            multiplexer.close()

    def __enter__(self) -> "BuiltCircuit":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class CircuitBuilder:
    def __init__(
        self,
        identity: ServiceIdentity,
        role: PeerRole,
        *,
        timeout: float = 10.0,
        max_streams: int = 128,
        cover_profile: CoverTrafficProfile | str | None = None,
        identity_factory=ServiceIdentity.generate,
    ) -> None:
        if role not in {PeerRole.CLIENT, PeerRole.SERVICE}:
            raise OverlayRoutingError("endpoint circuit role is invalid")
        self.identity = identity
        self.role = role
        self.timeout = timeout
        self.max_streams = max_streams
        self.cover_profile = (
            cover_profile_from_environment()
            if cover_profile is None
            else CoverTrafficProfile(cover_profile)
        )
        if not callable(identity_factory):
            raise OverlayRoutingError("circuit identity factory is invalid")
        self.identity_factory = identity_factory

    def _hop_identity(self, role: str) -> ServiceIdentity:
        if self.role is PeerRole.SERVICE and role == "introduction":
            return self.identity
        identity = self.identity_factory()
        if not isinstance(identity, ServiceIdentity):
            raise OverlayRoutingError("circuit identity factory returned an invalid identity")
        return identity

    def open(
        self,
        route: list[tuple[NodeDescriptor, str]] | tuple[tuple[NodeDescriptor, str], ...],
    ) -> BuiltCircuit:
        normalized = tuple(route)
        if len(normalized) < 2:
            raise OverlayRoutingError("private WAN circuit requires at least two relay nodes")
        node_ids: set[str] = set()
        for descriptor, role in normalized:
            descriptor.verify()
            _validate_role(role)
            if role not in descriptor.capabilities or descriptor.reachability != "reachable":
                raise OverlayRoutingError("route node does not advertise its selected role")
            if descriptor.node_id in node_ids:
                raise OverlayRoutingError("route repeats a relay identity")
            node_ids.add(descriptor.node_id)

        peer: AuthenticatedPeer | None = None
        multiplexers: list[CellMultiplexer] = []
        streams: list[MuxStream] = []
        circuit_ids: list[bytes] = []
        hop_keys: list[bytes] = []
        try:
            first_identity = self._hop_identity(normalized[0][1])
            hop_keys.append(first_identity.public_key_bytes)
            peer = connect_authenticated_peer(
                normalized[0][0],
                first_identity,
                self.role,
                timeout=self.timeout,
                attempts=2,
            )
            peer.channel.connection.settimeout(self.timeout)
            for index in range(len(normalized) - 1):
                current, current_role = normalized[index]
                next_node, next_role = normalized[index + 1]
                incoming_id = secrets.token_bytes(16)
                outgoing_id = secrets.token_bytes(16)
                request = CircuitExtendRequest(
                    incoming_id,
                    outgoing_id,
                    current_role,
                    next_role,
                    next_node,
                )
                response = peer.rpc.request(
                    RpcType.EXTEND_CIRCUIT,
                    encode_extend_circuit(request),
                    expected=RpcType.CIRCUIT_CREATED,
                )
                if response.payload:
                    raise ProtocolError("circuit creation response has an unexpected payload")
                peer.channel.connection.settimeout(None)
                multiplexer = CellMultiplexer(
                    peer.channel,
                    incoming_id,
                    initiator=True,
                    max_streams=self.max_streams,
                    cover_profile=self.cover_profile,
                )
                stream = multiplexer.open_stream(self.timeout)
                multiplexers.append(multiplexer)
                streams.append(stream)
                circuit_ids.extend((incoming_id, outgoing_id))
                next_identity = self._hop_identity(next_role)
                hop_keys.append(next_identity.public_key_bytes)
                peer = authenticate_client_stream(
                    stream,
                    next_node,
                    next_identity,
                    self.role,
                )
                if index + 1 < len(normalized) - 1:
                    stream.settimeout(self.timeout)
                else:
                    stream.settimeout(None)
            for multiplexer in multiplexers:
                multiplexer.channel.connection.settimeout(None)
            for stream in streams:
                stream.settimeout(None)
            peer.channel.connection.settimeout(None)
            return BuiltCircuit(
                normalized,
                peer,
                multiplexers,
                streams,
                tuple(circuit_ids),
                tuple(hop_keys),
            )
        except Exception:
            if peer is not None:
                peer.close()
            for stream in reversed(streams):
                stream.close()
            for multiplexer in reversed(multiplexers):
                multiplexer.close()
            raise
