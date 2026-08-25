from __future__ import annotations

import secrets
import socket
import struct
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .binary import BinaryReader, BinaryWriter
from .errors import IdentityVerificationError, ProtocolError, TransportPolicyError
from .identity import ServiceIdentity
from .peer import NodeDescriptor, node_id_from_public_key
from .protocol import VERSION_3, SecureChannel, client_handshake, server_handshake
from .transport import RendezvousEndpoint


RPC_MAGIC = b"GNRP"
RPC_VERSION = 1
RPC_HEADER = struct.Struct("!4sBBBB16sQI")
MAX_RPC_PAYLOAD = 256 * 1024
MAX_DESCRIPTOR_BYTES = 64 * 1024
RPC_FLAG_RESPONSE = 0x01
RPC_FLAG_ERROR = 0x02
RPC_ALLOWED_FLAGS = RPC_FLAG_RESPONSE | RPC_FLAG_ERROR
PEER_AUTH_DOMAIN = b"granger-network-v0.4/peer-auth\x00"


class RpcType(IntEnum):
    HELLO = 1
    AUTH = 2
    CAPABILITIES = 3
    PING = 4
    PONG = 5
    FIND_NODE = 6
    FIND_RECORD = 7
    STORE_RECORD = 8
    OPEN_CIRCUIT = 9
    EXTEND_CIRCUIT = 10
    CIRCUIT_CREATED = 11
    CIRCUIT_FAILED = 12
    CLOSE_CIRCUIT = 13
    INTRO_REGISTER = 14
    INTRO_REQUEST = 15
    INTRO_DELIVER = 16
    RENDEZVOUS_REGISTER = 17
    RENDEZVOUS_JOIN = 18
    STREAM_OPEN = 19
    STREAM_DATA = 20
    STREAM_CLOSE = 21
    STREAM_RESET = 22
    WINDOW_UPDATE = 23
    ERROR = 24


class PeerRole(IntEnum):
    CLIENT = 1
    SERVICE = 2
    RELAY = 3
    BOOTSTRAP = 4


class DuplexConnection(Protocol):
    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...

    def settimeout(self, value: float | None) -> None: ...


@dataclass(frozen=True)
class RpcFrame:
    message_type: RpcType
    flags: int
    request_id: bytes
    sequence: int
    payload: bytes

    @property
    def is_response(self) -> bool:
        return bool(self.flags & RPC_FLAG_RESPONSE)

    @property
    def is_error(self) -> bool:
        return bool(self.flags & RPC_FLAG_ERROR)


def encode_rpc_frame(frame: RpcFrame) -> bytes:
    if not isinstance(frame.message_type, RpcType):
        raise ProtocolError("peer RPC message type is invalid")
    if (
        isinstance(frame.flags, bool)
        or not isinstance(frame.flags, int)
        or frame.flags & ~RPC_ALLOWED_FLAGS
        or (frame.flags & RPC_FLAG_ERROR and frame.message_type is not RpcType.ERROR)
        or (frame.message_type is RpcType.ERROR and not frame.flags & RPC_FLAG_ERROR)
    ):
        raise ProtocolError("peer RPC flags are invalid")
    if not isinstance(frame.request_id, bytes) or len(frame.request_id) != 16:
        raise ProtocolError("peer RPC request identifier is invalid")
    if (
        isinstance(frame.sequence, bool)
        or not isinstance(frame.sequence, int)
        or not 0 <= frame.sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise ProtocolError("peer RPC sequence is invalid")
    if not isinstance(frame.payload, bytes) or len(frame.payload) > MAX_RPC_PAYLOAD:
        raise ProtocolError("peer RPC payload exceeds its size limit")
    return RPC_HEADER.pack(
        RPC_MAGIC,
        RPC_VERSION,
        int(frame.message_type),
        frame.flags,
        0,
        frame.request_id,
        frame.sequence,
        len(frame.payload),
    ) + frame.payload


def decode_rpc_frame(content: bytes) -> RpcFrame:
    if not isinstance(content, bytes) or not RPC_HEADER.size <= len(content) <= RPC_HEADER.size + MAX_RPC_PAYLOAD:
        raise ProtocolError("peer RPC frame size is invalid")
    header = content[: RPC_HEADER.size]
    magic, version, raw_type, flags, reserved, request_id, sequence, payload_size = RPC_HEADER.unpack(header)
    if magic != RPC_MAGIC or version != RPC_VERSION or reserved != 0:
        raise ProtocolError("peer RPC header is invalid")
    if flags & ~RPC_ALLOWED_FLAGS:
        raise ProtocolError("peer RPC flags are invalid")
    try:
        message_type = RpcType(raw_type)
    except ValueError as error:
        raise ProtocolError("peer RPC message type is unknown") from error
    if (flags & RPC_FLAG_ERROR and message_type is not RpcType.ERROR) or (
        message_type is RpcType.ERROR and not flags & RPC_FLAG_ERROR
    ):
        raise ProtocolError("peer RPC error flags are inconsistent")
    payload = content[RPC_HEADER.size :]
    if payload_size != len(payload) or payload_size > MAX_RPC_PAYLOAD:
        raise ProtocolError("peer RPC payload length is invalid")
    return RpcFrame(message_type, flags, request_id, sequence, payload)


class PeerRpcSession:
    def __init__(self, channel: SecureChannel) -> None:
        if not isinstance(channel, SecureChannel) or channel.protocol_version != VERSION_3:
            raise ProtocolError("peer RPC requires a wire 3 channel")
        self.channel = channel
        self._tx_sequence = 0
        self._rx_sequence = 0
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()

    def send(
        self,
        message_type: RpcType,
        payload: bytes = b"",
        *,
        request_id: bytes | None = None,
        response: bool = False,
        error: bool = False,
    ) -> bytes:
        identifier = secrets.token_bytes(16) if request_id is None else request_id
        flags = (RPC_FLAG_RESPONSE if response else 0) | (RPC_FLAG_ERROR if error else 0)
        with self._send_lock:
            if self._tx_sequence > 0xFFFFFFFFFFFFFFFF:
                raise ProtocolError("peer RPC transmit sequence is exhausted")
            encoded = encode_rpc_frame(
                RpcFrame(message_type, flags, identifier, self._tx_sequence, payload)
            )
            self.channel.send_bytes(encoded)
            self._tx_sequence += 1
        return identifier

    def receive(self) -> RpcFrame:
        with self._receive_lock:
            frame = decode_rpc_frame(self.channel.receive_bytes())
            if frame.sequence != self._rx_sequence:
                raise ProtocolError("peer RPC sequence is out of order")
            self._rx_sequence += 1
            return frame

    def request(
        self,
        message_type: RpcType,
        payload: bytes = b"",
        *,
        expected: RpcType,
    ) -> RpcFrame:
        request_id = self.send(message_type, payload)
        response = self.receive()
        if not response.is_response or response.request_id != request_id:
            raise ProtocolError("peer RPC response does not match its request")
        if response.is_error or response.message_type is RpcType.ERROR:
            try:
                reader = BinaryReader(response.payload, MAX_RPC_PAYLOAD)
                code = reader.text_u16(64)
                reader.finish()
            except ProtocolError:
                code = "REMOTE_ERROR"
            raise ProtocolError(f"peer RPC request failed: {code}")
        if response.message_type is not expected:
            raise ProtocolError("peer RPC response has an unexpected type")
        return response


@dataclass(frozen=True)
class PeerPrincipal:
    role: PeerRole
    node_id: str
    public_key: bytes
    descriptor: NodeDescriptor | None


@dataclass
class AuthenticatedPeer:
    channel: SecureChannel
    rpc: PeerRpcSession
    remote: PeerPrincipal

    def close(self) -> None:
        self.channel.destroy()
        try:
            self.channel.connection.close()
        except OSError:
            pass


@dataclass(frozen=True)
class _Hello:
    role: PeerRole
    public_key: bytes
    nonce: bytes
    descriptor: NodeDescriptor | None
    encoded: bytes


def _encode_hello(
    role: PeerRole,
    identity: ServiceIdentity,
    descriptor: NodeDescriptor | None,
) -> bytes:
    if not isinstance(role, PeerRole):
        raise ProtocolError("peer role is invalid")
    if descriptor is not None:
        descriptor.verify()
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise IdentityVerificationError("peer descriptor does not match its identity")
        descriptor_bytes = descriptor.to_json().encode("ascii")
    else:
        descriptor_bytes = b""
    return (
        BinaryWriter(MAX_DESCRIPTOR_BYTES + 80)
        .u8(int(role))
        .fixed(identity.public_key_bytes, 32)
        .fixed(secrets.token_bytes(32), 32)
        .bytes_u32(descriptor_bytes, MAX_DESCRIPTOR_BYTES)
        .build()
    )


def _decode_hello(payload: bytes) -> _Hello:
    reader = BinaryReader(payload, MAX_DESCRIPTOR_BYTES + 80)
    try:
        role = PeerRole(reader.u8())
    except ValueError as error:
        raise ProtocolError("peer role is unknown") from error
    public_key = reader.fixed(32)
    nonce = reader.fixed(32)
    descriptor_bytes = reader.bytes_u32(MAX_DESCRIPTOR_BYTES)
    reader.finish()
    descriptor = None
    if descriptor_bytes:
        try:
            descriptor = NodeDescriptor.from_json(descriptor_bytes.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ProtocolError("peer descriptor encoding is invalid") from error
        if descriptor.identity_public_key != public_key:
            raise IdentityVerificationError("peer descriptor identity was substituted")
    if role in {PeerRole.RELAY, PeerRole.BOOTSTRAP} and descriptor is None:
        raise IdentityVerificationError("infrastructure peer omitted its signed descriptor")
    if role in {PeerRole.CLIENT, PeerRole.SERVICE} and descriptor is not None:
        raise IdentityVerificationError("endpoint peer disclosed an unexpected relay descriptor")
    return _Hello(role, public_key, nonce, descriptor, payload)


def _auth_payload(channel_binding: bytes, client_hello: bytes, server_hello: bytes) -> bytes:
    return (
        PEER_AUTH_DOMAIN
        + channel_binding
        + len(client_hello).to_bytes(4, "big")
        + client_hello
        + len(server_hello).to_bytes(4, "big")
        + server_hello
    )


def _verify_auth(public_key: bytes, signature: bytes, payload: bytes) -> None:
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise IdentityVerificationError("peer authentication signature length is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError) as error:
        raise IdentityVerificationError("peer authentication signature is invalid") from error


def authenticate_client_stream(
    connection: DuplexConnection,
    expected_server: NodeDescriptor,
    identity: ServiceIdentity,
    role: PeerRole,
    *,
    local_descriptor: NodeDescriptor | None = None,
) -> AuthenticatedPeer:
    expected_server.verify()
    session_id = secrets.token_bytes(16)
    channel = client_handshake(
        connection,
        expected_server.identity_public_key,
        session_id=session_id,
        protocol_version=VERSION_3,
    )
    rpc = PeerRpcSession(channel)
    try:
        local_hello = _encode_hello(role, identity, local_descriptor)
        request_id = rpc.send(RpcType.HELLO, local_hello)
        response = rpc.receive()
        if (
            response.message_type is not RpcType.HELLO
            or not response.is_response
            or response.request_id != request_id
        ):
            raise ProtocolError("peer authentication HELLO state is invalid")
        remote_hello = _decode_hello(response.payload)
        if (
            remote_hello.public_key != expected_server.identity_public_key
            or remote_hello.descriptor != expected_server
            or remote_hello.role not in {PeerRole.RELAY, PeerRole.BOOTSTRAP}
        ):
            raise IdentityVerificationError("connected peer does not match its pinned descriptor")
        transcript = _auth_payload(channel.channel_binding, local_hello, remote_hello.encoded)
        rpc.send(
            RpcType.AUTH,
            identity.sign(transcript),
            request_id=request_id,
        )
        auth_response = rpc.receive()
        if (
            auth_response.message_type is not RpcType.AUTH
            or not auth_response.is_response
            or auth_response.request_id != request_id
        ):
            raise ProtocolError("peer authentication AUTH state is invalid")
        _verify_auth(remote_hello.public_key, auth_response.payload, transcript)
        return AuthenticatedPeer(
            channel,
            rpc,
            PeerPrincipal(
                remote_hello.role,
                node_id_from_public_key(remote_hello.public_key),
                remote_hello.public_key,
                remote_hello.descriptor,
            ),
        )
    except Exception:
        channel.destroy()
        raise


def authenticate_server_stream(
    connection: DuplexConnection,
    identity: ServiceIdentity,
    descriptor: NodeDescriptor,
    *,
    role: PeerRole = PeerRole.RELAY,
) -> AuthenticatedPeer:
    descriptor.verify()
    if descriptor.identity_public_key != identity.public_key_bytes:
        raise IdentityVerificationError("server descriptor does not match its identity")
    channel = server_handshake(
        connection,
        identity,
        protocol_version=VERSION_3,
    )
    rpc = PeerRpcSession(channel)
    try:
        hello_request = rpc.receive()
        if hello_request.message_type is not RpcType.HELLO or hello_request.is_response:
            raise ProtocolError("peer authentication HELLO state is invalid")
        remote_hello = _decode_hello(hello_request.payload)
        local_hello = _encode_hello(role, identity, descriptor)
        rpc.send(
            RpcType.HELLO,
            local_hello,
            request_id=hello_request.request_id,
            response=True,
        )
        auth_request = rpc.receive()
        if (
            auth_request.message_type is not RpcType.AUTH
            or auth_request.is_response
            or auth_request.request_id != hello_request.request_id
        ):
            raise ProtocolError("peer authentication AUTH state is invalid")
        transcript = _auth_payload(channel.channel_binding, remote_hello.encoded, local_hello)
        _verify_auth(remote_hello.public_key, auth_request.payload, transcript)
        rpc.send(
            RpcType.AUTH,
            identity.sign(transcript),
            request_id=hello_request.request_id,
            response=True,
        )
        return AuthenticatedPeer(
            channel,
            rpc,
            PeerPrincipal(
                remote_hello.role,
                node_id_from_public_key(remote_hello.public_key),
                remote_hello.public_key,
                remote_hello.descriptor,
            ),
        )
    except Exception:
        channel.destroy()
        raise


def connect_authenticated_peer(
    descriptor: NodeDescriptor,
    identity: ServiceIdentity,
    role: PeerRole,
    *,
    local_descriptor: NodeDescriptor | None = None,
    timeout: float = 10.0,
    socket_factory=socket.socket,
) -> AuthenticatedPeer:
    descriptor.verify()
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise TransportPolicyError("peer connection timeout must be positive")
    endpoint: RendezvousEndpoint = descriptor.endpoint
    connection = socket_factory(endpoint.family, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(endpoint.socket_address)
        return authenticate_client_stream(
            connection,
            descriptor,
            identity,
            role,
            local_descriptor=local_descriptor,
        )
    except Exception:
        try:
            connection.close()
        finally:
            raise


def encode_error(code: str) -> bytes:
    return BinaryWriter(128).text_u16(code, 64).build()
