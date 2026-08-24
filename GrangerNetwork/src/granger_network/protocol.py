from __future__ import annotations

import hashlib
import json
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IdentityVerificationError, ProtocolError, ReplayError
from .identity import ServiceIdentity


MAGIC_V1 = b"GRN1"
MAGIC_V2 = b"GRN2"
VERSION_1 = 1
VERSION_2 = 2
VERSION = VERSION_1
MAX_MESSAGE_SIZE = 4 * 1024 * 1024
MAX_HANDSHAKE_CLOCK_SKEW = 120
CLIENT_HELLO_V1 = struct.Struct("!4sB32s32s")
SERVER_HELLO_BODY_V1 = struct.Struct("!4sB32s32s")
CLIENT_HELLO_V2 = struct.Struct("!4sB16sQ32s32s")
SERVER_HELLO_BODY_V2 = struct.Struct("!4sB16s32s32s")
FRAME_HEADER = struct.Struct("!IQ")
SERVER_AUTH_DOMAIN_V1 = b"granger-network-v0.1/server-auth\x00"
SERVER_AUTH_DOMAIN_V2 = b"granger-network-v0.2/server-auth\x00"
KEY_DERIVATION_DOMAIN_V1 = b"granger-network-v0.1/session-keys\x00"
KEY_DERIVATION_DOMAIN_V2 = b"granger-network-v0.2/session-keys\x00"
FRAME_DOMAIN_V1 = b"granger-network-v0.1/frame\x00"
FRAME_DOMAIN_V2 = b"granger-network-v0.2/frame\x00"
CLIENT_TO_SERVER_V1 = b"C2S1"
SERVER_TO_CLIENT_V1 = b"S2C1"
CLIENT_TO_SERVER_V2 = b"C2S2"
SERVER_TO_CLIENT_V2 = b"S2C2"


def _public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ProtocolError("connection closed before the protocol frame was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def _derive_keys(
    shared_secret: bytes,
    transcript: bytes,
    client_nonce: bytes,
    protocol_version: int,
    session_id: bytes,
) -> tuple[bytes, bytes]:
    transcript_hash = hashlib.sha256(transcript).digest()
    domain = (
        KEY_DERIVATION_DOMAIN_V1
        if protocol_version == VERSION_1
        else KEY_DERIVATION_DOMAIN_V2
    )
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(session_id + client_nonce + transcript_hash).digest(),
        info=domain + session_id + transcript_hash,
    ).derive(shared_secret)
    return material[:32], material[32:]


def _decode_json_object(payload: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError(f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("encrypted message is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ProtocolError("encrypted protocol message must be a JSON object")
    return value


@dataclass
class SecureChannel:
    connection: socket.socket
    tx_key: bytes
    rx_key: bytes
    tx_direction: bytes
    rx_direction: bytes
    protocol_version: int = VERSION_1
    session_id: bytes = b""

    def __post_init__(self) -> None:
        if self.protocol_version not in {VERSION_1, VERSION_2}:
            raise ProtocolError("unsupported secure channel version")
        if self.protocol_version == VERSION_1 and self.session_id:
            raise ProtocolError("v0.1 channels cannot carry a rendezvous session identifier")
        if self.protocol_version == VERSION_2 and len(self.session_id) != 16:
            raise ProtocolError("v0.2 channels require a 16-byte session identifier")
        self._tx = ChaCha20Poly1305(self.tx_key)
        self._rx = ChaCha20Poly1305(self.rx_key)
        self._tx_counter = 0
        self._rx_counter = 0
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()

    @staticmethod
    def _nonce(direction: bytes, counter: int) -> bytes:
        if len(direction) != 4 or not 0 <= counter < 2**64:
            raise ProtocolError("invalid channel nonce state")
        return direction + counter.to_bytes(8, "big")

    def _associated_data(self, direction: bytes, header: bytes) -> bytes:
        domain = FRAME_DOMAIN_V1 if self.protocol_version == VERSION_1 else FRAME_DOMAIN_V2
        return domain + self.session_id + direction + header

    def send_bytes(self, plaintext: bytes) -> None:
        if not isinstance(plaintext, bytes):
            raise ProtocolError("encrypted message must be bytes")
        if len(plaintext) > MAX_MESSAGE_SIZE:
            raise ProtocolError("encrypted message exceeds the protocol size limit")
        with self._send_lock:
            counter = self._tx_counter
            ciphertext_size = len(plaintext) + 16
            header = FRAME_HEADER.pack(ciphertext_size, counter)
            ciphertext = self._tx.encrypt(
                self._nonce(self.tx_direction, counter),
                plaintext,
                self._associated_data(self.tx_direction, header),
            )
            self.connection.sendall(header + ciphertext)
            self._tx_counter += 1

    def receive_bytes(self) -> bytes:
        with self._receive_lock:
            header = _recv_exact(self.connection, FRAME_HEADER.size)
            ciphertext_size, counter = FRAME_HEADER.unpack(header)
            if counter != self._rx_counter:
                raise ReplayError("encrypted frame counter is out of sequence")
            if not 16 <= ciphertext_size <= MAX_MESSAGE_SIZE + 16:
                raise ProtocolError("encrypted frame has an invalid size")
            ciphertext = _recv_exact(self.connection, ciphertext_size)
            try:
                plaintext = self._rx.decrypt(
                    self._nonce(self.rx_direction, counter),
                    ciphertext,
                    self._associated_data(self.rx_direction, header),
                )
            except InvalidTag as error:
                raise ProtocolError("encrypted frame authentication failed") from error
            self._rx_counter += 1
            return plaintext

    def send_json(self, value: dict[str, Any]) -> None:
        try:
            payload = json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        except (TypeError, ValueError) as error:
            raise ProtocolError("message cannot be represented as protocol JSON") from error
        self.send_bytes(payload)

    def receive_json(self) -> dict[str, Any]:
        return _decode_json_object(self.receive_bytes())


def client_handshake(
    connection: socket.socket,
    expected_identity_public_key: bytes,
    *,
    session_id: bytes | None = None,
    protocol_version: int = VERSION_1,
    now: int | None = None,
) -> SecureChannel:
    if len(expected_identity_public_key) != 32:
        raise IdentityVerificationError("expected service identity has an invalid length")
    ephemeral = X25519PrivateKey.generate()
    client_nonce = secrets.token_bytes(32)

    if protocol_version == VERSION_1:
        if session_id not in {None, b""}:
            raise ProtocolError("v0.1 handshake does not accept a rendezvous session")
        bound_session = b""
        client_hello = CLIENT_HELLO_V1.pack(
            MAGIC_V1,
            VERSION_1,
            _public_bytes(ephemeral),
            client_nonce,
        )
        server_body_struct = SERVER_HELLO_BODY_V1
        server_auth_domain = SERVER_AUTH_DOMAIN_V1
        tx_direction = CLIENT_TO_SERVER_V1
        rx_direction = SERVER_TO_CLIENT_V1
    elif protocol_version == VERSION_2:
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            raise ProtocolError("v0.2 handshake requires a 16-byte session identifier")
        timestamp = int(time.time()) if now is None else now
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise ProtocolError("handshake timestamp must be a positive integer")
        bound_session = session_id
        client_hello = CLIENT_HELLO_V2.pack(
            MAGIC_V2,
            VERSION_2,
            bound_session,
            timestamp,
            _public_bytes(ephemeral),
            client_nonce,
        )
        server_body_struct = SERVER_HELLO_BODY_V2
        server_auth_domain = SERVER_AUTH_DOMAIN_V2
        tx_direction = CLIENT_TO_SERVER_V2
        rx_direction = SERVER_TO_CLIENT_V2
    else:
        raise ProtocolError("unsupported Granger protocol version")

    connection.sendall(client_hello)
    server_hello = _recv_exact(connection, server_body_struct.size + 64)
    server_body = server_hello[: server_body_struct.size]
    signature = server_hello[server_body_struct.size :]
    if protocol_version == VERSION_1:
        magic, version, server_ephemeral_bytes, identity_public_key = server_body_struct.unpack(
            server_body
        )
        returned_session = b""
    else:
        (
            magic,
            version,
            returned_session,
            server_ephemeral_bytes,
            identity_public_key,
        ) = server_body_struct.unpack(server_body)
    expected_magic = MAGIC_V1 if protocol_version == VERSION_1 else MAGIC_V2
    if magic != expected_magic or version != protocol_version:
        raise ProtocolError("server selected an unsupported Granger protocol")
    if returned_session != bound_session:
        raise ReplayError("server handshake is bound to a different rendezvous session")
    if identity_public_key != expected_identity_public_key:
        raise IdentityVerificationError("connected service identity does not match the resolved address")
    try:
        Ed25519PublicKey.from_public_bytes(identity_public_key).verify(
            signature,
            server_auth_domain + client_hello + server_body,
        )
    except (InvalidSignature, ValueError) as error:
        raise IdentityVerificationError("service handshake signature is invalid") from error
    try:
        shared_secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(server_ephemeral_bytes))
    except ValueError as error:
        raise ProtocolError("server supplied an invalid X25519 key") from error
    client_key, server_key = _derive_keys(
        shared_secret,
        client_hello + server_hello,
        client_nonce,
        protocol_version,
        bound_session,
    )
    return SecureChannel(
        connection,
        client_key,
        server_key,
        tx_direction,
        rx_direction,
        protocol_version,
        bound_session,
    )


def server_handshake(
    connection: socket.socket,
    identity: ServiceIdentity,
    *,
    expected_session_id: bytes | None = None,
    protocol_version: int = VERSION_1,
    now: int | None = None,
    max_clock_skew: int = MAX_HANDSHAKE_CLOCK_SKEW,
) -> SecureChannel:
    if protocol_version == VERSION_1:
        if expected_session_id not in {None, b""}:
            raise ProtocolError("v0.1 handshake cannot be bound to a rendezvous session")
        client_hello = _recv_exact(connection, CLIENT_HELLO_V1.size)
        magic, version, client_ephemeral_bytes, client_nonce = CLIENT_HELLO_V1.unpack(client_hello)
        if magic != MAGIC_V1 or version != VERSION_1:
            raise ProtocolError("client selected an unsupported Granger protocol")
        bound_session = b""
        server_body_struct = SERVER_HELLO_BODY_V1
        server_auth_domain = SERVER_AUTH_DOMAIN_V1
        tx_direction = SERVER_TO_CLIENT_V1
        rx_direction = CLIENT_TO_SERVER_V1
    elif protocol_version == VERSION_2:
        client_hello = _recv_exact(connection, CLIENT_HELLO_V2.size)
        (
            magic,
            version,
            bound_session,
            timestamp,
            client_ephemeral_bytes,
            client_nonce,
        ) = CLIENT_HELLO_V2.unpack(client_hello)
        if magic != MAGIC_V2 or version != VERSION_2:
            raise ProtocolError("client selected an unsupported Granger protocol")
        if len(bound_session) != 16 or (
            expected_session_id is not None and bound_session != expected_session_id
        ):
            raise ReplayError("client handshake is bound to the wrong rendezvous session")
        current_time = int(time.time()) if now is None else now
        if abs(current_time - timestamp) > max_clock_skew:
            raise ReplayError("client handshake timestamp is outside the freshness window")
        server_body_struct = SERVER_HELLO_BODY_V2
        server_auth_domain = SERVER_AUTH_DOMAIN_V2
        tx_direction = SERVER_TO_CLIENT_V2
        rx_direction = CLIENT_TO_SERVER_V2
    else:
        raise ProtocolError("unsupported Granger protocol version")

    ephemeral = X25519PrivateKey.generate()
    if protocol_version == VERSION_1:
        server_body = server_body_struct.pack(
            MAGIC_V1,
            VERSION_1,
            _public_bytes(ephemeral),
            identity.public_key_bytes,
        )
    else:
        server_body = server_body_struct.pack(
            MAGIC_V2,
            VERSION_2,
            bound_session,
            _public_bytes(ephemeral),
            identity.public_key_bytes,
        )
    signature = identity.sign(server_auth_domain + client_hello + server_body)
    server_hello = server_body + signature
    connection.sendall(server_hello)
    try:
        shared_secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(client_ephemeral_bytes))
    except ValueError as error:
        raise ProtocolError("client supplied an invalid X25519 key") from error
    client_key, server_key = _derive_keys(
        shared_secret,
        client_hello + server_hello,
        client_nonce,
        protocol_version,
        bound_session,
    )
    return SecureChannel(
        connection,
        server_key,
        client_key,
        tx_direction,
        rx_direction,
        protocol_version,
        bound_session,
    )
