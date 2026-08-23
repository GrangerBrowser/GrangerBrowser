from __future__ import annotations

import hashlib
import json
import secrets
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IdentityVerificationError, ProtocolError
from .identity import ServiceIdentity


MAGIC = b"GRN1"
VERSION = 1
MAX_MESSAGE_SIZE = 4 * 1024 * 1024
CLIENT_HELLO = struct.Struct("!4sB32s32s")
SERVER_HELLO_BODY = struct.Struct("!4sB32s32s")
SERVER_HELLO_SIZE = SERVER_HELLO_BODY.size + 64
FRAME_HEADER = struct.Struct("!IQ")
SERVER_AUTH_DOMAIN = b"granger-network-v0.1/server-auth\x00"
KEY_DERIVATION_DOMAIN = b"granger-network-v0.1/session-keys\x00"
FRAME_DOMAIN = b"granger-network-v0.1/frame\x00"
CLIENT_TO_SERVER = b"C2S1"
SERVER_TO_CLIENT = b"S2C1"


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


def _derive_keys(shared_secret: bytes, transcript: bytes, client_nonce: bytes) -> tuple[bytes, bytes]:
    transcript_hash = hashlib.sha256(transcript).digest()
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(client_nonce + transcript_hash).digest(),
        info=KEY_DERIVATION_DOMAIN + transcript_hash,
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

    def __post_init__(self) -> None:
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

    def send_bytes(self, plaintext: bytes) -> None:
        if len(plaintext) > MAX_MESSAGE_SIZE:
            raise ProtocolError("encrypted message exceeds the v0.1 size limit")
        with self._send_lock:
            counter = self._tx_counter
            ciphertext_size = len(plaintext) + 16
            header = FRAME_HEADER.pack(ciphertext_size, counter)
            associated_data = FRAME_DOMAIN + self.tx_direction + header
            ciphertext = self._tx.encrypt(
                self._nonce(self.tx_direction, counter),
                plaintext,
                associated_data,
            )
            self.connection.sendall(header + ciphertext)
            self._tx_counter += 1

    def receive_bytes(self) -> bytes:
        with self._receive_lock:
            header = _recv_exact(self.connection, FRAME_HEADER.size)
            ciphertext_size, counter = FRAME_HEADER.unpack(header)
            if counter != self._rx_counter:
                raise ProtocolError("encrypted frame counter is out of sequence")
            if not 16 <= ciphertext_size <= MAX_MESSAGE_SIZE + 16:
                raise ProtocolError("encrypted frame has an invalid size")
            ciphertext = _recv_exact(self.connection, ciphertext_size)
            associated_data = FRAME_DOMAIN + self.rx_direction + header
            try:
                plaintext = self._rx.decrypt(
                    self._nonce(self.rx_direction, counter),
                    ciphertext,
                    associated_data,
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
) -> SecureChannel:
    if len(expected_identity_public_key) != 32:
        raise IdentityVerificationError("expected service identity has an invalid length")
    ephemeral = X25519PrivateKey.generate()
    client_nonce = secrets.token_bytes(32)
    client_hello = CLIENT_HELLO.pack(MAGIC, VERSION, _public_bytes(ephemeral), client_nonce)
    connection.sendall(client_hello)

    server_hello = _recv_exact(connection, SERVER_HELLO_SIZE)
    server_body = server_hello[: SERVER_HELLO_BODY.size]
    signature = server_hello[SERVER_HELLO_BODY.size :]
    magic, version, server_ephemeral_bytes, identity_public_key = SERVER_HELLO_BODY.unpack(server_body)
    if magic != MAGIC or version != VERSION:
        raise ProtocolError("server selected an unsupported Granger protocol")
    if identity_public_key != expected_identity_public_key:
        raise IdentityVerificationError("connected service identity does not match the resolved address")
    try:
        Ed25519PublicKey.from_public_bytes(identity_public_key).verify(
            signature,
            SERVER_AUTH_DOMAIN + client_hello + server_body,
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
    )
    return SecureChannel(connection, client_key, server_key, CLIENT_TO_SERVER, SERVER_TO_CLIENT)


def server_handshake(connection: socket.socket, identity: ServiceIdentity) -> SecureChannel:
    client_hello = _recv_exact(connection, CLIENT_HELLO.size)
    magic, version, client_ephemeral_bytes, client_nonce = CLIENT_HELLO.unpack(client_hello)
    if magic != MAGIC or version != VERSION:
        raise ProtocolError("client selected an unsupported Granger protocol")
    ephemeral = X25519PrivateKey.generate()
    server_body = SERVER_HELLO_BODY.pack(
        MAGIC,
        VERSION,
        _public_bytes(ephemeral),
        identity.public_key_bytes,
    )
    signature = identity.sign(SERVER_AUTH_DOMAIN + client_hello + server_body)
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
    )
    return SecureChannel(connection, server_key, client_key, SERVER_TO_CLIENT, CLIENT_TO_SERVER)
