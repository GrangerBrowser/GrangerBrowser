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

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import (
    DEFAULT_REKEY_INTERVAL,
    DEFAULT_SESSION_MAX_AGE,
    MAX_SESSION_MAX_AGE,
    MLKEM768_CIPHERTEXT_SIZE,
    MLKEM768_PUBLIC_KEY_SIZE,
    SUPPORTED_SUITE_MASK,
    SessionParameters,
    TrafficKeyRatchet,
    combine_hybrid_secrets,
    derive_session_secrets,
    select_suite,
    suite_is_offered,
    validate_suite_mask,
)
from .errors import ConnectionClosedError, IdentityVerificationError, ProtocolError, ReplayError
from .identity import ServiceIdentity


MAGIC_V1 = b"GRN1"
MAGIC_V2 = b"GRN2"
MAGIC_V3 = b"GRN3"
VERSION_1 = 1
VERSION_2 = 2
VERSION_3 = 3
VERSION = VERSION_3
MAX_MESSAGE_SIZE = 4 * 1024 * 1024
MAX_HANDSHAKE_CLOCK_SKEW = 120
CLIENT_HELLO_V1 = struct.Struct("!4sB32s32s")
SERVER_HELLO_BODY_V1 = struct.Struct("!4sB32s32s")
CLIENT_HELLO_V2 = struct.Struct("!4sB16sQ32s32s")
SERVER_HELLO_BODY_V2 = struct.Struct("!4sB16s32s32s")
CLIENT_HELLO_V3 = struct.Struct(f"!4sBI16sQIII32s{MLKEM768_PUBLIC_KEY_SIZE}s32s")
SERVER_HELLO_BODY_V3 = struct.Struct(
    f"!4sBH16sIII32s{MLKEM768_CIPHERTEXT_SIZE}s32s32s"
)
FRAME_HEADER = struct.Struct("!IQ")
FRAME_HEADER_V3 = struct.Struct("!BBQIQ")
FRAME_KIND_CONTROL = 1
FRAME_KIND_DATA = 2
FRAME_FLAGS_NONE = 0
SERVER_AUTH_DOMAIN_V1 = b"granger-network-v0.1/server-auth\x00"
SERVER_AUTH_DOMAIN_V2 = b"granger-network-v0.2/server-auth\x00"
SERVER_AUTH_DOMAIN_V3 = b"granger-network-v0.3/server-auth\x00"
FINISHED_DOMAIN_V3 = b"granger-network-v0.3/finished\x00"
KEY_DERIVATION_DOMAIN_V1 = b"granger-network-v0.1/session-keys\x00"
KEY_DERIVATION_DOMAIN_V2 = b"granger-network-v0.2/session-keys\x00"
FRAME_DOMAIN_V1 = b"granger-network-v0.1/frame\x00"
FRAME_DOMAIN_V2 = b"granger-network-v0.2/frame\x00"
FRAME_DOMAIN_V3 = b"granger-network-v0.3/frame\x00"
CLIENT_TO_SERVER_V1 = b"C2S1"
SERVER_TO_CLIENT_V1 = b"S2C1"
CLIENT_TO_SERVER_V2 = b"C2S2"
SERVER_TO_CLIENT_V2 = b"S2C2"
CLIENT_TO_SERVER_V3 = b"C2S3"
SERVER_TO_CLIENT_V3 = b"S2C3"
MAX_SEQUENCE_NUMBER = 2**64 - 1


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
            if not chunks:
                raise ConnectionClosedError("peer closed the protocol channel")
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
    tx_control_key: bytes | None = None
    rx_control_key: bytes | None = None
    suite: int = 0
    channel_binding: bytes = b""
    max_message_size: int = MAX_MESSAGE_SIZE
    rekey_interval: int = DEFAULT_REKEY_INTERVAL
    max_session_age: int = DEFAULT_SESSION_MAX_AGE

    def __post_init__(self) -> None:
        if self.protocol_version not in {VERSION_1, VERSION_2, VERSION_3}:
            raise ProtocolError("unsupported secure channel version")
        if self.protocol_version == VERSION_1 and self.session_id:
            raise ProtocolError("v0.1 channels cannot carry a rendezvous session identifier")
        if self.protocol_version in {VERSION_2, VERSION_3} and len(self.session_id) != 16:
            raise ProtocolError("remote channels require a 16-byte session identifier")
        if len(self.tx_key) != 32 or len(self.rx_key) != 32:
            raise ProtocolError("secure channel traffic keys have invalid lengths")

        self._tx: ChaCha20Poly1305 | None = None
        self._rx: ChaCha20Poly1305 | None = None
        self._tx_states: dict[int, TrafficKeyRatchet] = {}
        self._rx_states: dict[int, TrafficKeyRatchet] = {}
        if self.protocol_version == VERSION_3:
            if (
                self.tx_control_key is None
                or self.rx_control_key is None
                or len(self.tx_control_key) != 32
                or len(self.rx_control_key) != 32
                or self.suite <= 0
                or len(self.channel_binding) != 32
                or not 1 <= self.max_message_size <= MAX_MESSAGE_SIZE
                or not 1 <= self.rekey_interval <= 0xFFFFFFFF
                or not 1 <= self.max_session_age <= MAX_SESSION_MAX_AGE
            ):
                raise ProtocolError("v0.3 secure channel parameters are invalid")
            self._tx_states = {
                FRAME_KIND_CONTROL: TrafficKeyRatchet(
                    self.tx_control_key,
                    channel_binding=self.channel_binding,
                    direction=self.tx_direction,
                    purpose=b"control",
                ),
                FRAME_KIND_DATA: TrafficKeyRatchet(
                    self.tx_key,
                    channel_binding=self.channel_binding,
                    direction=self.tx_direction,
                    purpose=b"data",
                ),
            }
            self._rx_states = {
                FRAME_KIND_CONTROL: TrafficKeyRatchet(
                    self.rx_control_key,
                    channel_binding=self.channel_binding,
                    direction=self.rx_direction,
                    purpose=b"control",
                ),
                FRAME_KIND_DATA: TrafficKeyRatchet(
                    self.rx_key,
                    channel_binding=self.channel_binding,
                    direction=self.rx_direction,
                    purpose=b"data",
                ),
            }
        else:
            self._tx = ChaCha20Poly1305(self.tx_key)
            self._rx = ChaCha20Poly1305(self.rx_key)
        self.tx_key = b""
        self.rx_key = b""
        self.tx_control_key = None
        self.rx_control_key = None
        self._tx_counter = 0
        self._rx_counter = 0
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()
        self._created_at = time.monotonic()
        self._failed = False

    @property
    def tx_epoch(self) -> int:
        return max((state.epoch for state in self._tx_states.values()), default=0)

    @property
    def rx_epoch(self) -> int:
        return max((state.epoch for state in self._rx_states.values()), default=0)

    def _fail(self) -> None:
        if self._failed:
            return
        self._failed = True
        for state in (*self._tx_states.values(), *self._rx_states.values()):
            state.destroy()
        self._tx = None
        self._rx = None

    def destroy(self) -> None:
        self._fail()

    def _ensure_usable(self) -> None:
        if self._failed:
            raise ProtocolError("secure channel is no longer usable")
        if (
            self.protocol_version == VERSION_3
            and time.monotonic() - self._created_at > self.max_session_age
        ):
            self._fail()
            raise ProtocolError("secure channel session has expired")

    @staticmethod
    def _nonce(direction: bytes, counter: int) -> bytes:
        if len(direction) != 4 or not 0 <= counter < 2**64:
            raise ProtocolError("invalid channel nonce state")
        return direction + counter.to_bytes(8, "big")

    def _legacy_associated_data(self, direction: bytes, header: bytes) -> bytes:
        domain = FRAME_DOMAIN_V1 if self.protocol_version == VERSION_1 else FRAME_DOMAIN_V2
        return domain + self.session_id + direction + header

    def _v3_associated_data(self, direction: bytes, header: bytes) -> bytes:
        return (
            FRAME_DOMAIN_V3
            + self.suite.to_bytes(2, "big")
            + self.session_id
            + self.channel_binding
            + direction
            + header
        )

    def _send_payload(self, plaintext: bytes, frame_kind: int) -> None:
        if not isinstance(plaintext, bytes):
            raise ProtocolError("encrypted message must be bytes")
        if len(plaintext) > self.max_message_size:
            raise ProtocolError("encrypted message exceeds the protocol size limit")
        with self._send_lock:
            self._ensure_usable()
            try:
                counter = self._tx_counter
                if counter > MAX_SEQUENCE_NUMBER:
                    raise ProtocolError("secure channel sequence number is exhausted")
                ciphertext_size = len(plaintext) + 16
                if self.protocol_version == VERSION_3:
                    if frame_kind not in {FRAME_KIND_CONTROL, FRAME_KIND_DATA}:
                        raise ProtocolError("encrypted frame kind is invalid")
                    epoch = counter // self.rekey_interval
                    header = FRAME_HEADER_V3.pack(
                        frame_kind,
                        FRAME_FLAGS_NONE,
                        epoch,
                        ciphertext_size,
                        counter,
                    )
                    aead = self._tx_states[frame_kind].for_epoch(epoch)
                    associated_data = self._v3_associated_data(self.tx_direction, header)
                else:
                    header = FRAME_HEADER.pack(ciphertext_size, counter)
                    assert self._tx is not None
                    aead = self._tx
                    associated_data = self._legacy_associated_data(self.tx_direction, header)
                ciphertext = aead.encrypt(
                    self._nonce(self.tx_direction, counter),
                    plaintext,
                    associated_data,
                )
                self.connection.sendall(header + ciphertext)
                self._tx_counter += 1
            except Exception:
                self._fail()
                raise

    def send_bytes(self, plaintext: bytes) -> None:
        self._send_payload(plaintext, FRAME_KIND_DATA)

    def _receive_payload(self, expected_kind: int) -> bytes:
        with self._receive_lock:
            try:
                self._ensure_usable()
                if self.protocol_version == VERSION_3:
                    header = _recv_exact(self.connection, FRAME_HEADER_V3.size)
                    frame_kind, flags, epoch, ciphertext_size, counter = FRAME_HEADER_V3.unpack(
                        header
                    )
                    if frame_kind not in {FRAME_KIND_CONTROL, FRAME_KIND_DATA}:
                        raise ProtocolError("encrypted frame kind is invalid")
                    if flags != FRAME_FLAGS_NONE:
                        raise ProtocolError("encrypted frame flags are invalid")
                    if counter != self._rx_counter:
                        raise ReplayError("encrypted frame counter is out of sequence")
                    expected_epoch = counter // self.rekey_interval
                    if epoch != expected_epoch:
                        raise ReplayError("encrypted frame uses an unexpected key epoch")
                    if not 16 <= ciphertext_size <= self.max_message_size + 16:
                        raise ProtocolError("encrypted frame has an invalid size")
                    ciphertext = _recv_exact(self.connection, ciphertext_size)
                    aead = self._rx_states[frame_kind].for_epoch(epoch)
                    associated_data = self._v3_associated_data(self.rx_direction, header)
                else:
                    header = _recv_exact(self.connection, FRAME_HEADER.size)
                    ciphertext_size, counter = FRAME_HEADER.unpack(header)
                    if counter != self._rx_counter:
                        raise ReplayError("encrypted frame counter is out of sequence")
                    if not 16 <= ciphertext_size <= self.max_message_size + 16:
                        raise ProtocolError("encrypted frame has an invalid size")
                    ciphertext = _recv_exact(self.connection, ciphertext_size)
                    assert self._rx is not None
                    aead = self._rx
                    associated_data = self._legacy_associated_data(self.rx_direction, header)
                    frame_kind = expected_kind
                plaintext = aead.decrypt(
                    self._nonce(self.rx_direction, counter),
                    ciphertext,
                    associated_data,
                )
                if frame_kind != expected_kind:
                    raise ProtocolError("encrypted frame has an unexpected channel kind")
                self._rx_counter += 1
                return plaintext
            except InvalidTag as error:
                self._fail()
                raise ProtocolError("encrypted frame authentication failed") from error
            except Exception:
                self._fail()
                raise

    def receive_bytes(self) -> bytes:
        return self._receive_payload(FRAME_KIND_DATA)

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
        self._send_payload(payload, FRAME_KIND_CONTROL)

    def receive_json(self) -> dict[str, Any]:
        try:
            return _decode_json_object(self._receive_payload(FRAME_KIND_CONTROL))
        except ProtocolError:
            self._fail()
            raise


def _validate_v3_parameters(
    max_frame_size: int,
    rekey_interval: int,
    max_session_age: int,
) -> None:
    if (
        isinstance(max_frame_size, bool)
        or not isinstance(max_frame_size, int)
        or not 1 <= max_frame_size <= MAX_MESSAGE_SIZE
    ):
        raise ProtocolError("maximum encrypted frame size is invalid")
    if (
        isinstance(rekey_interval, bool)
        or not isinstance(rekey_interval, int)
        or not 1 <= rekey_interval <= 0xFFFFFFFF
    ):
        raise ProtocolError("traffic-key rekey interval is invalid")
    if (
        isinstance(max_session_age, bool)
        or not isinstance(max_session_age, int)
        or not 1 <= max_session_age <= MAX_SESSION_MAX_AGE
    ):
        raise ProtocolError("secure session lifetime is invalid")


def _finished_value(key: bytes, role: bytes, transcript_hash: bytes, prior: bytes = b"") -> bytes:
    authenticator = hmac.HMAC(key, hashes.SHA256())
    authenticator.update(FINISHED_DOMAIN_V3 + role + transcript_hash + prior)
    return authenticator.finalize()


def _verify_finished(
    key: bytes,
    role: bytes,
    transcript_hash: bytes,
    value: bytes,
    prior: bytes = b"",
) -> None:
    authenticator = hmac.HMAC(key, hashes.SHA256())
    authenticator.update(FINISHED_DOMAIN_V3 + role + transcript_hash + prior)
    try:
        authenticator.verify(value)
    except InvalidSignature as error:
        raise ProtocolError("hybrid handshake key confirmation failed") from error


def _client_handshake_v3(
    connection: socket.socket,
    expected_identity_public_key: bytes,
    *,
    session_id: bytes | None,
    now: int | None,
    supported_suites: int,
    max_frame_size: int,
    rekey_interval: int,
    max_session_age: int,
) -> SecureChannel:
    if not isinstance(session_id, bytes) or len(session_id) != 16:
        raise ProtocolError("v0.3 handshake requires a 16-byte session identifier")
    suite_mask = validate_suite_mask(supported_suites)
    if not suite_mask & SUPPORTED_SUITE_MASK:
        raise ProtocolError("client has no supported v0.3 crypto suite")
    _validate_v3_parameters(max_frame_size, rekey_interval, max_session_age)
    timestamp = int(time.time()) if now is None else now
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ProtocolError("handshake timestamp must be a positive integer")

    x25519_ephemeral = X25519PrivateKey.generate()
    try:
        mlkem_ephemeral = MLKEM768PrivateKey.generate()
        mlkem_public = mlkem_ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    except UnsupportedAlgorithm as error:
        raise ProtocolError("ML-KEM-768 is unavailable in the cryptographic backend") from error
    client_nonce = secrets.token_bytes(32)
    client_hello = CLIENT_HELLO_V3.pack(
        MAGIC_V3,
        VERSION_3,
        suite_mask,
        session_id,
        timestamp,
        max_frame_size,
        rekey_interval,
        max_session_age,
        _public_bytes(x25519_ephemeral),
        mlkem_public,
        client_nonce,
    )
    connection.sendall(client_hello)

    server_hello = _recv_exact(connection, SERVER_HELLO_BODY_V3.size + 64)
    server_body = server_hello[: SERVER_HELLO_BODY_V3.size]
    signature = server_hello[SERVER_HELLO_BODY_V3.size :]
    (
        magic,
        version,
        selected_suite,
        returned_session,
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
        server_x25519_public,
        mlkem_ciphertext,
        identity_public_key,
        server_nonce,
    ) = SERVER_HELLO_BODY_V3.unpack(server_body)
    if magic != MAGIC_V3 or version != VERSION_3:
        raise ProtocolError("server selected an unsupported Granger protocol")
    if returned_session != session_id:
        raise ReplayError("server handshake is bound to a different rendezvous session")
    if not suite_is_offered(suite_mask, selected_suite):
        raise ProtocolError("server selected an unoffered crypto suite")
    _validate_v3_parameters(
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
    )
    if (
        selected_max_frame_size > max_frame_size
        or selected_rekey_interval > rekey_interval
        or selected_session_age > max_session_age
    ):
        raise ProtocolError("server exceeded the authenticated session parameter offer")
    if identity_public_key != expected_identity_public_key:
        raise IdentityVerificationError(
            "connected service identity does not match the resolved address"
        )
    try:
        Ed25519PublicKey.from_public_bytes(identity_public_key).verify(
            signature,
            SERVER_AUTH_DOMAIN_V3 + client_hello + server_body,
        )
    except (InvalidSignature, ValueError) as error:
        raise IdentityVerificationError("service handshake signature is invalid") from error

    try:
        x25519_secret = x25519_ephemeral.exchange(
            X25519PublicKey.from_public_bytes(server_x25519_public)
        )
        mlkem_secret = mlkem_ephemeral.decapsulate(mlkem_ciphertext)
    except (UnsupportedAlgorithm, ValueError) as error:
        raise ProtocolError("server supplied invalid hybrid key exchange material") from error
    parameters = SessionParameters(
        selected_suite,
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
    )
    session_secrets = derive_session_secrets(
        combine_hybrid_secrets(mlkem_secret, x25519_secret),
        client_hello + server_hello,
        client_nonce,
        server_nonce,
        session_id,
        parameters,
    )
    client_finished = _finished_value(
        session_secrets.client_finished,
        b"client",
        session_secrets.transcript_hash,
    )
    connection.sendall(client_finished)
    server_finished = _recv_exact(connection, 32)
    _verify_finished(
        session_secrets.server_finished,
        b"server",
        session_secrets.transcript_hash,
        server_finished,
        client_finished,
    )
    return SecureChannel(
        connection,
        session_secrets.client_data,
        session_secrets.server_data,
        CLIENT_TO_SERVER_V3,
        SERVER_TO_CLIENT_V3,
        VERSION_3,
        session_id,
        session_secrets.client_control,
        session_secrets.server_control,
        selected_suite,
        session_secrets.channel_binding,
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
    )


def _server_handshake_v3(
    connection: socket.socket,
    identity: ServiceIdentity,
    *,
    expected_session_id: bytes | None,
    now: int | None,
    max_clock_skew: int,
    supported_suites: int,
    max_frame_size: int,
    rekey_interval: int,
    max_session_age: int,
) -> SecureChannel:
    allowed_suites = validate_suite_mask(supported_suites)
    _validate_v3_parameters(max_frame_size, rekey_interval, max_session_age)
    client_hello = _recv_exact(connection, CLIENT_HELLO_V3.size)
    (
        magic,
        version,
        offered_suites,
        session_id,
        timestamp,
        offered_max_frame_size,
        offered_rekey_interval,
        offered_session_age,
        client_x25519_public,
        client_mlkem_public,
        client_nonce,
    ) = CLIENT_HELLO_V3.unpack(client_hello)
    if magic != MAGIC_V3 or version != VERSION_3:
        raise ProtocolError("client selected an unsupported Granger protocol")
    if len(session_id) != 16 or (
        expected_session_id is not None and session_id != expected_session_id
    ):
        raise ReplayError("client handshake is bound to the wrong rendezvous session")
    current_time = int(time.time()) if now is None else now
    if abs(current_time - timestamp) > max_clock_skew:
        raise ReplayError("client handshake timestamp is outside the freshness window")
    _validate_v3_parameters(
        offered_max_frame_size,
        offered_rekey_interval,
        offered_session_age,
    )
    selected_suite = select_suite(offered_suites, allowed_suites)
    selected_max_frame_size = min(offered_max_frame_size, max_frame_size)
    selected_rekey_interval = min(offered_rekey_interval, rekey_interval)
    selected_session_age = min(offered_session_age, max_session_age)

    x25519_ephemeral = X25519PrivateKey.generate()
    server_nonce = secrets.token_bytes(32)
    try:
        mlkem_public = MLKEM768PublicKey.from_public_bytes(client_mlkem_public)
        mlkem_secret, mlkem_ciphertext = mlkem_public.encapsulate()
        x25519_secret = x25519_ephemeral.exchange(
            X25519PublicKey.from_public_bytes(client_x25519_public)
        )
    except (UnsupportedAlgorithm, ValueError) as error:
        raise ProtocolError("client supplied invalid hybrid key exchange material") from error
    server_body = SERVER_HELLO_BODY_V3.pack(
        MAGIC_V3,
        VERSION_3,
        selected_suite,
        session_id,
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
        _public_bytes(x25519_ephemeral),
        mlkem_ciphertext,
        identity.public_key_bytes,
        server_nonce,
    )
    signature = identity.sign(SERVER_AUTH_DOMAIN_V3 + client_hello + server_body)
    server_hello = server_body + signature
    connection.sendall(server_hello)
    parameters = SessionParameters(
        selected_suite,
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
    )
    session_secrets = derive_session_secrets(
        combine_hybrid_secrets(mlkem_secret, x25519_secret),
        client_hello + server_hello,
        client_nonce,
        server_nonce,
        session_id,
        parameters,
    )
    client_finished = _recv_exact(connection, 32)
    _verify_finished(
        session_secrets.client_finished,
        b"client",
        session_secrets.transcript_hash,
        client_finished,
    )
    connection.sendall(
        _finished_value(
            session_secrets.server_finished,
            b"server",
            session_secrets.transcript_hash,
            client_finished,
        )
    )
    return SecureChannel(
        connection,
        session_secrets.server_data,
        session_secrets.client_data,
        SERVER_TO_CLIENT_V3,
        CLIENT_TO_SERVER_V3,
        VERSION_3,
        session_id,
        session_secrets.server_control,
        session_secrets.client_control,
        selected_suite,
        session_secrets.channel_binding,
        selected_max_frame_size,
        selected_rekey_interval,
        selected_session_age,
    )


def client_handshake(
    connection: socket.socket,
    expected_identity_public_key: bytes,
    *,
    session_id: bytes | None = None,
    protocol_version: int = VERSION_1,
    now: int | None = None,
    supported_suites: int = SUPPORTED_SUITE_MASK,
    max_frame_size: int = MAX_MESSAGE_SIZE,
    rekey_interval: int = DEFAULT_REKEY_INTERVAL,
    max_session_age: int = DEFAULT_SESSION_MAX_AGE,
) -> SecureChannel:
    if len(expected_identity_public_key) != 32:
        raise IdentityVerificationError("expected service identity has an invalid length")
    if protocol_version == VERSION_3:
        return _client_handshake_v3(
            connection,
            expected_identity_public_key,
            session_id=session_id,
            now=now,
            supported_suites=supported_suites,
            max_frame_size=max_frame_size,
            rekey_interval=rekey_interval,
            max_session_age=max_session_age,
        )
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
    supported_suites: int = SUPPORTED_SUITE_MASK,
    max_frame_size: int = MAX_MESSAGE_SIZE,
    rekey_interval: int = DEFAULT_REKEY_INTERVAL,
    max_session_age: int = DEFAULT_SESSION_MAX_AGE,
) -> SecureChannel:
    if protocol_version == VERSION_3:
        return _server_handshake_v3(
            connection,
            identity,
            expected_session_id=expected_session_id,
            now=now,
            max_clock_skew=max_clock_skew,
            supported_suites=supported_suites,
            max_frame_size=max_frame_size,
            rekey_interval=rekey_interval,
            max_session_age=max_session_age,
        )
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
