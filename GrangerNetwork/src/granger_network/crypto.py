from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from .errors import ProtocolError, ReplayError


SUITE_X25519_MLKEM768 = 1
SUITE_X25519_MLKEM768_MASK = 1 << (SUITE_X25519_MLKEM768 - 1)
SUPPORTED_SUITE_MASK = SUITE_X25519_MLKEM768_MASK
MLKEM768_PUBLIC_KEY_SIZE = 1184
MLKEM768_CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32
DEFAULT_REKEY_INTERVAL = 1 << 20
DEFAULT_SESSION_MAX_AGE = 15 * 60
MAX_SESSION_MAX_AGE = 60 * 60

_KEY_SCHEDULE_DOMAIN = b"granger-network-v0.3/key-schedule\x00"
_KEY_LABEL_DOMAIN = b"granger-network-v0.3/key-label\x00"
_CHANNEL_BINDING_DOMAIN = b"granger-network-v0.3/channel-binding\x00"
_TRAFFIC_KEY_DOMAIN = b"granger-network-v0.3/traffic-key\x00"
_TRAFFIC_RATCHET_DOMAIN = b"granger-network-v0.3/traffic-ratchet\x00"
_PARAMETERS = struct.Struct("!HIII")


@dataclass(frozen=True)
class SessionParameters:
    suite: int
    max_frame_size: int
    rekey_interval: int
    max_session_age: int

    def encode(self) -> bytes:
        return _PARAMETERS.pack(
            self.suite,
            self.max_frame_size,
            self.rekey_interval,
            self.max_session_age,
        )


@dataclass(frozen=True)
class SessionSecrets:
    client_data: bytes
    server_data: bytes
    client_control: bytes
    server_control: bytes
    client_finished: bytes
    server_finished: bytes
    exporter: bytes
    transcript_hash: bytes
    channel_binding: bytes


def validate_suite_mask(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError("crypto suite mask must be an unsigned 32-bit integer")
    return value


def select_suite(offered_mask: int, allowed_mask: int = SUPPORTED_SUITE_MASK) -> int:
    offered = validate_suite_mask(offered_mask)
    allowed = validate_suite_mask(allowed_mask) & SUPPORTED_SUITE_MASK
    if offered & allowed & SUITE_X25519_MLKEM768_MASK:
        return SUITE_X25519_MLKEM768
    raise ProtocolError("no mutually supported authenticated crypto suite")


def suite_is_offered(mask: int, suite: int) -> bool:
    validate_suite_mask(mask)
    return suite == SUITE_X25519_MLKEM768 and bool(mask & SUITE_X25519_MLKEM768_MASK)


def combine_hybrid_secrets(mlkem_secret: bytes, x25519_secret: bytes) -> bytes:
    if len(mlkem_secret) != SHARED_SECRET_SIZE or len(x25519_secret) != SHARED_SECRET_SIZE:
        raise ProtocolError("hybrid key exchange produced an invalid shared secret")
    if not any(x25519_secret):
        raise ProtocolError("X25519 produced an all-zero shared secret")
    return mlkem_secret + x25519_secret


def _expand(root: bytes, label: bytes, context: bytes) -> bytes:
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=_KEY_LABEL_DOMAIN + label + b"\x00" + context,
    ).derive(root)


def derive_session_secrets(
    hybrid_secret: bytes,
    transcript: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    session_id: bytes,
    parameters: SessionParameters,
) -> SessionSecrets:
    if len(hybrid_secret) != 2 * SHARED_SECRET_SIZE:
        raise ProtocolError("hybrid key material has an invalid length")
    if len(client_nonce) != 32 or len(server_nonce) != 32 or len(session_id) != 16:
        raise ProtocolError("hybrid key schedule inputs have invalid lengths")
    if parameters.suite != SUITE_X25519_MLKEM768:
        raise ProtocolError("unsupported hybrid key schedule")

    transcript_hash = hashlib.sha256(transcript).digest()
    parameter_bytes = parameters.encode()
    salt = hashlib.sha256(
        _KEY_SCHEDULE_DOMAIN
        + session_id
        + client_nonce
        + server_nonce
        + transcript_hash
    ).digest()
    root = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_KEY_SCHEDULE_DOMAIN + parameter_bytes + transcript_hash,
    ).derive(hybrid_secret)
    context = parameter_bytes + transcript_hash
    channel_binding = hashlib.sha256(
        _CHANNEL_BINDING_DOMAIN + session_id + context
    ).digest()
    return SessionSecrets(
        client_data=_expand(root, b"client-data", context),
        server_data=_expand(root, b"server-data", context),
        client_control=_expand(root, b"client-control", context),
        server_control=_expand(root, b"server-control", context),
        client_finished=_expand(root, b"client-finished", context),
        server_finished=_expand(root, b"server-finished", context),
        exporter=_expand(root, b"exporter", context),
        transcript_hash=transcript_hash,
        channel_binding=channel_binding,
    )


class TrafficKeyRatchet:
    def __init__(
        self,
        secret: bytes,
        *,
        channel_binding: bytes,
        direction: bytes,
        purpose: bytes,
    ) -> None:
        if len(secret) != 32 or len(channel_binding) != 32 or len(direction) != 4:
            raise ProtocolError("traffic key state has invalid inputs")
        if purpose not in {b"control", b"data"}:
            raise ProtocolError("traffic key purpose is invalid")
        self._secret = bytearray(secret)
        self._context = channel_binding + direction + purpose
        self._epoch = 0
        self._aead = self._derive_key(0)
        self._destroyed = False

    @property
    def epoch(self) -> int:
        return self._epoch

    def _derive_key(self, epoch: int) -> ChaCha20Poly1305:
        key = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=_TRAFFIC_KEY_DOMAIN + self._context + epoch.to_bytes(8, "big"),
        ).derive(bytes(self._secret))
        return ChaCha20Poly1305(key)

    def for_epoch(self, epoch: int) -> ChaCha20Poly1305:
        if self._destroyed:
            raise ProtocolError("traffic key state is unavailable")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < self._epoch:
            raise ReplayError("encrypted frame uses an expired traffic key epoch")
        while self._epoch < epoch:
            next_secret = HKDFExpand(
                algorithm=hashes.SHA256(),
                length=32,
                info=(
                    _TRAFFIC_RATCHET_DOMAIN
                    + self._context
                    + self._epoch.to_bytes(8, "big")
                ),
            ).derive(bytes(self._secret))
            for index in range(len(self._secret)):
                self._secret[index] = 0
            self._secret = bytearray(next_secret)
            self._epoch += 1
            self._aead = self._derive_key(self._epoch)
        return self._aead

    def destroy(self) -> None:
        for index in range(len(self._secret)):
            self._secret[index] = 0
        self._aead = None
        self._destroyed = True
