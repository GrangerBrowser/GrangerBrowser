from __future__ import annotations

import secrets
import socket
import struct
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import canonical_json, decode_base64url, encode_base64url, parse_json_object
from .address import service_id_from_name, service_id_from_public_key
from .errors import (
    AddressError,
    IdentityVerificationError,
    ProtocolError,
    ReplayError,
    RendezvousError,
)
from .identity import ServiceIdentity


CONTROL_VERSION = 1
MAX_CONTROL_SIZE = 16 * 1024
MAX_CLOCK_SKEW = 120
CONTROL_HEADER = struct.Struct("!I")
REGISTRATION_SIGNATURE_DOMAIN = b"granger-network-v0.2/rendezvous-registration\x00"


def receive_exact(connection: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ProtocolError("negative protocol read size")
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ProtocolError("connection closed before the protocol message was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def send_control(connection: socket.socket, document: dict[str, Any]) -> None:
    payload = canonical_json(document)
    if not payload or len(payload) > MAX_CONTROL_SIZE:
        raise RendezvousError("rendezvous control message exceeds the size limit")
    connection.sendall(CONTROL_HEADER.pack(len(payload)) + payload)


def receive_control(connection: socket.socket) -> dict[str, Any]:
    size = CONTROL_HEADER.unpack(receive_exact(connection, CONTROL_HEADER.size))[0]
    if not 1 <= size <= MAX_CONTROL_SIZE:
        raise ProtocolError("rendezvous control message has an invalid size")
    try:
        return parse_json_object(receive_exact(connection, size).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("rendezvous control message is invalid JSON") from error


def validate_service_id(service_id: str) -> str:
    try:
        if service_id_from_name(f"{service_id}.granger") != service_id:
            raise ValueError("non-canonical service identifier")
        return service_id
    except (AddressError, TypeError, ValueError) as error:
        raise RendezvousError("service identifier is invalid") from error


def validate_fresh_timestamp(timestamp: object, now: int | None = None) -> int:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ProtocolError("rendezvous timestamp must be an integer")
    current_time = int(time.time()) if now is None else now
    if abs(current_time - timestamp) > MAX_CLOCK_SKEW:
        raise ReplayError("rendezvous message timestamp is outside the freshness window")
    return timestamp


def create_host_registration(
    identity: ServiceIdentity,
    service_id: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    validate_service_id(service_id)
    if service_id_from_public_key(identity.public_key_bytes) != service_id:
        raise IdentityVerificationError("host identity does not own the requested service identifier")
    unsigned = {
        "identityKey": encode_base64url(identity.public_key_bytes),
        "nonce": encode_base64url(secrets.token_bytes(16)),
        "serviceId": service_id,
        "timestamp": int(time.time()) if now is None else now,
        "type": "register",
        "version": CONTROL_VERSION,
    }
    return {
        **unsigned,
        "signature": encode_base64url(
            identity.sign(REGISTRATION_SIGNATURE_DOMAIN + canonical_json(unsigned))
        ),
    }


def verify_host_registration(
    document: dict[str, Any],
    *,
    now: int | None = None,
) -> tuple[str, bytes]:
    expected = {
        "identityKey",
        "nonce",
        "serviceId",
        "signature",
        "timestamp",
        "type",
        "version",
    }
    if set(document) != expected or document.get("type") != "register":
        raise ProtocolError("invalid host registration fields")
    if document.get("version") != CONTROL_VERSION or isinstance(document.get("version"), bool):
        raise ProtocolError("unsupported rendezvous control version")
    service_id = validate_service_id(document["serviceId"])
    validate_fresh_timestamp(document["timestamp"], now)
    try:
        identity_key = decode_base64url(document["identityKey"])
        nonce = decode_base64url(document["nonce"])
        signature = decode_base64url(document["signature"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("host registration encoding is invalid") from error
    if len(identity_key) != 32 or len(nonce) != 16 or len(signature) != 64:
        raise ProtocolError("host registration key, nonce, or signature length is invalid")
    if service_id_from_public_key(identity_key) != service_id:
        raise IdentityVerificationError("host registration identity does not own the service")
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(identity_key).verify(
            signature,
            REGISTRATION_SIGNATURE_DOMAIN + canonical_json(unsigned),
        )
    except (InvalidSignature, ValueError) as error:
        raise IdentityVerificationError("host registration signature is invalid") from error
    return service_id, nonce


def create_connect_request(
    service_id: str,
    session_id: bytes,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    validate_service_id(service_id)
    if not isinstance(session_id, bytes) or len(session_id) != 16:
        raise RendezvousError("rendezvous session identifier must contain 16 bytes")
    return {
        "serviceId": service_id,
        "sessionId": encode_base64url(session_id),
        "timestamp": int(time.time()) if now is None else now,
        "type": "connect",
        "version": CONTROL_VERSION,
    }


def verify_connect_request(
    document: dict[str, Any],
    *,
    now: int | None = None,
) -> tuple[str, bytes]:
    if set(document) != {"serviceId", "sessionId", "timestamp", "type", "version"}:
        raise ProtocolError("invalid client rendezvous fields")
    if (
        document.get("type") != "connect"
        or document.get("version") != CONTROL_VERSION
        or isinstance(document.get("version"), bool)
    ):
        raise ProtocolError("unsupported client rendezvous request")
    service_id = validate_service_id(document["serviceId"])
    validate_fresh_timestamp(document["timestamp"], now)
    try:
        session_id = decode_base64url(document["sessionId"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("rendezvous session identifier is invalid") from error
    if len(session_id) != 16:
        raise ProtocolError("rendezvous session identifier must contain 16 bytes")
    return service_id, session_id


def paired_document(session_id: bytes) -> dict[str, Any]:
    if not isinstance(session_id, bytes) or len(session_id) != 16:
        raise RendezvousError("invalid paired session identifier")
    return {
        "sessionId": encode_base64url(session_id),
        "type": "paired",
        "version": CONTROL_VERSION,
    }


def parse_paired(document: dict[str, Any], expected_session_id: bytes | None = None) -> bytes:
    if set(document) != {"sessionId", "type", "version"}:
        raise ProtocolError("invalid rendezvous pairing response")
    if (
        document.get("type") != "paired"
        or document.get("version") != CONTROL_VERSION
        or isinstance(document.get("version"), bool)
    ):
        raise ProtocolError("unsupported rendezvous pairing response")
    try:
        session_id = decode_base64url(document["sessionId"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("paired session identifier is invalid") from error
    if len(session_id) != 16 or (
        expected_session_id is not None and session_id != expected_session_id
    ):
        raise ReplayError("rendezvous paired the wrong session")
    return session_id
