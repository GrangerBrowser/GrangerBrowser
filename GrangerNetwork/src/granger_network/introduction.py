from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import canonical_json, decode_base64url, encode_base64url, parse_json_object
from .address import is_canonical_name, normalize_name, service_id_from_public_key
from .descriptor import ServiceDescriptor
from .errors import AddressError, DescriptorError, ReplayError
from .identity import ServiceIdentity
from .peer import validate_node_id
from .protocol import VERSION_3


INTRODUCTION_DESCRIPTOR_VERSION = 1
ALIAS_RECORD_VERSION = 1
INTRODUCTION_SIGNATURE_DOMAIN = b"granger-network-v0.3/introduction-descriptor\x00"
ALIAS_SIGNATURE_DOMAIN = b"granger-network-v0.3/alias-record\x00"
MAX_INTRODUCTION_LIFETIME = 30 * 60
MAX_ALIAS_LIFETIME = 24 * 60 * 60
MAX_INTRODUCTION_POINTS = 8
MAX_RECORD_CLOCK_SKEW = 120
MAX_RECORD_SEQUENCE = 2**64 - 1


def service_descriptor_digest(
    descriptor: ServiceDescriptor,
    now: int | None = None,
) -> bytes:
    descriptor.verify(now=now)
    return hashlib.sha256(canonical_json(descriptor.to_document())).digest()


def _validate_record_window(
    issued_at: int,
    expires_at: int,
    maximum_lifetime: int,
    now: int | None,
    label: str,
) -> None:
    for value in (issued_at, expires_at):
        if isinstance(value, bool) or not isinstance(value, int):
            raise DescriptorError(f"{label} timestamps must be integers")
    if issued_at < 0 or expires_at <= issued_at:
        raise DescriptorError(f"{label} validity window is invalid")
    if expires_at - issued_at > maximum_lifetime:
        raise DescriptorError(f"{label} lifetime exceeds the limit")
    current_time = int(time.time()) if now is None else now
    if isinstance(current_time, bool) or not isinstance(current_time, int):
        raise DescriptorError(f"{label} verification time must be an integer")
    if issued_at > current_time + MAX_RECORD_CLOCK_SKEW:
        raise DescriptorError(f"{label} issue time is in the future")
    if expires_at <= current_time:
        raise DescriptorError(f"{label} has expired")


def _validate_sequence(sequence: int, label: str) -> None:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 0 <= sequence <= MAX_RECORD_SEQUENCE
    ):
        raise DescriptorError(f"{label} sequence is invalid")


@dataclass(frozen=True)
class IntroductionPoint:
    node_id: str
    token: bytes

    def __post_init__(self) -> None:
        validate_node_id(self.node_id)
        if not isinstance(self.token, bytes) or len(self.token) != 32:
            raise DescriptorError("introduction token must contain 32 random bytes")

    def to_document(self) -> dict[str, str]:
        return {
            "nodeId": self.node_id,
            "token": encode_base64url(self.token),
        }

    @classmethod
    def from_document(cls, document: object) -> "IntroductionPoint":
        if not isinstance(document, dict) or set(document) != {"nodeId", "token"}:
            raise DescriptorError("introduction point has an invalid schema")
        try:
            return cls(
                node_id=document["nodeId"],
                token=decode_base64url(document["token"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise DescriptorError(f"invalid introduction point: {error}") from error


@dataclass(frozen=True)
class IntroductionDescriptor:
    service_id: str
    identity_public_key: bytes
    service_descriptor_digest: bytes
    points: tuple[IntroductionPoint, ...]
    sequence: int
    issued_at: int
    expires_at: int
    signature: bytes
    version: int = INTRODUCTION_DESCRIPTOR_VERSION

    def unsigned_document(self) -> dict:
        return {
            "expiresAt": self.expires_at,
            "identityKey": encode_base64url(self.identity_public_key),
            "issuedAt": self.issued_at,
            "points": [point.to_document() for point in self.points],
            "sequence": self.sequence,
            "serviceDescriptorDigest": encode_base64url(self.service_descriptor_digest),
            "serviceId": self.service_id,
            "version": self.version,
        }

    def signature_payload(self) -> bytes:
        return INTRODUCTION_SIGNATURE_DOMAIN + canonical_json(self.unsigned_document())

    def verify(self, now: int | None = None) -> None:
        if self.version != INTRODUCTION_DESCRIPTOR_VERSION or isinstance(self.version, bool):
            raise DescriptorError("unsupported introduction descriptor version")
        if (
            not isinstance(self.identity_public_key, bytes)
            or len(self.identity_public_key) != 32
            or not isinstance(self.signature, bytes)
            or len(self.signature) != 64
            or not isinstance(self.service_descriptor_digest, bytes)
            or len(self.service_descriptor_digest) != 32
        ):
            raise DescriptorError("introduction descriptor key, digest, or signature is invalid")
        if self.service_id != service_id_from_public_key(self.identity_public_key):
            raise DescriptorError("introduction service identifier is not identity-bound")
        if (
            not isinstance(self.points, tuple)
            or not 1 <= len(self.points) <= MAX_INTRODUCTION_POINTS
            or any(not isinstance(point, IntroductionPoint) for point in self.points)
            or tuple(sorted(self.points, key=lambda point: point.node_id)) != self.points
            or len({point.node_id for point in self.points}) != len(self.points)
            or len({point.token for point in self.points}) != len(self.points)
        ):
            raise DescriptorError("introduction point set is invalid")
        _validate_sequence(self.sequence, "introduction descriptor")
        _validate_record_window(
            self.issued_at,
            self.expires_at,
            MAX_INTRODUCTION_LIFETIME,
            now,
            "introduction descriptor",
        )
        try:
            Ed25519PublicKey.from_public_bytes(self.identity_public_key).verify(
                self.signature,
                self.signature_payload(),
            )
        except (InvalidSignature, ValueError) as error:
            raise DescriptorError("introduction descriptor signature is invalid") from error

    def verify_for(self, descriptor: ServiceDescriptor, now: int | None = None) -> None:
        descriptor.verify(now=now)
        self.verify(now=now)
        if descriptor.protocol_version != VERSION_3:
            raise DescriptorError("distributed introductions require wire protocol 3")
        if (
            descriptor.service_id != self.service_id
            or descriptor.identity_public_key != self.identity_public_key
            or service_descriptor_digest(descriptor, now=now) != self.service_descriptor_digest
        ):
            raise DescriptorError("introduction descriptor does not match the service descriptor")

    def to_document(self) -> dict:
        document = self.unsigned_document()
        document["signature"] = encode_base64url(self.signature)
        return document

    def to_json(self) -> str:
        return json.dumps(self.to_document(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"

    @classmethod
    def create(
        cls,
        identity: ServiceIdentity,
        descriptor: ServiceDescriptor,
        introduction_node_ids: tuple[str, ...] | list[str],
        *,
        sequence: int,
        issued_at: int | None = None,
        lifetime: int = 10 * 60,
    ) -> "IntroductionDescriptor":
        timestamp = int(time.time()) if issued_at is None else issued_at
        if (
            isinstance(lifetime, bool)
            or not isinstance(lifetime, int)
            or not 1 <= lifetime <= MAX_INTRODUCTION_LIFETIME
        ):
            raise DescriptorError("introduction descriptor lifetime is outside the limit")
        _validate_sequence(sequence, "introduction descriptor")
        descriptor.verify(now=timestamp)
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise DescriptorError("introduction identity does not match the service descriptor")
        try:
            node_ids = tuple(sorted(set(introduction_node_ids)))
        except TypeError as error:
            raise DescriptorError("introduction node identifiers are invalid") from error
        points = tuple(
            IntroductionPoint(validate_node_id(node_id), secrets.token_bytes(32))
            for node_id in node_ids
        )
        unsigned = cls(
            service_id=descriptor.service_id,
            identity_public_key=identity.public_key_bytes,
            service_descriptor_digest=service_descriptor_digest(descriptor, now=timestamp),
            points=points,
            sequence=sequence,
            issued_at=timestamp,
            expires_at=timestamp + lifetime,
            signature=b"\x00" * 64,
        )
        result = replace(unsigned, signature=identity.sign(unsigned.signature_payload()))
        result.verify_for(descriptor, now=timestamp)
        return result

    @classmethod
    def from_json(cls, content: str, now: int | None = None) -> "IntroductionDescriptor":
        try:
            document = parse_json_object(content)
            expected = {
                "expiresAt",
                "identityKey",
                "issuedAt",
                "points",
                "sequence",
                "serviceDescriptorDigest",
                "serviceId",
                "signature",
                "version",
            }
            if set(document) != expected or not isinstance(document["points"], list):
                raise ValueError("unexpected introduction descriptor fields")
            descriptor = cls(
                service_id=document["serviceId"],
                identity_public_key=decode_base64url(document["identityKey"]),
                service_descriptor_digest=decode_base64url(
                    document["serviceDescriptorDigest"]
                ),
                points=tuple(
                    IntroductionPoint.from_document(point) for point in document["points"]
                ),
                sequence=document["sequence"],
                issued_at=document["issuedAt"],
                expires_at=document["expiresAt"],
                signature=decode_base64url(document["signature"]),
                version=document["version"],
            )
            descriptor.verify(now=now)
            return descriptor
        except DescriptorError:
            raise
        except (AddressError, KeyError, TypeError, ValueError) as error:
            raise DescriptorError(f"invalid introduction descriptor: {error}") from error


@dataclass(frozen=True)
class AliasRecord:
    alias: str
    service_id: str
    identity_public_key: bytes
    sequence: int
    issued_at: int
    expires_at: int
    signature: bytes
    version: int = ALIAS_RECORD_VERSION

    def unsigned_document(self) -> dict:
        return {
            "alias": self.alias,
            "expiresAt": self.expires_at,
            "identityKey": encode_base64url(self.identity_public_key),
            "issuedAt": self.issued_at,
            "sequence": self.sequence,
            "serviceId": self.service_id,
            "version": self.version,
        }

    def signature_payload(self) -> bytes:
        return ALIAS_SIGNATURE_DOMAIN + canonical_json(self.unsigned_document())

    def verify(self, now: int | None = None) -> None:
        if self.version != ALIAS_RECORD_VERSION or isinstance(self.version, bool):
            raise DescriptorError("unsupported alias record version")
        try:
            normalized = normalize_name(self.alias)
        except AddressError as error:
            raise DescriptorError(str(error)) from error
        if normalized != self.alias or is_canonical_name(self.alias):
            raise DescriptorError("alias record requires a normalized non-canonical alias")
        if (
            not isinstance(self.identity_public_key, bytes)
            or len(self.identity_public_key) != 32
            or not isinstance(self.signature, bytes)
            or len(self.signature) != 64
            or self.service_id != service_id_from_public_key(self.identity_public_key)
        ):
            raise DescriptorError("alias record identity binding is invalid")
        _validate_sequence(self.sequence, "alias record")
        _validate_record_window(
            self.issued_at,
            self.expires_at,
            MAX_ALIAS_LIFETIME,
            now,
            "alias record",
        )
        try:
            Ed25519PublicKey.from_public_bytes(self.identity_public_key).verify(
                self.signature,
                self.signature_payload(),
            )
        except (InvalidSignature, ValueError) as error:
            raise DescriptorError("alias record signature is invalid") from error

    def to_document(self) -> dict:
        document = self.unsigned_document()
        document["signature"] = encode_base64url(self.signature)
        return document

    def to_json(self) -> str:
        return json.dumps(self.to_document(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"

    @classmethod
    def create(
        cls,
        identity: ServiceIdentity,
        alias: str,
        *,
        sequence: int,
        issued_at: int | None = None,
        lifetime: int = 60 * 60,
    ) -> "AliasRecord":
        timestamp = int(time.time()) if issued_at is None else issued_at
        if (
            isinstance(lifetime, bool)
            or not isinstance(lifetime, int)
            or not 1 <= lifetime <= MAX_ALIAS_LIFETIME
        ):
            raise DescriptorError("alias record lifetime is outside the limit")
        _validate_sequence(sequence, "alias record")
        try:
            normalized = normalize_name(alias)
        except AddressError as error:
            raise DescriptorError(str(error)) from error
        if is_canonical_name(normalized):
            raise DescriptorError("canonical service names cannot be alias records")
        public_key = identity.public_key_bytes
        unsigned = cls(
            alias=normalized,
            service_id=service_id_from_public_key(public_key),
            identity_public_key=public_key,
            sequence=sequence,
            issued_at=timestamp,
            expires_at=timestamp + lifetime,
            signature=b"\x00" * 64,
        )
        result = replace(unsigned, signature=identity.sign(unsigned.signature_payload()))
        result.verify(now=timestamp)
        return result

    @classmethod
    def from_json(cls, content: str, now: int | None = None) -> "AliasRecord":
        try:
            document = parse_json_object(content)
            expected = {
                "alias",
                "expiresAt",
                "identityKey",
                "issuedAt",
                "sequence",
                "serviceId",
                "signature",
                "version",
            }
            if set(document) != expected:
                raise ValueError("unexpected alias record fields")
            record = cls(
                alias=document["alias"],
                service_id=document["serviceId"],
                identity_public_key=decode_base64url(document["identityKey"]),
                sequence=document["sequence"],
                issued_at=document["issuedAt"],
                expires_at=document["expiresAt"],
                signature=decode_base64url(document["signature"]),
                version=document["version"],
            )
            record.verify(now=now)
            return record
        except DescriptorError:
            raise
        except (AddressError, KeyError, TypeError, ValueError) as error:
            raise DescriptorError(f"invalid alias record: {error}") from error


class IntroductionRegistry:
    """Introduction-point state with signed-record and request replay checks."""

    def __init__(self) -> None:
        self._records: dict[str, IntroductionDescriptor] = {}
        self._used_requests: set[tuple[str, str, bytes]] = set()
        self._lock = threading.Lock()

    def install(
        self,
        record: IntroductionDescriptor,
        descriptor: ServiceDescriptor,
        now: int | None = None,
    ) -> None:
        record.verify_for(descriptor, now=now)
        with self._lock:
            previous = self._records.get(record.service_id)
            if previous is not None:
                if record.sequence < previous.sequence:
                    raise ReplayError("introduction point rejected an older descriptor")
                if record.sequence == previous.sequence and record != previous:
                    raise ReplayError("introduction point rejected descriptor equivocation")
                if record.sequence == previous.sequence:
                    return
                self._used_requests = {
                    entry
                    for entry in self._used_requests
                    if entry[0] != record.service_id
                }
            self._records[record.service_id] = record

    def authorize(
        self,
        service_id: str,
        node_id: str,
        token: bytes,
        request_nonce: bytes,
        now: int | None = None,
    ) -> None:
        validate_node_id(node_id)
        if not isinstance(token, bytes) or len(token) != 32:
            raise DescriptorError("introduction authorization token is invalid")
        if not isinstance(request_nonce, bytes) or len(request_nonce) != 16:
            raise DescriptorError("introduction request nonce is invalid")
        with self._lock:
            record = self._records.get(service_id)
            if record is None:
                raise DescriptorError("service has no installed introduction descriptor")
            record.verify(now=now)
            point = next(
                (candidate for candidate in record.points if candidate.node_id == node_id),
                None,
            )
            if point is None or not secrets.compare_digest(point.token, token):
                raise DescriptorError("introduction authorization does not match the service")
            replay_key = (service_id, node_id, request_nonce)
            if replay_key in self._used_requests:
                raise ReplayError("introduction request nonce was replayed")
            self._used_requests.add(replay_key)
