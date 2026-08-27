from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .binary import BinaryReader, BinaryWriter
from .descriptor import ServiceDescriptor
from .errors import DescriptorError, IdentityVerificationError, ProtocolError, ReplayError
from .identity import ServiceIdentity
from .introduction import IntroductionDescriptor
from .peer import NodeDescriptor
from .rendezvous_control import validate_service_id


MAX_CONTROL_DOCUMENT = 64 * 1024
MAX_RENDEZVOUS_GRANT_LIFETIME = 5 * 60
RENDEZVOUS_GRANT_DOMAIN = b"granger-network-v0.4/rendezvous-grant\x00"
RENDEZVOUS_COOKIE_TAG_DOMAIN = b"granger-network-v0.4/rendezvous-cookie-tag\x00"


def rendezvous_cookie_tag(cookie: bytes) -> bytes:
    if not isinstance(cookie, bytes) or len(cookie) != 32:
        raise ProtocolError("rendezvous cookie must contain 32 bytes")
    import hashlib

    return hashlib.sha256(RENDEZVOUS_COOKIE_TAG_DOMAIN + cookie).digest()


def encode_intro_registration(
    service: ServiceDescriptor,
    introduction: IntroductionDescriptor,
) -> bytes:
    service.verify()
    introduction.verify_for(service)
    return (
        BinaryWriter(2 * MAX_CONTROL_DOCUMENT + 16)
        .bytes_u32(service.to_json().encode("ascii"), MAX_CONTROL_DOCUMENT)
        .bytes_u32(introduction.to_json().encode("ascii"), MAX_CONTROL_DOCUMENT)
        .build()
    )


def decode_intro_registration(
    content: bytes,
    *,
    now: int | None = None,
) -> tuple[ServiceDescriptor, IntroductionDescriptor]:
    reader = BinaryReader(content, 2 * MAX_CONTROL_DOCUMENT + 16)
    try:
        service = ServiceDescriptor.from_json(
            reader.bytes_u32(MAX_CONTROL_DOCUMENT).decode("ascii"),
            now=now,
        )
        introduction = IntroductionDescriptor.from_json(
            reader.bytes_u32(MAX_CONTROL_DOCUMENT).decode("ascii"),
            now=now,
        )
    except UnicodeDecodeError as error:
        raise ProtocolError("introduction registration is not ASCII") from error
    reader.finish()
    introduction.verify_for(service, now=now)
    return service, introduction


@dataclass(frozen=True)
class IntroductionRequest:
    service_id: str
    token: bytes
    nonce: bytes


def encode_intro_request(request: IntroductionRequest) -> bytes:
    if not isinstance(request, IntroductionRequest):
        raise ProtocolError("introduction request is invalid")
    return (
        BinaryWriter(256)
        .text_u16(validate_service_id(request.service_id), 64)
        .fixed(request.token, 32)
        .fixed(request.nonce, 16)
        .build()
    )


def decode_intro_request(content: bytes) -> IntroductionRequest:
    reader = BinaryReader(content, 256)
    result = IntroductionRequest(
        validate_service_id(reader.text_u16(64)),
        reader.fixed(32),
        reader.fixed(16),
    )
    reader.finish()
    return result


@dataclass(frozen=True)
class RendezvousGrant:
    service_id: str
    request_nonce: bytes
    rendezvous: NodeDescriptor
    cookie: bytes
    expires_at: int
    signature: bytes

    def unsigned_bytes(self) -> bytes:
        self.rendezvous.verify()
        return (
            BinaryWriter(MAX_CONTROL_DOCUMENT + 256)
            .text_u16(validate_service_id(self.service_id), 64)
            .fixed(self.request_nonce, 16)
            .bytes_u32(self.rendezvous.to_json().encode("ascii"), MAX_CONTROL_DOCUMENT)
            .fixed(self.cookie, 32)
            .u64(self.expires_at)
            .build()
        )

    def verify(
        self,
        service: ServiceDescriptor,
        *,
        request_nonce: bytes | None = None,
        now: int | None = None,
    ) -> None:
        service.verify(now=now)
        if self.service_id != service.service_id:
            raise IdentityVerificationError("rendezvous grant service identity is invalid")
        if request_nonce is not None and self.request_nonce != request_nonce:
            raise ReplayError("rendezvous grant is bound to another introduction request")
        if len(self.request_nonce) != 16 or len(self.cookie) != 32 or len(self.signature) != 64:
            raise ProtocolError("rendezvous grant field length is invalid")
        if "rendezvous" not in self.rendezvous.capabilities or self.rendezvous.reachability != "reachable":
            raise ProtocolError("rendezvous grant points to an ineligible node")
        current = int(time.time()) if now is None else now
        if (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, int)
            or self.expires_at <= current
            or self.expires_at > current + MAX_RENDEZVOUS_GRANT_LIFETIME
        ):
            raise ReplayError("rendezvous grant validity window is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(service.identity_public_key).verify(
                self.signature,
                RENDEZVOUS_GRANT_DOMAIN + self.unsigned_bytes(),
            )
        except (InvalidSignature, ValueError) as error:
            raise IdentityVerificationError("rendezvous grant signature is invalid") from error

    def encode(self) -> bytes:
        return BinaryWriter(MAX_CONTROL_DOCUMENT + 384).bytes_u32(
            self.unsigned_bytes(),
            MAX_CONTROL_DOCUMENT + 256,
        ).fixed(self.signature, 64).build()

    @classmethod
    def create(
        cls,
        identity: ServiceIdentity,
        service: ServiceDescriptor,
        request_nonce: bytes,
        rendezvous: NodeDescriptor,
        *,
        cookie: bytes | None = None,
        now: int | None = None,
        lifetime: int = 120,
    ) -> "RendezvousGrant":
        timestamp = int(time.time()) if now is None else now
        if not 1 <= lifetime <= MAX_RENDEZVOUS_GRANT_LIFETIME:
            raise ProtocolError("rendezvous grant lifetime is invalid")
        unsigned = cls(
            service.service_id,
            request_nonce,
            rendezvous,
            secrets.token_bytes(32) if cookie is None else cookie,
            timestamp + lifetime,
            b"\x00" * 64,
        )
        result = replace(
            unsigned,
            signature=identity.sign(RENDEZVOUS_GRANT_DOMAIN + unsigned.unsigned_bytes()),
        )
        result.verify(service, request_nonce=request_nonce, now=timestamp)
        return result

    @classmethod
    def decode(
        cls,
        content: bytes,
        service: ServiceDescriptor,
        *,
        request_nonce: bytes | None = None,
        now: int | None = None,
    ) -> "RendezvousGrant":
        reader = BinaryReader(content, MAX_CONTROL_DOCUMENT + 384)
        unsigned = BinaryReader(
            reader.bytes_u32(MAX_CONTROL_DOCUMENT + 256),
            MAX_CONTROL_DOCUMENT + 256,
        )
        service_id = validate_service_id(unsigned.text_u16(64))
        nonce = unsigned.fixed(16)
        try:
            rendezvous = NodeDescriptor.from_json(
                unsigned.bytes_u32(MAX_CONTROL_DOCUMENT).decode("ascii"),
                now=now,
            )
        except UnicodeDecodeError as error:
            raise ProtocolError("rendezvous descriptor is not ASCII") from error
        cookie = unsigned.fixed(32)
        expires_at = unsigned.u64()
        unsigned.finish()
        signature = reader.fixed(64)
        reader.finish()
        result = cls(service_id, nonce, rendezvous, cookie, expires_at, signature)
        result.verify(service, request_nonce=request_nonce, now=now)
        return result


@dataclass(frozen=True)
class RendezvousRegistration:
    cookie_tag: bytes
    nonce: bytes
    expires_at: int
    cell_circuit_id: bytes

    def verify(self, now: int | None = None) -> None:
        if (
            len(self.cookie_tag) != 32
            or len(self.nonce) != 16
            or len(self.cell_circuit_id) != 16
        ):
            raise ProtocolError("rendezvous registration field length is invalid")
        current = int(time.time()) if now is None else now
        if self.expires_at <= current or self.expires_at > current + MAX_RENDEZVOUS_GRANT_LIFETIME:
            raise ReplayError("rendezvous registration is expired or too long")

    def encode(self) -> bytes:
        self.verify()
        return (
            BinaryWriter(96)
            .fixed(self.cookie_tag, 32)
            .fixed(self.nonce, 16)
            .u64(self.expires_at)
            .fixed(self.cell_circuit_id, 16)
            .build()
        )

    @classmethod
    def create(
        cls,
        cookie: bytes,
        expires_at: int,
        cell_circuit_id: bytes,
        nonce: bytes | None = None,
    ) -> "RendezvousRegistration":
        result = cls(
            rendezvous_cookie_tag(cookie),
            secrets.token_bytes(16) if nonce is None else nonce,
            expires_at,
            cell_circuit_id,
        )
        result.verify()
        return result

    @classmethod
    def decode(cls, content: bytes, now: int | None = None) -> "RendezvousRegistration":
        reader = BinaryReader(content, 96)
        result = cls(
            reader.fixed(32),
            reader.fixed(16),
            reader.u64(),
            reader.fixed(16),
        )
        reader.finish()
        result.verify(now=now)
        return result


@dataclass(frozen=True)
class RendezvousJoin:
    cookie_tag: bytes
    nonce: bytes
    cell_circuit_id: bytes

    def encode(self) -> bytes:
        return (
            BinaryWriter(80)
            .fixed(self.cookie_tag, 32)
            .fixed(self.nonce, 16)
            .fixed(self.cell_circuit_id, 16)
            .build()
        )

    @classmethod
    def create(
        cls,
        cookie: bytes,
        cell_circuit_id: bytes,
        nonce: bytes | None = None,
    ) -> "RendezvousJoin":
        return cls(
            rendezvous_cookie_tag(cookie),
            secrets.token_bytes(16) if nonce is None else nonce,
            cell_circuit_id,
        )

    @classmethod
    def decode(cls, content: bytes) -> "RendezvousJoin":
        reader = BinaryReader(content, 80)
        result = cls(
            reader.fixed(32),
            reader.fixed(16),
            reader.fixed(16),
        )
        reader.finish()
        return result
