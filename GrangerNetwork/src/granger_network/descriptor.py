from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import canonical_json, decode_base64url, encode_base64url, parse_json_object
from .address import NAMESPACE, service_id_from_public_key
from .discovery import validate_rendezvous_id
from .errors import DescriptorError, DiscoveryError, TransportPolicyError
from .identity import ServiceIdentity
from .protocol import VERSION_2, VERSION_3
from .transport import LoopbackEndpoint


V1_DESCRIPTOR_SIGNATURE_DOMAIN = b"granger-network-v0.1/descriptor\x00"
V2_DESCRIPTOR_SIGNATURE_DOMAIN = b"granger-network-v0.2/descriptor\x00"
MAX_DESCRIPTOR_LIFETIME = 7 * 24 * 60 * 60
MAX_CLOCK_SKEW = 120
_CONTENT_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
_SAFE_METADATA_LIMITS = {"title": 256, "contentType": 128}


def _validated_metadata(metadata: object) -> dict[str, str]:
    if not isinstance(metadata, dict):
        raise DescriptorError("descriptor metadata must be an object")
    if not set(metadata).issubset(_SAFE_METADATA_LIMITS):
        raise DescriptorError("descriptor contains unsupported metadata")
    result: dict[str, str] = {}
    for name, value in metadata.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise DescriptorError("descriptor metadata values must be text")
        if not value or len(value.encode("utf-8")) > _SAFE_METADATA_LIMITS[name]:
            raise DescriptorError(f"descriptor metadata field is invalid: {name}")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise DescriptorError(f"descriptor metadata contains control characters: {name}")
        if name == "contentType" and not _CONTENT_TYPE.fullmatch(value.lower()):
            raise DescriptorError("descriptor content type is invalid")
        result[name] = value
    return result


@dataclass(frozen=True)
class ServiceDescriptor:
    service_id: str
    identity_public_key: bytes
    endpoint: LoopbackEndpoint | None
    signature: bytes
    version: int = 1
    protocol_version: int = 1
    transports: tuple[str, ...] = ()
    rendezvous_id: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def canonical_name(self) -> str:
        return f"{self.service_id}{NAMESPACE}"

    @property
    def is_remote(self) -> bool:
        return self.version == 2

    def unsigned_document(self) -> dict:
        if self.version == 1:
            if not isinstance(self.endpoint, LoopbackEndpoint):
                raise DescriptorError("local descriptor has no loopback endpoint")
            return {
                "identityKey": encode_base64url(self.identity_public_key),
                "serviceId": self.service_id,
                "transport": {
                    "host": self.endpoint.host,
                    "port": self.endpoint.port,
                    "type": "loopback-tcp",
                },
                "version": 1,
            }
        if self.version == 2:
            return {
                "expiresAt": self.expires_at,
                "identityKey": encode_base64url(self.identity_public_key),
                "issuedAt": self.issued_at,
                "metadata": dict(self.metadata),
                "protocolVersion": self.protocol_version,
                "rendezvousId": self.rendezvous_id,
                "serviceId": self.service_id,
                "transports": list(self.transports),
                "version": 2,
            }
        raise DescriptorError("unsupported descriptor version")

    def signature_payload(self) -> bytes:
        domain = (
            V1_DESCRIPTOR_SIGNATURE_DOMAIN
            if self.version == 1
            else V2_DESCRIPTOR_SIGNATURE_DOMAIN
        )
        return domain + canonical_json(self.unsigned_document())

    def verify(self, now: int | None = None) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise DescriptorError("descriptor version must be an integer")
        if self.version not in {1, 2}:
            raise DescriptorError("unsupported descriptor version")
        if not isinstance(self.service_id, str):
            raise DescriptorError("service identifier must be text")
        if (
            not isinstance(self.identity_public_key, bytes)
            or not isinstance(self.signature, bytes)
            or len(self.identity_public_key) != 32
            or len(self.signature) != 64
        ):
            raise DescriptorError("invalid descriptor key or signature length")
        expected_id = service_id_from_public_key(self.identity_public_key)
        if self.service_id != expected_id:
            raise DescriptorError("service identifier is not derived from the identity key")

        if self.version == 1:
            if not isinstance(self.endpoint, LoopbackEndpoint):
                raise DescriptorError("service descriptor has an unsupported endpoint")
            if (
                self.protocol_version != 1
                or self.transports
                or self.rendezvous_id is not None
                or self.issued_at is not None
                or self.expires_at is not None
                or self.metadata
            ):
                raise DescriptorError("local descriptor contains v0.2 fields")
        else:
            if self.endpoint is not None:
                raise DescriptorError("remote descriptor must not disclose a service endpoint")
            if self.protocol_version not in {VERSION_2, VERSION_3}:
                raise DescriptorError("remote descriptor has an unsupported protocol version")
            if self.transports != ("rendezvous-v1",):
                raise DescriptorError("remote descriptor has unsupported transports")
            try:
                validate_rendezvous_id(self.rendezvous_id)
            except DiscoveryError as error:
                raise DescriptorError(str(error)) from error
            if any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (self.issued_at, self.expires_at)
            ):
                raise DescriptorError("descriptor timestamps must be integers")
            assert self.issued_at is not None and self.expires_at is not None
            if self.expires_at <= self.issued_at:
                raise DescriptorError("descriptor expiry must follow its issue time")
            if self.expires_at - self.issued_at > MAX_DESCRIPTOR_LIFETIME:
                raise DescriptorError("descriptor validity period exceeds the v0.2 limit")
            current_time = int(time.time()) if now is None else now
            if isinstance(current_time, bool) or not isinstance(current_time, int):
                raise DescriptorError("verification time must be an integer")
            if self.issued_at > current_time + MAX_CLOCK_SKEW:
                raise DescriptorError("descriptor issue time is in the future")
            if self.expires_at <= current_time:
                raise DescriptorError("service descriptor has expired")
            _validated_metadata(self.metadata)

        try:
            Ed25519PublicKey.from_public_bytes(self.identity_public_key).verify(
                self.signature,
                self.signature_payload(),
            )
        except (InvalidSignature, ValueError) as error:
            raise DescriptorError("service descriptor signature is invalid") from error

    def to_document(self) -> dict:
        document = self.unsigned_document()
        document["signature"] = encode_base64url(self.signature)
        return document

    def to_json(self) -> str:
        return json.dumps(self.to_document(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"

    @classmethod
    def create(cls, identity: ServiceIdentity, endpoint: LoopbackEndpoint) -> "ServiceDescriptor":
        public_key = identity.public_key_bytes
        unsigned = cls(
            service_id=service_id_from_public_key(public_key),
            identity_public_key=public_key,
            endpoint=endpoint,
            signature=b"\x00" * 64,
        )
        descriptor = cls(
            service_id=unsigned.service_id,
            identity_public_key=public_key,
            endpoint=endpoint,
            signature=identity.sign(unsigned.signature_payload()),
        )
        descriptor.verify()
        return descriptor

    @classmethod
    def create_remote(
        cls,
        identity: ServiceIdentity,
        rendezvous_id: str,
        *,
        metadata: dict[str, str] | None = None,
        issued_at: int | None = None,
        lifetime: int = 24 * 60 * 60,
        protocol_version: int = VERSION_3,
    ) -> "ServiceDescriptor":
        if isinstance(lifetime, bool) or not isinstance(lifetime, int) or not 1 <= lifetime <= MAX_DESCRIPTOR_LIFETIME:
            raise DescriptorError("descriptor lifetime is outside the v0.2 limit")
        timestamp = int(time.time()) if issued_at is None else issued_at
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise DescriptorError("descriptor issue time must be a positive integer")
        safe_metadata = _validated_metadata(metadata or {})
        public_key = identity.public_key_bytes
        unsigned = cls(
            service_id=service_id_from_public_key(public_key),
            identity_public_key=public_key,
            endpoint=None,
            signature=b"\x00" * 64,
            version=2,
            protocol_version=protocol_version,
            transports=("rendezvous-v1",),
            rendezvous_id=validate_rendezvous_id(rendezvous_id),
            issued_at=timestamp,
            expires_at=timestamp + lifetime,
            metadata=safe_metadata,
        )
        descriptor = replace(unsigned, signature=identity.sign(unsigned.signature_payload()))
        descriptor.verify(now=timestamp)
        return descriptor

    @classmethod
    def from_json(cls, content: str, now: int | None = None) -> "ServiceDescriptor":
        try:
            document = parse_json_object(content)
            version = document.get("version")
            if isinstance(version, bool) or not isinstance(version, int):
                raise ValueError("descriptor version must be an integer")
            if version == 1:
                if set(document) != {"identityKey", "serviceId", "signature", "transport", "version"}:
                    raise ValueError("unexpected descriptor fields")
                transport = document["transport"]
                if not isinstance(transport, dict) or set(transport) != {"host", "port", "type"}:
                    raise ValueError("unexpected transport fields")
                if transport["type"] != "loopback-tcp":
                    raise ValueError("unsupported transport type")
                if isinstance(transport["port"], bool) or not isinstance(transport["port"], int):
                    raise ValueError("transport port must be an integer")
                descriptor = cls(
                    service_id=document["serviceId"],
                    identity_public_key=decode_base64url(document["identityKey"]),
                    endpoint=LoopbackEndpoint(transport["host"], transport["port"]),
                    signature=decode_base64url(document["signature"]),
                )
            elif version == 2:
                expected = {
                    "expiresAt",
                    "identityKey",
                    "issuedAt",
                    "metadata",
                    "protocolVersion",
                    "rendezvousId",
                    "serviceId",
                    "signature",
                    "transports",
                    "version",
                }
                if set(document) != expected:
                    raise ValueError("unexpected descriptor fields")
                if not isinstance(document["transports"], list):
                    raise ValueError("descriptor transports must be an array")
                descriptor = cls(
                    service_id=document["serviceId"],
                    identity_public_key=decode_base64url(document["identityKey"]),
                    endpoint=None,
                    signature=decode_base64url(document["signature"]),
                    version=2,
                    protocol_version=document["protocolVersion"],
                    transports=tuple(document["transports"]),
                    rendezvous_id=document["rendezvousId"],
                    issued_at=document["issuedAt"],
                    expires_at=document["expiresAt"],
                    metadata=document["metadata"],
                )
            else:
                raise ValueError("unsupported descriptor version")
            descriptor.verify(now=now)
            return descriptor
        except DescriptorError:
            raise
        except (DiscoveryError, KeyError, TypeError, ValueError, TransportPolicyError) as error:
            raise DescriptorError(f"invalid service descriptor: {error}") from error
