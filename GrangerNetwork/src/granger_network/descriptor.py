from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import canonical_json, decode_base64url, encode_base64url, parse_json_object
from .address import NAMESPACE, service_id_from_public_key
from .errors import DescriptorError, TransportPolicyError
from .identity import ServiceIdentity
from .transport import LoopbackEndpoint


DESCRIPTOR_SIGNATURE_DOMAIN = b"granger-network-v0.1/descriptor\x00"


@dataclass(frozen=True)
class ServiceDescriptor:
    service_id: str
    identity_public_key: bytes
    endpoint: LoopbackEndpoint
    signature: bytes
    version: int = 1

    @property
    def canonical_name(self) -> str:
        return f"{self.service_id}{NAMESPACE}"

    def unsigned_document(self) -> dict:
        return {
            "identityKey": encode_base64url(self.identity_public_key),
            "serviceId": self.service_id,
            "transport": {
                "host": self.endpoint.host,
                "port": self.endpoint.port,
                "type": "loopback-tcp",
            },
            "version": self.version,
        }

    def signature_payload(self) -> bytes:
        return DESCRIPTOR_SIGNATURE_DOMAIN + canonical_json(self.unsigned_document())

    def verify(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version != 1:
            raise DescriptorError("unsupported descriptor version")
        if not isinstance(self.service_id, str):
            raise DescriptorError("service identifier must be text")
        if not isinstance(self.endpoint, LoopbackEndpoint):
            raise DescriptorError("service descriptor has an unsupported endpoint")
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
        return json.dumps(self.to_document(), indent=2, sort_keys=True) + "\n"

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
    def from_json(cls, content: str) -> "ServiceDescriptor":
        try:
            document = parse_json_object(content)
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
                version=document["version"],
            )
            descriptor.verify()
            return descriptor
        except DescriptorError:
            raise
        except (KeyError, TypeError, ValueError, TransportPolicyError) as error:
            raise DescriptorError(f"invalid service descriptor: {error}") from error
