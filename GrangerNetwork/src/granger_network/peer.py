from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import canonical_json, decode_base64url, encode_base64url, parse_json_object
from .errors import DescriptorError, ResourceLimitError, TransportPolicyError
from .identity import ServiceIdentity
from .transport import RendezvousEndpoint


NODE_DESCRIPTOR_VERSION = 1
NODE_ID_DOMAIN = b"granger-network-v0.3/node-id\x00"
NODE_DESCRIPTOR_SIGNATURE_DOMAIN = b"granger-network-v0.3/node-descriptor\x00"
MAX_NODE_DESCRIPTOR_LIFETIME = 24 * 60 * 60
MAX_NODE_CLOCK_SKEW = 120
NODE_CAPABILITIES = frozenset(
    {"discovery", "entry", "middle", "introduction", "service-relay"}
)
RELAY_CAPABILITIES = NODE_CAPABILITIES - {"discovery"}
_NODE_ID = re.compile(r"^[a-z2-7]{52}$")


def node_id_from_public_key(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise DescriptorError("a node Ed25519 public key must contain 32 bytes")
    digest = hashlib.sha256(NODE_ID_DOMAIN + public_key).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=").lower()


def validate_node_id(value: str) -> str:
    if not isinstance(value, str) or not _NODE_ID.fullmatch(value):
        raise DescriptorError("node identifier is invalid")
    return value


@dataclass(frozen=True)
class RelayPolicy:
    enabled: bool = False
    max_circuits: int = 32
    max_bytes_per_circuit: int = 64 * 1024 * 1024
    max_bandwidth_kib_per_second: int = 1024

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ResourceLimitError("relay participation flag must be boolean")
        limits = (
            (self.max_circuits, 1, 4096, "relay circuit limit"),
            (
                self.max_bytes_per_circuit,
                64 * 1024,
                1024 * 1024 * 1024,
                "relay per-circuit byte limit",
            ),
            (
                self.max_bandwidth_kib_per_second,
                64,
                1024 * 1024,
                "relay bandwidth limit",
            ),
        )
        for value, minimum, maximum, label in limits:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ResourceLimitError(f"{label} is outside the supported range")

    def to_document(self) -> dict[str, int | bool]:
        return {
            "enabled": self.enabled,
            "maxBandwidthKiBPerSecond": self.max_bandwidth_kib_per_second,
            "maxBytesPerCircuit": self.max_bytes_per_circuit,
            "maxCircuits": self.max_circuits,
        }

    @classmethod
    def from_document(cls, document: object) -> "RelayPolicy":
        if not isinstance(document, dict) or set(document) != {
            "enabled",
            "maxBandwidthKiBPerSecond",
            "maxBytesPerCircuit",
            "maxCircuits",
        }:
            raise DescriptorError("node relay policy has an invalid schema")
        try:
            return cls(
                enabled=document["enabled"],
                max_circuits=document["maxCircuits"],
                max_bytes_per_circuit=document["maxBytesPerCircuit"],
                max_bandwidth_kib_per_second=document["maxBandwidthKiBPerSecond"],
            )
        except ResourceLimitError as error:
            raise DescriptorError(str(error)) from error


@dataclass(frozen=True)
class NodeDescriptor:
    node_id: str
    identity_public_key: bytes
    endpoint: RendezvousEndpoint
    capabilities: tuple[str, ...]
    relay_policy: RelayPolicy
    issued_at: int
    expires_at: int
    signature: bytes
    version: int = NODE_DESCRIPTOR_VERSION

    def unsigned_document(self) -> dict:
        return {
            "capabilities": list(self.capabilities),
            "endpoint": {
                "host": self.endpoint.host,
                "port": self.endpoint.port,
                "type": "tcp",
            },
            "expiresAt": self.expires_at,
            "identityKey": encode_base64url(self.identity_public_key),
            "issuedAt": self.issued_at,
            "nodeId": self.node_id,
            "relayPolicy": self.relay_policy.to_document(),
            "version": self.version,
        }

    def signature_payload(self) -> bytes:
        return NODE_DESCRIPTOR_SIGNATURE_DOMAIN + canonical_json(self.unsigned_document())

    def verify(self, now: int | None = None) -> None:
        if self.version != NODE_DESCRIPTOR_VERSION or isinstance(self.version, bool):
            raise DescriptorError("unsupported node descriptor version")
        validate_node_id(self.node_id)
        if (
            not isinstance(self.identity_public_key, bytes)
            or len(self.identity_public_key) != 32
            or not isinstance(self.signature, bytes)
            or len(self.signature) != 64
        ):
            raise DescriptorError("node descriptor key or signature length is invalid")
        if self.node_id != node_id_from_public_key(self.identity_public_key):
            raise DescriptorError("node identifier is not derived from its identity")
        if not isinstance(self.endpoint, RendezvousEndpoint):
            raise DescriptorError("node descriptor endpoint is invalid")
        if (
            not isinstance(self.capabilities, tuple)
            or not self.capabilities
            or tuple(sorted(set(self.capabilities))) != self.capabilities
            or not set(self.capabilities).issubset(NODE_CAPABILITIES)
        ):
            raise DescriptorError("node capabilities are invalid")
        if not isinstance(self.relay_policy, RelayPolicy):
            raise DescriptorError("node relay policy is invalid")
        if set(self.capabilities) & RELAY_CAPABILITIES and not self.relay_policy.enabled:
            raise DescriptorError("relay capabilities require explicit opt-in")
        for value in (self.issued_at, self.expires_at):
            if isinstance(value, bool) or not isinstance(value, int):
                raise DescriptorError("node descriptor timestamps must be integers")
        if self.issued_at < 0 or self.expires_at <= self.issued_at:
            raise DescriptorError("node descriptor validity window is invalid")
        if self.expires_at - self.issued_at > MAX_NODE_DESCRIPTOR_LIFETIME:
            raise DescriptorError("node descriptor lifetime exceeds the limit")
        current_time = int(time.time()) if now is None else now
        if isinstance(current_time, bool) or not isinstance(current_time, int):
            raise DescriptorError("node descriptor verification time must be an integer")
        if self.issued_at > current_time + MAX_NODE_CLOCK_SKEW:
            raise DescriptorError("node descriptor issue time is in the future")
        if self.expires_at <= current_time:
            raise DescriptorError("node descriptor has expired")
        try:
            Ed25519PublicKey.from_public_bytes(self.identity_public_key).verify(
                self.signature,
                self.signature_payload(),
            )
        except (InvalidSignature, ValueError) as error:
            raise DescriptorError("node descriptor signature is invalid") from error

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
        endpoint: RendezvousEndpoint,
        capabilities: tuple[str, ...] | list[str],
        relay_policy: RelayPolicy,
        *,
        issued_at: int | None = None,
        lifetime: int = 60 * 60,
    ) -> "NodeDescriptor":
        timestamp = int(time.time()) if issued_at is None else issued_at
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise DescriptorError("node descriptor issue time is invalid")
        if (
            isinstance(lifetime, bool)
            or not isinstance(lifetime, int)
            or not 1 <= lifetime <= MAX_NODE_DESCRIPTOR_LIFETIME
        ):
            raise DescriptorError("node descriptor lifetime is outside the limit")
        if not isinstance(endpoint, RendezvousEndpoint):
            raise DescriptorError("node descriptor requires a numeric endpoint")
        if not isinstance(relay_policy, RelayPolicy):
            raise DescriptorError("node descriptor requires a relay policy")
        try:
            normalized_capabilities = tuple(sorted(set(capabilities)))
        except TypeError as error:
            raise DescriptorError("node capabilities must be text") from error
        if any(not isinstance(capability, str) for capability in normalized_capabilities):
            raise DescriptorError("node capabilities must be text")
        public_key = identity.public_key_bytes
        unsigned = cls(
            node_id=node_id_from_public_key(public_key),
            identity_public_key=public_key,
            endpoint=endpoint,
            capabilities=normalized_capabilities,
            relay_policy=relay_policy,
            issued_at=timestamp,
            expires_at=timestamp + lifetime,
            signature=b"\x00" * 64,
        )
        descriptor = replace(unsigned, signature=identity.sign(unsigned.signature_payload()))
        descriptor.verify(now=timestamp)
        return descriptor

    @classmethod
    def from_json(cls, content: str, now: int | None = None) -> "NodeDescriptor":
        try:
            document = parse_json_object(content)
            expected = {
                "capabilities",
                "endpoint",
                "expiresAt",
                "identityKey",
                "issuedAt",
                "nodeId",
                "relayPolicy",
                "signature",
                "version",
            }
            if set(document) != expected:
                raise ValueError("unexpected node descriptor fields")
            endpoint = document["endpoint"]
            if not isinstance(endpoint, dict) or set(endpoint) != {"host", "port", "type"}:
                raise ValueError("invalid node endpoint")
            if endpoint["type"] != "tcp":
                raise ValueError("unsupported node endpoint transport")
            if not isinstance(document["capabilities"], list):
                raise ValueError("node capabilities must be an array")
            descriptor = cls(
                node_id=document["nodeId"],
                identity_public_key=decode_base64url(document["identityKey"]),
                endpoint=RendezvousEndpoint(endpoint["host"], endpoint["port"]),
                capabilities=tuple(document["capabilities"]),
                relay_policy=RelayPolicy.from_document(document["relayPolicy"]),
                issued_at=document["issuedAt"],
                expires_at=document["expiresAt"],
                signature=decode_base64url(document["signature"]),
                version=document["version"],
            )
            descriptor.verify(now=now)
            return descriptor
        except DescriptorError:
            raise
        except (KeyError, TypeError, ValueError, TransportPolicyError) as error:
            raise DescriptorError(f"invalid node descriptor: {error}") from error


class GrangerNode:
    """Opt-in relay runtime with local circuit and byte limits."""

    def __init__(
        self,
        identity: ServiceIdentity,
        descriptor: NodeDescriptor,
        policy: RelayPolicy,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        descriptor.verify()
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise DescriptorError("node identity does not match its descriptor")
        if descriptor.relay_policy != policy:
            raise DescriptorError("node runtime policy does not match its signed descriptor")
        if not callable(monotonic):
            raise DescriptorError("node runtime requires a monotonic clock")
        self.identity = identity
        self.descriptor = descriptor
        self.policy = policy
        self._monotonic = monotonic
        self._circuits: dict[bytes, int] = {}
        self._lock = threading.Lock()
        self._bandwidth_window_started = self._read_monotonic()
        self._bandwidth_bytes = 0

    def _read_monotonic(self) -> float:
        try:
            value = float(self._monotonic())
        except (TypeError, ValueError, OverflowError) as error:
            raise ResourceLimitError("relay monotonic clock is invalid") from error
        if not math.isfinite(value) or value < 0:
            raise ResourceLimitError("relay monotonic clock is invalid")
        return value

    def begin_circuit(self, circuit_id: bytes, capability: str) -> None:
        self.descriptor.verify()
        if (
            not isinstance(circuit_id, bytes)
            or len(circuit_id) != 16
            or capability not in RELAY_CAPABILITIES
        ):
            raise ResourceLimitError("relay circuit request is invalid")
        if not self.policy.enabled or capability not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not opt in to the requested relay role")
        with self._lock:
            if circuit_id in self._circuits:
                raise ResourceLimitError("relay circuit identifier is already active")
            if len(self._circuits) >= self.policy.max_circuits:
                raise ResourceLimitError("relay circuit limit is exhausted")
            self._circuits[circuit_id] = 0

    def account_bytes(self, circuit_id: bytes, count: int) -> None:
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ResourceLimitError("relay byte accounting value is invalid")
        with self._lock:
            if circuit_id not in self._circuits:
                raise ResourceLimitError("relay circuit is not active")
            current_time = self._read_monotonic()
            elapsed = current_time - self._bandwidth_window_started
            if elapsed < 0:
                raise ResourceLimitError("relay monotonic clock moved backwards")
            if elapsed >= 1.0:
                self._bandwidth_window_started = current_time
                self._bandwidth_bytes = 0
            bandwidth_limit = self.policy.max_bandwidth_kib_per_second * 1024
            if self._bandwidth_bytes + count > bandwidth_limit:
                raise ResourceLimitError("relay bandwidth limit is exhausted")
            total = self._circuits[circuit_id] + count
            if total > self.policy.max_bytes_per_circuit:
                raise ResourceLimitError("relay per-circuit byte limit is exhausted")
            self._bandwidth_bytes += count
            self._circuits[circuit_id] = total

    def end_circuit(self, circuit_id: bytes) -> None:
        with self._lock:
            self._circuits.pop(circuit_id, None)

    @property
    def active_circuits(self) -> int:
        with self._lock:
            return len(self._circuits)
