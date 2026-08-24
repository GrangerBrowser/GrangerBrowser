from __future__ import annotations

import base64
import hashlib
import threading
from dataclasses import dataclass
from typing import TypeAlias

from .address import is_canonical_name, normalize_name, service_id_from_name
from .descriptor import ServiceDescriptor
from .discovery import DiscoveryProvider
from .errors import (
    AddressError,
    DescriptorError,
    DiscoveryError,
    GrangerNetworkError,
    ProtocolError,
    ReplayError,
    ResolutionError,
)
from .introduction import AliasRecord, IntroductionDescriptor
from .peer import NodeDescriptor, validate_node_id
from .protocol import VERSION_3
from .rendezvous_control import validate_service_id
from .transport import RendezvousEndpoint


NODE_RECORD = "node"
SERVICE_RECORD = "service"
INTRODUCTION_RECORD = "introduction"
ALIAS_RECORD = "alias"
RECORD_KINDS = frozenset(
    {NODE_RECORD, SERVICE_RECORD, INTRODUCTION_RECORD, ALIAS_RECORD}
)
MAX_DISTRIBUTED_RECORD_SIZE = 64 * 1024
MAX_PEER_RECORDS = 4096
_ROUTING_KEY_DOMAIN = b"granger-network-v0.3/discovery-routing-key\x00"

DistributedRecord: TypeAlias = (
    NodeDescriptor | ServiceDescriptor | IntroductionDescriptor | AliasRecord
)


@dataclass(frozen=True)
class RecordEnvelope:
    kind: str
    key: str
    sequence: int
    expires_at: int
    payload: bytes


def _record_fields(record: DistributedRecord) -> tuple[str, str, int, int]:
    if isinstance(record, NodeDescriptor):
        return NODE_RECORD, record.node_id, record.issued_at, record.expires_at
    if isinstance(record, ServiceDescriptor):
        if (
            not record.is_remote
            or record.endpoint is not None
            or record.protocol_version != VERSION_3
            or record.issued_at is None
            or record.expires_at is None
        ):
            raise DiscoveryError("distributed discovery requires a remote wire 3 descriptor")
        return SERVICE_RECORD, record.service_id, record.issued_at, record.expires_at
    if isinstance(record, IntroductionDescriptor):
        return (
            INTRODUCTION_RECORD,
            record.service_id,
            record.sequence,
            record.expires_at,
        )
    if isinstance(record, AliasRecord):
        return ALIAS_RECORD, record.alias, record.sequence, record.expires_at
    raise DiscoveryError("unsupported distributed discovery record")


def encode_record(record: DistributedRecord, now: int | None = None) -> RecordEnvelope:
    if isinstance(record, NodeDescriptor):
        record.verify(now=now)
    elif isinstance(record, ServiceDescriptor):
        record.verify(now=now)
    elif isinstance(record, IntroductionDescriptor):
        record.verify(now=now)
    elif isinstance(record, AliasRecord):
        record.verify(now=now)
    kind, key, sequence, expires_at = _record_fields(record)
    payload = record.to_json().encode("ascii")
    if len(payload) > MAX_DISTRIBUTED_RECORD_SIZE:
        raise DiscoveryError("distributed discovery record exceeds the size limit")
    return RecordEnvelope(kind, key, sequence, expires_at, payload)


def decode_record(
    kind: str,
    key: str,
    payload: bytes,
    now: int | None = None,
) -> DistributedRecord:
    if kind not in RECORD_KINDS or not isinstance(key, str):
        raise DiscoveryError("distributed record key is invalid")
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_DISTRIBUTED_RECORD_SIZE:
        raise DiscoveryError("distributed record payload is invalid")
    try:
        content = payload.decode("ascii")
        if kind == NODE_RECORD:
            record: DistributedRecord = NodeDescriptor.from_json(content, now=now)
        elif kind == SERVICE_RECORD:
            record = ServiceDescriptor.from_json(content, now=now)
        elif kind == INTRODUCTION_RECORD:
            record = IntroductionDescriptor.from_json(content, now=now)
        else:
            record = AliasRecord.from_json(content, now=now)
        record_kind, record_key, _sequence, _expires = _record_fields(record)
        if record_kind != kind or record_key != key:
            raise DiscoveryError("distributed record does not match its storage key")
        return record
    except (UnicodeDecodeError, DescriptorError) as error:
        raise DiscoveryError(f"invalid distributed discovery record: {error}") from error


def _node_id_bytes(node_id: str) -> bytes:
    validated = validate_node_id(node_id)
    padding = "=" * (-len(validated) % 8)
    try:
        return base64.b32decode(validated.upper() + padding)
    except ValueError as error:
        raise DiscoveryError("node identifier encoding is invalid") from error


def _routing_key(kind: str, key: str) -> bytes:
    if kind not in RECORD_KINDS or not isinstance(key, str) or not key:
        raise DiscoveryError("distributed routing key is invalid")
    try:
        encoded_kind = kind.encode("ascii")
        encoded_key = key.encode("ascii")
    except UnicodeEncodeError as error:
        raise DiscoveryError("distributed routing key must be ASCII") from error
    return hashlib.sha256(
        _ROUTING_KEY_DOMAIN + encoded_kind + b"\x00" + encoded_key
    ).digest()


class DiscoveryPeer:
    """Bounded in-memory store owned by an opt-in discovery participant."""

    def __init__(
        self,
        descriptor: NodeDescriptor,
        *,
        max_records: int = MAX_PEER_RECORDS,
    ) -> None:
        descriptor.verify()
        if "discovery" not in descriptor.capabilities:
            raise DiscoveryError("discovery peer did not advertise discovery capability")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 1 <= max_records <= MAX_PEER_RECORDS
        ):
            raise DiscoveryError("discovery peer record limit is invalid")
        self.descriptor = descriptor
        self.max_records = max_records
        self._records: dict[tuple[str, str], RecordEnvelope] = {}
        self._lock = threading.Lock()

    def store(self, envelope: RecordEnvelope, now: int | None = None) -> None:
        if not isinstance(envelope, RecordEnvelope):
            raise DiscoveryError("discovery peer received an invalid record envelope")
        decoded = decode_record(envelope.kind, envelope.key, envelope.payload, now=now)
        validated = encode_record(decoded, now=now)
        if validated != envelope:
            raise DiscoveryError("discovery record envelope metadata is not canonical")
        record_key = (envelope.kind, envelope.key)
        with self._lock:
            previous = self._records.get(record_key)
            if previous is not None:
                if envelope.sequence < previous.sequence:
                    raise ReplayError("discovery peer rejected an older record sequence")
                if (
                    envelope.sequence == previous.sequence
                    and envelope.payload != previous.payload
                ):
                    raise ReplayError("discovery peer rejected equivocation at one sequence")
                if envelope.sequence == previous.sequence:
                    return
            elif len(self._records) >= self.max_records:
                raise DiscoveryError("discovery peer record limit is exhausted")
            self._records[record_key] = envelope

    def fetch(self, kind: str, key: str) -> RecordEnvelope | None:
        with self._lock:
            return self._records.get((kind, key))


class DistributedDiscoveryNetwork:
    """XOR-nearest replicated signed-record store for local overlay experiments."""

    def __init__(
        self,
        peers: list[DiscoveryPeer] | tuple[DiscoveryPeer, ...],
        *,
        replication_factor: int = 3,
        minimum_replicas: int = 2,
    ) -> None:
        if (
            isinstance(replication_factor, bool)
            or not isinstance(replication_factor, int)
            or replication_factor < 2
            or isinstance(minimum_replicas, bool)
            or not isinstance(minimum_replicas, int)
            or not 2 <= minimum_replicas <= replication_factor
        ):
            raise DiscoveryError("distributed replication policy is invalid")
        if len(peers) < replication_factor:
            raise DiscoveryError("distributed discovery requires enough independent peers")
        node_ids = [peer.descriptor.node_id for peer in peers]
        if len(set(node_ids)) != len(node_ids):
            raise DiscoveryError("distributed discovery peer identities must be unique")
        self._peers = tuple(peers)
        self.replication_factor = replication_factor
        self.minimum_replicas = minimum_replicas
        self._highest_seen: dict[tuple[str, str], int] = {}
        self._known_node_ids: set[str] = set(node_ids)
        self._lock = threading.Lock()

    def _closest_peers(self, kind: str, key: str, now: int | None) -> tuple[DiscoveryPeer, ...]:
        target = int.from_bytes(_routing_key(kind, key), "big")
        eligible: list[DiscoveryPeer] = []
        for peer in self._peers:
            try:
                peer.descriptor.verify(now=now)
            except DescriptorError:
                continue
            eligible.append(peer)
        eligible.sort(
            key=lambda peer: int.from_bytes(
                _node_id_bytes(peer.descriptor.node_id), "big"
            )
            ^ target
        )
        if len(eligible) < self.minimum_replicas:
            raise DiscoveryError("too few valid discovery peers are available")
        return tuple(eligible[: self.replication_factor])

    def publish(self, record: DistributedRecord, now: int | None = None) -> int:
        envelope = encode_record(record, now=now)
        with self._lock:
            current = self._highest_seen.get((envelope.kind, envelope.key), -1)
            if envelope.sequence < current:
                raise ReplayError("distributed publication attempted a local rollback")
        peers = self._closest_peers(envelope.kind, envelope.key, now)
        stored = 0
        last_error: BaseException | None = None
        for peer in peers:
            try:
                peer.store(envelope, now=now)
                stored += 1
            except GrangerNetworkError as error:
                last_error = error
        if stored < self.minimum_replicas:
            if last_error is not None:
                raise DiscoveryError(
                    f"distributed publication did not reach enough replicas: {last_error}"
                ) from last_error
            raise DiscoveryError("distributed publication did not reach enough replicas")
        with self._lock:
            self._highest_seen[(envelope.kind, envelope.key)] = envelope.sequence
            if envelope.kind == NODE_RECORD:
                self._known_node_ids.add(envelope.key)
        return stored

    def lookup(
        self,
        kind: str,
        key: str,
        now: int | None = None,
    ) -> DistributedRecord:
        candidates: list[tuple[RecordEnvelope, DistributedRecord]] = []
        for peer in self._closest_peers(kind, key, now):
            envelope = peer.fetch(kind, key)
            if envelope is None:
                continue
            try:
                record = decode_record(kind, key, envelope.payload, now=now)
                canonical = encode_record(record, now=now)
                if canonical == envelope:
                    candidates.append((envelope, record))
            except GrangerNetworkError:
                continue
        if not candidates:
            raise ResolutionError(f"distributed record is unavailable: {kind}:{key}")
        highest_sequence = max(envelope.sequence for envelope, _record in candidates)
        with self._lock:
            previous_highest = self._highest_seen.get((kind, key), -1)
            if highest_sequence < previous_highest:
                raise ReplayError("distributed lookup detected a record rollback")
        winners = [
            (envelope, record)
            for envelope, record in candidates
            if envelope.sequence == highest_sequence
        ]
        payloads = {envelope.payload for envelope, _record in winners}
        if len(payloads) != 1:
            raise DiscoveryError("distributed lookup detected signed record equivocation")
        with self._lock:
            self._highest_seen[(kind, key)] = highest_sequence
        return winners[0][1]

    def replica_node_ids(
        self,
        kind: str,
        key: str,
        now: int | None = None,
    ) -> tuple[str, ...]:
        return tuple(
            peer.descriptor.node_id for peer in self._closest_peers(kind, key, now)
        )

    def known_nodes(
        self,
        capability: str,
        now: int | None = None,
    ) -> tuple[NodeDescriptor, ...]:
        if not isinstance(capability, str):
            raise DiscoveryError("node capability query must be text")
        with self._lock:
            node_ids = tuple(sorted(self._known_node_ids))
        result: list[NodeDescriptor] = []
        for node_id in node_ids:
            try:
                record = self.lookup(NODE_RECORD, node_id, now=now)
            except GrangerNetworkError:
                continue
            if isinstance(record, NodeDescriptor) and capability in record.capabilities:
                result.append(record)
        return tuple(result)


class DistributedResolver(DiscoveryProvider):
    """Signed overlay resolver with local alias identity pins and no DNS path."""

    def __init__(
        self,
        network: DistributedDiscoveryNetwork,
        alias_pins: dict[str, str] | None = None,
    ) -> None:
        if not isinstance(network, DistributedDiscoveryNetwork):
            raise DiscoveryError("distributed resolver requires a discovery network")
        self.network = network
        self._alias_pins: dict[str, str] = {}
        for alias, service_id in (alias_pins or {}).items():
            self.pin_alias(alias, service_id)

    def pin_alias(self, alias: str, service_id: str) -> None:
        try:
            normalized = normalize_name(alias)
            if is_canonical_name(normalized):
                raise AddressError("canonical addresses do not require alias pins")
            self._alias_pins[normalized] = validate_service_id(service_id)
        except (AddressError, DescriptorError, ProtocolError) as error:
            raise DiscoveryError(str(error)) from error

    def resolve(self, name: str) -> ServiceDescriptor:
        try:
            normalized = normalize_name(name)
            if is_canonical_name(normalized):
                service_id = service_id_from_name(normalized)
            else:
                expected_service_id = self._alias_pins.get(normalized)
                if expected_service_id is None:
                    raise ResolutionError(
                        f"distributed alias requires a local identity pin: {normalized}"
                    )
                record = self.network.lookup(ALIAS_RECORD, normalized)
                if not isinstance(record, AliasRecord):
                    raise ResolutionError("distributed alias record has the wrong type")
                if record.service_id != expected_service_id:
                    raise ResolutionError("distributed alias does not match its identity pin")
                service_id = expected_service_id
            descriptor = self.network.lookup(SERVICE_RECORD, service_id)
            if not isinstance(descriptor, ServiceDescriptor):
                raise ResolutionError("distributed service record has the wrong type")
            descriptor.verify()
            return descriptor
        except ResolutionError:
            raise
        except (AddressError, DescriptorError, DiscoveryError) as error:
            raise ResolutionError(str(error)) from error

    def resolve_introduction(
        self,
        descriptor: ServiceDescriptor,
        now: int | None = None,
    ) -> IntroductionDescriptor:
        descriptor.verify(now=now)
        record = self.network.lookup(INTRODUCTION_RECORD, descriptor.service_id, now=now)
        if not isinstance(record, IntroductionDescriptor):
            raise ResolutionError("distributed introduction record has the wrong type")
        record.verify_for(descriptor, now=now)
        return record

    def resolve_node(self, node_id: str, now: int | None = None) -> NodeDescriptor:
        validated = validate_node_id(node_id)
        record = self.network.lookup(NODE_RECORD, validated, now=now)
        if not isinstance(record, NodeDescriptor):
            raise ResolutionError("distributed node record has the wrong type")
        return record

    def resolve_rendezvous(self, rendezvous_id: str) -> RendezvousEndpoint:
        raise DiscoveryError(
            "distributed overlay discovery has no single rendezvous endpoint"
        )
