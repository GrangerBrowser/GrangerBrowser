from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path

from ._codec import atomic_write_text, decode_base64url, encode_base64url, parse_json_object
from .binary import BinaryReader, BinaryWriter
from .bootstrap import BootstrapPool, PeerCache
from .distributed import (
    ALIAS_RECORD,
    INTRODUCTION_RECORD,
    MAX_DISTRIBUTED_RECORD_SIZE,
    NODE_RECORD,
    RECORD_KINDS,
    SERVICE_RECORD,
    DistributedRecord,
    RecordEnvelope,
    decode_record,
    encode_record,
)
from .errors import DescriptorError, DiscoveryError, GrangerNetworkError, ProtocolError, ReplayError, ResolutionError
from .identity import ServiceIdentity
from .peer import NodeDescriptor, validate_node_id
from .peer_rpc import PeerRole, RpcType, connect_authenticated_peer
from .address import is_canonical_name, normalize_name, service_id_from_name
from .descriptor import ServiceDescriptor
from .introduction import AliasRecord, IntroductionDescriptor
from .rendezvous_control import validate_service_id


WAN_DISCOVERY_VERSION = 1
MAX_WAN_RECORDS = 4096
MAX_FIND_NODE_RESULTS = 32
MAX_DISCOVERY_QUERIES = 32
_ROUTING_KEY_DOMAIN = b"granger-network-v0.4/wan-routing-key\x00"


def _node_id_bytes(node_id: str) -> bytes:
    validated = validate_node_id(node_id)
    try:
        return base64.b32decode(validated.upper() + "=" * (-len(validated) % 8))
    except ValueError as error:
        raise DiscoveryError("node identifier encoding is invalid") from error


def wan_routing_key(kind: str, key: str) -> bytes:
    if kind not in RECORD_KINDS or not isinstance(key, str) or not key:
        raise DiscoveryError("WAN discovery routing key is invalid")
    try:
        return hashlib.sha256(
            _ROUTING_KEY_DOMAIN + kind.encode("ascii") + b"\x00" + key.encode("ascii")
        ).digest()
    except UnicodeEncodeError as error:
        raise DiscoveryError("WAN discovery routing key must be ASCII") from error


def encode_record_envelope(envelope: RecordEnvelope) -> bytes:
    if not isinstance(envelope, RecordEnvelope):
        raise ProtocolError("WAN record envelope is invalid")
    return (
        BinaryWriter(MAX_DISTRIBUTED_RECORD_SIZE + 512)
        .text_u16(envelope.kind, 32)
        .text_u16(envelope.key, 256)
        .u64(envelope.sequence)
        .u64(envelope.expires_at)
        .bytes_u32(envelope.payload, MAX_DISTRIBUTED_RECORD_SIZE)
        .build()
    )


def decode_record_envelope(content: bytes, now: int | None = None) -> RecordEnvelope:
    reader = BinaryReader(content, MAX_DISTRIBUTED_RECORD_SIZE + 512)
    envelope = RecordEnvelope(
        reader.text_u16(32),
        reader.text_u16(256),
        reader.u64(),
        reader.u64(),
        reader.bytes_u32(MAX_DISTRIBUTED_RECORD_SIZE),
    )
    reader.finish()
    record = decode_record(envelope.kind, envelope.key, envelope.payload, now=now)
    if encode_record(record, now=now) != envelope:
        raise DiscoveryError("WAN record envelope metadata is not canonical")
    return envelope


def encode_find_record(kind: str, key: str) -> bytes:
    if kind not in RECORD_KINDS:
        raise ProtocolError("WAN record kind is invalid")
    return BinaryWriter(512).text_u16(kind, 32).text_u16(key, 256).build()


def decode_find_record(content: bytes) -> tuple[str, str]:
    reader = BinaryReader(content, 512)
    kind = reader.text_u16(32)
    key = reader.text_u16(256)
    reader.finish()
    if kind not in RECORD_KINDS or not key:
        raise ProtocolError("WAN record query is invalid")
    return kind, key


def encode_optional_record(envelope: RecordEnvelope | None) -> bytes:
    writer = BinaryWriter(MAX_DISTRIBUTED_RECORD_SIZE + 520).u8(1 if envelope else 0)
    if envelope is not None:
        writer.bytes_u32(encode_record_envelope(envelope), MAX_DISTRIBUTED_RECORD_SIZE + 512)
    return writer.build()


def decode_optional_record(content: bytes, now: int | None = None) -> RecordEnvelope | None:
    reader = BinaryReader(content, MAX_DISTRIBUTED_RECORD_SIZE + 520)
    present = reader.u8()
    if present not in {0, 1}:
        raise ProtocolError("WAN record response flag is invalid")
    envelope = None
    if present:
        envelope = decode_record_envelope(
            reader.bytes_u32(MAX_DISTRIBUTED_RECORD_SIZE + 512),
            now=now,
        )
    reader.finish()
    return envelope


def encode_find_node(target: bytes, capability: str) -> bytes:
    if not isinstance(target, bytes) or len(target) != 32:
        raise ProtocolError("WAN node lookup target is invalid")
    return BinaryWriter(128).fixed(target, 32).text_u16(capability, 32).build()


def decode_find_node(content: bytes) -> tuple[bytes, str]:
    reader = BinaryReader(content, 128)
    target = reader.fixed(32)
    capability = reader.text_u16(32)
    reader.finish()
    if not capability:
        raise ProtocolError("WAN node lookup capability is empty")
    return target, capability


def encode_node_list(peers: list[NodeDescriptor] | tuple[NodeDescriptor, ...]) -> bytes:
    if len(peers) > MAX_FIND_NODE_RESULTS:
        raise ProtocolError("WAN node response has too many peers")
    writer = BinaryWriter(MAX_FIND_NODE_RESULTS * 64 * 1024 + 4).u16(len(peers))
    for peer in peers:
        peer.verify()
        writer.bytes_u32(peer.to_json().encode("ascii"), 64 * 1024)
    return writer.build()


def decode_node_list(content: bytes, now: int | None = None) -> tuple[NodeDescriptor, ...]:
    reader = BinaryReader(content, MAX_FIND_NODE_RESULTS * 64 * 1024 + 4)
    count = reader.u16()
    if count > MAX_FIND_NODE_RESULTS:
        raise ProtocolError("WAN node response has too many peers")
    peers: list[NodeDescriptor] = []
    seen: set[str] = set()
    for _ in range(count):
        try:
            peer = NodeDescriptor.from_json(
                reader.bytes_u32(64 * 1024).decode("ascii"),
                now=now,
            )
        except UnicodeDecodeError as error:
            raise ProtocolError("WAN node descriptor is not ASCII") from error
        if peer.node_id in seen:
            raise ProtocolError("WAN node response repeats a peer")
        seen.add(peer.node_id)
        peers.append(peer)
    reader.finish()
    return tuple(peers)


class PersistentRecordStore:
    def __init__(self, path: Path, *, maximum: int = MAX_WAN_RECORDS) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= MAX_WAN_RECORDS:
            raise DiscoveryError("WAN record store limit is invalid")
        self.path = Path(path)
        self.maximum = maximum
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], RecordEnvelope] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            document = parse_json_object(self.path.read_text(encoding="utf-8"))
            if set(document) != {"records", "version"} or document["version"] != WAN_DISCOVERY_VERSION:
                raise ValueError("WAN record store version is unsupported")
            if not isinstance(document["records"], list) or len(document["records"]) > self.maximum:
                raise ValueError("WAN record store count is invalid")
            now = int(time.time())
            for raw in document["records"]:
                if not isinstance(raw, dict) or set(raw) != {"expiresAt", "key", "kind", "payload", "sequence"}:
                    raise ValueError("WAN record store entry is malformed")
                if raw["expiresAt"] <= now:
                    continue
                envelope = RecordEnvelope(
                    raw["kind"],
                    raw["key"],
                    raw["sequence"],
                    raw["expiresAt"],
                    decode_base64url(raw["payload"]),
                )
                decode_record_envelope(encode_record_envelope(envelope), now=now)
                self._records[(envelope.kind, envelope.key)] = envelope
        except (OSError, TypeError, ValueError, GrangerNetworkError) as error:
            raise DiscoveryError(f"WAN record store is invalid: {error}") from error

    def _persist_unlocked(self) -> None:
        records = sorted(self._records.values(), key=lambda item: (item.kind, item.key))
        document = {
            "records": [
                {
                    "expiresAt": item.expires_at,
                    "key": item.key,
                    "kind": item.kind,
                    "payload": encode_base64url(item.payload),
                    "sequence": item.sequence,
                }
                for item in records
            ],
            "version": WAN_DISCOVERY_VERSION,
        }
        atomic_write_text(
            self.path,
            json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    def store(self, envelope: RecordEnvelope, now: int | None = None) -> None:
        canonical = decode_record_envelope(encode_record_envelope(envelope), now=now)
        key = (canonical.kind, canonical.key)
        with self._lock:
            previous = self._records.get(key)
            if previous is not None:
                if canonical.sequence < previous.sequence:
                    raise ReplayError("WAN record store rejected a rollback")
                if canonical.sequence == previous.sequence and canonical.payload != previous.payload:
                    raise ReplayError("WAN record store rejected equivocation")
                if canonical.sequence == previous.sequence:
                    return
            elif len(self._records) >= self.maximum:
                raise DiscoveryError("WAN record store is full")
            self._records[key] = canonical
            self._persist_unlocked()

    def fetch(self, kind: str, key: str, now: int | None = None) -> RecordEnvelope | None:
        current = int(time.time()) if now is None else now
        with self._lock:
            envelope = self._records.get((kind, key))
            if envelope is not None and envelope.expires_at <= current:
                del self._records[(kind, key)]
                self._persist_unlocked()
                return None
            return envelope


class WanDiscoveryClient:
    def __init__(
        self,
        identity: ServiceIdentity,
        pool: BootstrapPool,
        *,
        cache: PeerCache | None = None,
        replication_factor: int = 3,
        minimum_replicas: int = 2,
        timeout: float = 5.0,
    ) -> None:
        if not 2 <= minimum_replicas <= replication_factor <= 8:
            raise DiscoveryError("WAN discovery replication policy is invalid")
        self.identity = identity
        self.pool = pool
        self.cache = cache
        self.replication_factor = replication_factor
        self.minimum_replicas = minimum_replicas
        self.timeout = timeout
        self._highest_seen: dict[tuple[str, str], int] = {}
        self._failed_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _request(self, peer: NodeDescriptor, message: RpcType, payload: bytes, expected: RpcType) -> bytes:
        connection = None
        try:
            connection = connect_authenticated_peer(
                peer,
                self.identity,
                PeerRole.CLIENT,
                timeout=self.timeout,
            )
            response = connection.rpc.request(message, payload, expected=expected)
            if self.cache is not None:
                self.cache.add(peer)
            with self._lock:
                self._failed_until.pop(peer.node_id, None)
            return response.payload
        except (GrangerNetworkError, OSError):
            with self._lock:
                self._failed_until[peer.node_id] = time.monotonic() + max(
                    5.0,
                    min(60.0, self.timeout * 4.0),
                )
            raise
        finally:
            if connection is not None:
                connection.close()

    def find_nodes(self, target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        seeds = list(self.pool.candidates("discovery"))
        with self._lock:
            current = time.monotonic()
            pending = [
                peer
                for peer in seeds
                if self._failed_until.get(peer.node_id, 0.0) <= current
            ]
        if not pending:
            pending = seeds
        known = {peer.node_id: peer for peer in pending}
        queried: set[str] = set()
        while pending and len(queried) < MAX_DISCOVERY_QUERIES:
            pending.sort(key=lambda peer: int.from_bytes(_node_id_bytes(peer.node_id), "big") ^ int.from_bytes(target, "big"))
            peer = pending.pop(0)
            if peer.node_id in queried:
                continue
            queried.add(peer.node_id)
            try:
                content = self._request(
                    peer,
                    RpcType.FIND_NODE,
                    encode_find_node(target, capability),
                    RpcType.FIND_NODE,
                )
                learned = decode_node_list(content)
            except (GrangerNetworkError, OSError):
                continue
            for candidate in learned:
                if self.cache is not None:
                    self.cache.add(candidate)
                previous = known.get(candidate.node_id)
                if previous is None or candidate.issued_at > previous.issued_at:
                    known[candidate.node_id] = candidate
                    if candidate.node_id not in queried and "discovery" in candidate.capabilities:
                        pending.append(candidate)
        result = [
            peer
            for peer in known.values()
            if capability in peer.capabilities and peer.reachability == "reachable"
        ]
        result.sort(key=lambda peer: int.from_bytes(_node_id_bytes(peer.node_id), "big") ^ int.from_bytes(target, "big"))
        return tuple(result)

    def publish(self, record: DistributedRecord, now: int | None = None) -> int:
        envelope = encode_record(record, now=now)
        target = wan_routing_key(envelope.kind, envelope.key)
        peers = self.find_nodes(target, "discovery")
        if len(peers) < self.minimum_replicas:
            raise DiscoveryError("WAN discovery found too few storage peers")
        stored = 0
        for peer in peers:
            try:
                self._request(
                    peer,
                    RpcType.STORE_RECORD,
                    encode_record_envelope(envelope),
                    RpcType.STORE_RECORD,
                )
                stored += 1
                if stored >= self.replication_factor:
                    break
            except (GrangerNetworkError, OSError):
                continue
        if stored < self.minimum_replicas:
            raise DiscoveryError("WAN publication did not reach its replica quorum")
        with self._lock:
            self._highest_seen[(envelope.kind, envelope.key)] = envelope.sequence
        return stored

    def lookup(self, kind: str, key: str, now: int | None = None) -> DistributedRecord:
        target = wan_routing_key(kind, key)
        peers = self.find_nodes(target, "discovery")
        candidates: list[RecordEnvelope] = []
        for peer in peers:
            try:
                payload = self._request(
                    peer,
                    RpcType.FIND_RECORD,
                    encode_find_record(kind, key),
                    RpcType.FIND_RECORD,
                )
                envelope = decode_optional_record(payload, now=now)
                if envelope is not None and envelope.kind == kind and envelope.key == key:
                    candidates.append(envelope)
            except (GrangerNetworkError, OSError):
                continue
        if len(candidates) < self.minimum_replicas:
            raise ResolutionError(f"WAN record replica quorum is unavailable: {kind}:{key}")
        highest = max(candidate.sequence for candidate in candidates)
        with self._lock:
            previous = self._highest_seen.get((kind, key), -1)
            if highest < previous:
                raise ReplayError("WAN lookup detected a record rollback")
        winners = [candidate for candidate in candidates if candidate.sequence == highest]
        payloads = {candidate.payload for candidate in winners}
        if len(payloads) != 1 or len(winners) < self.minimum_replicas:
            raise DiscoveryError("WAN lookup did not obtain an unambiguous replica quorum")
        result = decode_record(kind, key, winners[0].payload, now=now)
        with self._lock:
            self._highest_seen[(kind, key)] = highest
        return result


class WanDistributedResolver:
    """WAN signed-record resolver with no DNS or compatibility fallback."""

    def __init__(
        self,
        discovery: WanDiscoveryClient,
        alias_pins: dict[str, str] | None = None,
    ) -> None:
        self.discovery = discovery
        self._alias_pins: dict[str, str] = {}
        for alias, service_id in (alias_pins or {}).items():
            normalized = normalize_name(alias)
            self._alias_pins[normalized] = validate_service_id(service_id)

    def resolve(self, name: str, now: int | None = None) -> ServiceDescriptor:
        normalized = normalize_name(name)
        if is_canonical_name(normalized):
            service_id = service_id_from_name(normalized)
        else:
            expected = self._alias_pins.get(normalized)
            if expected is None:
                raise ResolutionError(
                    f"WAN alias requires a local identity pin: {normalized}"
                )
            alias = self.discovery.lookup(ALIAS_RECORD, normalized, now=now)
            if not isinstance(alias, AliasRecord) or alias.service_id != expected:
                raise ResolutionError("WAN alias does not match its local identity pin")
            service_id = expected
        record = self.discovery.lookup(SERVICE_RECORD, service_id, now=now)
        if not isinstance(record, ServiceDescriptor):
            raise ResolutionError("WAN service record has the wrong type")
        if record.endpoint is not None:
            raise ResolutionError("WAN service record disclosed a service endpoint")
        return record

    def resolve_introduction(
        self,
        service: ServiceDescriptor,
        now: int | None = None,
    ) -> IntroductionDescriptor:
        service.verify(now=now)
        record = self.discovery.lookup(
            INTRODUCTION_RECORD,
            service.service_id,
            now=now,
        )
        if not isinstance(record, IntroductionDescriptor):
            raise ResolutionError("WAN introduction record has the wrong type")
        record.verify_for(service, now=now)
        return record

    def resolve_node(self, node_id: str, now: int | None = None) -> NodeDescriptor:
        record = self.discovery.lookup(NODE_RECORD, validate_node_id(node_id), now=now)
        if not isinstance(record, NodeDescriptor):
            raise ResolutionError("WAN node record has the wrong type")
        return record
