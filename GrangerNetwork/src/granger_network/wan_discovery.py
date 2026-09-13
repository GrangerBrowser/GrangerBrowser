from __future__ import annotations

from .stage_trace import traced
from .stage_trace import stage

import base64
import hashlib
import ipaddress
import json
import secrets
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ._codec import atomic_write_text, decode_base64url, encode_base64url, parse_json_object
from .binary import BinaryReader, BinaryWriter
from .bootstrap import BootstrapPool, BootstrapSet, PeerCache
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
from .errors import DescriptorError, DiscoveryError, GrangerNetworkError, IdentityVerificationError, NetworkUnavailableError, ProtocolError, RecordQuorumError, ReplayError, ResolutionError, ResourceLimitError
from .identity import ServiceIdentity
from .peer import NodeDescriptor, node_supports_route_role, validate_node_id
from .peer_rpc import (
    PeerRole,
    RESILIENT_PEER_CONNECT_ATTEMPTS,
    RpcType,
    _verify_pinned_server_descriptor,
    connect_authenticated_peer,
)
from .reseed import (
    MAX_RESEED_BUNDLE_BYTES,
    MAX_RESEED_TRANSPORT_CHUNK_BYTES,
    ReseedAdvertisement,
    ReseedStore,
    decode_reseed_advertisements,
    decode_reseed_chunk_response,
    encode_reseed_chunk_request,
)
from .address import is_canonical_name, normalize_name, service_id_from_name
from .descriptor import ServiceDescriptor
from .introduction import AliasRecord, IntroductionDescriptor
from .network_health import NetworkHealth, NetworkHealthSnapshot, NetworkState
from .peer import RELAY_CAPABILITIES
from .rendezvous_control import validate_service_id
from .wan_routing import order_diverse_relay_combinations


WAN_DISCOVERY_VERSION = 1
MAX_WAN_RECORDS = 4096
MAX_FIND_NODE_RESULTS = 32
MAX_PEER_SAMPLE_RESULTS = 32
MAX_PUBLIC_SERVICE_SAMPLE = 16
MAX_DISCOVERY_QUERIES = 32
MAX_PARALLEL_DISCOVERY_REQUESTS = 4
MAX_RECORD_REQUEST_ROUNDS = 2
MAX_ROUTE_CANDIDATE_CACHE_ENTRIES = 128
MAX_DISCOVERY_PEER_TRACKING_ENTRIES = 2048
MAX_ROLLBACK_TRACKING_ENTRIES = 4096
ROUTE_CANDIDATE_CACHE_TTL_SECONDS = 5 * 60.0
PRIVATE_ROUTE_HINT_TTL_SECONDS = 60.0
RESEED_REFRESH_MARGIN_SECONDS = 15 * 60
MAX_RESEED_FETCH_ATTEMPTS = 8
MAX_RESEED_QUERY_PEERS = 16
RESEED_REFRESH_RETRY_SECONDS = 60.0
MAX_PRIVATE_ROUTE_ATTEMPTS = 12
MAX_PRIVATE_ROUTE_ROLE_CANDIDATES = 32
_ROUTING_KEY_DOMAIN = b"granger-network-v0.4/wan-routing-key\x00"
_PRIVATE_DISCOVERY_ROUTE_DOMAIN = b"granger-network-v0.5/private-discovery-route\x00"


def _route_edge_key(left, left_role, right, right_role):
    return (left.node_id, left.issued_at, left_role, right.node_id, right.issued_at, right_role)


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


def encode_peer_sample(capability: str, limit: int = 16) -> bytes:
    if (
        not isinstance(capability, str)
        or not capability
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_PEER_SAMPLE_RESULTS
    ):
        raise ProtocolError("WAN peer sample request is invalid")
    return BinaryWriter(128).text_u16(capability, 32).u8(limit).build()


def decode_peer_sample(content: bytes) -> tuple[str, int]:
    reader = BinaryReader(content, 128)
    capability = reader.text_u16(32)
    limit = reader.u8()
    reader.finish()
    if not capability or not 1 <= limit <= MAX_PEER_SAMPLE_RESULTS:
        raise ProtocolError("WAN peer sample request is invalid")
    return capability, limit


def encode_node_list(peers: list[NodeDescriptor] | tuple[NodeDescriptor, ...]) -> bytes:
    if len(peers) > MAX_FIND_NODE_RESULTS:
        raise ProtocolError("WAN node response has too many peers")
    writer = BinaryWriter(MAX_FIND_NODE_RESULTS * 64 * 1024 + 4).u16(len(peers))
    for peer in peers:
        peer.verify()
        writer.bytes_u32(peer.to_json().encode("ascii"), 64 * 1024)
    return writer.build()


def decode_node_list(
    content: bytes,
    now: int | None = None,
    *,
    expected_network_id: str | None = None,
    expected_protocol_version: int | None = None,
) -> tuple[NodeDescriptor, ...]:
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
                expected_network_id=expected_network_id,
                expected_protocol_version=expected_protocol_version,
            )
        except UnicodeDecodeError as error:
            raise ProtocolError("WAN node descriptor is not ASCII") from error
        if peer.node_id in seen:
            raise ProtocolError("WAN node response repeats a peer")
        seen.add(peer.node_id)
        peers.append(peer)
    reader.finish()
    return tuple(peers)


def encode_public_service_sample(records: tuple[RecordEnvelope, ...]) -> bytes:
    if len(records) > MAX_PUBLIC_SERVICE_SAMPLE:
        raise ProtocolError("public service sample exceeds its limit")
    writer = BinaryWriter(MAX_PUBLIC_SERVICE_SAMPLE * (MAX_DISTRIBUTED_RECORD_SIZE + 512))
    writer.u8(len(records))
    for record in records:
        service = decode_record(record.kind, record.key, record.payload)
        if not isinstance(service, ServiceDescriptor) or not service.publicly_listed:
            raise ProtocolError("public service sample contains an unlisted record")
        writer.bytes_u32(encode_record_envelope(record), MAX_DISTRIBUTED_RECORD_SIZE + 512)
    return writer.build()


def decode_public_service_sample(payload: bytes) -> tuple[ServiceDescriptor, ...]:
    reader = BinaryReader(payload, MAX_PUBLIC_SERVICE_SAMPLE * (MAX_DISTRIBUTED_RECORD_SIZE + 512))
    count = reader.u8()
    if count > MAX_PUBLIC_SERVICE_SAMPLE:
        raise ProtocolError("public service sample exceeds its limit")
    result = []
    seen = set()
    for _ in range(count):
        envelope = decode_record_envelope(reader.bytes_u32(MAX_DISTRIBUTED_RECORD_SIZE + 512))
        service = decode_record(envelope.kind, envelope.key, envelope.payload)
        if (not isinstance(service, ServiceDescriptor) or not service.publicly_listed
                or service.service_id in seen):
            raise ProtocolError("public service sample is invalid")
        seen.add(service.service_id)
        result.append(service)
    reader.finish()
    return tuple(result)


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

    def _purge_expired_unlocked(self, now: int) -> bool:
        expired = tuple(
            key for key, envelope in self._records.items()
            if envelope.expires_at <= now
        )
        for key in expired:
            del self._records[key]
        return bool(expired)

    def store(self, envelope: RecordEnvelope, now: int | None = None) -> None:
        canonical = decode_record_envelope(encode_record_envelope(envelope), now=now)
        key = (canonical.kind, canonical.key)
        current = int(time.time()) if now is None else now
        with self._lock:
            self._purge_expired_unlocked(current)
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
            if self._purge_expired_unlocked(current):
                self._persist_unlocked()
            return self._records.get((kind, key))

    def public_service_sample(self, now: int | None = None) -> tuple[RecordEnvelope, ...]:
        current = int(time.time()) if now is None else now
        with self._lock:
            self._purge_expired_unlocked(current)
            records = tuple(self._records.values())
        result = []
        for record in sorted(records, key=lambda item: item.key):
            if record.kind != SERVICE_RECORD:
                continue
            service = decode_record(record.kind, record.key, record.payload, now=current)
            if isinstance(service, ServiceDescriptor) and service.publicly_listed:
                result.append(record)
                if len(result) == MAX_PUBLIC_SERVICE_SAMPLE:
                    break
        return tuple(result)


class _RecordCircuits:
    """Bounded circuits for one record transaction, never shared across records."""

    def __init__(self, target: bytes, message: RpcType, payload: bytes, timeout: float):
        self.allowed = {RpcType.FIND_NODE: encode_find_node(target, "discovery"), message: payload}
        self.timeout = min(timeout, 30.0)
        self.lock = threading.Lock()
        self.circuits = {}
        self.route_failures = {}
        self.closed = False

    def failed_routes(self, peer):
        with self.lock:
            routes, edges = self.route_failures.get(peer.node_id, (set(), set()))
            return set(routes), set(edges)

    def remember_route_failure(self, peer, route_ids, edges):
        with self.lock:
            if self.closed:
                return
            if peer.node_id not in self.route_failures and len(self.route_failures) >= MAX_FIND_NODE_RESULTS:
                return
            routes, previous_edges = self.route_failures.setdefault(peer.node_id, (set(), set()))
            if len(routes) < MAX_PRIVATE_ROUTE_ATTEMPTS:
                routes.add(route_ids)
                previous_edges.update(edges)

    def validate_request(self, message: RpcType, payload: bytes) -> None:
        if self.closed or self.allowed.get(message) != payload:
            raise DiscoveryError("record circuit scope does not authorize this request")

    def take(self, peer: NodeDescriptor):
        with self.lock:
            entry = self.circuits.pop(peer.node_id, None)
        if entry is None:
            return None
        circuit, retained_at = entry
        try:
            if time.monotonic() - retained_at > self.timeout or circuit._closed:
                raise DiscoveryError("record circuit reuse window expired")
            for descriptor, _role in circuit.route:
                descriptor.verify(expected_network_id=peer.network_id,
                                  expected_protocol_version=peer.protocol_version)
            _verify_pinned_server_descriptor(peer, circuit.endpoint.remote.descriptor)
            if any(mux.failed for mux in circuit.multiplexers):
                raise DiscoveryError("record circuit transport failed")
            return circuit
        except (GrangerNetworkError, OSError):
            circuit.close()
            return None

    def keep(self, peer: NodeDescriptor, circuit) -> None:
        with self.lock:
            if (not self.closed and peer.node_id not in self.circuits
                    and len(self.circuits) < MAX_PARALLEL_DISCOVERY_REQUESTS):
                self.circuits[peer.node_id] = (circuit, time.monotonic())
                return
        circuit.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        with self.lock:
            self.closed = True
            circuits = tuple(self.circuits.values())
            self.circuits.clear()
            self.route_failures.clear()
        for circuit, _retained_at in circuits:
            circuit.close()


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
        reseed_store: ReseedStore | None = None,
    ) -> None:
        if not 2 <= minimum_replicas <= replication_factor <= 8:
            raise DiscoveryError("WAN discovery replication policy is invalid")
        self.identity = identity
        self.pool = pool
        self.cache = cache
        self.replication_factor = replication_factor
        self.minimum_replicas = minimum_replicas
        self.timeout = timeout
        if reseed_store is not None and (
            reseed_store.network_id != pool.network_id
            or reseed_store.protocol_version != pool.protocol_version
        ):
            raise DiscoveryError("WAN discovery reseed store belongs to a different network")
        self.reseed_store = reseed_store
        self._reseed_refresh_lock = threading.Lock()
        self.reseed_refreshes = 0
        self._reseed_next_attempt = 0.0
        self._highest_seen: dict[tuple[str, str], tuple[int, int]] = {}
        self._max_rollback_tracking_entries = MAX_ROLLBACK_TRACKING_ENTRIES
        self._failed_until: OrderedDict[str, float] = OrderedDict()
        self._failed_route_edges: OrderedDict[tuple[str, int, str, str, int, str], float] = OrderedDict()
        self._exhausted_discovery_searches: OrderedDict[tuple[str, int], float] = OrderedDict()
        self._lock = threading.Lock()
        self._join_lock = threading.Lock()
        self._joined = False
        self._private_routes_ready = False
        self._route_nodes: dict[str, NodeDescriptor] = {}
        self._route_candidate_cache: OrderedDict[
            tuple[bytes, str], tuple[float, tuple[NodeDescriptor, ...]]
        ] = OrderedDict()
        self._private_route_hints: OrderedDict[
            str, tuple[float, tuple[str, ...]]
        ] = OrderedDict()
        self.direct_first_contact_requests = 0
        self.private_discovery_requests = 0
        self.last_private_route: tuple[str, ...] = ()
        self._health = NetworkHealth()
        self._authenticated_nodes: OrderedDict[str, None] = OrderedDict()
        self._first_contact_operation = ""
        self._first_contact_trace: deque[dict[str, object]] = deque(maxlen=32)

    def health(self) -> NetworkHealthSnapshot:
        return self._health.snapshot()

    def signed_bootstrap_node(
        self,
        node_id: str,
        *,
        now: int | None = None,
    ) -> NodeDescriptor | None:
        """Return a current node descriptor covered by a verified bootstrap set."""
        validated = validate_node_id(node_id)
        selected = None
        for bootstrap_set in getattr(self.pool, "bootstrap_sets", ()):
            for peer in bootstrap_set.peers:
                if peer.node_id != validated or peer.reachability != "reachable":
                    continue
                try:
                    peer.verify(
                        now=now,
                        expected_network_id=self.pool.network_id,
                        expected_protocol_version=self.pool.protocol_version,
                    )
                except DescriptorError:
                    continue
                if selected is None or peer.issued_at > selected.issued_at:
                    selected = peer
                elif peer.issued_at == selected.issued_at and peer != selected:
                    raise DiscoveryError("signed bootstrap node descriptor equivocation")
        return selected

    def first_contact_diagnostics(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(dict(event) for event in self._first_contact_trace)

    def _prune_peer_tracking_unlocked(self, now: float) -> None:
        expired = tuple(
            node_id
            for node_id, retry_at in self._failed_until.items()
            if retry_at <= now
        )
        for node_id in expired:
            self._failed_until.pop(node_id, None)
        while len(self._failed_until) > MAX_DISCOVERY_PEER_TRACKING_ENTRIES:
            self._failed_until.popitem(last=False)
        while len(self._authenticated_nodes) > MAX_DISCOVERY_PEER_TRACKING_ENTRIES:
            self._authenticated_nodes.popitem(last=False)
        for edge, retry_at in tuple(self._failed_route_edges.items()):
            if retry_at <= now:
                self._failed_route_edges.pop(edge, None)
        while len(self._failed_route_edges) > MAX_DISCOVERY_PEER_TRACKING_ENTRIES:
            self._failed_route_edges.popitem(last=False)
        for key, retry_at in tuple(self._exhausted_discovery_searches.items()):
            if retry_at <= now:
                self._exhausted_discovery_searches.pop(key, None)
        while len(self._exhausted_discovery_searches) > MAX_DISCOVERY_PEER_TRACKING_ENTRIES:
            self._exhausted_discovery_searches.popitem(last=False)

    def _record_peer_success(self, node_id: str) -> None:
        with self._lock:
            self._prune_peer_tracking_unlocked(time.monotonic())
            self._failed_until.pop(node_id, None)
            self._authenticated_nodes[node_id] = None
            self._authenticated_nodes.move_to_end(node_id)
            self._prune_peer_tracking_unlocked(time.monotonic())

    def _record_peer_failure(self, node_id: str, retry_at: float) -> None:
        with self._lock:
            self._prune_peer_tracking_unlocked(time.monotonic())
            self._failed_until[node_id] = retry_at
            self._failed_until.move_to_end(node_id)
            self._prune_peer_tracking_unlocked(time.monotonic())

    def _purge_rollback_tracking_unlocked(self, now: int) -> None:
        expired = tuple(
            key
            for key, (_sequence, expires_at) in self._highest_seen.items()
            if expires_at <= now
        )
        for key in expired:
            del self._highest_seen[key]

    def _remember_record_sequence(
        self,
        kind: str,
        key: str,
        sequence: int,
        expires_at: int,
        *,
        now: int,
    ) -> None:
        record_key = (kind, key)
        with self._lock:
            self._purge_rollback_tracking_unlocked(now)
            previous = self._highest_seen.get(record_key)
            if previous is not None and sequence < previous[0]:
                raise ReplayError("WAN lookup detected a record rollback")
            if (
                previous is None
                and len(self._highest_seen) >= self._max_rollback_tracking_entries
            ):
                raise ResourceLimitError("WAN rollback tracking limit is exhausted")
            self._highest_seen[record_key] = (sequence, expires_at)

    def _record_first_contact(
        self, peer: NodeDescriptor, stage: str, reason: str,
        started: float, attempt: int,
    ) -> None:
        # Only public node fingerprints and fixed codes leave this boundary.
        # Exception strings may contain paths, addresses, or remote input.
        with self._lock:
            self._first_contact_trace.append({
                "operationId": self._first_contact_operation,
                "monotonicSeconds": round(time.monotonic(), 3),
                "elapsedMs": round((time.monotonic() - started) * 1000, 3),
                "nodeId": peer.node_id,
                "role": "discovery",
                "stage": stage,
                "reason": reason,
                "attempt": attempt,
                "timeoutSeconds": self.timeout,
            })

    @staticmethod
    def _first_contact_reason(peer: NodeDescriptor, stage: str, error: BaseException) -> str:
        if isinstance(error, DescriptorError):
            return (
                "FIRST_CONTACT_DESCRIPTOR_EXPIRED"
                if peer.expires_at <= int(time.time())
                else "FIRST_CONTACT_DESCRIPTOR_REJECTED"
            )
        if isinstance(error, IdentityVerificationError):
            return "FIRST_CONTACT_AUTH_REJECTED"
        prefix = {
            "tcp": "FIRST_CONTACT_TCP",
            "authentication": "FIRST_CONTACT_AUTH",
            "peer-sample": "FIRST_CONTACT_PEER_SAMPLE",
        }.get(stage, "FIRST_CONTACT")
        if isinstance(error, TimeoutError):
            return prefix + "_TIMEOUT"
        if isinstance(error, ConnectionRefusedError):
            return prefix + "_REFUSED"
        if isinstance(error, ProtocolError):
            return prefix + "_REJECTED"
        return prefix + "_FAILED"

    def _health_counts(self, peers: tuple[NodeDescriptor, ...] | None = None) -> tuple[int, int]:
        known = peers if peers is not None else self.pool.candidates("discovery")
        reachable_relays = sum(
            peer.reachability == "reachable"
            and bool(set(peer.capabilities) & RELAY_CAPABILITIES)
            for peer in known
        )
        return len({peer.node_id for peer in known}), reachable_relays

    @staticmethod
    def _network_group(peer: NodeDescriptor) -> tuple[int, int]:
        address = ipaddress.ip_address(peer.endpoint.host)
        prefix = 16 if address.version == 4 else 32
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        return address.version, int(network.network_address)

    def _private_route_candidates(
        self,
        peer: NodeDescriptor,
        *,
        limit: int = 4,
        attempted_routes: set[tuple[str, ...]] | None = None,
        failed_edges: set[tuple[str, str, str, str]] | None = None,
    ) -> tuple[tuple[tuple[NodeDescriptor, str], ...], ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 64:
            raise DiscoveryError("private route candidate limit is invalid")
        excluded = {peer.node_id}
        wall_now = int(time.time())
        guard_seed = hashlib.sha256(
            _PRIVATE_DISCOVERY_ROUTE_DOMAIN + self.identity.public_key_bytes
        ).digest()
        with self._lock:
            current = time.monotonic()
            self._prune_peer_tracking_unlocked(current)
            route_nodes = tuple(self._route_nodes.values())
            authenticated = frozenset(self._authenticated_nodes)
            unavailable_route_edges = frozenset(self._failed_route_edges)
            failed = {
                node_id
                for node_id, retry_at in self._failed_until.items()
                if retry_at > current
            }

        def candidates(capability: str) -> list[NodeDescriptor]:
            selected = {
                node.node_id: node
                for node in (*self.pool.candidates(capability), *route_nodes)
                if node_supports_route_role(node, capability)
                and node.expires_at > wall_now
                and node.node_id not in excluded
                and (capability != "access" or node.node_id not in failed)
            }
            if capability == "middle":
                selected = {
                    node_id: node for node_id, node in selected.items()
                    if node.reachability != "adjacent" or node.via_node_id in guard_ids
                }
            result = list(selected.values())
            if len(result) <= MAX_PRIVATE_ROUTE_ROLE_CANDIDATES:
                return result
            # Bound the cubic search while sampling across advertised network groups.
            groups: dict[tuple[int, int], deque[NodeDescriptor]] = {}
            for node in sorted(result, key=lambda item: hashlib.sha256(
                guard_seed + item.node_id.encode("ascii")
            ).digest()):
                groups.setdefault(self._network_group(node), deque()).append(node)
            result = []
            while groups and len(result) < MAX_PRIVATE_ROUTE_ROLE_CANDIDATES:
                for group in tuple(groups):
                    result.append(groups[group].popleft())
                    if not groups[group]:
                        del groups[group]
                    if len(result) == MAX_PRIVATE_ROUTE_ROLE_CANDIDATES:
                        break
            return result

        accesses = [
            node for node in candidates("access")
        ]
        guards = [
            node for node in candidates("entry")
        ]
        guard_ids = {node.node_id for node in guards}
        middles = [
            node for node in candidates("middle")
        ]
        guards.sort(
            key=lambda node: hashlib.sha256(
                guard_seed + node.node_id.encode("ascii")
            ).digest()
        )
        choices: list[
            tuple[int, int, int, NodeDescriptor, NodeDescriptor, NodeDescriptor]
        ] = []
        eligible_before_retry_filter = False
        random_offset = int.from_bytes(secrets.token_bytes(4), "big")
        network_groups = {
            node.node_id: self._network_group(node)
            for node in (*accesses, *guards, *middles, peer)
        }
        for guard_index, guard in enumerate(guards):
            for access_index, access in enumerate(accesses):
                for middle_index, middle in enumerate(middles):
                    if (
                        not node_supports_route_role(
                            middle,
                            "middle",
                            previous_node_id=guard.node_id,
                        )
                        or (
                            middle.reachability == "adjacent"
                            and middle.endpoint != guard.endpoint
                        )
                    ):
                        continue
                    route_nodes = (access, guard, middle, peer)
                    if len({node.node_id for node in route_nodes}) != len(route_nodes):
                        continue
                    eligible_before_retry_filter = True
                    if unavailable_route_edges and (
                        _route_edge_key(access, "access", guard, "entry") in unavailable_route_edges
                        or _route_edge_key(guard, "entry", middle, "middle") in unavailable_route_edges
                        or _route_edge_key(middle, "middle", peer, "discovery") in unavailable_route_edges
                    ):
                        continue
                    if attempted_routes and tuple(node.node_id for node in route_nodes) in attempted_routes:
                        continue
                    roles = ("access", "entry", "middle", "discovery")
                    if failed_edges and any(
                        (left.node_id, roles[index], right.node_id, roles[index + 1]) in failed_edges
                        for index, (left, right) in enumerate(zip(route_nodes, route_nodes[1:]))
                    ):
                        continue
                    groups = {network_groups[node.node_id] for node in route_nodes}
                    choices.append(
                        (
                            len(route_nodes) - len(groups),
                            sum(node.node_id not in authenticated for node in route_nodes[:-1])
                                * (len(guards) + 1) + guard_index,
                            (access_index + middle_index + random_offset) % 65536,
                            access,
                            guard,
                            middle,
                        )
                    )
        if not choices:
            if eligible_before_retry_filter:
                return ()
            raise DiscoveryError("private discovery ingress is unavailable")
        ordered_choices = order_diverse_relay_combinations(choices, limit=limit)
        with self._lock:
            hint = self._private_route_hints.get(peer.node_id)
            if hint is not None and hint[0] <= time.monotonic():
                self._private_route_hints.pop(peer.node_id, None)
                hint = None
        if hint is not None:
            # Reuse only currently eligible identities; every circuit authenticates anew.
            best_diversity = min(item[0] for item in choices)
            preferred = next(
                (
                    choice for choice in choices
                    if (*tuple(node.node_id for node in choice[3:]), peer.node_id) == hint[1]
                    and choice[0] == best_diversity
                ),
                None,
            )
            if preferred is not None:
                ordered_choices = (
                    preferred,
                    *(choice for choice in ordered_choices if choice != preferred),
                )[:limit]
            else:
                with self._lock:
                    self._private_route_hints.pop(peer.node_id, None)
        routes: list[tuple[tuple[NodeDescriptor, str], ...]] = []
        seen: set[tuple[str, str, str]] = set()
        for _relaxed, _guard, _offset, access, guard, middle in ordered_choices:
            route_key = (access.node_id, guard.node_id, middle.node_id)
            if route_key in seen:
                continue
            seen.add(route_key)
            routes.append(
                (
                    (access, "access"),
                    (guard, "entry"),
                    (middle, "middle"),
                    (peer, "discovery"),
                )
            )
            if len(routes) >= limit:
                break
        return tuple(routes)

    def _private_route(
        self,
        peer: NodeDescriptor,
    ) -> tuple[tuple[NodeDescriptor, str], ...]:
        return self._private_route_candidates(peer, limit=1)[0]

    @traced("discovery-request")
    def _request(
        self,
        peer: NodeDescriptor,
        message: RpcType,
        payload: bytes,
        expected: RpcType,
        *,
        direct_first_contact: bool = False,
        penalize_failure: bool = True,
        record_circuits: _RecordCircuits | None = None,
    ) -> bytes:
        connection = None
        started = time.monotonic()
        stage = "descriptor"
        attempt = 0
        penalize_requested_peer = direct_first_contact

        def connection_stage(value: str, number: int) -> None:
            nonlocal stage, attempt
            stage, attempt = value, number

        try:
            if record_circuits is not None:
                if direct_first_contact:
                    raise DiscoveryError("record operations require private ingress")
                record_circuits.validate_request(message, payload)
            if direct_first_contact:
                connection = connect_authenticated_peer(
                    peer,
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=self.timeout,
                    attempts=RESILIENT_PEER_CONNECT_ATTEMPTS,
                    on_stage=connection_stage,
                )
                stage = "peer-sample"
                self.direct_first_contact_requests += 1
                response = connection.rpc.request(message, payload, expected=expected)
                self._record_first_contact(peer, stage, "OK", started, attempt)
            else:
                if not self._joined or not self._private_routes_ready:
                    raise DiscoveryError(
                        "post-join discovery requires private ingress"
                    )
                from .circuit import CircuitBuilder

                search_key = (peer.node_id, peer.issued_at)
                if message is RpcType.FIND_NODE:
                    with self._lock:
                        self._prune_peer_tracking_unlocked(time.monotonic())
                        if search_key in self._exhausted_discovery_searches:
                            raise DiscoveryError("private discovery search is cooling down")
                response = None
                last_error: BaseException | None = None
                tracked_failures = set()
                attempted_routes, failed_edges = (record_circuits.failed_routes(peer)
                    if record_circuits is not None else (set(), set()))
                pending_routes = []

                def eligible(candidate):
                    if (tuple(node.node_id for node, _ in candidate) in attempted_routes
                            or any((left.node_id, left_role, right.node_id, right_role) in failed_edges
                                for (left, left_role), (right, right_role) in zip(candidate, candidate[1:]))):
                        return False
                    # Other record lookups can learn failures while this queue waits.
                    with self._lock:
                        current = time.monotonic()
                    return (self._failed_until.get(candidate[0][0].node_id, 0.0) <= current
                        and not any(self._failed_route_edges.get(
                            _route_edge_key(left, left_role, right, right_role), 0.0) > current
                            for (left, left_role), (right, right_role) in zip(candidate, candidate[1:])))

                for _route_attempt in range(MAX_PRIVATE_ROUTE_ATTEMPTS - len(attempted_routes)):
                    circuit = (record_circuits.take(peer)
                               if record_circuits is not None and _route_attempt == 0 else None)
                    if circuit is not None:
                        route = circuit.route
                    else:
                        pending_routes = [candidate for candidate in pending_routes if eligible(candidate)]
                        if not pending_routes:
                            pending_routes = [candidate for candidate in self._private_route_candidates(
                                peer, attempted_routes=attempted_routes, failed_edges=failed_edges)
                                if eligible(candidate)]
                        route = pending_routes.pop(0) if pending_routes else None
                    if route is None:
                        break
                    route_ids = tuple(node.node_id for node, _role in route)
                    attempted_routes.add(route_ids)
                    try:
                        if circuit is None:
                            circuit = CircuitBuilder(
                                self.identity,
                                PeerRole.CLIENT,
                                timeout=self.timeout,
                            ).open(route)
                        self.private_discovery_requests += 1
                        self.last_private_route = tuple(
                            descriptor.node_id for descriptor, _role in circuit.route
                        )
                        circuit.endpoint.channel.connection.settimeout(self.timeout)
                        response = circuit.endpoint.rpc.request(
                            message,
                            payload,
                            expected=expected,
                        )
                        for authenticated_peer, _role in circuit.route:
                            self._record_peer_success(authenticated_peer.node_id)
                        with self._lock:
                            if message is RpcType.FIND_NODE:
                                self._exhausted_discovery_searches.pop(search_key, None)
                            for (left, left_role), (right, right_role) in zip(circuit.route, circuit.route[1:]):
                                self._failed_route_edges.pop(_route_edge_key(left, left_role, right, right_role), None)
                            self._private_route_hints[peer.node_id] = (
                                time.monotonic() + PRIVATE_ROUTE_HINT_TTL_SECONDS,
                                route_ids,
                            )
                            self._private_route_hints.move_to_end(peer.node_id)
                            while len(self._private_route_hints) > MAX_ROUTE_CANDIDATE_CACHE_ENTRIES:
                                self._private_route_hints.popitem(last=False)
                        if record_circuits is not None:
                            record_circuits.keep(peer, circuit)
                            circuit = None
                        break
                    except (GrangerNetworkError, OSError) as error:
                        last_error = error
                        failed_hop = getattr(error, "circuit_failure_hop_index", None)
                        if (
                            penalize_failure
                            and isinstance(failed_hop, int)
                            and not isinstance(failed_hop, bool)
                            and 0 <= failed_hop < len(route)
                        ):
                            if failed_hop == 0:
                                pending_routes.clear()
                                failed_peer = route[0][0]
                                retry_at = time.monotonic() + max(
                                    60.0, min(300.0, self.timeout * 12.0),
                                )
                                if self.cache is not None:
                                    self.cache.record_failure(failed_peer)
                                self._record_peer_failure(failed_peer.node_id, retry_at)
                            else:
                                # A nested failure identifies a directed role edge,
                                # not global node reachability. Retain bounded,
                                # descriptor-versioned backoff across searches.
                                left, left_role = route[failed_hop - 1]
                                right, right_role = route[failed_hop]
                                failed_edges.add((left.node_id, left_role, right.node_id, right_role))
                                if (failed_hop == len(route) - 1
                                        or getattr(error, "circuit_failure_stage", None) == "extension"):
                                    tracked_failures.add(route_ids)
                                    edge = _route_edge_key(left, left_role, right, right_role)
                                    with self._lock:
                                        self._failed_route_edges[edge] = time.monotonic() + max(
                                            60.0, min(300.0, self.timeout * 12.0))
                                        self._failed_route_edges.move_to_end(edge)
                                        self._prune_peer_tracking_unlocked(time.monotonic())
                        if record_circuits is not None:
                            # FIND_NODE and the following record operation share a
                            # route failure budget, not a service-offline assertion.
                            record_circuits.remember_route_failure(peer, route_ids, failed_edges)
                        # A lost end-to-end transport cannot prove that the final
                        # discovery peer is down; any preceding hop may have failed.
                        penalize_requested_peer = False
                        with self._lock:
                            hint = self._private_route_hints.get(peer.node_id)
                            if hint is not None and hint[1] == route_ids:
                                self._private_route_hints.pop(peer.node_id, None)
                    finally:
                        if circuit is not None:
                            circuit.close()
                if response is None:
                    if (message is RpcType.FIND_NODE
                            and tracked_failures
                            and (len(tracked_failures) == len(attempted_routes)
                                 or len(attempted_routes) >= MAX_PRIVATE_ROUTE_ATTEMPTS)):
                        # A completed search owns its retry window, including
                        # intermediate extension failures. Other roles, record
                        # RPCs and newer descriptors remain eligible.
                        with self._lock:
                            self._exhausted_discovery_searches[search_key] = time.monotonic() + 60.0
                            self._exhausted_discovery_searches.move_to_end(search_key)
                            self._prune_peer_tracking_unlocked(time.monotonic())
                    if last_error is None:
                        raise DiscoveryError("private discovery ingress is unavailable")
                    raise last_error
            if self.cache is not None:
                self.cache.record_success(peer)
            self._record_peer_success(peer.node_id)
            return response.payload
        except (GrangerNetworkError, OSError) as error:
            if direct_first_contact:
                self._record_first_contact(
                    peer, stage, self._first_contact_reason(peer, stage, error),
                    started, attempt,
                )
            if penalize_failure and penalize_requested_peer:
                if self.cache is not None:
                    self.cache.record_failure(peer)
                self._record_peer_failure(
                    peer.node_id,
                    time.monotonic() + max(
                        60.0,
                        min(300.0, self.timeout * 12.0),
                    ),
                )
            raise
        finally:
            if connection is not None:
                connection.close()

    @traced("route-candidates")
    def route_candidates(
        self,
        target: bytes,
        capability: str,
    ) -> tuple[NodeDescriptor, ...]:
        if not isinstance(target, bytes) or len(target) != 32:
            raise DiscoveryError("route candidate target is invalid")
        if not isinstance(capability, str) or not capability:
            raise DiscoveryError("route candidate capability is invalid")
        joined = self.join_network()
        if joined.state is NetworkState.OFFLINE:
            raise NetworkUnavailableError(f"Granger Network first contact failed: {joined.failure_reason}")
        self.maybe_refresh_reseed()
        selected = {
            peer.node_id: peer for peer in self.pool.candidates(capability)
        }
        with self._lock:
            self._prune_peer_tracking_unlocked(time.monotonic())
            route_nodes = tuple(self._route_nodes.values())
            authenticated = frozenset(self._authenticated_nodes)
            failed_until = dict(self._failed_until)
            cache_key = (target, capability)
            cached = self._route_candidate_cache.get(cache_key)
            current = time.monotonic()
            if cached is not None and cached[0] > current:
                discovered = cached[1]
                self._route_candidate_cache.move_to_end(cache_key)
            else:
                self._route_candidate_cache.pop(cache_key, None)
                discovered = None
        for peer in route_nodes:
            try:
                peer.verify(
                    expected_network_id=self.pool.network_id,
                    expected_protocol_version=self.pool.protocol_version,
                )
            except DescriptorError:
                continue
            if not node_supports_route_role(peer, capability):
                continue
            previous = selected.get(peer.node_id)
            if previous is None or peer.issued_at > previous.issued_at:
                selected[peer.node_id] = peer
        if discovered is None and (
            not joined.dht_ready or len(selected) < self.replication_factor
        ):
            try:
                discovered = self.find_nodes(target, capability)
            except (DiscoveryError, OSError):
                if len(selected) < self.minimum_replicas:
                    raise
                discovered = ()
            if discovered:
                with self._lock:
                    self._route_candidate_cache[cache_key] = (
                        time.monotonic() + ROUTE_CANDIDATE_CACHE_TTL_SECONDS,
                        discovered,
                    )
                    self._route_candidate_cache.move_to_end(cache_key)
                    while (
                        len(self._route_candidate_cache)
                        > MAX_ROUTE_CANDIDATE_CACHE_ENTRIES
                    ):
                        self._route_candidate_cache.popitem(last=False)
        for peer in discovered or ():
            try:
                peer.verify(
                    expected_network_id=self.pool.network_id,
                    expected_protocol_version=self.pool.protocol_version,
                )
            except DescriptorError:
                continue
            if not node_supports_route_role(peer, capability):
                continue
            previous = selected.get(peer.node_id)
            if previous is None or peer.issued_at > previous.issued_at:
                selected[peer.node_id] = peer
        target_value = int.from_bytes(target, "big")
        current = time.monotonic()
        result = list(selected.values())
        result.sort(
            key=lambda peer: (
                peer.node_id not in authenticated,
                failed_until.get(peer.node_id, 0.0) > current,
                int.from_bytes(_node_id_bytes(peer.node_id), "big") ^ target_value,
            )
        )
        return tuple(result)

    @traced("dht-request-batch")
    def _request_batch(
        self,
        peers: list[NodeDescriptor],
        message: RpcType,
        payload: bytes,
        expected: RpcType,
        *,
        direct_first_contact: bool = False,
        penalize_failure: bool = True,
        record_circuits: _RecordCircuits | None = None,
    ) -> tuple[tuple[NodeDescriptor, bytes | None], ...]:
        selected = peers[:MAX_PARALLEL_DISCOVERY_REQUESTS]
        if not selected:
            return ()
        outcomes: list[bytes | BaseException | None] = [None] * len(selected)

        def request_peer(index: int, peer: NodeDescriptor) -> None:
            try:
                outcomes[index] = self._request(
                    peer,
                    message,
                    payload,
                    expected,
                    direct_first_contact=direct_first_contact,
                    penalize_failure=penalize_failure,
                    record_circuits=record_circuits,
                )
            except BaseException as error:
                outcomes[index] = error

        workers = [
            threading.Thread(
                target=request_peer,
                args=(index, peer),
                name=f"granger-discovery-{index}",
                daemon=True,
            )
            for index, peer in enumerate(selected)
        ]
        started_workers = []
        try:
            for worker in workers:
                worker.start()
                started_workers.append(worker)
        finally:
            for worker in started_workers:
                worker.join()
        results: list[tuple[NodeDescriptor, bytes | None]] = []
        for peer, outcome in zip(selected, outcomes, strict=True):
            if isinstance(outcome, (GrangerNetworkError, OSError)):
                results.append((peer, None))
            elif isinstance(outcome, BaseException):
                raise outcome
            elif outcome is None:
                raise RuntimeError("discovery request worker did not return a result")
            else:
                results.append((peer, outcome))
        return tuple(results)

    def _fetch_reseed_advertisement(
        self,
        peer: NodeDescriptor,
        advertisement: ReseedAdvertisement,
        *,
        direct_first_contact: bool,
    ) -> bool:
        if self.reseed_store is None:
            return False
        content = bytearray()
        chunk_count = 0
        while len(content) < advertisement.size:
            if chunk_count >= (
                MAX_RESEED_BUNDLE_BYTES + MAX_RESEED_TRANSPORT_CHUNK_BYTES - 1
            ) // MAX_RESEED_TRANSPORT_CHUNK_BYTES:
                raise ResourceLimitError("reseed transfer chunk limit is exhausted")
            chunk_count += 1
            response = self._request(
                peer,
                RpcType.RESEED_CHUNK,
                encode_reseed_chunk_request(advertisement.sha256, len(content)),
                RpcType.RESEED_CHUNK,
                direct_first_contact=direct_first_contact,
                penalize_failure=False,
            )
            digest, offset, total_size, chunk = decode_reseed_chunk_response(response)
            if (
                digest != advertisement.sha256
                or offset != len(content)
                or total_size != advertisement.size
                or len(chunk) != min(
                    MAX_RESEED_TRANSPORT_CHUNK_BYTES, advertisement.size - len(content)
                )
            ):
                raise ProtocolError("reseed transfer does not match its advertisement")
            content.extend(chunk)
        if len(content) != advertisement.size:
            raise ProtocolError("reseed transfer size is inconsistent")
        try:
            encoded = bytes(content).decode("ascii")
        except UnicodeDecodeError as error:
            raise ProtocolError("reseed transfer is not ASCII") from error
        result = self.reseed_store.import_content(
            encoded,
            source=f"overlay:{peer.node_id[:64]}",
            expected_advertisement=advertisement,
        )
        return result.installed

    def refresh_reseed(self, *, direct_first_contact: bool = False) -> int:
        if self.reseed_store is None:
            return 0
        with self._reseed_refresh_lock:
            peers = list(self.pool.candidates("discovery"))[:MAX_RESEED_QUERY_PEERS]
            if not peers:
                raise DiscoveryError("no authenticated reseed transport peer is available")
            responses: list[tuple[NodeDescriptor, bytes | None]] = []
            for offset in range(0, len(peers), MAX_PARALLEL_DISCOVERY_REQUESTS):
                responses.extend(
                    self._request_batch(
                        peers[offset : offset + MAX_PARALLEL_DISCOVERY_REQUESTS],
                        RpcType.RESEED_QUERY,
                        b"",
                        RpcType.RESEED_QUERY,
                        direct_first_contact=direct_first_contact,
                        penalize_failure=False,
                    )
                )
            trusted = frozenset(self.reseed_store.authority_pins)
            high_water = self.reseed_store.high_water_marks()
            candidates: list[tuple[NodeDescriptor, ReseedAdvertisement]] = []
            seen: set[tuple[str, bytes, int, str]] = set()
            current = int(time.time())
            for peer, payload in responses:
                if payload is None:
                    continue
                try:
                    advertisements = decode_reseed_advertisements(payload)
                except ProtocolError:
                    continue
                for advertisement in advertisements:
                    previous = high_water.get(advertisement.authority_public_key)
                    key = (
                        peer.node_id,
                        advertisement.authority_public_key,
                        advertisement.generation,
                        advertisement.sha256,
                    )
                    if (
                        advertisement.authority_public_key not in trusted
                        or advertisement.expires_at <= current
                        or (
                            previous is not None
                            and (
                                advertisement.generation < previous[0]
                                or (
                                    advertisement.generation == previous[0]
                                    and advertisement.sha256 == previous[1]
                                )
                            )
                        )
                        or key in seen
                    ):
                        continue
                    seen.add(key)
                    candidates.append((peer, advertisement))
            candidates.sort(
                key=lambda item: (
                    -item[1].generation,
                    item[1].sha256,
                    item[0].node_id,
                )
            )
            installed = 0
            attempted = 0
            for peer, advertisement in candidates:
                if attempted >= MAX_RESEED_FETCH_ATTEMPTS:
                    break
                attempted += 1
                try:
                    installed += int(
                        self._fetch_reseed_advertisement(
                            peer,
                            advertisement,
                            direct_first_contact=direct_first_contact,
                        )
                    )
                except DiscoveryError as error:
                    if "equivocation" in str(error).lower():
                        raise
                except (OSError, ProtocolError):
                    continue
            if installed:
                active = self.reseed_store.load_active()
                if not active:
                    raise DiscoveryError("installed reseed generation is not currently valid")
                self.pool = BootstrapPool(active, self.cache)
                self.reseed_refreshes += installed
            return installed

    def maybe_refresh_reseed(self) -> int:
        if self.reseed_store is None:
            return 0
        active = self.reseed_store.load_active()
        latest_by_authority: dict[bytes, BootstrapSet] = {}
        for bundle in active:
            previous = latest_by_authority.get(bundle.authority_public_key)
            if previous is None or bundle.generation > previous.generation:
                latest_by_authority[bundle.authority_public_key] = bundle
        if latest_by_authority and all(
            min(bundle.expires_at, *(peer.expires_at for peer in bundle.peers))
            - int(time.time()) > RESEED_REFRESH_MARGIN_SECONDS
            for bundle in latest_by_authority.values()
        ):
            return 0
        with self._lock:
            current = time.monotonic()
            if self._reseed_next_attempt > current:
                return 0
            self._reseed_next_attempt = current + RESEED_REFRESH_RETRY_SECONDS
        return self.refresh_reseed(direct_first_contact=not self._private_routes_ready)

    def _prime_private_routes(
        self,
        contacts: tuple[NodeDescriptor, ...],
    ) -> bool:
        with self._lock:
            current = time.monotonic()
            self._prune_peer_tracking_unlocked(current)
            discovery_contacts = [
                peer
                for peer in contacts
                if "discovery" in peer.capabilities
                and peer.reachability == "reachable"
                and self._failed_until.get(peer.node_id, 0.0) <= current
            ][:MAX_PARALLEL_DISCOVERY_REQUESTS]
        if not discovery_contacts:
            return False
        for capability in ("access", "entry", "middle"):
            with self._lock:
                current = time.monotonic()
                self._prune_peer_tracking_unlocked(current)
                eligible_contacts = [
                    peer
                    for peer in discovery_contacts
                    if self._failed_until.get(peer.node_id, 0.0) <= current
                ]
            if not eligible_contacts:
                return False
            target = hashlib.sha256(
                _PRIVATE_DISCOVERY_ROUTE_DOMAIN
                + capability.encode("ascii")
                + secrets.token_bytes(32)
            ).digest()
            responses = self._request_batch(
                eligible_contacts,
                RpcType.FIND_NODE,
                encode_find_node(target, capability),
                RpcType.FIND_NODE,
                direct_first_contact=True,
            )
            for source, content in responses:
                if content is None:
                    continue
                try:
                    learned = decode_node_list(
                        content,
                        expected_network_id=self.pool.network_id,
                        expected_protocol_version=self.pool.protocol_version,
                    )
                except GrangerNetworkError:
                    continue
                if self.cache is not None:
                    self.cache.ingest(learned, source=f"prime:{source.node_id}")
                for candidate in learned:
                    previous = self._route_nodes.get(candidate.node_id)
                    if previous is None or candidate.issued_at > previous.issued_at:
                        self._route_nodes[candidate.node_id] = candidate
        try:
            target_peer = discovery_contacts[0]
            self._private_route(target_peer)
        except (DiscoveryError, DescriptorError):
            return False
        return True

    @traced("bootstrap-auth-dht")
    def join_network(self) -> NetworkHealthSnapshot:
        if self._joined:
            return self._health.snapshot()
        with self._join_lock:
            if self._joined:
                return self._health.snapshot()
            with self._lock:
                self._first_contact_operation = secrets.token_hex(8)
                self._first_contact_trace.clear()
            candidates = self.pool.candidates("discovery")
            cached_contacts = (
                list(self.cache.ranked("discovery"))[:8]
                if self.cache is not None
                else []
            )
            seed_contacts = list(self.pool.seed_candidates("discovery"))[:8]
            known_count, relay_count = self._health_counts(candidates)
            self._health.update(
                NetworkState.BOOTSTRAPPING,
                bootstrap_attempted=0,
                authenticated_peers=len(self._authenticated_nodes),
                known_peers=known_count,
                reachable_relays=relay_count,
                dht_ready=False,
                failure_reason="",
            )
            if not cached_contacts and not seed_contacts:
                return self._health.update(
                    NetworkState.OFFLINE,
                    failure_reason="NO_RESEED_SOURCE",
                )
            learned: dict[str, NodeDescriptor] = {
                peer.node_id: peer for peer in candidates
            }
            bootstrap_attempted = 0
            authenticated = 0
            phases = (
                (NetworkState.JOINING, cached_contacts, False),
                (
                    NetworkState.RESEEDING if cached_contacts else NetworkState.BOOTSTRAPPING,
                    seed_contacts,
                    True,
                ),
            )
            attempted_descriptors: set[tuple[str, str, int, int]] = set()
            for state, contacts, is_bootstrap in phases:
                pending_contacts = [
                    peer
                    for peer in contacts
                    if (
                        peer.node_id,
                        peer.endpoint.host,
                        peer.endpoint.port,
                        peer.issued_at,
                    )
                    not in attempted_descriptors
                ]
                for offset in range(
                    0,
                    len(pending_contacts),
                    MAX_PARALLEL_DISCOVERY_REQUESTS,
                ):
                    batch = pending_contacts[
                        offset : offset + MAX_PARALLEL_DISCOVERY_REQUESTS
                    ]
                    attempted_descriptors.update(
                        (
                            peer.node_id,
                            peer.endpoint.host,
                            peer.endpoint.port,
                            peer.issued_at,
                        )
                        for peer in batch
                    )
                    if is_bootstrap:
                        bootstrap_attempted += len(batch)
                    self._health.update(
                        state,
                        bootstrap_attempted=bootstrap_attempted,
                    )
                    responses = self._request_batch(
                        batch,
                        RpcType.PEER_SAMPLE,
                        encode_peer_sample("discovery", MAX_PEER_SAMPLE_RESULTS),
                        RpcType.PEER_SAMPLE,
                        direct_first_contact=True,
                    )
                    for peer, content in responses:
                        if content is None:
                            continue
                        try:
                            sample = decode_node_list(
                                content,
                                expected_network_id=self.pool.network_id,
                                expected_protocol_version=self.pool.protocol_version,
                            )
                        except GrangerNetworkError:
                            self._record_first_contact(
                                peer, "peer-sample", "FIRST_CONTACT_PEER_SAMPLE_REJECTED",
                                time.monotonic(), 0,
                            )
                            continue
                        authenticated += 1
                        if self.cache is not None:
                            self.cache.ingest(
                                sample,
                                source=f"peer:{peer.node_id}",
                            )
                        for candidate in sample:
                            previous = learned.get(candidate.node_id)
                            if previous is None or candidate.issued_at > previous.issued_at:
                                learned[candidate.node_id] = candidate
                    if (
                        authenticated >= self.minimum_replicas
                        and len(learned) >= self.replication_factor
                    ):
                        break
                if (
                    authenticated >= self.minimum_replicas
                    and len(learned) >= self.replication_factor
                ):
                    break
            known = tuple(learned.values())
            known_count, relay_count = self._health_counts(known)
            if authenticated == 0:
                reasons = {
                    event["reason"] for event in self.first_contact_diagnostics()
                    if event["reason"] != "OK"
                }
                failure_reason = (
                    next(iter(reasons)) if len(reasons) == 1
                    else "FIRST_CONTACT_MULTIPLE_FAILURES" if reasons
                    else "FIRST_CONTACT_FAILED"
                )
                return self._health.update(
                    NetworkState.OFFLINE,
                    bootstrap_attempted=bootstrap_attempted,
                    authenticated_peers=len(self._authenticated_nodes),
                    known_peers=known_count,
                    reachable_relays=relay_count,
                    dht_ready=False,
                    failure_reason=failure_reason,
                )
            if not self._prime_private_routes(known):
                return self._health.update(
                    NetworkState.OFFLINE,
                    bootstrap_attempted=bootstrap_attempted,
                    authenticated_peers=len(self._authenticated_nodes),
                    known_peers=known_count,
                    reachable_relays=relay_count,
                    dht_ready=False,
                    failure_reason="PRIVATE_INGRESS_UNAVAILABLE",
                )
            self._private_routes_ready = True
            self._joined = True
            health = self._health.update(
                NetworkState.JOINING,
                bootstrap_attempted=bootstrap_attempted,
                authenticated_peers=len(self._authenticated_nodes),
                known_peers=known_count,
                reachable_relays=relay_count,
                dht_ready=False,
                failure_reason="",
            )
            self.maybe_refresh_reseed()
            return health

    @traced("peer-discovery")
    def find_nodes(self, target: bytes, capability: str, *,
                   record_circuits: _RecordCircuits | None = None) -> tuple[NodeDescriptor, ...]:
        joined = self.join_network()
        if joined.state is NetworkState.OFFLINE:
            raise NetworkUnavailableError(f"Granger Network first contact failed: {joined.failure_reason}")
        self.maybe_refresh_reseed()
        seeds = list(self.pool.candidates("discovery"))
        with self._lock:
            current = time.monotonic()
            self._prune_peer_tracking_unlocked(current)
            pending = [
                peer
                for peer in seeds
                if self._failed_until.get(peer.node_id, 0.0) <= current
            ]
        known = {peer.node_id: peer for peer in pending}
        queried: set[str] = set()
        responsive: set[str] = set()
        while pending and len(queried) < MAX_DISCOVERY_QUERIES:
            pending.sort(key=lambda peer: int.from_bytes(_node_id_bytes(peer.node_id), "big") ^ int.from_bytes(target, "big"))
            batch: list[NodeDescriptor] = []
            batch_limit = min(
                MAX_PARALLEL_DISCOVERY_REQUESTS,
                MAX_DISCOVERY_QUERIES - len(queried),
            )
            while pending and len(batch) < batch_limit:
                peer = pending.pop(0)
                if peer.node_id in queried:
                    continue
                queried.add(peer.node_id)
                batch.append(peer)
            responses = self._request_batch(
                batch,
                RpcType.FIND_NODE,
                encode_find_node(target, capability),
                RpcType.FIND_NODE,
                record_circuits=record_circuits,
            )
            for peer, content in responses:
                if content is None:
                    continue
                try:
                    learned = decode_node_list(
                        content,
                        expected_network_id=self.pool.network_id,
                        expected_protocol_version=self.pool.protocol_version,
                    )
                except GrangerNetworkError:
                    continue
                responsive.add(peer.node_id)
                if self.cache is not None:
                    self.cache.ingest(learned, source=f"peer:{peer.node_id}")
                for candidate in learned:
                    previous = known.get(candidate.node_id)
                    if previous is None or candidate.issued_at > previous.issued_at:
                        known[candidate.node_id] = candidate
                        with self._lock:
                            eligible = (
                                self._failed_until.get(candidate.node_id, 0.0)
                                <= time.monotonic()
                            )
                        if (
                            candidate.node_id not in queried
                            and "discovery" in candidate.capabilities
                            and eligible
                        ):
                            pending.append(candidate)
        with self._lock:
            current = time.monotonic()
            result = [
                peer
                for peer in known.values()
                if node_supports_route_role(peer, capability)
                and self._failed_until.get(peer.node_id, 0.0) <= current
                and (record_circuits is None or peer.node_id in responsive)
            ]
        result.sort(key=lambda peer: int.from_bytes(_node_id_bytes(peer.node_id), "big") ^ int.from_bytes(target, "big"))
        all_known = tuple(known.values())
        known_count, relay_count = self._health_counts(all_known)
        if len(result) >= self.minimum_replicas and len(responsive) >= self.minimum_replicas:
            self._health.update(
                NetworkState.CONNECTED,
                authenticated_peers=len(self._authenticated_nodes),
                known_peers=known_count,
                reachable_relays=relay_count,
                dht_ready=True,
                failure_reason="",
            )
        else:
            self._health.update(
                NetworkState.DEGRADED,
                authenticated_peers=len(self._authenticated_nodes),
                known_peers=known_count,
                reachable_relays=relay_count,
                dht_ready=False,
                failure_reason="INSUFFICIENT_DHT_PEERS",
            )
        return tuple(result)

    @traced("descriptor-publication")
    def publish(self, record: DistributedRecord, now: int | None = None) -> int:
        envelope = encode_record(record, now=now)
        target = wan_routing_key(envelope.kind, envelope.key)
        payload = encode_record_envelope(envelope)
        with _RecordCircuits(target, RpcType.STORE_RECORD, payload, self.timeout) as circuits:
            return self._publish_record(envelope, target, payload, now, circuits)

    def _publish_record(self, envelope, target, payload, now, circuits) -> int:
        peers = self.find_nodes(target, "discovery", record_circuits=circuits)
        if len(peers) < self.minimum_replicas:
            raise NetworkUnavailableError("WAN discovery found too few storage peers")
        stored_peers: set[str] = set()
        for round_index in range(MAX_RECORD_REQUEST_ROUNDS):
            pending = [peer for peer in peers if peer.node_id not in stored_peers]
            offset = 0
            while offset < len(pending) and len(stored_peers) < self.replication_factor:
                remaining = self.replication_factor - len(stored_peers)
                batch_size = min(MAX_PARALLEL_DISCOVERY_REQUESTS, remaining)
                batch = pending[offset : offset + batch_size]
                if not batch:
                    break
                offset += len(batch)
                responses = self._request_batch(
                    batch,
                    RpcType.STORE_RECORD,
                    payload,
                    RpcType.STORE_RECORD,
                    record_circuits=circuits,
                )
                stored_peers.update(
                    peer.node_id
                    for peer, content in responses
                    if content is not None
                )
            if len(stored_peers) >= self.replication_factor:
                break
            if round_index + 1 < MAX_RECORD_REQUEST_ROUNDS:
                time.sleep(0.1 * (round_index + 1))
        if len(stored_peers) < self.minimum_replicas:
            raise NetworkUnavailableError("WAN publication did not reach its replica quorum")
        self._remember_record_sequence(
            envelope.kind,
            envelope.key,
            envelope.sequence,
            envelope.expires_at,
            now=int(time.time()) if now is None else now,
        )
        return len(stored_peers)

    def public_service_sample(self) -> tuple[ServiceDescriptor, ...]:
        # Samples are hints, never an authority. Revalidate current visibility
        # through the normal signed quorum lookup before presenting a service.
        self.join_network()
        peers = list(self.pool.candidates("discovery"))[:MAX_PARALLEL_DISCOVERY_REQUESTS]
        candidates = {}
        for _peer, content in self._request_batch(
            peers, RpcType.PUBLIC_SERVICE_SAMPLE, b"", RpcType.PUBLIC_SERVICE_SAMPLE,
        ):
            if content is None:
                continue
            try:
                for service in decode_public_service_sample(content):
                    candidates[service.service_id] = service
            except GrangerNetworkError:
                continue
        result = []
        for key in sorted(candidates)[:MAX_PUBLIC_SERVICE_SAMPLE]:
            try:
                service = self.lookup(SERVICE_RECORD, key)
                if isinstance(service, ServiceDescriptor) and service.publicly_listed:
                    result.append(service)
            except GrangerNetworkError:
                continue
        return tuple(result)

    def lookup(self, kind: str, key: str, now: int | None = None) -> DistributedRecord:
        target = wan_routing_key(kind, key)
        payload = encode_find_record(kind, key)
        with _RecordCircuits(target, RpcType.FIND_RECORD, payload, self.timeout) as circuits:
            return self._lookup_record(kind, key, target, payload, now, circuits)

    def _lookup_record(self, kind, key, target, payload, now, circuits) -> DistributedRecord:
        peers = self.find_nodes(target, "discovery", record_circuits=circuits)
        candidates_by_peer: dict[str, RecordEnvelope] = {}
        for round_index in range(MAX_RECORD_REQUEST_ROUNDS):
            pending = [
                peer for peer in peers
                if peer.node_id not in candidates_by_peer
            ]
            for offset in range(0, len(pending), MAX_PARALLEL_DISCOVERY_REQUESTS):
                responses = self._request_batch(
                    list(pending[offset : offset + MAX_PARALLEL_DISCOVERY_REQUESTS]),
                    RpcType.FIND_RECORD,
                    payload,
                    RpcType.FIND_RECORD,
                    record_circuits=circuits,
                )
                for peer, content in responses:
                    if content is None:
                        continue
                    try:
                        envelope = decode_optional_record(content, now=now)
                    except GrangerNetworkError:
                        continue
                    if envelope is not None and envelope.kind == kind and envelope.key == key:
                        candidates_by_peer[peer.node_id] = envelope
            if len(candidates_by_peer) >= self.minimum_replicas:
                break
            if round_index + 1 < MAX_RECORD_REQUEST_ROUNDS:
                time.sleep(0.1 * (round_index + 1))
        candidates = list(candidates_by_peer.values())
        if len(candidates) < self.minimum_replicas:
            raise RecordQuorumError(f"WAN record replica quorum is unavailable: {kind}:{key}")
        highest = max(candidate.sequence for candidate in candidates)
        winners = [candidate for candidate in candidates if candidate.sequence == highest]
        payloads = {candidate.payload for candidate in winners}
        if len(payloads) != 1 or len(winners) < self.minimum_replicas:
            raise RecordQuorumError("WAN lookup did not obtain an unambiguous replica quorum")
        result = decode_record(kind, key, winners[0].payload, now=now)
        self._remember_record_sequence(
            kind,
            key,
            highest,
            winners[0].expires_at,
            now=int(time.time()) if now is None else now,
        )
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

    @traced("connection-records")
    def resolve_connection(
        self, name: str, now: int | None = None,
    ) -> tuple[ServiceDescriptor, IntroductionDescriptor]:
        normalized = normalize_name(name)
        if not is_canonical_name(normalized):
            service = self.resolve(normalized, now=now)
            return service, self.resolve_introduction(service, now=now)
        service_id = service_id_from_name(normalized)
        # The crypto address names both records. Fetch independently, but do
        # not expose either result until the service binding is verified.
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="granger-record-lookup") as workers:
            service_lookup = workers.submit(self.resolve, normalized, now=now)

            def introduction_lookup():
                with stage("introduction-descriptor-lookup"):
                    record = self.discovery.lookup(INTRODUCTION_RECORD, service_id, now=now)
                    if not isinstance(record, IntroductionDescriptor):
                        raise ResolutionError("WAN introduction record has the wrong type")
                    record.verify_for(service_lookup.result(), now=now)
                    return record

            introduction = workers.submit(introduction_lookup)
            return service_lookup.result(), introduction.result()

    @traced("service-descriptor-lookup")
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

    @traced("introduction-descriptor-lookup")
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

    @traced("node-descriptor-lookup")
    def resolve_node(self, node_id: str, now: int | None = None) -> NodeDescriptor:
        validated = validate_node_id(node_id)
        signed_bootstrap = self.discovery.signed_bootstrap_node(validated, now=now)
        if signed_bootstrap is not None:
            return signed_bootstrap
        record = self.discovery.lookup(NODE_RECORD, validated, now=now)
        if not isinstance(record, NodeDescriptor):
            raise ResolutionError("WAN node record has the wrong type")
        return record
