from __future__ import annotations

import base64
from concurrent.futures import Future, ThreadPoolExecutor
import hashlib
import ipaddress
import json
import secrets
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
from .network_health import NetworkHealth, NetworkHealthSnapshot, NetworkState
from .peer import RELAY_CAPABILITIES
from .rendezvous_control import validate_service_id


WAN_DISCOVERY_VERSION = 1
MAX_WAN_RECORDS = 4096
MAX_FIND_NODE_RESULTS = 32
MAX_PEER_SAMPLE_RESULTS = 32
MAX_DISCOVERY_QUERIES = 32
MAX_PARALLEL_DISCOVERY_REQUESTS = 4
_ROUTING_KEY_DOMAIN = b"granger-network-v0.4/wan-routing-key\x00"
_PRIVATE_DISCOVERY_ROUTE_DOMAIN = b"granger-network-v0.5/private-discovery-route\x00"


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
        self._join_lock = threading.Lock()
        self._joined = False
        self._private_routes_ready = False
        self._route_nodes: dict[str, NodeDescriptor] = {}
        self.direct_first_contact_requests = 0
        self.private_discovery_requests = 0
        self.last_private_route: tuple[str, ...] = ()
        self._health = NetworkHealth()
        self._authenticated_nodes: set[str] = set()

    def health(self) -> NetworkHealthSnapshot:
        return self._health.snapshot()

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
    ) -> tuple[tuple[tuple[NodeDescriptor, str], ...], ...]:
        excluded = {peer.node_id}
        def candidates(capability: str) -> list[NodeDescriptor]:
            selected = {
                node.node_id: node
                for node in (*self.pool.candidates(capability), *self._route_nodes.values())
                if capability in node.capabilities
                and node.reachability == "reachable"
                and node.node_id not in excluded
            }
            return list(selected.values())

        accesses = [
            node for node in candidates("access")
        ]
        guards = [
            node for node in candidates("entry")
        ]
        middles = [
            node for node in candidates("middle")
        ]
        guard_seed = hashlib.sha256(
            _PRIVATE_DISCOVERY_ROUTE_DOMAIN + self.identity.public_key_bytes
        ).digest()
        guards.sort(
            key=lambda node: hashlib.sha256(
                guard_seed + node.node_id.encode("ascii")
            ).digest()
        )
        choices: list[
            tuple[int, int, int, NodeDescriptor, NodeDescriptor, NodeDescriptor]
        ] = []
        random_offset = int.from_bytes(secrets.token_bytes(4), "big")
        for guard_index, guard in enumerate(guards):
            for access_index, access in enumerate(accesses):
                for middle_index, middle in enumerate(middles):
                    route_nodes = (access, guard, middle, peer)
                    if len({node.node_id for node in route_nodes}) != len(route_nodes):
                        continue
                    groups = {self._network_group(node) for node in route_nodes}
                    choices.append(
                        (
                            len(route_nodes) - len(groups),
                            guard_index,
                            (access_index + middle_index + random_offset) % 65536,
                            access,
                            guard,
                            middle,
                        )
                    )
        if not choices:
            raise DiscoveryError("private discovery ingress is unavailable")
        choices.sort(key=lambda item: item[:3])
        ordered_choices: list[
            tuple[int, int, int, NodeDescriptor, NodeDescriptor, NodeDescriptor]
        ] = []
        remaining = list(enumerate(choices))
        node_use: dict[str, int] = {}
        while remaining:
            selected_index, selected = min(
                remaining,
                key=lambda item: (
                    sum(
                        node_use.get(node.node_id, 0)
                        for node in item[1][3:]
                    ),
                    item[0],
                ),
            )
            ordered_choices.append(selected)
            for node in selected[3:]:
                node_use[node.node_id] = node_use.get(node.node_id, 0) + 1
            remaining = [item for item in remaining if item[0] != selected_index]
            if len(ordered_choices) >= limit:
                break
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

    def _request(
        self,
        peer: NodeDescriptor,
        message: RpcType,
        payload: bytes,
        expected: RpcType,
        *,
        direct_first_contact: bool = False,
    ) -> bytes:
        connection = None
        try:
            if direct_first_contact:
                connection = connect_authenticated_peer(
                    peer,
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=self.timeout,
                )
                self.direct_first_contact_requests += 1
                response = connection.rpc.request(message, payload, expected=expected)
            else:
                if not self._joined or not self._private_routes_ready:
                    raise DiscoveryError(
                        "post-join discovery requires private ingress"
                    )
                from .circuit import CircuitBuilder

                response = None
                last_error: BaseException | None = None
                routes = self._private_route_candidates(peer)
                attempt_timeout = max(0.1, self.timeout / len(routes))
                for route in routes:
                    circuit = None
                    try:
                        circuit = CircuitBuilder(
                            self.identity,
                            PeerRole.CLIENT,
                            timeout=attempt_timeout,
                        ).open(route)
                        self.private_discovery_requests += 1
                        self.last_private_route = tuple(
                            descriptor.node_id for descriptor, _role in circuit.route
                        )
                        response = circuit.endpoint.rpc.request(
                            message,
                            payload,
                            expected=expected,
                        )
                        break
                    except (GrangerNetworkError, OSError) as error:
                        last_error = error
                    finally:
                        if circuit is not None:
                            circuit.close()
                if response is None:
                    if last_error is None:
                        raise DiscoveryError("private discovery ingress is unavailable")
                    raise last_error
            if self.cache is not None:
                self.cache.record_success(peer)
            with self._lock:
                self._failed_until.pop(peer.node_id, None)
                self._authenticated_nodes.add(peer.node_id)
            return response.payload
        except (GrangerNetworkError, OSError):
            if self.cache is not None:
                self.cache.record_failure(peer)
            with self._lock:
                self._failed_until[peer.node_id] = time.monotonic() + max(
                    60.0,
                    min(300.0, self.timeout * 12.0),
                )
            raise
        finally:
            if connection is not None:
                connection.close()

    def _request_batch(
        self,
        peers: list[NodeDescriptor],
        message: RpcType,
        payload: bytes,
        expected: RpcType,
        *,
        direct_first_contact: bool = False,
    ) -> tuple[tuple[NodeDescriptor, bytes | None], ...]:
        selected = peers[:MAX_PARALLEL_DISCOVERY_REQUESTS]
        if not selected:
            return ()
        with ThreadPoolExecutor(
            max_workers=len(selected),
            thread_name_prefix="granger-discovery",
        ) as executor:
            requests: list[tuple[NodeDescriptor, Future[bytes]]] = [
                (
                    peer,
                    executor.submit(
                        self._request,
                        peer,
                        message,
                        payload,
                        expected,
                        direct_first_contact=direct_first_contact,
                    ),
                )
                for peer in selected
            ]
            results: list[tuple[NodeDescriptor, bytes | None]] = []
            for peer, request in requests:
                try:
                    results.append((peer, request.result()))
                except (GrangerNetworkError, OSError):
                    results.append((peer, None))
            return tuple(results)

    def _prime_private_routes(
        self,
        contacts: tuple[NodeDescriptor, ...],
    ) -> bool:
        with self._lock:
            current = time.monotonic()
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

    def join_network(self) -> NetworkHealthSnapshot:
        if self._joined:
            return self._health.snapshot()
        with self._join_lock:
            if self._joined:
                return self._health.snapshot()
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
                return self._health.update(
                    NetworkState.OFFLINE,
                    bootstrap_attempted=bootstrap_attempted,
                    authenticated_peers=len(self._authenticated_nodes),
                    known_peers=known_count,
                    reachable_relays=relay_count,
                    dht_ready=False,
                    failure_reason="FIRST_CONTACT_FAILED",
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
            return self._health.update(
                NetworkState.JOINING,
                bootstrap_attempted=bootstrap_attempted,
                authenticated_peers=len(self._authenticated_nodes),
                known_peers=known_count,
                reachable_relays=relay_count,
                dht_ready=False,
                failure_reason="",
            )

    def find_nodes(self, target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        joined = self.join_network()
        if joined.state is NetworkState.OFFLINE:
            raise DiscoveryError("Granger Network first contact failed")
        seeds = list(self.pool.candidates("discovery"))
        with self._lock:
            current = time.monotonic()
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
                for candidate in learned:
                    if self.cache is not None:
                        self.cache.add(candidate, source=f"peer:{peer.node_id}")
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
                if capability in peer.capabilities
                and peer.reachability == "reachable"
                and self._failed_until.get(peer.node_id, 0.0) <= current
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
        payload = encode_find_record(kind, key)
        for offset in range(0, len(peers), MAX_PARALLEL_DISCOVERY_REQUESTS):
            responses = self._request_batch(
                list(peers[offset : offset + MAX_PARALLEL_DISCOVERY_REQUESTS]),
                RpcType.FIND_RECORD,
                payload,
                RpcType.FIND_RECORD,
            )
            for _peer, content in responses:
                if content is None:
                    continue
                try:
                    envelope = decode_optional_record(content, now=now)
                except GrangerNetworkError:
                    continue
                if envelope is not None and envelope.kind == kind and envelope.key == key:
                    candidates.append(envelope)
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
