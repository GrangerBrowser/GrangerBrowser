from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import atomic_write_text, canonical_json, decode_base64url, encode_base64url, parse_json_object
from .errors import DescriptorError, DiscoveryError
from .identity import ServiceIdentity
from .peer import NodeDescriptor


LEGACY_BOOTSTRAP_SET_VERSION = 1
BOOTSTRAP_SET_VERSION = 2
BOOTSTRAP_SIGNATURE_DOMAIN = b"granger-network-v0.5/bootstrap-set\x00"
LEGACY_BOOTSTRAP_SIGNATURE_DOMAIN = b"granger-network-v0.4/bootstrap-set\x00"
DEFAULT_NETWORK_ID = "granger-network-v0.4"
DEFAULT_PROTOCOL_VERSION = 3
MAX_BOOTSTRAP_SET_LIFETIME = 30 * 24 * 60 * 60
MAX_BOOTSTRAP_PEERS = 64
MAX_CACHE_PEERS = 512
MAX_CACHE_PEERS_PER_SOURCE = 64
MAX_CACHE_PEERS_PER_NETWORK_GROUP = 32
MAX_CACHE_SOURCES_PER_PEER = 4
_MAX_GENERATION = 2**63 - 1
_NETWORK_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_SOURCE_ID = re.compile(r"^[a-zA-Z0-9_.:-]{1,96}$")


def _validate_network_id(value: object) -> str:
    if not isinstance(value, str) or not _NETWORK_ID.fullmatch(value):
        raise DiscoveryError("bootstrap network identifier is invalid")
    return value


@dataclass(frozen=True)
class BootstrapSet:
    authority_public_key: bytes
    network_id: str
    protocol_version: int
    generation: int
    issued_at: int
    expires_at: int
    peers: tuple[NodeDescriptor, ...]
    signature: bytes
    version: int = BOOTSTRAP_SET_VERSION

    def unsigned_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "authorityKey": encode_base64url(self.authority_public_key),
            "expiresAt": self.expires_at,
            "issuedAt": self.issued_at,
            "peers": [peer.to_document() for peer in self.peers],
            "version": self.version,
        }
        if self.version == BOOTSTRAP_SET_VERSION:
            document.update(
                {
                    "generation": self.generation,
                    "networkId": self.network_id,
                    "protocolVersion": self.protocol_version,
                }
            )
        return document

    def signature_payload(self) -> bytes:
        domain = (
            LEGACY_BOOTSTRAP_SIGNATURE_DOMAIN
            if self.version == LEGACY_BOOTSTRAP_SET_VERSION
            else BOOTSTRAP_SIGNATURE_DOMAIN
        )
        return domain + canonical_json(self.unsigned_document())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.to_document())).hexdigest()

    def verify(
        self,
        pinned_authority_key: bytes,
        now: int | None = None,
        *,
        expected_network_id: str | None = None,
        expected_protocol_version: int | None = None,
        allow_legacy: bool = False,
    ) -> None:
        if self.version == LEGACY_BOOTSTRAP_SET_VERSION:
            if not allow_legacy:
                raise DiscoveryError("legacy bootstrap set is not allowed")
        elif self.version != BOOTSTRAP_SET_VERSION or isinstance(self.version, bool):
            raise DiscoveryError("bootstrap set version is unsupported")
        if (
            not isinstance(pinned_authority_key, bytes)
            or len(pinned_authority_key) != 32
            or self.authority_public_key != pinned_authority_key
        ):
            raise DiscoveryError("bootstrap authority does not match its local pin")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise DiscoveryError("bootstrap set signature length is invalid")
        if self.version == BOOTSTRAP_SET_VERSION:
            network_id = _validate_network_id(self.network_id)
            if expected_network_id is not None and network_id != expected_network_id:
                raise DiscoveryError("bootstrap set belongs to a different network")
            if (
                isinstance(self.protocol_version, bool)
                or not isinstance(self.protocol_version, int)
                or not 1 <= self.protocol_version <= 255
                or (
                    expected_protocol_version is not None
                    and self.protocol_version != expected_protocol_version
                )
            ):
                raise DiscoveryError("bootstrap set protocol is unsupported")
            if (
                isinstance(self.generation, bool)
                or not isinstance(self.generation, int)
                or not 1 <= self.generation <= _MAX_GENERATION
            ):
                raise DiscoveryError("bootstrap set generation is invalid")
        for value in (self.issued_at, self.expires_at):
            if isinstance(value, bool) or not isinstance(value, int):
                raise DiscoveryError("bootstrap set timestamps must be integers")
        current = int(time.time()) if now is None else now
        if isinstance(current, bool) or not isinstance(current, int):
            raise DiscoveryError("bootstrap verification time is invalid")
        if self.issued_at < 0 or self.expires_at <= self.issued_at:
            raise DiscoveryError("bootstrap set validity window is invalid")
        if self.expires_at - self.issued_at > MAX_BOOTSTRAP_SET_LIFETIME:
            raise DiscoveryError("bootstrap set lifetime exceeds its limit")
        if self.issued_at > current + 120 or self.expires_at <= current:
            raise DiscoveryError("bootstrap set is not currently valid")
        if not 2 <= len(self.peers) <= MAX_BOOTSTRAP_PEERS:
            raise DiscoveryError("bootstrap set requires multiple bounded peers")
        node_ids: set[str] = set()
        endpoints: set[tuple[str, int]] = set()
        for peer in self.peers:
            peer.verify(
                now=now,
                expected_network_id=(self.network_id if self.version == BOOTSTRAP_SET_VERSION else None),
                expected_protocol_version=(
                    self.protocol_version if self.version == BOOTSTRAP_SET_VERSION else None
                ),
            )
            if "bootstrap" not in peer.capabilities or peer.reachability != "reachable":
                raise DiscoveryError("bootstrap peer is not a reachable bootstrap node")
            endpoint = (peer.endpoint.host, peer.endpoint.port)
            if peer.node_id in node_ids or endpoint in endpoints:
                raise DiscoveryError("bootstrap set contains a duplicate peer")
            node_ids.add(peer.node_id)
            endpoints.add(endpoint)
        try:
            Ed25519PublicKey.from_public_bytes(self.authority_public_key).verify(
                self.signature,
                self.signature_payload(),
            )
        except (InvalidSignature, ValueError) as error:
            raise DiscoveryError("bootstrap set signature is invalid") from error

    def to_document(self) -> dict[str, object]:
        document = self.unsigned_document()
        document["signature"] = encode_base64url(self.signature)
        return document

    def to_json(self) -> str:
        return json.dumps(self.to_document(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"

    @classmethod
    def create(
        cls,
        authority: ServiceIdentity,
        peers: list[NodeDescriptor] | tuple[NodeDescriptor, ...],
        *,
        network_id: str = DEFAULT_NETWORK_ID,
        protocol_version: int = DEFAULT_PROTOCOL_VERSION,
        generation: int = 1,
        issued_at: int | None = None,
        lifetime: int = 7 * 24 * 60 * 60,
    ) -> "BootstrapSet":
        timestamp = int(time.time()) if issued_at is None else issued_at
        unsigned = cls(
            authority.public_key_bytes,
            network_id,
            protocol_version,
            generation,
            timestamp,
            timestamp + lifetime,
            tuple(sorted(peers, key=lambda peer: peer.node_id)),
            b"\x00" * 64,
        )
        result = replace(unsigned, signature=authority.sign(unsigned.signature_payload()))
        result.verify(
            authority.public_key_bytes,
            now=timestamp,
            expected_network_id=network_id,
            expected_protocol_version=protocol_version,
        )
        return result

    @classmethod
    def from_json(
        cls,
        content: str,
        pinned_authority_key: bytes,
        *,
        now: int | None = None,
        expected_network_id: str | None = None,
        expected_protocol_version: int | None = None,
        allow_legacy: bool = False,
    ) -> "BootstrapSet":
        try:
            document = parse_json_object(content)
            version = document.get("version")
            if version == BOOTSTRAP_SET_VERSION:
                expected = {
                    "authorityKey",
                    "expiresAt",
                    "generation",
                    "issuedAt",
                    "networkId",
                    "peers",
                    "protocolVersion",
                    "signature",
                    "version",
                }
            elif version == LEGACY_BOOTSTRAP_SET_VERSION and allow_legacy:
                expected = {
                    "authorityKey",
                    "expiresAt",
                    "issuedAt",
                    "peers",
                    "signature",
                    "version",
                }
            else:
                raise ValueError("unsupported bootstrap set version")
            if set(document) != expected:
                raise ValueError("unexpected bootstrap set fields")
            if not isinstance(document["peers"], list):
                raise ValueError("bootstrap peers must be an array")
            peers = tuple(
                NodeDescriptor.from_json(
                    json.dumps(peer, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
                    now=now,
                    expected_network_id=(
                        document["networkId"] if version == BOOTSTRAP_SET_VERSION else None
                    ),
                    expected_protocol_version=(
                        document["protocolVersion"]
                        if version == BOOTSTRAP_SET_VERSION
                        else None
                    ),
                )
                for peer in document["peers"]
            )
            result = cls(
                decode_base64url(document["authorityKey"]),
                document.get("networkId", "legacy"),
                document.get("protocolVersion", DEFAULT_PROTOCOL_VERSION),
                document.get("generation", 0),
                document["issuedAt"],
                document["expiresAt"],
                peers,
                decode_base64url(document["signature"]),
                version,
            )
            result.verify(
                pinned_authority_key,
                now=now,
                expected_network_id=expected_network_id,
                expected_protocol_version=expected_protocol_version,
                allow_legacy=allow_legacy,
            )
            return result
        except DiscoveryError:
            raise
        except (DescriptorError, KeyError, TypeError, ValueError) as error:
            raise DiscoveryError(f"invalid bootstrap set: {error}") from error


@dataclass(frozen=True)
class PeerCacheEntry:
    descriptor: NodeDescriptor
    last_seen: int
    last_successful_connection: int | None = None
    successful_connections: int = 0
    failed_connections: int = 0
    sources: tuple[str, ...] = ()

    @property
    def reliability(self) -> int:
        return max(-32, min(32, self.successful_connections - self.failed_connections))


def _network_group(peer: NodeDescriptor) -> str:
    address = ipaddress.ip_address(peer.endpoint.host)
    if address.is_loopback:
        return "loopback"
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


class PeerCache:
    def __init__(
        self,
        path: Path,
        *,
        maximum: int = MAX_CACHE_PEERS,
        network_id: str = DEFAULT_NETWORK_ID,
        protocol_version: int = DEFAULT_PROTOCOL_VERSION,
    ) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 2 <= maximum <= MAX_CACHE_PEERS:
            raise DiscoveryError("peer cache limit is invalid")
        self.path = Path(path)
        self.maximum = maximum
        self.network_id = _validate_network_id(network_id)
        if (
            isinstance(protocol_version, bool)
            or not isinstance(protocol_version, int)
            or not 1 <= protocol_version <= 255
        ):
            raise DiscoveryError("peer cache protocol is invalid")
        self.protocol_version = protocol_version
        self._lock = threading.Lock()
        self.last_load_error = ""

    def load(self, now: int | None = None) -> tuple[NodeDescriptor, ...]:
        return tuple(entry.descriptor for entry in self.entries(now=now))

    def entries(self, now: int | None = None) -> tuple[PeerCacheEntry, ...]:
        with self._lock:
            return self._load_entries_unlocked(now)

    def _load_entries_unlocked(self, now: int | None) -> tuple[PeerCacheEntry, ...]:
        if not self.path.exists():
            self.last_load_error = ""
            return ()
        current = int(time.time()) if now is None else now
        try:
            document = parse_json_object(self.path.read_text(encoding="utf-8"))
            version = document.get("version")
            if set(document) != {"peers", "version"} or version not in {1, 2}:
                raise ValueError("peer cache schema is unsupported")
            if not isinstance(document["peers"], list) or len(document["peers"]) > self.maximum:
                raise ValueError("peer cache entry count is invalid")
            peers: dict[str, PeerCacheEntry] = {}
            for raw in document["peers"]:
                try:
                    if version == 1:
                        descriptor_document = raw
                        metadata = {
                            "failedConnections": 0,
                            "lastSeen": current,
                            "lastSuccessfulConnection": None,
                            "sources": ["legacy-cache"],
                            "successfulConnections": 0,
                        }
                    else:
                        if not isinstance(raw, dict) or set(raw) != {
                            "descriptor",
                            "failedConnections",
                            "lastSeen",
                            "lastSuccessfulConnection",
                            "sources",
                            "successfulConnections",
                        }:
                            raise ValueError("peer cache entry schema is invalid")
                        descriptor_document = raw["descriptor"]
                        metadata = raw
                    descriptor = NodeDescriptor.from_json(
                        json.dumps(
                            descriptor_document,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        now=now,
                        expected_network_id=self.network_id,
                        expected_protocol_version=self.protocol_version,
                    )
                    last_seen = metadata["lastSeen"]
                    last_success = metadata["lastSuccessfulConnection"]
                    successes = metadata["successfulConnections"]
                    failures = metadata["failedConnections"]
                    sources = metadata["sources"]
                    if (
                        isinstance(last_seen, bool)
                        or not isinstance(last_seen, int)
                        or last_seen < 0
                        or (
                            last_success is not None
                            and (
                                isinstance(last_success, bool)
                                or not isinstance(last_success, int)
                                or last_success < 0
                            )
                        )
                        or any(
                            isinstance(value, bool)
                            or not isinstance(value, int)
                            or not 0 <= value <= 2**31 - 1
                            for value in (successes, failures)
                        )
                        or not isinstance(sources, list)
                        or not 1 <= len(sources) <= MAX_CACHE_SOURCES_PER_PEER
                        or any(not isinstance(source, str) or not _SOURCE_ID.fullmatch(source) for source in sources)
                    ):
                        raise ValueError("peer cache metadata is invalid")
                    entry = PeerCacheEntry(
                        descriptor,
                        last_seen,
                        last_success,
                        successes,
                        failures,
                        tuple(sorted(set(sources))),
                    )
                    previous = peers.get(descriptor.node_id)
                    if previous is None or descriptor.issued_at > previous.descriptor.issued_at:
                        peers[descriptor.node_id] = entry
                except (DescriptorError, KeyError, TypeError, ValueError):
                    continue
            self.last_load_error = ""
            return tuple(peers.values())
        except (OSError, TypeError, ValueError) as error:
            self.last_load_error = type(error).__name__
            return ()

    def _write_entries_unlocked(self, entries: Iterable[PeerCacheEntry]) -> None:
        ordered = sorted(
            entries,
            key=lambda entry: (
                entry.last_successful_connection is None,
                -entry.reliability,
                -(entry.last_successful_connection or 0),
                -entry.last_seen,
                entry.descriptor.node_id,
            ),
        )[: self.maximum]
        document = {
            "peers": [
                {
                    "descriptor": entry.descriptor.to_document(),
                    "failedConnections": entry.failed_connections,
                    "lastSeen": entry.last_seen,
                    "lastSuccessfulConnection": entry.last_successful_connection,
                    "sources": list(entry.sources),
                    "successfulConnections": entry.successful_connections,
                }
                for entry in ordered
            ],
            "version": 2,
        }
        atomic_write_text(
            self.path,
            json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    def store(self, peers: Sequence[NodeDescriptor], now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        valid: dict[str, PeerCacheEntry] = {}
        for peer in peers[: self.maximum]:
            peer.verify(
                now=now,
                expected_network_id=self.network_id,
                expected_protocol_version=self.protocol_version,
            )
            previous = valid.get(peer.node_id)
            if previous is None or peer.issued_at > previous.descriptor.issued_at:
                valid[peer.node_id] = PeerCacheEntry(peer, current, sources=("bootstrap",))
        with self._lock:
            self._write_entries_unlocked(valid.values())

    def ingest(
        self,
        peers: Iterable[NodeDescriptor],
        *,
        source: str,
        now: int | None = None,
    ) -> int:
        if not isinstance(source, str) or not _SOURCE_ID.fullmatch(source):
            raise DiscoveryError("peer cache source identifier is invalid")
        current_time = int(time.time()) if now is None else now
        candidates: list[NodeDescriptor] = []
        for peer in peers:
            if len(candidates) >= MAX_CACHE_PEERS_PER_SOURCE:
                break
            try:
                peer.verify(
                    now=now,
                    expected_network_id=self.network_id,
                    expected_protocol_version=self.protocol_version,
                )
            except DescriptorError:
                continue
            if peer.reachability == "reachable":
                candidates.append(peer)
        with self._lock:
            entries = {entry.descriptor.node_id: entry for entry in self._load_entries_unlocked(now)}
            endpoint_owners = {
                (entry.descriptor.endpoint.host, entry.descriptor.endpoint.port): node_id
                for node_id, entry in entries.items()
            }
            group_counts: dict[str, int] = {}
            for entry in entries.values():
                group = _network_group(entry.descriptor)
                group_counts[group] = group_counts.get(group, 0) + 1
            accepted = 0
            for peer in candidates:
                endpoint = (peer.endpoint.host, peer.endpoint.port)
                owner = endpoint_owners.get(endpoint)
                if owner is not None and owner != peer.node_id:
                    continue
                group = _network_group(peer)
                existing = entries.get(peer.node_id)
                group_limit = self.maximum if group == "loopback" else MAX_CACHE_PEERS_PER_NETWORK_GROUP
                if existing is None and group_counts.get(group, 0) >= group_limit:
                    continue
                if existing is not None and peer.issued_at < existing.descriptor.issued_at:
                    continue
                sources = tuple(sorted(set((existing.sources if existing else ()) + (source,))))
                if len(sources) > MAX_CACHE_SOURCES_PER_PEER:
                    sources = sources[-MAX_CACHE_SOURCES_PER_PEER:]
                entries[peer.node_id] = PeerCacheEntry(
                    peer,
                    current_time,
                    existing.last_successful_connection if existing else None,
                    existing.successful_connections if existing else 0,
                    existing.failed_connections if existing else 0,
                    sources,
                )
                endpoint_owners[endpoint] = peer.node_id
                if existing is None:
                    group_counts[group] = group_counts.get(group, 0) + 1
                accepted += 1
            self._write_entries_unlocked(entries.values())
            return accepted

    def add(
        self,
        peer: NodeDescriptor,
        now: int | None = None,
        *,
        source: str = "authenticated-peer",
    ) -> None:
        self.ingest((peer,), source=source, now=now)

    def record_success(self, peer: NodeDescriptor, now: int | None = None) -> None:
        current_time = int(time.time()) if now is None else now
        self.ingest((peer,), source="authenticated-peer", now=now)
        with self._lock:
            entries = {entry.descriptor.node_id: entry for entry in self._load_entries_unlocked(now)}
            entry = entries.get(peer.node_id)
            if entry is None:
                return
            entries[peer.node_id] = replace(
                entry,
                last_seen=current_time,
                last_successful_connection=current_time,
                successful_connections=min(2**31 - 1, entry.successful_connections + 1),
            )
            self._write_entries_unlocked(entries.values())

    def record_failure(self, peer: NodeDescriptor, now: int | None = None) -> None:
        current_time = int(time.time()) if now is None else now
        with self._lock:
            entries = {entry.descriptor.node_id: entry for entry in self._load_entries_unlocked(now)}
            entry = entries.get(peer.node_id)
            if entry is None:
                return
            entries[peer.node_id] = replace(
                entry,
                last_seen=current_time,
                failed_connections=min(2**31 - 1, entry.failed_connections + 1),
            )
            self._write_entries_unlocked(entries.values())

    def ranked(self, capability: str, now: int | None = None) -> tuple[NodeDescriptor, ...]:
        entries = [
            entry
            for entry in self.entries(now=now)
            if capability in entry.descriptor.capabilities
            and entry.descriptor.reachability == "reachable"
        ]
        entries.sort(
            key=lambda entry: (
                entry.last_successful_connection is None,
                -entry.reliability,
                -(entry.last_successful_connection or 0),
                -entry.last_seen,
                entry.descriptor.node_id,
            )
        )
        return tuple(entry.descriptor for entry in entries)

    def stats(self, now: int | None = None) -> dict[str, int | str]:
        entries = self.entries(now=now)
        return {
            "loadError": self.last_load_error,
            "peers": len(entries),
            "successfulPeers": sum(entry.last_successful_connection is not None for entry in entries),
            "version": 2,
        }


class BootstrapPool:
    def __init__(
        self,
        bootstrap_set: BootstrapSet | Sequence[BootstrapSet],
        cache: PeerCache | None = None,
    ) -> None:
        sets = (bootstrap_set,) if isinstance(bootstrap_set, BootstrapSet) else tuple(bootstrap_set)
        if not sets or any(not isinstance(item, BootstrapSet) for item in sets):
            raise DiscoveryError("bootstrap pool requires verified bootstrap sets")
        network_id = sets[0].network_id
        protocol_version = sets[0].protocol_version
        unique: dict[tuple[bytes, int], BootstrapSet] = {}
        for item in sets:
            item.verify(
                item.authority_public_key,
                expected_network_id=network_id,
                expected_protocol_version=protocol_version,
            )
            key = (item.authority_public_key, item.generation)
            previous = unique.get(key)
            if previous is not None and previous.sha256 != item.sha256:
                raise DiscoveryError("bootstrap pool contains generation equivocation")
            unique[key] = item
        self.bootstrap_sets = tuple(
            sorted(unique.values(), key=lambda item: (-item.generation, item.sha256))
        )
        self.bootstrap_set = self.bootstrap_sets[0]
        self.network_id = network_id
        self.protocol_version = protocol_version
        if cache is not None and (
            cache.network_id != network_id or cache.protocol_version != protocol_version
        ):
            raise DiscoveryError("peer cache belongs to a different network")
        self.cache = cache

    def seed_candidates(self, capability: str, now: int | None = None) -> tuple[NodeDescriptor, ...]:
        selected: dict[str, NodeDescriptor] = {}
        for bootstrap_set in self.bootstrap_sets:
            for peer in bootstrap_set.peers:
                try:
                    peer.verify(
                        now=now,
                        expected_network_id=self.network_id,
                        expected_protocol_version=self.protocol_version,
                    )
                except DescriptorError:
                    continue
                if capability not in peer.capabilities or peer.reachability != "reachable":
                    continue
                previous = selected.get(peer.node_id)
                if previous is None or peer.issued_at > previous.issued_at:
                    selected[peer.node_id] = peer
        return tuple(selected.values())

    def candidates(self, capability: str, now: int | None = None) -> tuple[NodeDescriptor, ...]:
        ordered: list[NodeDescriptor] = []
        if self.cache is not None:
            ordered.extend(self.cache.ranked(capability, now=now))
        ordered.extend(self.seed_candidates(capability, now=now))
        selected: dict[str, NodeDescriptor] = {}
        order: list[str] = []
        for peer in ordered:
            try:
                peer.verify(
                    now=now,
                    expected_network_id=self.network_id,
                    expected_protocol_version=self.protocol_version,
                )
            except DescriptorError:
                continue
            if capability not in peer.capabilities or peer.reachability != "reachable":
                continue
            previous = selected.get(peer.node_id)
            if previous is None:
                selected[peer.node_id] = peer
                order.append(peer.node_id)
            elif peer.issued_at > previous.issued_at:
                selected[peer.node_id] = peer
        return tuple(selected[node_id] for node_id in order)
