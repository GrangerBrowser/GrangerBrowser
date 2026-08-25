from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import atomic_write_text, canonical_json, decode_base64url, encode_base64url, parse_json_object
from .errors import DescriptorError, DiscoveryError
from .identity import ServiceIdentity
from .peer import NodeDescriptor


BOOTSTRAP_SET_VERSION = 1
BOOTSTRAP_SIGNATURE_DOMAIN = b"granger-network-v0.4/bootstrap-set\x00"
MAX_BOOTSTRAP_SET_LIFETIME = 30 * 24 * 60 * 60
MAX_BOOTSTRAP_PEERS = 64
MAX_CACHE_PEERS = 512


@dataclass(frozen=True)
class BootstrapSet:
    authority_public_key: bytes
    issued_at: int
    expires_at: int
    peers: tuple[NodeDescriptor, ...]
    signature: bytes
    version: int = BOOTSTRAP_SET_VERSION

    def unsigned_document(self) -> dict:
        return {
            "authorityKey": encode_base64url(self.authority_public_key),
            "expiresAt": self.expires_at,
            "issuedAt": self.issued_at,
            "peers": [peer.to_document() for peer in self.peers],
            "version": self.version,
        }

    def signature_payload(self) -> bytes:
        return BOOTSTRAP_SIGNATURE_DOMAIN + canonical_json(self.unsigned_document())

    def verify(self, pinned_authority_key: bytes, now: int | None = None) -> None:
        if self.version != BOOTSTRAP_SET_VERSION or isinstance(self.version, bool):
            raise DiscoveryError("bootstrap set version is unsupported")
        if (
            not isinstance(pinned_authority_key, bytes)
            or len(pinned_authority_key) != 32
            or self.authority_public_key != pinned_authority_key
        ):
            raise DiscoveryError("bootstrap authority does not match its local pin")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise DiscoveryError("bootstrap set signature length is invalid")
        for value in (self.issued_at, self.expires_at):
            if isinstance(value, bool) or not isinstance(value, int):
                raise DiscoveryError("bootstrap set timestamps must be integers")
        current = int(time.time()) if now is None else now
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
            peer.verify(now=now)
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

    def to_document(self) -> dict:
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
        issued_at: int | None = None,
        lifetime: int = 7 * 24 * 60 * 60,
    ) -> "BootstrapSet":
        timestamp = int(time.time()) if issued_at is None else issued_at
        unsigned = cls(
            authority.public_key_bytes,
            timestamp,
            timestamp + lifetime,
            tuple(sorted(peers, key=lambda peer: peer.node_id)),
            b"\x00" * 64,
        )
        result = replace(unsigned, signature=authority.sign(unsigned.signature_payload()))
        result.verify(authority.public_key_bytes, now=timestamp)
        return result

    @classmethod
    def from_json(
        cls,
        content: str,
        pinned_authority_key: bytes,
        *,
        now: int | None = None,
    ) -> "BootstrapSet":
        try:
            document = parse_json_object(content)
            if set(document) != {
                "authorityKey",
                "expiresAt",
                "issuedAt",
                "peers",
                "signature",
                "version",
            }:
                raise ValueError("unexpected bootstrap set fields")
            if not isinstance(document["peers"], list):
                raise ValueError("bootstrap peers must be an array")
            peers = tuple(
                NodeDescriptor.from_json(
                    json.dumps(peer, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
                    now=now,
                )
                for peer in document["peers"]
            )
            result = cls(
                decode_base64url(document["authorityKey"]),
                document["issuedAt"],
                document["expiresAt"],
                peers,
                decode_base64url(document["signature"]),
                document["version"],
            )
            result.verify(pinned_authority_key, now=now)
            return result
        except DiscoveryError:
            raise
        except (DescriptorError, KeyError, TypeError, ValueError) as error:
            raise DiscoveryError(f"invalid bootstrap set: {error}") from error


class PeerCache:
    def __init__(self, path: Path, *, maximum: int = MAX_CACHE_PEERS) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 2 <= maximum <= MAX_CACHE_PEERS:
            raise DiscoveryError("peer cache limit is invalid")
        self.path = Path(path)
        self.maximum = maximum
        self._lock = threading.Lock()

    def load(self, now: int | None = None) -> tuple[NodeDescriptor, ...]:
        with self._lock:
            return self._load_unlocked(now)

    def _load_unlocked(self, now: int | None) -> tuple[NodeDescriptor, ...]:
        if not self.path.exists():
            return ()
        try:
            document = parse_json_object(self.path.read_text(encoding="utf-8"))
            if set(document) != {"peers", "version"} or document["version"] != 1:
                raise ValueError("peer cache schema is unsupported")
            if not isinstance(document["peers"], list) or len(document["peers"]) > self.maximum:
                raise ValueError("peer cache entry count is invalid")
            peers: list[NodeDescriptor] = []
            seen: set[str] = set()
            for raw in document["peers"]:
                try:
                    peer = NodeDescriptor.from_json(
                        json.dumps(raw, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
                        now=now,
                    )
                except DescriptorError:
                    continue
                if peer.node_id not in seen:
                    peers.append(peer)
                    seen.add(peer.node_id)
            return tuple(peers)
        except (OSError, TypeError, ValueError) as error:
            raise DiscoveryError(f"peer cache is invalid: {error}") from error

    def store(self, peers: list[NodeDescriptor] | tuple[NodeDescriptor, ...], now: int | None = None) -> None:
        valid: dict[str, NodeDescriptor] = {}
        for peer in peers:
            peer.verify(now=now)
            previous = valid.get(peer.node_id)
            if previous is None or peer.issued_at > previous.issued_at:
                valid[peer.node_id] = peer
        ordered = sorted(valid.values(), key=lambda peer: (-peer.issued_at, peer.node_id))[: self.maximum]
        document = {"peers": [peer.to_document() for peer in ordered], "version": 1}
        with self._lock:
            atomic_write_text(
                self.path,
                json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                mode=0o600,
            )

    def add(self, peer: NodeDescriptor, now: int | None = None) -> None:
        peer.verify(now=now)
        with self._lock:
            current = list(self._load_unlocked(now))
            by_id = {entry.node_id: entry for entry in current}
            previous = by_id.get(peer.node_id)
            if previous is None or peer.issued_at >= previous.issued_at:
                by_id[peer.node_id] = peer
            ordered = sorted(by_id.values(), key=lambda entry: (-entry.issued_at, entry.node_id))[: self.maximum]
            atomic_write_text(
                self.path,
                json.dumps(
                    {"peers": [entry.to_document() for entry in ordered], "version": 1},
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o600,
            )


class BootstrapPool:
    def __init__(self, bootstrap_set: BootstrapSet, cache: PeerCache | None = None) -> None:
        if not isinstance(bootstrap_set, BootstrapSet):
            raise DiscoveryError("bootstrap pool requires a verified bootstrap set")
        self.bootstrap_set = bootstrap_set
        self.cache = cache

    def candidates(self, capability: str, now: int | None = None) -> tuple[NodeDescriptor, ...]:
        peers = list(self.bootstrap_set.peers)
        if self.cache is not None:
            peers.extend(self.cache.load(now=now))
        selected: dict[str, NodeDescriptor] = {}
        for peer in peers:
            try:
                peer.verify(now=now)
            except DescriptorError:
                continue
            if capability not in peer.capabilities or peer.reachability != "reachable":
                continue
            previous = selected.get(peer.node_id)
            if previous is None or peer.issued_at > previous.issued_at:
                selected[peer.node_id] = peer
        return tuple(sorted(selected.values(), key=lambda peer: peer.node_id))
