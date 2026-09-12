"""Bounded authority-signed control snapshots over the existing authenticated RPC.

Carriers are not authorities. Historical contacts authorize only the recovery
role; normal peer authentication still requires currently valid descriptors.
"""
from __future__ import annotations

from .stage_trace import traced

import hashlib
import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path

from ._codec import atomic_write_bytes, canonical_json, decode_base64url, encode_base64url, parse_json_object
from .bootstrap import BootstrapSet, PeerCache
from .errors import DiscoveryError, GrangerNetworkError, ProtocolError
from .identity import ServiceIdentity
from .peer_rpc import ConfigRecoveryContact, RpcType, connect_config_recovery
from .reseed import (
    MAX_RESEED_BUNDLE_BYTES, MAX_RESEED_TRANSPORT_CHUNK_BYTES,
    ReseedAdvertisement, decode_reseed_advertisements,
    decode_reseed_chunk_response, encode_reseed_chunk_request,
)
from .wan_config import (
    MAX_CONFIG_CLOCK_SKEW, SIGNED_CONFIG_NETWORK_ID,
    _active_config_path, _config_member, _load_public_pin, _read_document,
    ensure_browser_wan_config, load_authority_pin, load_browser_wan_config,
)

MAX_RECOVERY_PEERS = 8
MAX_RECOVERY_SECONDS = 24.0
MAX_CONFIG_BYTES = 64 * 1024
RENEWAL_MARGIN_SECONDS = 15 * 60


def _bootstrap(config, *, now: int) -> BootstrapSet:
    return BootstrapSet.from_json(
        config.bootstrap_path.read_text(encoding="utf-8"),
        load_authority_pin(config.authority_pin_path), now=now,
        expected_network_id=config.network_id,
        expected_protocol_version=config.protocol_version,
    )


def export_public_config(path: Path, trust_anchor: Path, *, now: int | None = None) -> bytes:
    current = int(time.time()) if now is None else now
    config = load_browser_wan_config(path, trust_anchor_path=trust_anchor, now=current, allow_legacy=False)
    _bootstrap(config, now=current)
    _, content, document = _read_document(path, "WAN config")
    if len(content) > MAX_CONFIG_BYTES:
        raise DiscoveryError("WAN config exceeds its transfer limit")
    members = {
        name: encode_base64url(_config_member(path.parent, name, "public member").read_bytes())
        for name in (document["bootstrap"], document["authorityPin"])
    }
    result = canonical_json({"version": 1, "config": encode_base64url(content), "members": members})
    if len(result) > MAX_RESEED_BUNDLE_BYTES:
        raise DiscoveryError("WAN config snapshot exceeds its transfer limit")
    return result


class WanConfigPublisher:
    """In-memory public-only snapshot; operator/client validates before sharing."""

    def __init__(self, config_path: Path, trust_anchor: Path, *, now: int | None = None) -> None:
        self._lock = threading.Lock()
        self.replace(config_path, trust_anchor, now=now)

    def replace(self, path: Path, trust_anchor: Path, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        payload = export_public_config(path, trust_anchor, now=current)
        config = load_browser_wan_config(path, trust_anchor_path=trust_anchor, now=current, allow_legacy=False)
        bootstrap = _bootstrap(config, now=current)
        advertisement = ReseedAdvertisement(
            _load_public_pin(trust_anchor, "config authority"), config.generation,
            hashlib.sha256(payload).hexdigest(),
            min(config.expires_at, bootstrap.expires_at, *(peer.expires_at for peer in bootstrap.peers)),
            len(payload),
        )
        with self._lock:
            previous = getattr(self, "_advertisement", None)
            if previous is not None and (
                previous.authority_public_key != advertisement.authority_public_key
                or previous.generation > advertisement.generation
                or (previous.generation == advertisement.generation and previous.sha256 != advertisement.sha256)
            ):
                raise DiscoveryError("public config rollback or equivocation was rejected")
            self._advertisement = advertisement
            self._payload = payload

    def advertisements(self) -> tuple[ReseedAdvertisement, ...]:
        with self._lock:
            return (self._advertisement,) if self._advertisement.expires_at > int(time.time()) else ()

    def transport_chunk(self, digest: str, offset: int) -> tuple[int, bytes]:
        with self._lock:
            if (
                digest != self._advertisement.sha256
                or self._advertisement.expires_at <= int(time.time())
                or not 0 <= offset < len(self._payload)
                or offset % MAX_RESEED_TRANSPORT_CHUNK_BYTES
            ):
                raise DiscoveryError("public config snapshot is unavailable")
            return len(self._payload), self._payload[offset:offset + MAX_RESEED_TRANSPORT_CHUNK_BYTES]


class WanConfigRecovery:
    def __init__(self, bundled: Path, trust_anchor: Path, install_root: Path, rollback: Path) -> None:
        self.bundled = Path(bundled).resolve()
        self.trust_anchor = Path(trust_anchor).resolve()
        self.install_root = Path(install_root).resolve()
        self.rollback = Path(rollback).resolve()
        self.authority = _load_public_pin(self.trust_anchor, "config authority")
        self._lock = threading.Lock()
        self._next_attempt = 0.0
        self._failures = 0
        self.last_error = ""
        self.state = "VALIDATING_CONFIG"
        self.generation = 0
        self.expires_at = 0
        self.renewal_margin = RENEWAL_MARGIN_SECONDS - secrets.randbelow(181)

    def current(self, *, now: int | None = None) -> Path:
        if _load_public_pin(self.trust_anchor, "config authority") != self.authority:
            raise DiscoveryError("config recovery authority changed while running")
        path = ensure_browser_wan_config(
            self.bundled, self.trust_anchor, self.install_root, self.rollback, now=now,
        )
        config = load_browser_wan_config(
            path, trust_anchor_path=self.trust_anchor, rollback_state_path=self.rollback,
            now=now, allow_legacy=False,
        )
        self.generation = config.generation
        self.expires_at = config.expires_at
        return path

    def _historical(self, *, now: int) -> list[tuple[object, BootstrapSet]]:
        paths = [self.bundled]
        try:
            active = _active_config_path(self.install_root)
            if active is not None:
                paths.insert(0, active[0])
        except DiscoveryError:
            pass
        result = []
        for path in paths:
            try:
                _, _, document = _read_document(path, "recovery contact source")
                issued_at = document.get("issuedAt")
                if type(issued_at) is not int or issued_at > now + MAX_CONFIG_CLOCK_SKEW:
                    continue
                # Historical validation yields contacts only. Never return this
                # config to a gateway or use its capabilities for data routing.
                config = load_browser_wan_config(
                    path, trust_anchor_path=self.trust_anchor, now=issued_at, allow_legacy=False,
                )
                result.append((config, _bootstrap(config, now=issued_at)))
            except (GrangerNetworkError, OSError, ValueError):
                continue
        return result

    def contacts(self, *, cache: PeerCache | None = None, now: int | None = None) -> tuple[ConfigRecoveryContact, ...]:
        current = int(time.time()) if now is None else now
        historical = self._historical(now=current)
        peers = []
        if cache is not None:
            if cache.network_id != SIGNED_CONFIG_NETWORK_ID or cache.protocol_version != 3:
                raise DiscoveryError("config recovery cache belongs to another network")
            peers.extend(cache.ranked("discovery")[:MAX_RECOVERY_PEERS])
        for _, bootstrap in historical:
            peers.extend(bootstrap.peers)
        result = {}
        for peer in peers:
            if peer.reachability == "reachable":
                result.setdefault(peer.node_id, ConfigRecoveryContact(
                    peer.identity_public_key, peer.endpoint, peer.network_id,
                    peer.protocol_version, peer.issued_at,
                ))
        selected = list(result.values())
        secrets.SystemRandom().shuffle(selected)
        return tuple(selected[:MAX_RECOVERY_PEERS])

    def install(self, payload: bytes, *, advertisement: ReseedAdvertisement | None = None, now: int | None = None) -> Path:
        if _load_public_pin(self.trust_anchor, "config authority") != self.authority:
            raise DiscoveryError("config recovery authority changed while running")
        current = int(time.time()) if now is None else now
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_RESEED_BUNDLE_BYTES:
            raise DiscoveryError("WAN config snapshot size is invalid")
        if advertisement is not None and (
            advertisement.authority_public_key != self.authority
            or advertisement.size != len(payload)
            or advertisement.sha256 != hashlib.sha256(payload).hexdigest()
            or advertisement.expires_at <= current
        ):
            raise DiscoveryError("WAN config snapshot does not match its advertisement")
        try:
            envelope = parse_json_object(payload.decode("ascii"))
            if set(envelope) != {"version", "config", "members"} or type(envelope["version"]) is not int or envelope["version"] != 1:
                raise ValueError("unsupported snapshot")
            config_bytes = decode_base64url(envelope["config"])
            if len(config_bytes) > MAX_CONFIG_BYTES:
                raise ValueError("oversized config")
            document = parse_json_object(config_bytes.decode("utf-8"))
            names = [document["bootstrap"], document["authorityPin"]]
            members = envelope["members"]
            if not isinstance(members, dict) or set(members) != set(names) or len(members) != 2:
                raise ValueError("snapshot member mismatch")
            # A network snapshot has exactly three files, no extraction paths,
            # links, alternate data streams, device names or nested directories.
            for name in names:
                if not isinstance(name, str) or name not in {"bootstrap-set.json", "bootstrap-authority.pin"}:
                    raise ValueError("unsupported snapshot member name")
            decoded = {name: decode_base64url(members[name]) for name in names}
        except (KeyError, TypeError, ValueError, RecursionError) as error:
            raise DiscoveryError("WAN config snapshot is malformed") from error
        self.install_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".config-candidate-", dir=self.install_root) as directory:
            root = Path(directory)
            path = root / "browser-wan.json"
            atomic_write_bytes(path, config_bytes)
            for name, content in decoded.items():
                atomic_write_bytes(root / name, content)
            config = load_browser_wan_config(
                path, trust_anchor_path=self.trust_anchor, rollback_state_path=self.rollback,
                now=current, allow_legacy=False,
            )
            bootstrap = _bootstrap(config, now=current)
            historical = self._historical(now=current)
            pins = {load_authority_pin(old.authority_pin_path) for old, _ in historical}
            if not pins or bootstrap.authority_public_key not in pins:
                raise DiscoveryError("config recovery cannot replace the existing bootstrap authority")
            if advertisement is not None and (
                config.generation != advertisement.generation
                or advertisement.expires_at != min(config.expires_at, bootstrap.expires_at, *(peer.expires_at for peer in bootstrap.peers))
            ):
                raise DiscoveryError("signed config does not match advertised generation or validity")
            return ensure_browser_wan_config(
                path, self.trust_anchor, self.install_root, self.rollback, now=current,
            )

    @traced("signed-config-recovery")
    def refresh(self, identity: ServiceIdentity, *, cache: PeerCache | None = None, discovery=None,
                stop: threading.Event | None = None, now: int | None = None) -> Path | None:
        current = int(time.time()) if now is None else now
        if not self._lock.acquire(blocking=False):
            return None
        try:
            if time.monotonic() < self._next_attempt:
                return None
            self.state = "UPDATING_CONFIG"
            self._failures = min(6, self._failures + 1)
            delay = min(900, 30 * 2 ** (self._failures - 1))
            self._next_attempt = time.monotonic() + delay * (0.8 + secrets.randbelow(401) / 1000)
            deadline = time.monotonic() + MAX_RECOVERY_SECONDS
            sources = (tuple(discovery.pool.candidates("discovery"))[:MAX_RECOVERY_PEERS]
                       if discovery is not None else self.contacts(cache=cache, now=current))
            for contact in sources:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or (stop is not None and stop.is_set()):
                    break
                peer = None
                timer = None
                circuit = None
                try:
                    if discovery is None:
                        peer = connect_config_recovery(contact, ServiceIdentity.generate(), timeout=min(3.0, remaining))
                    else:
                        # Once joined, control propagation uses ordinary private
                        # ingress, never a direct retry to the target carrier.
                        from .circuit import CircuitBuilder
                        from .peer_rpc import PeerRole
                        routes = discovery._private_route_candidates(contact)
                        if not routes:
                            raise DiscoveryError("private config carrier is unavailable")
                        circuit = CircuitBuilder(identity, PeerRole.CLIENT, timeout=min(3.0, remaining)).open(routes[0])
                        peer = circuit.endpoint
                    def expire(connection=peer.channel.connection):
                        try:
                            connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        connection.close()
                    timer = threading.Timer(min(3.0, max(0.01, deadline - time.monotonic())), expire)
                    timer.daemon = True
                    timer.start()
                    response = peer.rpc.request(RpcType.WAN_CONFIG_QUERY, expected=RpcType.WAN_CONFIG_QUERY)
                    advertisements = decode_reseed_advertisements(response.payload)
                    # At most one snapshot per carrier per attempt. Untrusted
                    # advertising cannot advance persistent high-water state.
                    eligible = [ad for ad in advertisements if ad.authority_public_key == self.authority and ad.expires_at > current]
                    if not eligible:
                        continue
                    ad = max(eligible, key=lambda item: item.generation)
                    payload = bytearray()
                    for offset in range(0, ad.size, MAX_RESEED_TRANSPORT_CHUNK_BYTES):
                        if time.monotonic() >= deadline or (stop is not None and stop.is_set()):
                            raise TimeoutError("config transfer was cancelled or expired")
                        response = peer.rpc.request(
                            RpcType.WAN_CONFIG_CHUNK, encode_reseed_chunk_request(ad.sha256, offset),
                            expected=RpcType.WAN_CONFIG_CHUNK,
                        )
                        digest, received_offset, total, chunk = decode_reseed_chunk_response(response.payload)
                        if (digest != ad.sha256 or received_offset != offset or total != ad.size
                                or len(chunk) != min(MAX_RESEED_TRANSPORT_CHUNK_BYTES, ad.size - offset)):
                            raise ProtocolError("WAN config transfer framing mismatch")
                        payload.extend(chunk)
                    if stop is not None and stop.is_set():
                        return None
                    installed = self.install(bytes(payload), advertisement=ad, now=now)
                    config = load_browser_wan_config(installed, trust_anchor_path=self.trust_anchor, now=now, allow_legacy=False)
                    self.generation, self.expires_at = config.generation, config.expires_at
                    self._failures = 0
                    self._next_attempt = time.monotonic() + 60 + secrets.randbelow(61)
                    self.last_error = ""
                    self.state = "CONFIG_VALID"
                    return installed
                except (GrangerNetworkError, OSError, ValueError) as error:
                    self.last_error = "CONFIG_EQUIVOCATION" if "equivocation" in str(error) else "CONFIG_UPDATE_REJECTED_OR_UNAVAILABLE"
                finally:
                    if timer is not None:
                        timer.cancel()
                    if peer is not None:
                        if circuit is not None:
                            circuit.close()
                        else:
                            peer.close()
            self.state = "RECOVERING"
            return None
        finally:
            self._lock.release()

    def snapshot(self) -> dict[str, object]:
        return {"state": self.state, "generation": self.generation, "expiresAt": self.expires_at,
                "errorCode": self.last_error, "retryInSeconds": max(0, int(self._next_attempt - time.monotonic()))}
