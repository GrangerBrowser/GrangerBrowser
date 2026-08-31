from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .bootstrap import BootstrapPool, BootstrapSet, PeerCache
from .errors import DescriptorError, DiscoveryError, GrangerNetworkError
from .identity import ServiceIdentity
from .node import (
    NODE_DESCRIPTOR_FILE,
    NODE_IDENTITY_FILE,
    NodeListenerEndpoint,
    WanNodeServer,
    load_node,
)
from .peer import (
    MAX_NODE_DESCRIPTOR_LIFETIME,
    NODE_CAPABILITIES,
    NODE_NETWORK_ID,
    NODE_PROTOCOL_VERSION,
    RELAY_CAPABILITIES,
    NodeDescriptor,
    RelayPolicy,
)
from .reseed import ReseedStore
from .transport import RendezvousEndpoint
from .wan_config import load_authority_pin
from .wan_discovery import WanDiscoveryClient


OPERATOR_CONFIG_VERSION = 1
MAX_OPERATOR_PATHS = 64
DEFAULT_STATUS_INTERVAL = 30
OPERATOR_TERMINAL_EXIT_CODE = 78
MIN_PERSISTENT_ROUTER_PEERS = 3
MAX_PERSISTENT_PEER_SUCCESS_AGE_SECONDS = 6 * 60 * 60
NODE_DESCRIPTOR_REPUBLISH_INTERVAL_SECONDS = 15 * 60
DISCOVERY_SCHEDULE_DOMAIN = b"granger-network-v0.4/operator-discovery-schedule\x00"
DISCOVERY_CAPABILITY_DOMAIN = b"granger-network-v0.4/operator-discovery-capability\x00"
DISCOVERY_CAPABILITIES = ("discovery", *sorted(RELAY_CAPABILITIES))


@dataclass(frozen=True)
class OperatorConfig:
    listen: NodeListenerEndpoint
    advertise: RendezvousEndpoint
    capabilities: tuple[str, ...]
    relay_policy: RelayPolicy
    descriptor_lifetime: int
    renew_before: int
    discovery_interval: int
    peer_descriptors: tuple[Path, ...]
    authority_pins: tuple[Path, ...]
    bootstrap_bundles: tuple[Path, ...]


@dataclass(frozen=True)
class _BootstrapLoadResult:
    bootstrap_sets: tuple[BootstrapSet, ...]
    failure_reason: str = ""


class _PersistentPeerPool:
    """Bootstrap-compatible view over recently authenticated peer descriptors."""

    network_id = NODE_NETWORK_ID
    protocol_version = NODE_PROTOCOL_VERSION

    def __init__(self, peers: tuple[NodeDescriptor, ...]) -> None:
        selected: dict[str, NodeDescriptor] = {}
        for peer in peers:
            peer.verify(
                expected_network_id=self.network_id,
                expected_protocol_version=self.protocol_version,
            )
            if peer.reachability != "reachable" or "discovery" not in peer.capabilities:
                continue
            previous = selected.get(peer.node_id)
            if previous is None or peer.issued_at > previous.issued_at:
                selected[peer.node_id] = peer
        self.peers = tuple(selected.values())

    def candidates(
        self,
        capability: str,
        now: int | None = None,
    ) -> tuple[NodeDescriptor, ...]:
        result: list[NodeDescriptor] = []
        for peer in self.peers:
            try:
                peer.verify(
                    now=now,
                    expected_network_id=self.network_id,
                    expected_protocol_version=self.protocol_version,
                )
            except DescriptorError:
                continue
            if capability in peer.capabilities and peer.reachability == "reachable":
                result.append(peer)
        return tuple(result)

    def seed_candidates(
        self,
        capability: str,
        now: int | None = None,
    ) -> tuple[NodeDescriptor, ...]:
        return self.candidates(capability, now=now)


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the supported range")
    return value


def _discovery_wait_seconds(
    node_id: str,
    interval: int,
    cycle: int,
    *,
    initial: bool,
) -> int:
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("operator discovery node identity is invalid")
    if (
        isinstance(interval, bool)
        or not isinstance(interval, int)
        or interval < 1
        or isinstance(cycle, bool)
        or not isinstance(cycle, int)
        or cycle < 0
    ):
        raise ValueError("operator discovery schedule is invalid")
    window = max(1, min(60, interval))
    digest = hashlib.sha256(
        DISCOVERY_SCHEDULE_DOMAIN
        + node_id.encode("ascii")
        + cycle.to_bytes(8, "big")
    ).digest()
    offset = int.from_bytes(digest[:4], "big") % (window + 1)
    return offset if initial else interval + offset


def _discovery_capability(node_id: str, cycle: int) -> str:
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("operator discovery node identity is invalid")
    if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
        raise ValueError("operator discovery cycle is invalid")
    offset = int.from_bytes(
        hashlib.sha256(
            DISCOVERY_CAPABILITY_DOMAIN + node_id.encode("ascii")
        ).digest()[:4],
        "big",
    ) % len(DISCOVERY_CAPABILITIES)
    return DISCOVERY_CAPABILITIES[(offset + cycle) % len(DISCOVERY_CAPABILITIES)]


def _descriptor_publication_due(last_published_at: float | None, now: float) -> bool:
    if not isinstance(now, (int, float)) or now < 0:
        raise ValueError("operator descriptor publication time is invalid")
    if last_published_at is None:
        return True
    if not isinstance(last_published_at, (int, float)) or last_published_at < 0:
        raise ValueError("operator descriptor publication time is invalid")
    return now - last_published_at >= NODE_DESCRIPTOR_REPUBLISH_INTERVAL_SECONDS


def _endpoint(document: object, label: str, *, listener: bool):
    if not isinstance(document, dict) or set(document) != {"host", "port"}:
        raise ValueError(f"{label} endpoint schema is invalid")
    if listener:
        return NodeListenerEndpoint(document["host"], document["port"])
    return RendezvousEndpoint(document["host"], document["port"])


def _paths(base: Path, values: object, label: str, maximum: int) -> tuple[Path, ...]:
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{label} list is invalid")
    result: list[Path] = []
    for value in values:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(f"{label} path is invalid")
        candidate = Path(value).expanduser()
        result.append((base / candidate).resolve() if not candidate.is_absolute() else candidate.resolve())
    return tuple(result)


def load_operator_config(path: Path) -> OperatorConfig:
    source = Path(path).resolve()
    try:
        document = parse_json_object(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"operator config is unavailable: {error}") from error
    expected = {
        "advertise",
        "bootstrap",
        "capabilities",
        "descriptorLifetimeSeconds",
        "discoveryIntervalSeconds",
        "listen",
        "peerDescriptors",
        "relayPolicy",
        "renewBeforeSeconds",
        "version",
    }
    if set(document) != expected or document["version"] != OPERATOR_CONFIG_VERSION:
        raise ValueError("operator config schema is unsupported")
    capabilities = document["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or any(not isinstance(item, str) for item in capabilities)
    ):
        raise ValueError("operator capabilities are invalid")
    normalized_capabilities = tuple(sorted(set(capabilities)))
    if len(normalized_capabilities) != len(capabilities) or not set(normalized_capabilities) <= NODE_CAPABILITIES:
        raise ValueError("operator capabilities contain duplicates or unknown roles")
    policy = RelayPolicy.from_document(document["relayPolicy"])
    relay_enabled = bool(set(normalized_capabilities) & RELAY_CAPABILITIES)
    if policy.enabled != relay_enabled:
        raise ValueError("operator relay policy does not match its capabilities")
    bootstrap = document["bootstrap"]
    if not isinstance(bootstrap, dict) or set(bootstrap) != {"authorityPins", "bundles"}:
        raise ValueError("operator bootstrap config schema is invalid")
    base = source.parent
    pins = _paths(base, bootstrap["authorityPins"], "bootstrap authority", 8)
    bundles = _paths(base, bootstrap["bundles"], "bootstrap bundle", 64)
    if bool(pins) != bool(bundles):
        raise ValueError("bootstrap bundles and authority pins must be configured together")
    lifetime = _integer(
        document["descriptorLifetimeSeconds"],
        60,
        MAX_NODE_DESCRIPTOR_LIFETIME,
        "descriptor lifetime",
    )
    renew_before = _integer(
        document["renewBeforeSeconds"],
        60,
        lifetime - 1,
        "descriptor renewal window",
    )
    return OperatorConfig(
        listen=_endpoint(document["listen"], "listener", listener=True),
        advertise=_endpoint(document["advertise"], "advertised", listener=False),
        capabilities=normalized_capabilities,
        relay_policy=policy,
        descriptor_lifetime=lifetime,
        renew_before=renew_before,
        discovery_interval=_integer(
            document["discoveryIntervalSeconds"],
            30,
            3600,
            "discovery interval",
        ),
        peer_descriptors=_paths(base, document["peerDescriptors"], "peer descriptor", MAX_OPERATOR_PATHS),
        authority_pins=pins,
        bootstrap_bundles=bundles,
    )


def _parse_endpoint(value: str, *, listener: bool):
    if not isinstance(value, str) or not value:
        raise ValueError("endpoint is empty")
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("endpoint must use numeric HOST:PORT syntax")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port = int(port_text)
    return NodeListenerEndpoint(host, port) if listener else RendezvousEndpoint(host, port)


def _apply_overrides(
    config: OperatorConfig,
    *,
    bootstrap: bool,
    relay: bool,
    listen: str,
    advertise: str,
) -> OperatorConfig:
    capabilities = set(config.capabilities)
    if bootstrap:
        capabilities.update({"bootstrap", "discovery"})
    if relay:
        capabilities.update(RELAY_CAPABILITIES)
        capabilities.add("discovery")
    policy = config.relay_policy
    if relay and not policy.enabled:
        policy = replace(policy, enabled=True)
    if not (set(capabilities) & RELAY_CAPABILITIES) and policy.enabled:
        policy = replace(policy, enabled=False)
    return replace(
        config,
        listen=_parse_endpoint(listen, listener=True) if listen else config.listen,
        advertise=_parse_endpoint(advertise, listener=False) if advertise else config.advertise,
        capabilities=tuple(sorted(capabilities)),
        relay_policy=policy,
    )


def _chmod(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def _descriptor_matches(descriptor: NodeDescriptor, config: OperatorConfig) -> bool:
    return (
        descriptor.endpoint == config.advertise
        and descriptor.capabilities == config.capabilities
        and descriptor.relay_policy == config.relay_policy
        and descriptor.network_id == NODE_NETWORK_ID
        and descriptor.protocol_version == NODE_PROTOCOL_VERSION
    )


def prepare_node(
    config: OperatorConfig,
    state_dir: Path,
    public_dir: Path,
    *,
    now: int | None = None,
) -> tuple[NodeDescriptor, bool]:
    current = int(time.time()) if now is None else now
    state = Path(state_dir).resolve()
    public = Path(public_dir).resolve()
    state.mkdir(parents=True, exist_ok=True)
    public.mkdir(parents=True, exist_ok=True)
    _chmod(state, 0o700)
    _chmod(public, 0o755)
    identity_path = state / NODE_IDENTITY_FILE
    descriptor_path = state / NODE_DESCRIPTOR_FILE
    if descriptor_path.exists() and not identity_path.exists():
        raise DescriptorError("node descriptor exists without its private identity")
    created = False
    if identity_path.exists():
        identity = ServiceIdentity.load(identity_path)
    else:
        identity = ServiceIdentity.generate()
        identity.save(identity_path)
        _chmod(identity_path, 0o600)
        created = True
    descriptor: NodeDescriptor | None = None
    if descriptor_path.exists():
        content = descriptor_path.read_text(encoding="utf-8")
        try:
            candidate = NodeDescriptor.from_json(
                content,
                now=current,
                expected_network_id=NODE_NETWORK_ID,
                expected_protocol_version=NODE_PROTOCOL_VERSION,
            )
        except DescriptorError:
            raw = parse_json_object(content)
            if not isinstance(raw.get("expiresAt"), int) or raw["expiresAt"] > current:
                raise
        else:
            if candidate.identity_public_key != identity.public_key_bytes:
                raise DescriptorError("node descriptor does not match its private identity")
            if _descriptor_matches(candidate, config) and candidate.expires_at - current > config.renew_before:
                descriptor = candidate
    if descriptor is None:
        descriptor = NodeDescriptor.create(
            identity,
            config.advertise,
            config.capabilities,
            config.relay_policy,
            issued_at=current,
            lifetime=config.descriptor_lifetime,
            network_id=NODE_NETWORK_ID,
            protocol_version=NODE_PROTOCOL_VERSION,
        )
        atomic_write_text(descriptor_path, descriptor.to_json(), mode=0o644)
        created = True
    public_descriptor = public / NODE_DESCRIPTOR_FILE
    atomic_write_text(public_descriptor, descriptor.to_json(), mode=0o644)
    _chmod(identity_path, 0o600)
    _chmod(descriptor_path, 0o644)
    _chmod(public_descriptor, 0o644)
    return descriptor, created


def _load_peer_descriptors(config: OperatorConfig) -> tuple[NodeDescriptor, ...]:
    peers: dict[str, NodeDescriptor] = {}
    for path in config.peer_descriptors:
        descriptor = NodeDescriptor.from_json(
            path.read_text(encoding="utf-8"),
            expected_network_id=NODE_NETWORK_ID,
            expected_protocol_version=NODE_PROTOCOL_VERSION,
        )
        previous = peers.get(descriptor.node_id)
        if previous is None or descriptor.issued_at > previous.issued_at:
            peers[descriptor.node_id] = descriptor
    return tuple(peers.values())


def _load_bootstrap_sets(
    config: OperatorConfig,
    state_dir: Path,
    *,
    now: int | None = None,
) -> _BootstrapLoadResult:
    if not config.bootstrap_bundles:
        return _BootstrapLoadResult(())
    pins = tuple(load_authority_pin(path) for path in config.authority_pins)
    reseed = ReseedStore(
        Path(state_dir).resolve() / "reseed",
        pins,
        network_id=NODE_NETWORK_ID,
        protocol_version=NODE_PROTOCOL_VERSION,
    )
    expired = False
    for path in config.bootstrap_bundles:
        try:
            reseed.import_path(path, source="operator-config", now=now)
        except DiscoveryError:
            if reseed.expired_installed_bundle(path, now=now) is None:
                raise
            expired = True
    active = reseed.load_active(now=now)
    if active:
        return _BootstrapLoadResult(
            active,
            "REFRESH_REQUIRED" if expired else "",
        )
    return _BootstrapLoadResult((), "RESEED_EXPIRED" if expired else "")


def _persistent_router_peers(
    state_dir: Path,
    self_node_id: str,
    *,
    now: int | None = None,
) -> tuple[NodeDescriptor, ...]:
    current = int(time.time()) if now is None else now
    cache = PeerCache(
        Path(state_dir).resolve() / "peer-cache.json",
        network_id=NODE_NETWORK_ID,
        protocol_version=NODE_PROTOCOL_VERSION,
    )
    peers: list[NodeDescriptor] = []
    for entry in cache.entries(now=current):
        last_success = entry.last_successful_connection
        descriptor = entry.descriptor
        if (
            descriptor.node_id == self_node_id
            or descriptor.reachability != "reachable"
            or "discovery" not in descriptor.capabilities
            or last_success is None
            or last_success > current + 120
            or current - last_success > MAX_PERSISTENT_PEER_SUCCESS_AGE_SECONDS
        ):
            continue
        peers.append(descriptor)
    return tuple(peers)


class _DiscoverySupervisor:
    def __init__(
        self,
        node: WanNodeServer,
        identity: ServiceIdentity,
        bootstrap_sets: tuple[BootstrapSet, ...],
        interval: int,
        *,
        startup_failure_reason: str = "",
        persistent_peers: tuple[NodeDescriptor, ...] = (),
    ) -> None:
        self.node = node
        self.interval = interval
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self._descriptor_published_at: float | None = None
        self.startup_failure_reason = startup_failure_reason
        if bootstrap_sets:
            self.snapshot = {
                "dhtReady": False,
                "failureReason": startup_failure_reason,
                "refreshRequired": bool(startup_failure_reason),
                "state": "BOOTSTRAPPING",
            }
        elif startup_failure_reason:
            reachable_relays = sum(
                bool(set(peer.capabilities) & RELAY_CAPABILITIES)
                for peer in persistent_peers
            ) + int(bool(set(node.descriptor.capabilities) & RELAY_CAPABILITIES))
            self.snapshot = {
                "authenticatedPeers": 0,
                "dhtReady": False,
                "failureReason": startup_failure_reason,
                "knownPeers": len(persistent_peers) + 1,
                "reachableRelays": reachable_relays,
                "refreshRequired": True,
                "state": "DEGRADED",
            }
        else:
            self.snapshot = {
                "dhtReady": False,
                "failureReason": "NO_RESEED_SOURCE",
                "state": "BOOTSTRAP_LISTENING",
            }
        pool = None
        cache = None
        if bootstrap_sets:
            pool = BootstrapPool(bootstrap_sets, node.peer_cache)
            cache = node.peer_cache
        elif startup_failure_reason == "RESEED_EXPIRED" and persistent_peers:
            # The expired bundle is never admitted here. Only individually signed,
            # still-valid descriptors from recent authenticated sessions are used.
            pool = _PersistentPeerPool(persistent_peers)
        self.discovery = (
            WanDiscoveryClient(
                identity,
                pool,
                cache=cache,
                replication_factor=3,
                minimum_replicas=2,
                timeout=min(10.0, float(node.policy.connection_timeout_seconds)),
            )
            if pool is not None
            else None
        )

    def _with_reseed_status(self, document: dict[str, object]) -> dict[str, object]:
        if not self.startup_failure_reason:
            return document
        result = dict(document)
        result["refreshRequired"] = True
        result["reseedState"] = self.startup_failure_reason
        if (
            self.startup_failure_reason == "RESEED_EXPIRED"
            and result.get("state") != "OFFLINE"
        ):
            result["failureReason"] = "RESEED_EXPIRED"
            result["state"] = "DEGRADED"
        elif not result.get("failureReason"):
            result["failureReason"] = self.startup_failure_reason
        return result

    def start(self) -> None:
        if self.discovery is None:
            return
        self.thread = threading.Thread(
            target=self._run,
            name="granger-operator-discovery",
            daemon=True,
        )
        self.thread.start()

    def descriptor_renewed(self) -> None:
        with self.lock:
            self._descriptor_published_at = None
        self.wake_event.set()

    def _wait(self, timeout: float) -> bool:
        if self.stop_event.is_set():
            return True
        self.wake_event.wait(timeout)
        self.wake_event.clear()
        return self.stop_event.is_set()

    def _run(self) -> None:
        assert self.discovery is not None
        target_seed = hashlib.sha256(self.node.descriptor.node_id.encode("ascii")).digest()
        cycle = 0
        if self._wait(
            _discovery_wait_seconds(
                self.node.descriptor.node_id,
                self.interval,
                cycle,
                initial=True,
            )
        ):
            return
        while not self.stop_event.is_set():
            try:
                health = self.discovery.join_network()
                learned: dict[str, NodeDescriptor] = {}
                if health.state.value != "OFFLINE":
                    current = time.monotonic()
                    descriptor = self.node.descriptor
                    with self.lock:
                        publication_due = _descriptor_publication_due(
                            self._descriptor_published_at,
                            current,
                        )
                    if publication_due:
                        stored_replicas = self.discovery.publish(descriptor)
                        if stored_replicas >= self.discovery.replication_factor:
                            with self.lock:
                                if self.node.descriptor == descriptor:
                                    self._descriptor_published_at = current
                    capability = _discovery_capability(
                        self.node.descriptor.node_id,
                        cycle,
                    )
                    target = hashlib.sha256(
                        target_seed + capability.encode("ascii")
                    ).digest()
                    try:
                        for peer in self.discovery.find_nodes(target, capability):
                            if peer.node_id != self.node.descriptor.node_id:
                                learned[peer.node_id] = peer
                    except (GrangerNetworkError, OSError):
                        pass
                for peer in learned.values():
                    self.node.add_known_peer(peer, source="operator-dht")
                with self.lock:
                    self.snapshot = self._with_reseed_status(
                        self.discovery.health().to_document()
                    )
            except (GrangerNetworkError, OSError, ValueError) as error:
                with self.lock:
                    self.snapshot = self._with_reseed_status(
                        {
                            "dhtReady": False,
                            "failureReason": type(error).__name__,
                            "state": "DEGRADED",
                        }
                    )
            cycle += 1
            self._wait(
                _discovery_wait_seconds(
                    self.node.descriptor.node_id,
                    self.interval,
                    cycle,
                    initial=False,
                )
            )

    def status(self) -> dict[str, object]:
        with self.lock:
            return dict(self.snapshot)

    def stop(self) -> None:
        self.stop_event.set()
        self.wake_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)
            self.thread = None


def _renew_running_descriptor(
    config: OperatorConfig,
    state_dir: Path,
    public_dir: Path,
    node: WanNodeServer,
    supervisor: _DiscoverySupervisor,
    *,
    now: int | None = None,
) -> tuple[NodeDescriptor, bool]:
    current_time = int(time.time()) if now is None else now
    current = node.descriptor
    if current.expires_at - current_time > config.renew_before:
        return current, False
    renewed, changed = prepare_node(
        config,
        state_dir,
        public_dir,
        now=current_time,
    )
    if not changed:
        if renewed != current:
            raise DescriptorError("operator descriptor state changed without renewal")
        return current, False
    node.replace_descriptor(renewed, now=current_time)
    supervisor.descriptor_renewed()
    return renewed, True


class _PidLease:
    def __init__(self, path: Path) -> None:
        self.path = Path(path).resolve()
        self.acquired = False

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except (OSError, ValueError):
            return False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                existing = int(self.path.read_text(encoding="ascii").strip())
            except (OSError, UnicodeDecodeError, ValueError):
                existing = 0
            if existing > 0 and self._alive(existing):
                raise RuntimeError(f"Granger node already appears to be running as PID {existing}")
            self.path.unlink(missing_ok=True)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.acquired = True

    def release(self) -> None:
        if self.acquired:
            self.path.unlink(missing_ok=True)
            self.acquired = False


def _status_document(
    node: WanNodeServer,
    supervisor: _DiscoverySupervisor,
    *,
    state: str,
    started_at: int,
) -> dict[str, object]:
    return {
        "acceptedConnections": node.accepted_connections,
        "activeCircuits": node.runtime.active_circuits,
        "advertise": {
            "host": node.descriptor.endpoint.host,
            "port": node.descriptor.endpoint.port,
        },
        "capabilities": list(node.descriptor.capabilities),
        "descriptorExpiresAt": node.descriptor.expires_at,
        "identityPersistent": True,
        "listen": {
            "host": node.listener_endpoint.host,
            "port": node.listener_endpoint.port,
        },
        "network": supervisor.status(),
        "nodeId": node.descriptor.node_id,
        "peerCache": node.peer_cache.stats(),
        "pid": os.getpid(),
        "rejectedConnections": node.rejected_connections,
        "rpcRequests": node.rpc_requests,
        "startedAt": started_at,
        "state": state,
        "version": 1,
    }


def _stopped_status_document(
    node: WanNodeServer,
    status_file: Path,
    *,
    started_at: int,
) -> dict[str, object]:
    try:
        previous = json.loads(Path(status_file).read_text(encoding="utf-8"))
        if not isinstance(previous, dict):
            raise ValueError("operator status document must be an object")
        document: dict[str, object] = dict(previous)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        document = {
            "acceptedConnections": node.accepted_connections,
            "activeCircuits": 0,
            "advertise": {
                "host": node.descriptor.endpoint.host,
                "port": node.descriptor.endpoint.port,
            },
            "capabilities": list(node.descriptor.capabilities),
            "descriptorExpiresAt": node.descriptor.expires_at,
            "identityPersistent": True,
            "listen": {
                "host": node.listener_endpoint.host,
                "port": node.listener_endpoint.port,
            },
            "network": {
                "dhtReady": False,
                "failureReason": "STOPPED",
                "state": "OFFLINE",
            },
            "nodeId": node.descriptor.node_id,
            "peerCache": {
                "loadError": "",
                "peers": 0,
                "successfulPeers": 0,
                "version": 2,
            },
            "rejectedConnections": node.rejected_connections,
            "rpcRequests": node.rpc_requests,
            "version": 1,
        }
    document["activeCircuits"] = 0
    document["pid"] = os.getpid()
    document["startedAt"] = started_at
    document["state"] = "STOPPED"
    return document


def run_operator(
    config: OperatorConfig,
    state_dir: Path,
    public_dir: Path,
    pid_file: Path,
    ready_file: Path,
    status_file: Path,
    diagnostics_file: Path,
) -> int:
    state = Path(state_dir).resolve()
    identity_preexisting = (state / NODE_IDENTITY_FILE).is_file()
    bootstrap_load = _load_bootstrap_sets(config, state)
    if bootstrap_load.failure_reason == "RESEED_EXPIRED" and not identity_preexisting:
        raise DiscoveryError("expired reseed cannot initialize a fresh router")
    descriptor, _created = prepare_node(config, state_dir, public_dir)
    identity = ServiceIdentity.load(state / NODE_IDENTITY_FILE)
    persistent_peers = (
        _persistent_router_peers(state, descriptor.node_id)
        if bootstrap_load.failure_reason == "RESEED_EXPIRED"
        else ()
    )
    if (
        bootstrap_load.failure_reason == "RESEED_EXPIRED"
        and len(persistent_peers) < MIN_PERSISTENT_ROUTER_PEERS
    ):
        raise DiscoveryError(
            "expired reseed has insufficient valid authenticated persistent peer state"
        )
    known: dict[str, NodeDescriptor] = {
        peer.node_id: peer for peer in _load_peer_descriptors(config)
    }
    for bootstrap in bootstrap_load.bootstrap_sets:
        for peer in bootstrap.peers:
            if peer.node_id != descriptor.node_id:
                known[peer.node_id] = peer
    for peer in persistent_peers:
        known[peer.node_id] = peer
    node = load_node(
        state_dir,
        tuple(known.values()),
        listener_endpoint=config.listen,
        diagnostics_path=diagnostics_file,
    )
    supervisor = _DiscoverySupervisor(
        node,
        identity,
        bootstrap_load.bootstrap_sets,
        config.discovery_interval,
        startup_failure_reason=bootstrap_load.failure_reason,
        persistent_peers=persistent_peers,
    )
    lease = _PidLease(pid_file)
    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    previous_handlers: dict[int, object] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)
    started_at = int(time.time())
    try:
        lease.acquire()
        node.start_background()
        supervisor.start()
        atomic_write_text(
            ready_file,
            json.dumps(
                {
                    "advertise": {
                        "host": descriptor.endpoint.host,
                        "port": descriptor.endpoint.port,
                    },
                    "listen": {"host": config.listen.host, "port": config.listen.port},
                    "nodeId": descriptor.node_id,
                    "pid": os.getpid(),
                    "version": 1,
                },
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )
        atomic_write_text(
            status_file,
            json.dumps(
                _status_document(node, supervisor, state="RUNNING", started_at=started_at),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )
        while not stop_event.wait(DEFAULT_STATUS_INTERVAL):
            current_time = int(time.time())
            descriptor, _renewed = _renew_running_descriptor(
                config,
                state,
                public_dir,
                node,
                supervisor,
                now=current_time,
            )
            if current_time >= descriptor.expires_at:
                raise DescriptorError("node descriptor expired while the operator was running")
            atomic_write_text(
                status_file,
                json.dumps(
                    _status_document(node, supervisor, state="RUNNING", started_at=started_at),
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o600,
            )
        return 0
    finally:
        supervisor.stop()
        node.stop()
        atomic_write_text(
            status_file,
            json.dumps(
                _stopped_status_document(node, status_file, started_at=started_at),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )
        Path(ready_file).unlink(missing_ok=True)
        lease.release()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--relay", action="store_true")
    parser.add_argument("--listen", default="")
    parser.add_argument("--advertise", default="")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network bootstrap/relay operator")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    _common(prepare)
    run = commands.add_parser("run")
    _common(run)
    run.add_argument("--pid-file", type=Path, required=True)
    run.add_argument("--ready-file", type=Path, required=True)
    run.add_argument("--status-file", type=Path, required=True)
    run.add_argument("--diagnostics", type=Path, required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--state-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "inspect":
            state = options.state_dir.resolve()
            descriptor = NodeDescriptor.from_json(
                (state / NODE_DESCRIPTOR_FILE).read_text(encoding="utf-8"),
                expected_network_id=NODE_NETWORK_ID,
                expected_protocol_version=NODE_PROTOCOL_VERSION,
            )
            print(
                json.dumps(
                    {
                        "advertise": {
                            "host": descriptor.endpoint.host,
                            "port": descriptor.endpoint.port,
                        },
                        "capabilities": list(descriptor.capabilities),
                        "descriptorExpiresAt": descriptor.expires_at,
                        "nodeId": descriptor.node_id,
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        config = _apply_overrides(
            load_operator_config(options.config),
            bootstrap=options.bootstrap,
            relay=options.relay,
            listen=options.listen,
            advertise=options.advertise,
        )
        if options.command == "prepare":
            descriptor, created = prepare_node(config, options.state_dir, options.public_dir)
            print(
                json.dumps(
                    {
                        "createdOrRenewed": created,
                        "descriptor": str((options.public_dir / NODE_DESCRIPTOR_FILE).resolve()),
                        "expiresAt": descriptor.expires_at,
                        "nodeId": descriptor.node_id,
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        return run_operator(
            config,
            options.state_dir,
            options.public_dir,
            options.pid_file,
            options.ready_file,
            options.status_file,
            options.diagnostics,
        )
    except DiscoveryError as error:
        if options.command == "run":
            Path(options.ready_file).unlink(missing_ok=True)
            detail = str(error).lower()
            if "expired" in detail:
                failure_reason = "RESEED_EXPIRED_NO_VALID_STATE"
            elif "rollback" in detail:
                failure_reason = "SIGNED_TOPOLOGY_ROLLBACK_REJECTED"
            else:
                failure_reason = "SIGNED_TOPOLOGY_REJECTED"
            atomic_write_text(
                options.status_file,
                json.dumps(
                    {
                        "network": {
                            "dhtReady": False,
                            "failureReason": failure_reason,
                            "state": "OFFLINE",
                        },
                        "pid": os.getpid(),
                        "state": "STOPPED",
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o600,
            )
        print(f"granger-operator: {type(error).__name__}: {error}", file=sys.stderr)
        return OPERATOR_TERMINAL_EXIT_CODE
    except (GrangerNetworkError, OSError, RuntimeError, ValueError) as error:
        print(f"granger-operator: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
