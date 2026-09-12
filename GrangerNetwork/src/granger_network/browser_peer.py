from __future__ import annotations

import hashlib
import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ._codec import atomic_write_text
from .errors import GrangerNetworkError, OverlayRoutingError, ProtocolError, ResourceLimitError
from .identity import ServiceIdentity
from .node import NodeListenerEndpoint, WanNodeServer
from .peer import (
    ADJACENT_NODE_DESCRIPTOR_VERSION,
    NodeDescriptor,
    RelayPolicy,
)
from .peer_rpc import (
    PeerRole,
    RpcType,
    connect_authenticated_peer,
)
from .reseed import ReseedStore
from .transport import RendezvousEndpoint


_ANCHOR_SELECTION_DOMAIN = b"granger-network-v0.6/browser-peer-anchor\x00"
_PUBLIC_RELAY_SELECTION_DOMAIN = b"granger-network-v0.7/browser-public-relay\x00"
_RECONNECT_JITTER_DOMAIN = b"granger-network-v0.7/browser-peer-reconnect\x00"
PUBLIC_BROWSER_CAPABILITIES = (
    "access",
    "discovery",
    "entry",
    "introduction",
    "middle",
    "rendezvous",
    "service-relay",
)


class _BrowserDiscovery(Protocol):
    def route_candidates(self, target: bytes, capability: str) -> tuple[NodeDescriptor, ...]: ...

    def publish(self, record) -> int: ...


@dataclass(frozen=True)
class BrowserPeerPolicy:
    target_adjacencies: int = 2
    descriptor_lifetime_seconds: int = 10 * 60
    renewal_margin_seconds: int = 90
    reconnect_floor_seconds: float = 0.25
    reconnect_ceiling_seconds: float = 15.0
    public_listener_port: int = 0
    reachability_quorum: int = 2
    public_reprobe_seconds: float = 5 * 60.0
    public_retry_seconds: float = 60.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.target_adjacencies, bool)
            or not isinstance(self.target_adjacencies, int)
            or not 1 <= self.target_adjacencies <= 4
            or isinstance(self.descriptor_lifetime_seconds, bool)
            or not isinstance(self.descriptor_lifetime_seconds, int)
            or not 120 <= self.descriptor_lifetime_seconds <= 3600
            or isinstance(self.renewal_margin_seconds, bool)
            or not isinstance(self.renewal_margin_seconds, int)
            or not 30 <= self.renewal_margin_seconds < self.descriptor_lifetime_seconds
            or isinstance(self.reconnect_floor_seconds, bool)
            or not isinstance(self.reconnect_floor_seconds, (int, float))
            or not 0.05 <= self.reconnect_floor_seconds <= 5.0
            or isinstance(self.reconnect_ceiling_seconds, bool)
            or not isinstance(self.reconnect_ceiling_seconds, (int, float))
            or not self.reconnect_floor_seconds <= self.reconnect_ceiling_seconds <= 120.0
            or isinstance(self.public_listener_port, bool)
            or not isinstance(self.public_listener_port, int)
            or not (
                self.public_listener_port == 0
                or 1024 <= self.public_listener_port <= 65535
            )
            or isinstance(self.reachability_quorum, bool)
            or not isinstance(self.reachability_quorum, int)
            or not 2 <= self.reachability_quorum <= 4
            or isinstance(self.public_reprobe_seconds, bool)
            or not isinstance(self.public_reprobe_seconds, (int, float))
            or not 1.0 <= self.public_reprobe_seconds <= 3600.0
            or isinstance(self.public_retry_seconds, bool)
            or not isinstance(self.public_retry_seconds, (int, float))
            or not 1.0 <= self.public_retry_seconds <= 3600.0
        ):
            raise ResourceLimitError("browser peer lifecycle policy is invalid")


def default_browser_relay_policy() -> RelayPolicy:
    return RelayPolicy(
        enabled=True,
        max_circuits=4,
        max_streams=32,
        max_connections=4,
        max_bytes_per_circuit=16 * 1024 * 1024,
        max_bandwidth_kib_per_second=256,
        burst_kib=512,
        memory_budget_kib=16 * 1024,
        connection_timeout_seconds=10,
        idle_timeout_seconds=120,
    )


class BrowserPeerRuntime:
    """Restricted participation, with optional callback-proven public relay service."""

    def __init__(
        self,
        identity: ServiceIdentity,
        discovery: _BrowserDiscovery,
        state_dir: Path,
        *,
        relay_policy: RelayPolicy | None = None,
        lifecycle_policy: BrowserPeerPolicy | None = None,
        connector: Callable = connect_authenticated_peer,
        reseed_store: ReseedStore | None = None,
        wan_config_publisher=None,
        on_state_changed: Callable[[], None] | None = None,
    ) -> None:
        if not isinstance(identity, ServiceIdentity):
            raise ValueError("browser peer identity is invalid")
        if not hasattr(discovery, "route_candidates"):
            raise ValueError("browser peer discovery runtime is invalid")
        if not callable(connector):
            raise ValueError("browser peer connector is invalid")
        self.identity = identity
        self.discovery = discovery
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.relay_policy = relay_policy or default_browser_relay_policy()
        self.lifecycle_policy = lifecycle_policy or BrowserPeerPolicy()
        if self.lifecycle_policy.target_adjacencies > self.relay_policy.max_connections:
            raise ResourceLimitError("browser peer adjacency target exceeds its connection limit")
        self._connector = connector
        self.reseed_store = reseed_store
        self.wan_config_publisher = wan_config_publisher
        self._state_changed = on_state_changed or (lambda: None)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._server: WanNodeServer | None = None
        self._anchor: NodeDescriptor | None = None
        self._descriptor: NodeDescriptor | None = None
        self._lock = threading.Lock()
        self._started_at = 0.0
        self._active_adjacencies = 0
        self._registrations = 0
        self._connection_failures = 0
        self._consecutive_failures = 0
        self._retry_not_before = 0.0
        self._reconnects = 0
        self._anchor_changes = 0
        self._last_anchor_node_id = ""
        self._retired_circuits_started = 0
        self._retired_circuits_completed = 0
        self._retired_bytes_relayed = 0
        self._last_failure = ""
        self._joined = threading.Event()
        self._public_probes = 0
        self._public_probe_failures = 0
        self._next_public_attempt = 0.0
        self._last_descriptor_issued_at = 0

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if any(worker.is_alive() for worker in self._workers):
                return
            self._started_at = time.monotonic()
            self._joined.clear()
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._supervise,
                name="granger-browser-peer",
                daemon=True,
            )
            self._thread.start()

    def _anchor_target(self) -> bytes:
        return hashlib.sha256(
            _ANCHOR_SELECTION_DOMAIN + self.identity.public_key_bytes
        ).digest()

    def _select_anchor(self, excluded: set[str]) -> NodeDescriptor:
        candidates = self.discovery.route_candidates(self._anchor_target(), "entry")
        eligible = [
            candidate
            for candidate in candidates
            if candidate.reachability == "reachable"
            and candidate.identity_public_key != self.identity.public_key_bytes
            and "entry" in candidate.capabilities
            and "discovery" in candidate.capabilities
            and candidate.node_id not in excluded
        ]
        if not eligible and excluded:
            eligible = [
                candidate
                for candidate in candidates
                if candidate.reachability == "reachable"
                and candidate.identity_public_key != self.identity.public_key_bytes
                and "entry" in candidate.capabilities
                and "discovery" in candidate.capabilities
            ]
        if not eligible:
            raise OverlayRoutingError("no reachable browser peer anchor is available")
        eligible.sort(
            key=lambda candidate: hashlib.sha256(
                self.identity.public_key_bytes + candidate.node_id.encode("ascii")
            ).digest()
        )
        return eligible[0]

    def _create_descriptor(
        self,
        anchor: NodeDescriptor,
        *,
        issued_after: int | None = None,
    ) -> NodeDescriptor:
        issued_at = int(time.time())
        issued_at = max(issued_at, self._last_descriptor_issued_at + 1)
        if issued_after is not None:
            issued_at = max(issued_at, issued_after + 1)
        self._last_descriptor_issued_at = issued_at
        return NodeDescriptor.create(
            self.identity,
            anchor.endpoint,
            ("middle",),
            self.relay_policy,
            issued_at=issued_at,
            lifetime=self.lifecycle_policy.descriptor_lifetime_seconds,
            reachability="adjacent",
            network_id=anchor.network_id,
            protocol_version=anchor.protocol_version,
            version=ADJACENT_NODE_DESCRIPTOR_VERSION,
            via_node_id=anchor.node_id,
        )

    def _create_server(self, anchor: NodeDescriptor) -> tuple[NodeDescriptor, WanNodeServer]:
        descriptor = self._create_descriptor(anchor)
        server = WanNodeServer(
            self.identity,
            descriptor,
            self.state_dir / "relay",
            known_peers=(anchor,),
            enable_listener=False,
            reseed_store=self.reseed_store,
        )
        server.wan_config_publisher = self.wan_config_publisher
        return descriptor, server

    def _start_adjacencies(
        self,
        count: int,
        anchor: NodeDescriptor,
        descriptor: NodeDescriptor,
        server: WanNodeServer,
    ) -> None:
        for _ in range(max(0, count)):
            worker = threading.Thread(
                target=self._run_adjacency,
                args=(anchor, descriptor, server),
                name="granger-browser-adjacency",
                daemon=True,
            )
            with self._lock:
                self._workers.add(worker)
            worker.start()

    def _set_failure(self, error: BaseException) -> None:
        with self._lock:
            self._connection_failures += 1
            self._consecutive_failures += 1
            base_delay = min(
                self.lifecycle_policy.reconnect_ceiling_seconds,
                self.lifecycle_policy.reconnect_floor_seconds
                * (2 ** min(16, self._consecutive_failures - 1)),
            )
            jitter = int.from_bytes(
                hashlib.sha256(
                    _RECONNECT_JITTER_DOMAIN
                    + self.identity.public_key_bytes
                    + self._consecutive_failures.to_bytes(4, "big")
                ).digest()[:2],
                "big",
            ) / 65535.0
            retry_delay = base_delay * (0.75 + jitter * 0.5)
            self._retry_not_before = max(
                self._retry_not_before,
                time.monotonic() + retry_delay,
            )
            self._last_failure = type(error).__name__
        self._state_changed()

    def _wait_for_retry(self) -> bool:
        with self._lock:
            remaining = max(0.0, self._retry_not_before - time.monotonic())
        return bool(remaining and self._stop.wait(remaining))

    def _run_adjacency(
        self,
        anchor: NodeDescriptor,
        descriptor: NodeDescriptor,
        server: WanNodeServer,
    ) -> None:
        peer = None
        registered = False
        try:
            peer = self._connector(
                anchor,
                self.identity,
                PeerRole.RELAY,
                local_descriptor=descriptor,
                timeout=self.relay_policy.connection_timeout_seconds,
            )
            if self._stop.is_set():
                return
            response = peer.rpc.request(
                RpcType.REVERSE_REGISTER,
                expected=RpcType.REVERSE_REGISTER,
            )
            if response.payload:
                raise GrangerNetworkError("reverse adjacency registration response is invalid")
            peer.channel.connection.settimeout(
                float(max(1, descriptor.expires_at - int(time.time())))
            )
            registered = True
            with self._lock:
                self._active_adjacencies += 1
                self._registrations += 1
                self._consecutive_failures = 0
                self._retry_not_before = 0.0
                if self._registrations > self.lifecycle_policy.target_adjacencies:
                    self._reconnects += 1
                self._last_failure = ""
            self._joined.set()
            self._state_changed()
            server.serve_reverse_adjacency(peer, anchor)
            peer = None
        except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
            if not self._stop.is_set():
                self._set_failure(error)
        finally:
            if peer is not None:
                peer.close()
            if registered:
                with self._lock:
                    self._active_adjacencies = max(0, self._active_adjacencies - 1)
                    if not self._active_adjacencies and (
                        self._descriptor is None
                        or self._descriptor.reachability != "reachable"
                    ):
                        self._joined.clear()
            current = threading.current_thread()
            with self._lock:
                self._workers.discard(current)
            self._wake.set()
            self._state_changed()

    def _public_candidates(self) -> tuple[NodeDescriptor, ...]:
        target = hashlib.sha256(
            _PUBLIC_RELAY_SELECTION_DOMAIN + self.identity.public_key_bytes
        ).digest()
        selected = {
            candidate.node_id: candidate
            for candidate in self.discovery.route_candidates(target, "discovery")
            if candidate.reachability == "reachable"
            and "discovery" in candidate.capabilities
            and candidate.identity_public_key != self.identity.public_key_bytes
        }
        return tuple(
            sorted(
                selected.values(),
                key=lambda candidate: hashlib.sha256(
                    self.identity.public_key_bytes + candidate.node_id.encode("ascii")
                ).digest(),
            )
        )

    def _observed_public_host(
        self,
        candidates: tuple[NodeDescriptor, ...],
    ) -> tuple[str, tuple[NodeDescriptor, ...]]:
        observations: dict[str, list[NodeDescriptor]] = {}
        for candidate in candidates[:8]:
            if self._stop.is_set():
                break
            peer = None
            try:
                peer = self._connector(
                    candidate,
                    self.identity,
                    PeerRole.CLIENT,
                    timeout=self.relay_policy.connection_timeout_seconds,
                )
                response = peer.rpc.request(
                    RpcType.OBSERVED_ADDRESS,
                    expected=RpcType.OBSERVED_ADDRESS,
                )
                host = ipaddress.ip_address(response.payload.decode("ascii")).compressed
                observations.setdefault(host, []).append(candidate)
            except (GrangerNetworkError, OSError, UnicodeDecodeError, ValueError):
                continue
            finally:
                if peer is not None:
                    peer.close()
        eligible = [
            (host, peers)
            for host, peers in observations.items()
            if len(peers) >= self.lifecycle_policy.reachability_quorum
        ]
        if not eligible:
            raise OverlayRoutingError("public browser address did not reach observation quorum")
        eligible.sort(key=lambda item: (-len(item[1]), item[0]))
        return eligible[0][0], tuple(eligible[0][1])

    def _public_descriptor(self, host: str, *, issued_after: int | None = None) -> NodeDescriptor:
        issued_at = int(time.time())
        issued_at = max(issued_at, self._last_descriptor_issued_at + 1)
        if issued_after is not None:
            issued_at = max(issued_at, issued_after + 1)
        self._last_descriptor_issued_at = issued_at
        return NodeDescriptor.create(
            self.identity,
            RendezvousEndpoint(host, self.lifecycle_policy.public_listener_port),
            PUBLIC_BROWSER_CAPABILITIES,
            self.relay_policy,
            issued_at=issued_at,
            lifetime=self.lifecycle_policy.descriptor_lifetime_seconds,
        )

    def _prove_public_reachability(
        self,
        descriptor: NodeDescriptor,
        candidates: tuple[NodeDescriptor, ...],
    ) -> int:
        confirmed = 0
        for candidate in candidates[:8]:
            if self._stop.is_set():
                break
            peer = None
            try:
                peer = self._connector(
                    candidate,
                    self.identity,
                    PeerRole.RELAY,
                    local_descriptor=descriptor,
                    timeout=self.relay_policy.connection_timeout_seconds,
                )
                response = peer.rpc.request(
                    RpcType.REACHABILITY_PROBE,
                    expected=RpcType.REACHABILITY_PROBE,
                )
                if response.payload:
                    raise ProtocolError("reachability proof response is not empty")
                confirmed += 1
            except (GrangerNetworkError, OSError, ValueError):
                with self._lock:
                    self._public_probe_failures += 1
            finally:
                if peer is not None:
                    peer.close()
            if confirmed >= self.lifecycle_policy.reachability_quorum:
                break
        with self._lock:
            self._public_probes += confirmed
        return confirmed

    def _run_public_relay(self) -> bool:
        if not self.lifecycle_policy.public_listener_port:
            return False
        candidates = self._public_candidates()
        host, observers = self._observed_public_host(candidates)
        if self._stop.is_set():
            return False
        descriptor = self._public_descriptor(host)
        listener_host = "::" if ipaddress.ip_address(host).version == 6 else "0.0.0.0"
        server = WanNodeServer(
            self.identity,
            descriptor,
            self.state_dir / "relay",
            known_peers=candidates,
            listener_endpoint=NodeListenerEndpoint(
                listener_host,
                self.lifecycle_policy.public_listener_port,
            ),
            reseed_store=self.reseed_store,
        )
        server.wan_config_publisher = self.wan_config_publisher
        server.start_background()
        try:
            if self._prove_public_reachability(descriptor, observers) < (
                self.lifecycle_policy.reachability_quorum
            ) or self._stop.is_set():
                return False
            self.discovery.publish(descriptor)
            atomic_write_text(
                self.state_dir / "reachable-descriptor.json",
                descriptor.to_json(),
                mode=0o600,
            )
            self._stop_server()
            with self._lock:
                self._server = server
                self._descriptor = descriptor
                self._anchor = None
                self._last_failure = ""
                self._consecutive_failures = 0
                self._retry_not_before = 0.0
            self._joined.set()
            self._state_changed()
            while not self._stop.wait(
                min(
                    self.lifecycle_policy.public_reprobe_seconds,
                    max(
                        1.0,
                        descriptor.expires_at
                        - int(time.time())
                        - self.lifecycle_policy.renewal_margin_seconds,
                    ),
                )
            ):
                renew = (
                    descriptor.expires_at - int(time.time())
                    <= self.lifecycle_policy.renewal_margin_seconds
                )
                candidate = (
                    self._public_descriptor(host, issued_after=descriptor.issued_at)
                    if renew
                    else descriptor
                )
                candidates = self._public_candidates()
                observed_host, observers = self._observed_public_host(candidates)
                if observed_host != host:
                    return False
                if renew:
                    # Callbacks must authenticate the candidate before it is published.
                    server.replace_descriptor(candidate)
                if self._prove_public_reachability(
                    candidate,
                    observers,
                ) < self.lifecycle_policy.reachability_quorum:
                    return False
                if renew:
                    descriptor = candidate
                    self.discovery.publish(descriptor)
                    atomic_write_text(
                        self.state_dir / "reachable-descriptor.json",
                        descriptor.to_json(),
                        mode=0o600,
                    )
                    with self._lock:
                        self._descriptor = descriptor
            return True
        finally:
            with self._lock:
                if self._server is server:
                    self._server = None
                    self._descriptor = None
                    self._joined.clear()
            server.stop()
            self._state_changed()

    def _stop_server(self) -> None:
        with self._lock:
            server = self._server
            workers = tuple(self._workers)
            self._server = None
            self._descriptor = None
            self._anchor = None
            self._joined.clear()
        self._state_changed()
        if server is not None:
            retired = server.runtime.contribution_snapshot()
            with self._lock:
                self._retired_circuits_started += retired["circuitsStarted"]
                self._retired_circuits_completed += retired["circuitsCompleted"]
                self._retired_bytes_relayed += retired["bytesRelayed"]
            server.stop()
        deadline = time.monotonic() + 3.0
        for worker in workers:
            if worker is threading.current_thread():
                continue
            worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def _supervise(self) -> None:
        excluded: set[str] = set()
        try:
            while not self._stop.is_set():
                if (
                    self.lifecycle_policy.public_listener_port
                    and time.monotonic() >= self._next_public_attempt
                ):
                    self._next_public_attempt = (
                        time.monotonic() + self.lifecycle_policy.public_retry_seconds
                    )
                    try:
                        if self._run_public_relay():
                            return
                    except (GrangerNetworkError, OSError, ValueError) as error:
                        if not self._stop.is_set():
                            self._set_failure(error)
                    self._next_public_attempt = (
                        time.monotonic() + self.lifecycle_policy.public_retry_seconds
                    )
                if self._stop.is_set():
                    break
                with self._lock:
                    server = self._server
                    descriptor = self._descriptor
                    anchor = self._anchor
                    workers = tuple(self._workers)
                    active = self._active_adjacencies
                expired_workers = [worker for worker in workers if not worker.is_alive()]
                if expired_workers:
                    with self._lock:
                        for worker in expired_workers:
                            self._workers.discard(worker)
                    workers = tuple(worker for worker in workers if worker.is_alive())
                renew = (
                    descriptor is not None
                    and descriptor.expires_at - int(time.time())
                    <= self.lifecycle_policy.renewal_margin_seconds
                )
                if renew:
                    try:
                        renewed = self._create_descriptor(
                            anchor,
                            issued_after=descriptor.issued_at,
                        )
                        server.replace_descriptor(renewed)
                        with self._lock:
                            if self._server is server:
                                self._descriptor = renewed
                        descriptor = renewed
                        headroom = max(
                            0,
                            self.relay_policy.max_connections - len(workers),
                        )
                        self._start_adjacencies(
                            min(self.lifecycle_policy.target_adjacencies, headroom),
                            anchor,
                            descriptor,
                            server,
                        )
                        with self._lock:
                            workers = tuple(self._workers)
                    except (GrangerNetworkError, OSError, ValueError) as error:
                        self._set_failure(error)
                        if self._wait_for_retry():
                            break
                        continue
                if server is None or descriptor is None or anchor is None:
                    if self._wait_for_retry():
                        break
                    try:
                        selected = self._select_anchor(excluded)
                        descriptor, server = self._create_server(selected)
                        with self._lock:
                            if (
                                self._last_anchor_node_id
                                and self._last_anchor_node_id != selected.node_id
                            ):
                                self._anchor_changes += 1
                            self._last_anchor_node_id = selected.node_id
                            self._anchor = selected
                            self._descriptor = descriptor
                            self._server = server
                        anchor = selected
                    except (GrangerNetworkError, OSError, ValueError) as error:
                        self._set_failure(error)
                        continue
                with self._lock:
                    worker_count = len(self._workers)
                missing = self.lifecycle_policy.target_adjacencies - worker_count
                if missing > 0 and self._wait_for_retry():
                    break
                with self._lock:
                    worker_count = len(self._workers)
                missing = self.lifecycle_policy.target_adjacencies - worker_count
                self._start_adjacencies(missing, anchor, descriptor, server)
                renewal_wait = max(
                    0.05,
                    descriptor.expires_at
                    - int(time.time())
                    - self.lifecycle_policy.renewal_margin_seconds,
                )
                if self.lifecycle_policy.public_listener_port:
                    renewal_wait = min(
                        renewal_wait,
                        max(0.05, self._next_public_attempt - time.monotonic()),
                    )
                self._wake.wait(
                    renewal_wait
                    if active
                    else min(self.lifecycle_policy.reconnect_floor_seconds, renewal_wait)
                )
                self._wake.clear()
                with self._lock:
                    no_workers = not self._workers
                    consecutive_failures = self._consecutive_failures
                    active_adjacencies = self._active_adjacencies
                if active_adjacencies:
                    excluded.clear()
                if (
                    no_workers
                    and consecutive_failures
                    >= self.lifecycle_policy.target_adjacencies
                ):
                    excluded.add(anchor.node_id)
                    self._stop_server()
        finally:
            self._stop_server()

    def wait_until_joined(self, timeout: float) -> bool:
        return self._joined.wait(timeout)

    def current_descriptor(self) -> NodeDescriptor | None:
        with self._lock:
            return self._descriptor

    def contribution_snapshot(self) -> dict[str, object]:
        with self._lock:
            server = self._server
            anchor = self._anchor
            descriptor = self._descriptor
            result: dict[str, object] = {
                "activeAdjacencies": self._active_adjacencies,
                "anchorChanges": self._anchor_changes,
                "anchorNodeId": anchor.node_id if anchor is not None else "",
                "connectionFailures": self._connection_failures,
                "contributionState": (
                    "relay-active"
                    if server is not None and server.runtime.active_circuits
                    else "public-relay"
                    if server is not None
                    and descriptor is not None
                    and descriptor.reachability == "reachable"
                    else "connected"
                    if self._active_adjacencies
                    else "joining"
                ),
                "lastFailure": self._last_failure,
                "publicProbeFailures": self._public_probe_failures,
                "publicProbes": self._public_probes,
                "reachability": (
                    descriptor.reachability if descriptor is not None else "unknown"
                ),
                "reconnects": self._reconnects,
                "registrations": self._registrations,
                "relayEligible": True,
                "targetAdjacencies": self.lifecycle_policy.target_adjacencies,
                "uptimeSeconds": max(0.0, time.monotonic() - self._started_at),
            }
            retired_circuits_started = self._retired_circuits_started
            retired_circuits_completed = self._retired_circuits_completed
            retired_bytes_relayed = self._retired_bytes_relayed
        relay = server.contribution_snapshot() if server is not None else {}
        result.update(
            {
                "activeCircuits": int(relay.get("activeCircuits", 0)),
                "bytesRelayed": retired_bytes_relayed
                + int(relay.get("bytesRelayed", 0)),
                "circuitsCompleted": retired_circuits_completed
                + int(relay.get("circuitsCompleted", 0)),
                "circuitsRelayed": retired_circuits_started
                + int(relay.get("circuitsStarted", 0)),
            }
        )
        return result

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        self._joined.clear()
        with self._lock:
            server = self._server
            thread = self._thread
        if server is not None:
            server.stop()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)
        with self._lock:
            # A timed-out shutdown must not permit a second supervisor to start.
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None
