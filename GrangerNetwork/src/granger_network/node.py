from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import queue
import secrets
import socket
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .bootstrap import PeerCache
from .cells import (
    CELL_PAYLOAD_SIZE,
    MAX_CELLS_PER_BATCH,
    CellMultiplexer,
    CoverTrafficProfile,
    MuxStream,
    ReceiveMemoryBudget,
    cover_profile_from_environment,
)
from .circuit import decode_extend_circuit, decode_open_circuit, encode_open_circuit
from .errors import (
    ConnectionClosedError,
    DescriptorError,
    DiscoveryError,
    GrangerNetworkError,
    ProtocolError,
    ResourceLimitError,
)
from .identity import ServiceIdentity
from .introduction import IntroductionRegistry
from .peer import GrangerNode, NodeDescriptor, RelayPolicy, node_supports_route_role
from .peer_rpc import (
    AuthenticatedPeer,
    PeerRole,
    RESILIENT_PEER_CONNECT_ATTEMPTS,
    RpcFrame,
    RpcType,
    authenticate_server_stream,
    connect_authenticated_peer,
    encode_error,
)
from .reverse_adjacency import ReverseAdjacencyPool
from .reseed import (
    ReseedStore,
    decode_reseed_chunk_request,
    encode_reseed_advertisements,
    encode_reseed_chunk_response,
)
from .transport import RendezvousEndpoint
from .wan_discovery import (
    MAX_FIND_NODE_RESULTS,
    encode_public_service_sample,
    PersistentRecordStore,
    decode_find_node,
    decode_find_record,
    decode_peer_sample,
    decode_record_envelope,
    encode_node_list,
    encode_optional_record,
)
from .wan_control import (
    IntroductionRequest,
    RendezvousGrant,
    RendezvousJoin,
    RendezvousRegistration,
    decode_intro_registration,
    decode_intro_request,
    encode_intro_request,
)


NODE_IDENTITY_FILE = "node-identity.json"
NODE_DESCRIPTOR_FILE = "node-descriptor.json"
NODE_CACHE_FILE = "peer-cache.json"
NODE_RECORDS_FILE = "records.json"
_TRANSFER_PEER = object()
DEFAULT_MAX_RPC_REQUESTS_PER_CONNECTION = 1024
MAX_RENDEZVOUS_REPLAY_ENTRIES = 16384
MAX_CONCURRENT_REACHABILITY_PROBES = 8
MAX_CONNECTIONS_PER_SOURCE = 32
MAX_RPC_REQUESTS_PER_SOURCE_WINDOW = 4096
MAX_RPC_SOURCE_WINDOWS = 4096
RPC_SOURCE_WINDOW_SECONDS = 60.0


def _safe_forwarding_failure_category(error: BaseException) -> str:
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, ResourceLimitError):
        return "resource-limit"
    if isinstance(error, ProtocolError):
        return "protocol"
    return "transport"


@dataclass(frozen=True)
class NodeListenerEndpoint:
    """Local bind endpoint kept outside the signed public descriptor."""

    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.host, str):
            raise ValueError("node listener host must be text")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise ValueError("node listener port must be an integer")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as error:
            raise ValueError("node listener must use a numeric IP address") from error
        if address.is_multicast or address.is_link_local:
            raise ValueError("node listener address is not supported")
        if not 1 <= self.port <= 65535:
            raise ValueError("node listener port is outside the valid range")
        object.__setattr__(self, "host", address.compressed)

    @property
    def family(self) -> int:
        return socket.AF_INET6 if ipaddress.ip_address(self.host).version == 6 else socket.AF_INET

    @property
    def socket_address(self) -> tuple:
        if self.family == socket.AF_INET6:
            return (self.host, self.port, 0, 0)
        return (self.host, self.port)


class WanCircuitObservation:
    """Counters only by default; diagnostic payload sampling is explicit."""

    def __init__(
        self,
        circuit_id: bytes,
        role: str,
        upstream: str,
        downstream: str,
        *,
        sample_limit: int = 0,
        capture: Callable[[bytes], None] | None = None,
    ) -> None:
        if (
            isinstance(sample_limit, bool)
            or not isinstance(sample_limit, int)
            or not 0 <= sample_limit <= 2 * 1024 * 1024
        ):
            raise ResourceLimitError("relay observation sample limit is invalid")
        self.circuit_id = circuit_id
        self.role = role
        self.upstream = upstream
        self.downstream = downstream
        self.sample_limit = sample_limit
        self._capture = capture
        self.bytes_forwarded = 0
        self._sample = bytearray()
        self._lock = threading.Lock()

    def record(self, payload: bytes) -> None:
        with self._lock:
            self.bytes_forwarded += len(payload)
            remaining = self.sample_limit - len(self._sample)
            if remaining > 0:
                self._sample.extend(payload[:remaining])
        if self._capture is not None:
            self._capture(payload)

    def contains(self, marker: bytes) -> bool:
        with self._lock:
            return marker in self._sample


class _IntroductionDelivery:
    def __init__(self, request: IntroductionRequest) -> None:
        self.request = request
        self.result: bytes | None = None
        self.error: BaseException | None = None
        self.ready = threading.Event()


class _IntroductionSession:
    def __init__(self, service, introduction, upstream: str) -> None:
        self.service = service
        self.introduction = introduction
        self.upstream = upstream
        self.deliveries: queue.Queue[_IntroductionDelivery | None] = queue.Queue(maxsize=128)
        self.closed = threading.Event()


class _RendezvousSlot:
    def __init__(
        self,
        registration: RendezvousRegistration,
        upstream: str,
        accounting_circuit_id: bytes | None,
    ) -> None:
        self.registration = registration
        self.host_upstream = upstream
        self.host_accounting_circuit_id = accounting_circuit_id
        self.client_upstream = ""
        self.client_accounting_circuit_id: bytes | None = None
        self.host_mux: CellMultiplexer | None = None
        self.client_mux: CellMultiplexer | None = None
        self.host_stream: MuxStream | None = None
        self.client_stream: MuxStream | None = None
        self.host_ready = threading.Event()
        self.client_ready = threading.Event()
        self.done = threading.Event()
        self.error: BaseException | None = None


def _node_distance(node_id: str, target: bytes) -> int:
    try:
        raw = base64.b32decode(node_id.upper() + "=" * (-len(node_id) % 8))
    except ValueError as error:
        raise DiscoveryError("node identifier encoding is invalid") from error
    return int.from_bytes(raw, "big") ^ int.from_bytes(target, "big")


class WanNodeServer:
    def __init__(
        self,
        identity: ServiceIdentity,
        descriptor: NodeDescriptor,
        state_dir: Path,
        *,
        known_peers: list[NodeDescriptor] | tuple[NodeDescriptor, ...] = (),
        listener_endpoint: NodeListenerEndpoint | None = None,
        capture_path: Path | None = None,
        diagnostics_path: Path | None = None,
        cover_profile: CoverTrafficProfile | str | None = None,
        enable_listener: bool = True,
        max_rpc_requests_per_connection: int = DEFAULT_MAX_RPC_REQUESTS_PER_CONNECTION,
        reseed_store: ReseedStore | None = None,
    ) -> None:
        descriptor.verify()
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise DescriptorError("WAN node identity does not match its descriptor")
        if not isinstance(enable_listener, bool):
            raise DescriptorError("WAN listener mode must be boolean")
        if (
            isinstance(max_rpc_requests_per_connection, bool)
            or not isinstance(max_rpc_requests_per_connection, int)
            or not 1 <= max_rpc_requests_per_connection <= 65536
        ):
            raise ValueError("WAN RPC request limit is invalid")
        if enable_listener and descriptor.reachability != "reachable":
            raise DescriptorError("WAN listener requires reachable node status")
        if not enable_listener and descriptor.reachability != "adjacent":
            raise DescriptorError("listener-free WAN node requires adjacent reachability")
        self.identity = identity
        self.descriptor = descriptor
        self.policy = descriptor.relay_policy
        self.enable_listener = enable_listener
        self.max_rpc_requests_per_connection = max_rpc_requests_per_connection
        if reseed_store is not None and (
            reseed_store.network_id != descriptor.network_id
            or reseed_store.protocol_version != descriptor.protocol_version
        ):
            raise DescriptorError("WAN node reseed store belongs to a different network")
        self.reseed_store = reseed_store
        # Only an explicitly validated public snapshot publisher is attached by
        # the operator/browser lifecycle. No private authority lives on a relay.
        self.wan_config_publisher = None
        self.cover_profile = (
            cover_profile_from_environment()
            if cover_profile is None
            else CoverTrafficProfile(cover_profile)
        )
        self.listener_endpoint = None
        if enable_listener:
            self.listener_endpoint = listener_endpoint or NodeListenerEndpoint(
                descriptor.endpoint.host,
                descriptor.endpoint.port,
            )
            if self.listener_endpoint.family != descriptor.endpoint.family:
                raise DescriptorError("node listener and advertised endpoint families differ")
        elif listener_endpoint is not None:
            raise DescriptorError("listener-free WAN node cannot bind a listener endpoint")
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.capture_path = Path(capture_path) if capture_path is not None else None
        self._retain_connection_metadata = self.capture_path is not None
        self._capture_bytes = 0
        self._capture_limit = 8 * 1024 * 1024
        if self.capture_path is not None:
            self.capture_path.parent.mkdir(parents=True, exist_ok=True)
            self.capture_path.write_bytes(b"")
        self.diagnostics_path = (
            Path(diagnostics_path) if diagnostics_path is not None else None
        )
        if self.diagnostics_path is not None:
            self.diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
            self.diagnostics_path.write_text("", encoding="ascii")
        self._diagnostics_bytes = 0
        self._diagnostics_limit = 2 * 1024 * 1024
        self.records = PersistentRecordStore(self.state_dir / NODE_RECORDS_FILE)
        self.peer_cache = PeerCache(
            self.state_dir / NODE_CACHE_FILE,
            network_id=descriptor.network_id,
            protocol_version=descriptor.protocol_version,
        )
        self.runtime = GrangerNode(identity, descriptor, self.policy)
        self.receive_memory_budget = ReceiveMemoryBudget(
            self.policy.memory_budget_kib * 1024
        )
        for peer in known_peers:
            peer.verify(
                expected_network_id=descriptor.network_id,
                expected_protocol_version=descriptor.protocol_version,
            )
        if known_peers:
            self.peer_cache.ingest(known_peers, source="configured-peer")
        self._known: dict[str, NodeDescriptor] = {
            peer.node_id: peer for peer in self.peer_cache.load()
        }
        self._known[descriptor.node_id] = descriptor
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._threads: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._source_hash_key = secrets.token_bytes(32)
        self._active_sources: dict[bytes, int] = {}
        self._connection_sources: dict[socket.socket, bytes] = {}
        self._rpc_source_windows: OrderedDict[bytes, tuple[float, int]] = OrderedDict()
        self._max_connections_per_source = min(
            MAX_CONNECTIONS_PER_SOURCE,
            self.policy.max_connections,
        )
        self._max_rpc_requests_per_source_window = MAX_RPC_REQUESTS_PER_SOURCE_WINDOW
        self._lock = threading.Lock()
        self._descriptor_lock = threading.Lock()
        self._reverse_adjacencies = (
            ReverseAdjacencyPool(
                descriptor,
                max_peers=min(self.policy.max_connections, 4096),
                max_slots_per_peer=min(4, self.policy.max_connections),
                max_total_slots=min(self.policy.max_connections, 16384),
                on_discard=self._discard_reverse_peer,
            )
            if enable_listener
            else None
        )
        self.errors: list[str] = []
        self.accepted_connections = 0
        self.rejected_connections = 0
        self.rpc_requests = 0
        self.reachability_probes = 0
        self.reachability_probe_failures = 0
        self._reachability_probe_slots = threading.BoundedSemaphore(
            min(MAX_CONCURRENT_REACHABILITY_PROBES, self.policy.max_connections)
        )
        self.peer_addresses: list[tuple[str, int]] = []
        self.circuit_observations: list[WanCircuitObservation] = []
        self._introduction_registry = IntroductionRegistry()
        self._introduction_lock = threading.Lock()
        self._introduction_sessions: dict[str, _IntroductionSession] = {}
        self._rendezvous_slots: dict[bytes, _RendezvousSlot] = {}
        self._used_rendezvous_joins: dict[tuple[bytes, bytes], int] = {}
        self._max_rendezvous_replay_entries = MAX_RENDEZVOUS_REPLAY_ENTRIES
        if enable_listener:
            self.records.store(self._record_for_descriptor(descriptor))

    def _capture_relay_payload(self, payload: bytes) -> None:
        if self.capture_path is None:
            return
        with self._lock:
            remaining = self._capture_limit - self._capture_bytes
            if remaining <= 0:
                return
            content = payload[:remaining]
            with self.capture_path.open("ab") as output:
                output.write(content)
            self._capture_bytes += len(content)

    def _record_runtime_error(self, error: BaseException) -> None:
        category = type(error).__name__
        with self._lock:
            if len(self.errors) < 1024:
                self.errors.append(category)
            if (
                self.diagnostics_path is not None
                and self._diagnostics_bytes < self._diagnostics_limit
            ):
                document = {
                    "error": category,
                    "errorType": category,
                    "nodeId": self.descriptor.node_id,
                    "timeNs": time.time_ns(),
                    "version": 1,
                }
                encoded = (
                    json.dumps(
                        document,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                )
                remaining = self._diagnostics_limit - self._diagnostics_bytes
                if len(encoded) <= remaining:
                    with self.diagnostics_path.open(
                        "a", encoding="ascii", newline="\n"
                    ) as output:
                        output.write(encoded)
                    self._diagnostics_bytes += len(encoded)

    @staticmethod
    def _record_for_descriptor(descriptor: NodeDescriptor, now: int | None = None):
        from .distributed import encode_record

        return encode_record(descriptor, now=now)

    def replace_descriptor(
        self,
        descriptor: NodeDescriptor,
        *,
        now: int | None = None,
    ) -> None:
        descriptor.verify(
            now=now,
            expected_network_id=self.descriptor.network_id,
            expected_protocol_version=self.descriptor.protocol_version,
        )
        with self._descriptor_lock:
            current = self.descriptor
            if (
                descriptor.node_id != current.node_id
                or descriptor.identity_public_key != self.identity.public_key_bytes
            ):
                raise DescriptorError("renewed WAN descriptor changes the node identity")
            if (
                descriptor.endpoint != current.endpoint
                or descriptor.capabilities != current.capabilities
                or descriptor.relay_policy != current.relay_policy
                or descriptor.reachability != current.reachability
                or descriptor.network_id != current.network_id
                or descriptor.protocol_version != current.protocol_version
                or descriptor.version != current.version
                or descriptor.via_node_id != current.via_node_id
            ):
                raise DescriptorError("renewed WAN descriptor changes the listener policy")
            if (
                descriptor.issued_at <= current.issued_at
                or descriptor.expires_at <= current.expires_at
            ):
                raise DescriptorError("renewed WAN descriptor does not advance its validity")

            if self.enable_listener:
                record = self._record_for_descriptor(descriptor, now=now)
                self.records.store(record, now=now)
            self.runtime.replace_descriptor(descriptor, now=now)
            with self._lock:
                self.descriptor = descriptor
                self._known[descriptor.node_id] = descriptor

    def start_background(self) -> None:
        if not self.enable_listener or self.listener_endpoint is None:
            raise RuntimeError("listener-free WAN node cannot start an inbound listener")
        if self._listener is not None:
            raise RuntimeError("WAN node is already running")
        listener = socket.socket(self.listener_endpoint.family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(self.listener_endpoint.socket_address)
            listener.listen(min(self.policy.max_connections, 512))
            listener.settimeout(0.25)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"granger-node-{self.descriptor.node_id[:8]}",
            daemon=True,
        )
        self._accept_thread.start()

    def serve_forever(self) -> None:
        self.start_background()
        assert self._accept_thread is not None
        self._accept_thread.join()

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                raise
            source_key = self._source_key(str(address[0]))
            with self._lock:
                if (
                    len(self._connections) >= self.policy.max_connections
                    or self._active_sources.get(source_key, 0)
                    >= self._max_connections_per_source
                ):
                    self.rejected_connections += 1
                    connection.close()
                    continue
                self._connections.add(connection)
                self._connection_sources[connection] = source_key
                self._active_sources[source_key] = self._active_sources.get(source_key, 0) + 1
                self.accepted_connections += 1
                if self._retain_connection_metadata and len(self.peer_addresses) < 4096:
                    self.peer_addresses.append((str(address[0]), int(address[1])))
            thread = threading.Thread(
                target=self._handle_connection,
                args=(connection, (str(address[0]), int(address[1]))),
                name=f"granger-peer-{self.descriptor.node_id[:8]}",
                daemon=True,
            )
            with self._lock:
                self._threads.add(thread)
            thread.start()

    def _source_key(self, host: str) -> bytes:
        packed = ipaddress.ip_address(host).packed
        return hashlib.blake2s(
            packed,
            key=self._source_hash_key,
            digest_size=16,
        ).digest()

    def _consume_rpc_source_budget(self, host: str) -> None:
        source_key = self._source_key(host)
        current = time.monotonic()
        with self._lock:
            expired = tuple(
                key
                for key, (started, _count) in self._rpc_source_windows.items()
                if current - started >= RPC_SOURCE_WINDOW_SECONDS
            )
            for key in expired:
                self._rpc_source_windows.pop(key, None)
            state = self._rpc_source_windows.get(source_key)
            if state is None:
                if len(self._rpc_source_windows) >= MAX_RPC_SOURCE_WINDOWS:
                    raise ResourceLimitError("RPC source tracking capacity is exhausted")
                state = (current, 0)
            started, count = state
            if count >= self._max_rpc_requests_per_source_window:
                raise ResourceLimitError("RPC source request limit is exhausted")
            self._rpc_source_windows[source_key] = (started, count + 1)
            self._rpc_source_windows.move_to_end(source_key)

    def _discard_reverse_peer(self, peer: AuthenticatedPeer) -> None:
        connection = peer.channel.connection
        with self._lock:
            self._release_connection_unlocked(connection)
        peer.close()

    def _forget_reverse_peer(self, peer: AuthenticatedPeer) -> None:
        with self._lock:
            self._release_connection_unlocked(peer.channel.connection)

    def _release_connection_unlocked(self, connection: socket.socket) -> None:
        self._connections.discard(connection)
        source_key = self._connection_sources.pop(connection, None)
        if source_key is None:
            return
        remaining = self._active_sources.get(source_key, 0) - 1
        if remaining > 0:
            self._active_sources[source_key] = remaining
        else:
            self._active_sources.pop(source_key, None)

    def _known_peers(self) -> tuple[NodeDescriptor, ...]:
        with self._lock:
            known = tuple(self._known.values())
        adjacent = (
            self._reverse_adjacencies.descriptors()
            if self._reverse_adjacencies is not None
            else ()
        )
        return known + adjacent

    def _route_candidate_available(self, descriptor: NodeDescriptor, capability: str) -> bool:
        if not node_supports_route_role(descriptor, capability):
            return False
        return (
            descriptor.reachability != "adjacent"
            or (
                self._reverse_adjacencies is not None
                and self._reverse_adjacencies.available(descriptor)
            )
        )

    def _discovery_candidates(
        self,
        capability: str,
        *,
        include_adjacent: bool,
    ) -> list[NodeDescriptor]:
        candidates: list[NodeDescriptor] = []
        for candidate in self._known_peers():
            try:
                candidate.verify(
                    expected_network_id=self.descriptor.network_id,
                    expected_protocol_version=self.descriptor.protocol_version,
                )
            except DescriptorError:
                continue
            if candidate.reachability == "adjacent" and not include_adjacent:
                continue
            if self._route_candidate_available(candidate, capability):
                candidates.append(candidate)
        return candidates

    def add_known_peer(
        self,
        descriptor: NodeDescriptor,
        *,
        source: str = "authenticated-peer",
    ) -> None:
        descriptor.verify(
            expected_network_id=self.descriptor.network_id,
            expected_protocol_version=self.descriptor.protocol_version,
        )
        if descriptor.reachability == "adjacent":
            return
        self.peer_cache.add(descriptor, source=source)
        cached = self.peer_cache.load()
        with self._lock:
            self._known = {peer.node_id: peer for peer in cached}
            self._known[self.descriptor.node_id] = self.descriptor

    def _send_error(self, peer, request: RpcFrame, code: str) -> None:
        peer.rpc.send(
            RpcType.ERROR,
            encode_error(code),
            request_id=request.request_id,
            response=True,
            error=True,
        )

    def _bridge_streams(
        self,
        left: MuxStream,
        right: MuxStream,
        circuit_id: bytes,
        observation: WanCircuitObservation,
    ) -> None:
        stop = threading.Event()
        failures: list[BaseException] = []

        def pump(source: MuxStream, destination: MuxStream) -> None:
            try:
                while not stop.is_set() and not self._stop.is_set():
                    payload = source.recv(CELL_PAYLOAD_SIZE * MAX_CELLS_PER_BATCH)
                    if not payload:
                        break
                    self.runtime.account_bytes(circuit_id, len(payload))
                    observation.record(payload)
                    destination.sendall(payload)
            except (GrangerNetworkError, OSError, TimeoutError) as error:
                if not stop.is_set() and not self._stop.is_set():
                    failures.append(error)
            finally:
                stop.set()
                destination.close()

        threads = [
            threading.Thread(target=pump, args=(left, right), daemon=True),
            threading.Thread(target=pump, args=(right, left), daemon=True),
        ]
        for thread in threads:
            thread.start()
        while not stop.wait(0.25):
            if self._stop.is_set():
                left.reset()
                right.reset()
                break
        for thread in threads:
            thread.join(timeout=2.0)
        if any(thread.is_alive() for thread in threads):
            left.reset()
            right.reset()
            for thread in threads:
                thread.join(timeout=2.0)
        if failures and not self._stop.is_set():
            category = _safe_forwarding_failure_category(failures[0])
            raise ProtocolError(f"relay forwarding failed ({category})")

    def _handle_open_circuit(self, peer, request: RpcFrame, upstream: str) -> None:
        opened = decode_open_circuit(request.payload)
        if peer.remote.role not in {PeerRole.RELAY, PeerRole.BOOTSTRAP} or peer.remote.descriptor is None:
            raise ProtocolError("only an authenticated relay may open an adjacent circuit")
        if opened.role not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not advertise the requested circuit role")
        self.runtime.begin_circuit(opened.circuit_id, opened.role)
        multiplexer: CellMultiplexer | None = None
        nested = None
        try:
            peer.rpc.send(
                RpcType.CIRCUIT_CREATED,
                b"",
                request_id=request.request_id,
                response=True,
            )
            multiplexer = CellMultiplexer(
                peer.channel,
                opened.circuit_id,
                initiator=False,
                max_streams=self.policy.max_streams,
                receive_budget=self.receive_memory_budget,
                cover_profile=self.cover_profile,
            )
            stream = multiplexer.accept_stream(self.policy.connection_timeout_seconds)
            stream.settimeout(float(self.policy.idle_timeout_seconds))
            role = PeerRole.BOOTSTRAP if "bootstrap" in self.descriptor.capabilities else PeerRole.RELAY
            nested = authenticate_server_stream(
                stream,
                self.identity,
                self.descriptor,
                role=role,
            )
            self._serve_peer(nested, upstream, opened.circuit_id)
        finally:
            if nested is not None:
                nested.close()
            if multiplexer is not None:
                multiplexer.close()
            self.runtime.end_circuit(opened.circuit_id)

    def _handle_extend_circuit(self, peer, request: RpcFrame, upstream: str) -> None:
        extension = decode_extend_circuit(request.payload)
        if extension.current_role not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not advertise the current circuit role")
        if extension.next_node.node_id == self.descriptor.node_id:
            raise ProtocolError("circuit extension loops to the current node")
        if (
            peer.remote.descriptor is not None
            and extension.next_node.node_id == peer.remote.descriptor.node_id
        ):
            raise ProtocolError("circuit extension loops to the previous node")
        self.runtime.begin_circuit(extension.incoming_circuit_id, extension.current_role)
        outbound = None
        incoming_mux: CellMultiplexer | None = None
        outgoing_mux: CellMultiplexer | None = None
        reverse_outbound = False
        try:
            try:
                if extension.next_node.reachability == "adjacent":
                    if (
                        extension.next_role != "middle"
                        or extension.next_node.via_node_id != self.descriptor.node_id
                        or self._reverse_adjacencies is None
                    ):
                        raise ProtocolError("adjacent circuit hop is not registered at this node")
                    outbound = self._reverse_adjacencies.acquire(extension.next_node)
                    reverse_outbound = True
                else:
                    outbound = connect_authenticated_peer(
                        extension.next_node,
                        self.identity,
                        PeerRole.RELAY,
                        local_descriptor=self.descriptor,
                        timeout=self.policy.connection_timeout_seconds,
                        attempts=RESILIENT_PEER_CONNECT_ATTEMPTS,
                    )
            except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                raise ProtocolError(
                    "circuit extension next-hop authentication failed: "
                    f"{type(error).__name__}"
                ) from error
            outbound.channel.connection.settimeout(float(self.policy.idle_timeout_seconds))
            try:
                created = outbound.rpc.request(
                    RpcType.OPEN_CIRCUIT,
                    encode_open_circuit(extension.outgoing_circuit_id, extension.next_role),
                    expected=RpcType.CIRCUIT_CREATED,
                )
            except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                raise ProtocolError(
                    "circuit extension next-hop open failed: "
                    f"{type(error).__name__}"
                ) from error
            if created.payload:
                raise ProtocolError("adjacent circuit creation returned an unexpected payload")
            peer.rpc.send(
                RpcType.CIRCUIT_CREATED,
                b"",
                request_id=request.request_id,
                response=True,
            )
            incoming_mux = CellMultiplexer(
                peer.channel,
                extension.incoming_circuit_id,
                initiator=False,
                max_streams=self.policy.max_streams,
                cover_profile=self.cover_profile,
                receive_budget=self.receive_memory_budget,
            )
            outgoing_mux = CellMultiplexer(
                outbound.channel,
                extension.outgoing_circuit_id,
                initiator=True,
                max_streams=self.policy.max_streams,
                receive_budget=self.receive_memory_budget,
                cover_profile=self.cover_profile,
            )
            outgoing = outgoing_mux.open_stream(self.policy.connection_timeout_seconds)
            incoming = incoming_mux.accept_stream(self.policy.connection_timeout_seconds)
            outgoing.settimeout(float(self.policy.idle_timeout_seconds))
            incoming.settimeout(float(self.policy.idle_timeout_seconds))
            observation = WanCircuitObservation(
                extension.incoming_circuit_id,
                extension.current_role,
                upstream,
                extension.next_node.node_id,
                capture=self._capture_relay_payload,
            )
            with self._lock:
                if (
                    self._retain_connection_metadata
                    and len(self.circuit_observations) < 4096
                ):
                    self.circuit_observations.append(observation)
            self._bridge_streams(
                incoming,
                outgoing,
                extension.incoming_circuit_id,
                observation,
            )
        except Exception:
            if incoming_mux is None:
                try:
                    peer.rpc.send(
                        RpcType.CIRCUIT_FAILED,
                        b"",
                        request_id=request.request_id,
                        response=True,
                    )
                except (GrangerNetworkError, OSError):
                    pass
            raise
        finally:
            if incoming_mux is not None:
                incoming_mux.close()
            if outgoing_mux is not None:
                outgoing_mux.close()
            elif outbound is not None:
                outbound.close()
            if reverse_outbound and outbound is not None:
                self._forget_reverse_peer(outbound)
            self.runtime.end_circuit(extension.incoming_circuit_id)

    def _handle_intro_register(self, peer, request: RpcFrame, upstream: str) -> None:
        if "introduction" not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not advertise introduction capability")
        if peer.remote.role is not PeerRole.SERVICE:
            raise ProtocolError("introduction registration requires a service peer")
        service, introduction = decode_intro_registration(request.payload)
        if service.identity_public_key != peer.remote.public_key:
            raise ProtocolError("introduction registration service identity was substituted")
        if not any(point.node_id == self.descriptor.node_id for point in introduction.points):
            raise ProtocolError("introduction descriptor does not authorize this node")
        session = _IntroductionSession(service, introduction, upstream)
        with self._introduction_lock:
            self._introduction_registry.install(introduction, service)
            with self._lock:
                previous = self._introduction_sessions.get(service.service_id)
                self._introduction_sessions[service.service_id] = session
            if previous is not None and not previous.closed.is_set():
                previous.closed.set()
                try:
                    previous.deliveries.put_nowait(None)
                except queue.Full:
                    pass
        peer.rpc.send(
            RpcType.INTRO_REGISTER,
            b"",
            request_id=request.request_id,
            response=True,
        )
        heartbeat_interval = min(
            30.0,
            max(1.0, self.policy.idle_timeout_seconds / 3.0),
        )
        next_heartbeat = time.monotonic() + heartbeat_interval
        try:
            while not self._stop.is_set() and int(time.time()) < introduction.expires_at:
                if getattr(peer.channel.connection, "closed", False):
                    return
                try:
                    delivery = session.deliveries.get(
                        timeout=min(
                            0.25,
                            max(0.01, next_heartbeat - time.monotonic()),
                        )
                    )
                except queue.Empty:
                    if time.monotonic() >= next_heartbeat:
                        response = peer.rpc.request(
                            RpcType.PING,
                            b"introduction",
                            expected=RpcType.PONG,
                        )
                        if response.payload != b"introduction":
                            raise ProtocolError("introduction heartbeat response is invalid")
                        next_heartbeat = time.monotonic() + heartbeat_interval
                    continue
                if delivery is None:
                    return
                try:
                    delivery_id = peer.rpc.send(
                        RpcType.INTRO_DELIVER,
                        encode_intro_request(delivery.request),
                    )
                    response = peer.rpc.receive()
                    if (
                        response.message_type is not RpcType.INTRO_DELIVER
                        or not response.is_response
                        or response.request_id != delivery_id
                    ):
                        raise ProtocolError("introduction delivery response is invalid")
                    RendezvousGrant.decode(
                        response.payload,
                        service,
                        request_nonce=delivery.request.nonce,
                    )
                    delivery.result = response.payload
                    next_heartbeat = time.monotonic() + heartbeat_interval
                except BaseException as error:
                    delivery.error = error
                finally:
                    delivery.ready.set()
        finally:
            session.closed.set()
            while True:
                try:
                    pending = session.deliveries.get_nowait()
                except queue.Empty:
                    break
                if pending is not None:
                    pending.error = ProtocolError("introduction circuit closed")
                    pending.ready.set()
            with self._lock:
                if self._introduction_sessions.get(service.service_id) is session:
                    del self._introduction_sessions[service.service_id]

    def _handle_intro_request(self, peer, request: RpcFrame) -> None:
        if "introduction" not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not advertise introduction capability")
        introduced = decode_intro_request(request.payload)
        with self._introduction_lock:
            self._introduction_registry.authorize(
                introduced.service_id,
                self.descriptor.node_id,
                introduced.token,
                introduced.nonce,
            )
            with self._lock:
                session = self._introduction_sessions.get(introduced.service_id)
        if session is None or session.closed.is_set():
            self._send_error(peer, request, "SERVICE_OFFLINE")
            return
        delivery = _IntroductionDelivery(introduced)
        try:
            session.deliveries.put(delivery, timeout=0.5)
        except queue.Full:
            self._send_error(peer, request, "INTRODUCTION_BUSY")
            return
        if not delivery.ready.wait(self.policy.connection_timeout_seconds):
            self._send_error(peer, request, "INTRODUCTION_TIMEOUT")
            return
        if delivery.error is not None or delivery.result is None:
            self._send_error(peer, request, "INTRODUCTION_FAILED")
            return
        peer.rpc.send(
            RpcType.INTRO_REQUEST,
            delivery.result,
            request_id=request.request_id,
            response=True,
        )

    def _bridge_rendezvous(self, slot: _RendezvousSlot) -> None:
        assert slot.host_stream is not None and slot.client_stream is not None
        stop = threading.Event()
        failures: list[BaseException] = []
        observation = WanCircuitObservation(
            slot.registration.cell_circuit_id,
            "rendezvous",
            slot.host_upstream,
            slot.client_upstream,
            capture=self._capture_relay_payload,
        )
        with self._lock:
            if (
                self._retain_connection_metadata
                and len(self.circuit_observations) < 4096
            ):
                self.circuit_observations.append(observation)

        def pump(
            source: MuxStream,
            destination: MuxStream,
            accounting_circuit_id: bytes | None,
        ) -> None:
            try:
                while not stop.is_set() and not self._stop.is_set():
                    payload = source.recv(CELL_PAYLOAD_SIZE * MAX_CELLS_PER_BATCH)
                    if not payload:
                        break
                    if accounting_circuit_id is not None:
                        self.runtime.account_bytes(accounting_circuit_id, len(payload))
                    observation.record(payload)
                    destination.sendall(payload)
            except (GrangerNetworkError, OSError, TimeoutError) as error:
                if not stop.is_set() and not self._stop.is_set():
                    failures.append(error)
            finally:
                stop.set()
                destination.close()

        threads = [
            threading.Thread(
                target=pump,
                args=(slot.host_stream, slot.client_stream, slot.host_accounting_circuit_id),
                daemon=True,
            ),
            threading.Thread(
                target=pump,
                args=(slot.client_stream, slot.host_stream, slot.client_accounting_circuit_id),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        while not stop.wait(0.25):
            if self._stop.is_set():
                slot.host_stream.reset()
                slot.client_stream.reset()
                break
        for thread in threads:
            thread.join(timeout=2.0)
        if any(thread.is_alive() for thread in threads):
            slot.host_stream.reset()
            slot.client_stream.reset()
            for thread in threads:
                thread.join(timeout=2.0)
        if failures and not self._stop.is_set():
            category = _safe_forwarding_failure_category(failures[0])
            raise ProtocolError(f"rendezvous forwarding failed ({category})")

    def _handle_rendezvous_register(
        self,
        peer,
        request: RpcFrame,
        upstream: str,
        accounting_circuit_id: bytes | None,
    ) -> None:
        if "rendezvous" not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not advertise rendezvous capability")
        if peer.remote.role is not PeerRole.SERVICE:
            raise ProtocolError("rendezvous registration requires a service peer")
        registration = RendezvousRegistration.decode(request.payload)
        key = registration.cookie_tag
        slot = _RendezvousSlot(registration, upstream, accounting_circuit_id)
        with self._lock:
            previous = self._rendezvous_slots.get(key)
            if previous is not None and not previous.done.is_set():
                raise ResourceLimitError("rendezvous cookie is already registered")
            if len(self._rendezvous_slots) >= self.policy.max_circuits:
                raise ResourceLimitError("rendezvous slot limit is exhausted")
            self._rendezvous_slots[key] = slot
        try:
            peer.rpc.send(
                RpcType.RENDEZVOUS_REGISTER,
                b"",
                request_id=request.request_id,
                response=True,
            )
            slot.host_mux = CellMultiplexer(
                peer.channel,
                registration.cell_circuit_id,
                initiator=False,
                max_streams=self.policy.max_streams,
                receive_budget=self.receive_memory_budget,
                cover_profile=self.cover_profile,
            )
            slot.host_stream = slot.host_mux.accept_stream(self.policy.connection_timeout_seconds)
            slot.host_ready.set()
            remaining = max(0.0, registration.expires_at - time.time())
            if not slot.client_ready.wait(remaining):
                raise TimeoutError("rendezvous registration expired without a client")
            if slot.error is not None:
                raise ProtocolError("rendezvous client setup failed")
            self._bridge_rendezvous(slot)
        except BaseException as error:
            slot.error = error
            raise
        finally:
            slot.done.set()
            if slot.host_mux is not None:
                slot.host_mux.close()
            if slot.client_mux is not None:
                slot.client_mux.close()
            with self._lock:
                if self._rendezvous_slots.get(key) is slot:
                    del self._rendezvous_slots[key]

    def _reserve_rendezvous_join(
        self,
        joined: RendezvousJoin,
        now: int,
    ) -> _RendezvousSlot | None:
        replay_key = (joined.cookie_tag, joined.nonce)
        with self._lock:
            expired = tuple(
                key
                for key, expires_at in self._used_rendezvous_joins.items()
                if expires_at <= now
            )
            for key in expired:
                del self._used_rendezvous_joins[key]
            slot = self._rendezvous_slots.get(joined.cookie_tag)
            if slot is None or slot.registration.expires_at <= now:
                return None
            if replay_key in self._used_rendezvous_joins:
                raise ProtocolError("rendezvous join nonce was replayed")
            if (
                len(self._used_rendezvous_joins)
                >= self._max_rendezvous_replay_entries
            ):
                raise ResourceLimitError("rendezvous replay state limit is exhausted")
            self._used_rendezvous_joins[replay_key] = slot.registration.expires_at
            return slot

    def _handle_rendezvous_join(
        self,
        peer,
        request: RpcFrame,
        upstream: str,
        accounting_circuit_id: bytes | None,
    ) -> None:
        if "rendezvous" not in self.descriptor.capabilities:
            raise ResourceLimitError("node did not advertise rendezvous capability")
        joined = RendezvousJoin.decode(request.payload)
        slot = self._reserve_rendezvous_join(joined, int(time.time()))
        if slot is None:
            self._send_error(peer, request, "RENDEZVOUS_UNAVAILABLE")
            return
        if not slot.host_ready.wait(self.policy.connection_timeout_seconds):
            self._send_error(peer, request, "RENDEZVOUS_TIMEOUT")
            return
        try:
            peer.rpc.send(
                RpcType.RENDEZVOUS_JOIN,
                b"",
                request_id=request.request_id,
                response=True,
            )
            slot.client_mux = CellMultiplexer(
                peer.channel,
                joined.cell_circuit_id,
                initiator=False,
                max_streams=self.policy.max_streams,
                receive_budget=self.receive_memory_budget,
                cover_profile=self.cover_profile,
            )
            slot.client_stream = slot.client_mux.accept_stream(self.policy.connection_timeout_seconds)
            slot.client_upstream = upstream
            slot.client_accounting_circuit_id = accounting_circuit_id
            slot.client_ready.set()
            remaining = max(0.0, slot.registration.expires_at - time.time())
            if not slot.done.wait(remaining + self.policy.idle_timeout_seconds):
                raise TimeoutError("rendezvous forwarding did not finish")
            if slot.error is not None and not isinstance(slot.error, TimeoutError):
                raise ProtocolError("rendezvous forwarding failed")
        except BaseException as error:
            slot.error = error
            slot.client_ready.set()
            raise

    def _handle_reverse_register(
        self,
        peer: AuthenticatedPeer,
        request: RpcFrame,
        accounting_circuit_id: bytes | None,
    ) -> bool:
        if request.payload:
            raise ProtocolError("reverse adjacency registration payload must be empty")
        if accounting_circuit_id is not None:
            raise ProtocolError("reverse adjacency registration requires a direct transport")
        if self._reverse_adjacencies is None:
            raise ResourceLimitError("node does not accept reverse adjacencies")
        try:
            descriptor = self._reverse_adjacencies.register(peer)
        except ResourceLimitError:
            self._send_error(peer, request, "REVERSE_CAPACITY")
            return False
        except DescriptorError:
            self._send_error(peer, request, "REVERSE_DESCRIPTOR_REJECTED")
            return False
        try:
            peer.rpc.send(
                RpcType.REVERSE_REGISTER,
                b"",
                request_id=request.request_id,
                response=True,
            )
        except Exception:
            self._reverse_adjacencies.discard(peer)
            raise
        return True

    def _dispatch(
        self,
        peer,
        request: RpcFrame,
        upstream: str,
        accounting_circuit_id: bytes | None,
        direct_host: str | None = None,
    ) -> bool | object:
        if request.is_response or request.is_error:
            raise ProtocolError("WAN node received an unsolicited RPC response")
        self.rpc_requests += 1
        if request.message_type is RpcType.PING:
            if len(request.payload) > 64:
                raise ProtocolError("peer PING payload exceeds its limit")
            peer.rpc.send(
                RpcType.PONG,
                request.payload,
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.CAPABILITIES:
            peer.rpc.send(
                RpcType.CAPABILITIES,
                self.descriptor.to_json().encode("ascii"),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.PEER_SAMPLE:
            if "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "CAPABILITY_DISABLED")
                return True
            capability, limit = decode_peer_sample(request.payload)
            candidates = self._discovery_candidates(
                capability,
                include_adjacent=accounting_circuit_id is not None,
            )
            candidates.sort(key=lambda candidate: candidate.node_id)
            peer.rpc.send(
                RpcType.PEER_SAMPLE,
                encode_node_list(candidates[:limit]),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.FIND_NODE:
            if "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "CAPABILITY_DISABLED")
                return True
            target, capability = decode_find_node(request.payload)
            candidates = self._discovery_candidates(
                capability,
                include_adjacent=accounting_circuit_id is not None,
            )
            candidates.sort(key=lambda candidate: _node_distance(candidate.node_id, target))
            peer.rpc.send(
                RpcType.FIND_NODE,
                encode_node_list(candidates[:MAX_FIND_NODE_RESULTS]),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.PUBLIC_SERVICE_SAMPLE:
            if "discovery" not in self.descriptor.capabilities or accounting_circuit_id is None:
                self._send_error(peer, request, "PRIVATE_DISCOVERY_REQUIRED")
                return True
            if request.payload:
                raise ProtocolError("public service sample request must be empty")
            peer.rpc.send(
                RpcType.PUBLIC_SERVICE_SAMPLE,
                encode_public_service_sample(self.records.public_service_sample()),
                request_id=request.request_id, response=True,
            )
            return True
        if request.message_type is RpcType.FIND_RECORD:
            if "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "CAPABILITY_DISABLED")
                return True
            kind, key = decode_find_record(request.payload)
            envelope = self.records.fetch(kind, key)
            peer.rpc.send(
                RpcType.FIND_RECORD,
                encode_optional_record(envelope),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.STORE_RECORD:
            if "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "CAPABILITY_DISABLED")
                return True
            self.records.store(decode_record_envelope(request.payload))
            peer.rpc.send(
                RpcType.STORE_RECORD,
                b"",
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.WAN_CONFIG_QUERY:
            if request.payload:
                raise ProtocolError("WAN config query payload must be empty")
            publisher = self.wan_config_publisher
            peer.rpc.send(
                RpcType.WAN_CONFIG_QUERY,
                encode_reseed_advertisements(publisher.advertisements() if publisher else ()),
                request_id=request.request_id, response=True,
            )
            return True
        if request.message_type is RpcType.WAN_CONFIG_CHUNK:
            digest, offset = decode_reseed_chunk_request(request.payload)
            try:
                if self.wan_config_publisher is None:
                    raise DiscoveryError("WAN config is unavailable")
                size, content = self.wan_config_publisher.transport_chunk(digest, offset)
            except DiscoveryError:
                self._send_error(peer, request, "WAN_CONFIG_UNAVAILABLE")
                return True
            peer.rpc.send(
                RpcType.WAN_CONFIG_CHUNK, encode_reseed_chunk_response(digest, offset, size, content),
                request_id=request.request_id, response=True,
            )
            return True
        if request.message_type is RpcType.RESEED_QUERY:
            if request.payload:
                raise ProtocolError("reseed query payload must be empty")
            if self.reseed_store is None or "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "RESEED_UNAVAILABLE")
                return True
            peer.rpc.send(
                RpcType.RESEED_QUERY,
                encode_reseed_advertisements(self.reseed_store.advertisements()),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.RESEED_CHUNK:
            if self.reseed_store is None or "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "RESEED_UNAVAILABLE")
                return True
            digest, offset = decode_reseed_chunk_request(request.payload)
            try:
                total_size, content = self.reseed_store.transport_chunk(digest, offset)
            except DiscoveryError:
                self._send_error(peer, request, "RESEED_UNAVAILABLE")
                return True
            peer.rpc.send(
                RpcType.RESEED_CHUNK,
                encode_reseed_chunk_response(digest, offset, total_size, content),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.OBSERVED_ADDRESS:
            if request.payload or accounting_circuit_id is not None or direct_host is None:
                raise ProtocolError("observed-address query requires a direct empty request")
            peer.rpc.send(
                RpcType.OBSERVED_ADDRESS,
                ipaddress.ip_address(direct_host).compressed.encode("ascii"),
                request_id=request.request_id,
                response=True,
            )
            return True
        if request.message_type is RpcType.REACHABILITY_PROBE:
            if request.payload or accounting_circuit_id is not None or direct_host is None:
                raise ProtocolError("reachability probe requires a direct empty request")
            descriptor = peer.remote.descriptor
            if (
                peer.remote.role is not PeerRole.RELAY
                or descriptor is None
                or descriptor.reachability != "reachable"
                or descriptor.endpoint.host != ipaddress.ip_address(direct_host).compressed
                or "discovery" not in descriptor.capabilities
                or "entry" not in descriptor.capabilities
            ):
                self._send_error(peer, request, "REACHABILITY_POLICY_REJECTED")
                return True
            if not self._reachability_probe_slots.acquire(blocking=False):
                self._send_error(peer, request, "REACHABILITY_CAPACITY")
                return True
            callback = None
            try:
                callback = connect_authenticated_peer(
                    descriptor,
                    self.identity,
                    PeerRole.RELAY,
                    local_descriptor=self.descriptor,
                    timeout=min(3.0, float(self.policy.connection_timeout_seconds)),
                )
                challenge = secrets.token_bytes(32)
                response = callback.rpc.request(
                    RpcType.PING,
                    challenge,
                    expected=RpcType.PONG,
                )
                if response.payload != challenge:
                    raise ProtocolError("reachability callback challenge did not match")
                self.add_known_peer(descriptor, source="reachability-proof")
                with self._lock:
                    self.reachability_probes += 1
                peer.rpc.send(
                    RpcType.REACHABILITY_PROBE,
                    b"",
                    request_id=request.request_id,
                    response=True,
                )
            except (GrangerNetworkError, OSError, ValueError):
                with self._lock:
                    self.reachability_probe_failures += 1
                self._send_error(peer, request, "REACHABILITY_CALLBACK_FAILED")
            finally:
                if callback is not None:
                    callback.close()
                self._reachability_probe_slots.release()
            return True
        if request.message_type is RpcType.REVERSE_REGISTER:
            return (
                _TRANSFER_PEER
                if self._handle_reverse_register(peer, request, accounting_circuit_id)
                else False
            )
        if request.message_type is RpcType.OPEN_CIRCUIT:
            self._handle_open_circuit(peer, request, upstream)
            return False
        if request.message_type is RpcType.EXTEND_CIRCUIT:
            self._handle_extend_circuit(peer, request, upstream)
            return False
        if request.message_type is RpcType.INTRO_REGISTER:
            self._handle_intro_register(peer, request, upstream)
            return False
        if request.message_type is RpcType.INTRO_REQUEST:
            self._handle_intro_request(peer, request)
            return True
        if request.message_type is RpcType.RENDEZVOUS_REGISTER:
            self._handle_rendezvous_register(
                peer,
                request,
                upstream,
                accounting_circuit_id,
            )
            return False
        if request.message_type is RpcType.RENDEZVOUS_JOIN:
            self._handle_rendezvous_join(
                peer,
                request,
                upstream,
                accounting_circuit_id,
            )
            return False
        self._send_error(peer, request, "UNEXPECTED_STATE")
        return False

    def _serve_peer(
        self,
        peer,
        upstream: str,
        accounting_circuit_id: bytes | None = None,
        direct_host: str | None = None,
    ) -> bool:
        requests_served = 0
        while not self._stop.is_set():
            if requests_served >= self.max_rpc_requests_per_connection:
                raise ResourceLimitError("peer RPC request limit is exhausted")
            request = peer.rpc.receive()
            if peer.remote.role is PeerRole.CONFIG_RECOVERY and (
                request.message_type not in {RpcType.WAN_CONFIG_QUERY, RpcType.WAN_CONFIG_CHUNK}
                or requests_served >= 65
            ):
                self._send_error(peer, request, "CONFIG_RECOVERY_ONLY")
                return False
            if direct_host is not None:
                self._consume_rpc_source_budget(direct_host)
            requests_served += 1
            disposition = self._dispatch(
                peer,
                request,
                upstream,
                accounting_circuit_id,
                direct_host,
            )
            if disposition is _TRANSFER_PEER:
                return True
            if not disposition:
                return False
        return False

    def serve_reverse_adjacency(
        self,
        peer: AuthenticatedPeer,
        anchor: NodeDescriptor,
    ) -> None:
        if self.enable_listener or self.descriptor.reachability != "adjacent":
            raise ProtocolError("reverse adjacency server requires listener-free node mode")
        anchor.verify(
            expected_network_id=self.descriptor.network_id,
            expected_protocol_version=self.descriptor.protocol_version,
        )
        if (
            self.descriptor.via_node_id != anchor.node_id
            or self.descriptor.endpoint != anchor.endpoint
            or peer.remote.descriptor is None
            or peer.remote.descriptor.node_id != anchor.node_id
        ):
            raise ProtocolError("reverse adjacency server is connected to the wrong anchor")
        connection = peer.channel.connection
        with self._lock:
            if len(self._connections) >= self.policy.max_connections:
                raise ResourceLimitError("listener-free node connection limit is exhausted")
            self._connections.add(connection)
        try:
            transferred = self._serve_peer(peer, f"anchor:{anchor.node_id}")
            if transferred:
                raise ProtocolError("nested reverse adjacency transfer is forbidden")
        finally:
            peer.close()
            with self._lock:
                self._connections.discard(connection)

    def _handle_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        peer = None
        transferred = False
        recovery_deadline = None
        try:
            connection.settimeout(self.policy.connection_timeout_seconds)
            role = PeerRole.BOOTSTRAP if "bootstrap" in self.descriptor.capabilities else PeerRole.RELAY
            peer = authenticate_server_stream(
                connection,
                self.identity,
                self.descriptor,
                role=role,
            )
            connection.settimeout(self.policy.idle_timeout_seconds)
            if peer.remote.role is PeerRole.CONFIG_RECOVERY:
                def expire_recovery():
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    connection.close()
                recovery_deadline = threading.Timer(10.0, expire_recovery)
                recovery_deadline.daemon = True
                recovery_deadline.start()
            if (
                peer.remote.descriptor is not None
                and peer.remote.descriptor.reachability != "adjacent"
                and peer.remote.role is PeerRole.BOOTSTRAP
            ):
                self.add_known_peer(peer.remote.descriptor)
            transferred = self._serve_peer(
                peer,
                f"{address[0]}:{address[1]}",
                direct_host=str(address[0]),
            )
        except ConnectionClosedError:
            pass
        except (GrangerNetworkError, OSError, ValueError) as error:
            if not self._stop.is_set():
                self._record_runtime_error(error)
        finally:
            if recovery_deadline is not None:
                recovery_deadline.cancel()
            if peer is not None and not transferred:
                peer.close()
            elif peer is None:
                connection.close()
            current = threading.current_thread()
            with self._lock:
                if not transferred:
                    self._release_connection_unlocked(connection)
                self._threads.discard(current)

    def contribution_snapshot(self) -> dict[str, object]:
        result: dict[str, object] = self.runtime.contribution_snapshot()
        with self._lock:
            listener_metrics = {
                "acceptedConnections": self.accepted_connections,
                "rejectedConnections": self.rejected_connections,
                "relayEligible": self.policy.enabled,
                "reachability": self.descriptor.reachability,
                "rpcRequests": self.rpc_requests,
                "reachabilityProbeFailures": self.reachability_probe_failures,
                "reachabilityProbes": self.reachability_probes,
                "receiveMemoryBudgetBytes": self.receive_memory_budget.maximum_bytes,
                "receiveMemoryUsedBytes": self.receive_memory_budget.used_bytes,
                "rpcSourceWindows": len(self._rpc_source_windows),
            }
        result.update(listener_metrics)
        if self._reverse_adjacencies is not None:
            result["reverseAdjacency"] = self._reverse_adjacencies.snapshot().to_document()
        return result

    def stop(self) -> None:
        self._stop.set()
        if self._reverse_adjacencies is not None:
            self._reverse_adjacencies.close()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._lock.acquire(timeout=1.0):
            try:
                introduction_sessions = tuple(self._introduction_sessions.values())
                rendezvous_slots = tuple(self._rendezvous_slots.values())
                connections = list(self._connections)
                threads = list(self._threads)
            finally:
                self._lock.release()
        else:
            introduction_sessions = ()
            rendezvous_slots = ()
            connections = []
            threads = []
        for session in introduction_sessions:
            session.closed.set()
            try:
                session.deliveries.put_nowait(None)
            except queue.Full:
                pass
        for slot in rendezvous_slots:
            slot.error = ProtocolError("WAN node is stopping")
            slot.host_ready.set()
            slot.client_ready.set()
            slot.done.set()
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        join_deadline = time.monotonic() + 3.0
        if self._accept_thread is not None and self._accept_thread is not threading.current_thread():
            self._accept_thread.join(timeout=max(0.0, join_deadline - time.monotonic()))
            self._accept_thread = None
        for thread in threads:
            if thread is not threading.current_thread():
                remaining = join_deadline - time.monotonic()
                if remaining <= 0:
                    break
                thread.join(timeout=remaining)

    def __enter__(self) -> "WanNodeServer":
        self.start_background()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def initialize_node(
    state_dir: Path,
    endpoint: RendezvousEndpoint,
    capabilities: tuple[str, ...],
    policy: RelayPolicy,
    *,
    descriptor_lifetime: int = 60 * 60,
) -> NodeDescriptor:
    root = Path(state_dir)
    root.mkdir(parents=True, exist_ok=True)
    identity_path = root / NODE_IDENTITY_FILE
    if identity_path.exists():
        raise FileExistsError(f"node state already exists: {root}")
    identity = ServiceIdentity.generate()
    descriptor = NodeDescriptor.create(
        identity,
        endpoint,
        capabilities,
        policy,
        lifetime=descriptor_lifetime,
    )
    identity.save(identity_path)
    atomic_write_text(root / NODE_DESCRIPTOR_FILE, descriptor.to_json(), mode=0o644)
    return descriptor


def load_node(
    state_dir: Path,
    peers: tuple[NodeDescriptor, ...] = (),
    *,
    listener_endpoint: NodeListenerEndpoint | None = None,
    capture_path: Path | None = None,
    diagnostics_path: Path | None = None,
    reseed_store: ReseedStore | None = None,
) -> WanNodeServer:
    root = Path(state_dir)
    identity = ServiceIdentity.load(root / NODE_IDENTITY_FILE)
    descriptor = NodeDescriptor.from_json((root / NODE_DESCRIPTOR_FILE).read_text(encoding="utf-8"))
    return WanNodeServer(
        identity,
        descriptor,
        root,
        known_peers=peers,
        listener_endpoint=listener_endpoint,
        capture_path=capture_path,
        diagnostics_path=diagnostics_path,
        reseed_store=reseed_store,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network authenticated WAN node")
    subcommands = parser.add_subparsers(dest="command", required=True)
    initialize = subcommands.add_parser("init")
    initialize.add_argument("--state-dir", type=Path, required=True)
    initialize.add_argument("--listen-host", required=True)
    initialize.add_argument("--listen-port", type=int, required=True)
    initialize.add_argument("--capability", action="append", required=True)
    initialize.add_argument("--max-connections", type=int, default=128)
    initialize.add_argument("--max-circuits", type=int, default=32)
    initialize.add_argument("--descriptor-lifetime", type=int, default=60 * 60)

    run = subcommands.add_parser("run")
    run.add_argument("--state-dir", type=Path, required=True)
    run.add_argument("--ready-file", type=Path)
    run.add_argument("--peer-descriptor", type=Path, action="append", default=[])
    run.add_argument("--listen-host")
    run.add_argument("--listen-port", type=int)
    run.add_argument("--capture", type=Path)
    run.add_argument("--diagnostics", type=Path)
    run.add_argument("--wan-config-publication", type=Path)
    run.add_argument("--wan-config-trust-anchor", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    from .network_audit import install_from_environment

    install_from_environment("node")
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "init":
            capabilities = tuple(sorted(set(options.capability)))
            relay_roles = {"entry", "middle", "introduction", "rendezvous", "service-relay"}
            policy = RelayPolicy(
                enabled=bool(set(capabilities) & relay_roles),
                max_connections=options.max_connections,
                max_circuits=options.max_circuits,
            )
            descriptor = initialize_node(
                options.state_dir,
                RendezvousEndpoint(options.listen_host, options.listen_port),
                capabilities,
                policy,
                descriptor_lifetime=options.descriptor_lifetime,
            )
            print(descriptor.node_id)
            return 0
        peers = tuple(
            NodeDescriptor.from_json(path.read_text(encoding="utf-8"))
            for path in options.peer_descriptor
        )
        if (options.listen_host is None) != (options.listen_port is None):
            raise ValueError("node listener host and port must be provided together")
        listener_endpoint = (
            NodeListenerEndpoint(options.listen_host, options.listen_port)
            if options.listen_host is not None
            else None
        )
        node = load_node(
            options.state_dir,
            peers,
            listener_endpoint=listener_endpoint,
            capture_path=options.capture,
            diagnostics_path=options.diagnostics,
        )
        if bool(options.wan_config_publication) != bool(options.wan_config_trust_anchor):
            raise ValueError("config publication requires an existing trust anchor")
        if options.wan_config_publication is not None:
            from .wan_config_recovery import WanConfigPublisher
            node.wan_config_publisher = WanConfigPublisher(
                options.wan_config_publication, options.wan_config_trust_anchor,
            )
        node.start_background()
        if options.ready_file is not None:
            atomic_write_text(
                options.ready_file,
                json.dumps(
                    {
                        "endpoint": {
                            "host": node.descriptor.endpoint.host,
                            "port": node.descriptor.endpoint.port,
                        },
                        "advertiseEndpoint": {
                            "host": node.descriptor.endpoint.host,
                            "port": node.descriptor.endpoint.port,
                        },
                        "listenEndpoint": {
                            "host": node.listener_endpoint.host,
                            "port": node.listener_endpoint.port,
                        },
                        "nodeId": node.descriptor.node_id,
                        "pid": os.getpid(),
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o644,
            )
        assert node._accept_thread is not None
        node._accept_thread.join()
        return 0
    except KeyboardInterrupt:
        return 130
    except (GrangerNetworkError, OSError, ValueError) as error:
        print(f"granger-node: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
