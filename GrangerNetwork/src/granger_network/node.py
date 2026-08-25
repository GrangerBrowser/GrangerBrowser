from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import threading
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .cells import CELL_PAYLOAD_SIZE, CellMultiplexer, MuxStream
from .circuit import decode_extend_circuit, decode_open_circuit, encode_open_circuit
from .errors import DescriptorError, DiscoveryError, GrangerNetworkError, ProtocolError, ResourceLimitError
from .identity import ServiceIdentity
from .peer import GrangerNode, NodeDescriptor, RelayPolicy
from .peer_rpc import (
    PeerRole,
    RpcFrame,
    RpcType,
    authenticate_server_stream,
    connect_authenticated_peer,
    encode_error,
)
from .transport import RendezvousEndpoint
from .wan_discovery import (
    MAX_FIND_NODE_RESULTS,
    PersistentRecordStore,
    decode_find_node,
    decode_find_record,
    decode_record_envelope,
    encode_node_list,
    encode_optional_record,
)


NODE_IDENTITY_FILE = "node-identity.json"
NODE_DESCRIPTOR_FILE = "node-descriptor.json"
NODE_CACHE_FILE = "peer-cache.json"
NODE_RECORDS_FILE = "records.json"


class WanCircuitObservation:
    def __init__(
        self,
        circuit_id: bytes,
        role: str,
        upstream: str,
        downstream: str,
        *,
        sample_limit: int = 2 * 1024 * 1024,
    ) -> None:
        self.circuit_id = circuit_id
        self.role = role
        self.upstream = upstream
        self.downstream = downstream
        self.sample_limit = sample_limit
        self.bytes_forwarded = 0
        self._sample = bytearray()
        self._lock = threading.Lock()

    def record(self, payload: bytes) -> None:
        with self._lock:
            self.bytes_forwarded += len(payload)
            remaining = self.sample_limit - len(self._sample)
            if remaining > 0:
                self._sample.extend(payload[:remaining])

    def contains(self, marker: bytes) -> bool:
        with self._lock:
            return marker in self._sample


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
    ) -> None:
        descriptor.verify()
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise DescriptorError("WAN node identity does not match its descriptor")
        if descriptor.reachability != "reachable":
            raise DescriptorError("WAN listener requires reachable node status")
        self.identity = identity
        self.descriptor = descriptor
        self.policy = descriptor.relay_policy
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.records = PersistentRecordStore(self.state_dir / NODE_RECORDS_FILE)
        self.runtime = GrangerNode(identity, descriptor, self.policy)
        self._known: dict[str, NodeDescriptor] = {descriptor.node_id: descriptor}
        for peer in known_peers:
            peer.verify()
            self._known[peer.node_id] = peer
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._threads: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._lock = threading.Lock()
        self.errors: list[str] = []
        self.accepted_connections = 0
        self.rejected_connections = 0
        self.rpc_requests = 0
        self.peer_addresses: list[tuple[str, int]] = []
        self.circuit_observations: list[WanCircuitObservation] = []
        self.records.store(self._record_for_descriptor(descriptor))

    @staticmethod
    def _record_for_descriptor(descriptor: NodeDescriptor):
        from .distributed import encode_record

        return encode_record(descriptor)

    def start_background(self) -> None:
        if self._listener is not None:
            raise RuntimeError("WAN node is already running")
        listener = socket.socket(self.descriptor.endpoint.family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(self.descriptor.endpoint.socket_address)
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
            with self._lock:
                if len(self._connections) >= self.policy.max_connections:
                    self.rejected_connections += 1
                    connection.close()
                    continue
                self._connections.add(connection)
                self.accepted_connections += 1
                if len(self.peer_addresses) < 4096:
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

    def _known_peers(self) -> tuple[NodeDescriptor, ...]:
        with self._lock:
            return tuple(self._known.values())

    def add_known_peer(self, descriptor: NodeDescriptor) -> None:
        descriptor.verify()
        with self._lock:
            previous = self._known.get(descriptor.node_id)
            if previous is None or descriptor.issued_at >= previous.issued_at:
                self._known[descriptor.node_id] = descriptor

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
                    payload = source.recv(CELL_PAYLOAD_SIZE * 8)
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
        for thread in threads:
            thread.join(timeout=self.policy.idle_timeout_seconds + 2)
        if any(thread.is_alive() for thread in threads):
            left.reset()
            right.reset()
            for thread in threads:
                thread.join(timeout=2.0)
        if failures and not self._stop.is_set():
            raise ProtocolError(f"relay forwarding failed: {type(failures[0]).__name__}")

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
            )
            stream = multiplexer.accept_stream(self.policy.connection_timeout_seconds)
            role = PeerRole.BOOTSTRAP if "bootstrap" in self.descriptor.capabilities else PeerRole.RELAY
            nested = authenticate_server_stream(
                stream,
                self.identity,
                self.descriptor,
                role=role,
            )
            self._serve_peer(nested, upstream)
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
        try:
            outbound = connect_authenticated_peer(
                extension.next_node,
                self.identity,
                PeerRole.RELAY,
                local_descriptor=self.descriptor,
                timeout=self.policy.connection_timeout_seconds,
            )
            created = outbound.rpc.request(
                RpcType.OPEN_CIRCUIT,
                encode_open_circuit(extension.outgoing_circuit_id, extension.next_role),
                expected=RpcType.CIRCUIT_CREATED,
            )
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
            )
            outgoing_mux = CellMultiplexer(
                outbound.channel,
                extension.outgoing_circuit_id,
                initiator=True,
                max_streams=self.policy.max_streams,
            )
            outgoing = outgoing_mux.open_stream(self.policy.connection_timeout_seconds)
            incoming = incoming_mux.accept_stream(self.policy.connection_timeout_seconds)
            observation = WanCircuitObservation(
                extension.incoming_circuit_id,
                extension.current_role,
                upstream,
                extension.next_node.node_id,
            )
            with self._lock:
                if len(self.circuit_observations) < 4096:
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
            self.runtime.end_circuit(extension.incoming_circuit_id)

    def _dispatch(self, peer, request: RpcFrame, upstream: str) -> bool:
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
        if request.message_type is RpcType.FIND_NODE:
            if "discovery" not in self.descriptor.capabilities:
                self._send_error(peer, request, "CAPABILITY_DISABLED")
                return True
            target, capability = decode_find_node(request.payload)
            candidates = []
            for candidate in self._known_peers():
                try:
                    candidate.verify()
                except DescriptorError:
                    continue
                if capability in candidate.capabilities and candidate.reachability == "reachable":
                    candidates.append(candidate)
            candidates.sort(key=lambda candidate: _node_distance(candidate.node_id, target))
            peer.rpc.send(
                RpcType.FIND_NODE,
                encode_node_list(candidates[:MAX_FIND_NODE_RESULTS]),
                request_id=request.request_id,
                response=True,
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
        if request.message_type is RpcType.OPEN_CIRCUIT:
            self._handle_open_circuit(peer, request, upstream)
            return False
        if request.message_type is RpcType.EXTEND_CIRCUIT:
            self._handle_extend_circuit(peer, request, upstream)
            return False
        self._send_error(peer, request, "UNEXPECTED_STATE")
        return False

    def _serve_peer(self, peer, upstream: str) -> None:
        while not self._stop.is_set():
            request = peer.rpc.receive()
            if not self._dispatch(peer, request, upstream):
                return

    def _handle_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        peer = None
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
            if peer.remote.descriptor is not None:
                self.add_known_peer(peer.remote.descriptor)
            self._serve_peer(peer, f"{address[0]}:{address[1]}")
        except (GrangerNetworkError, OSError, ValueError) as error:
            if not self._stop.is_set():
                with self._lock:
                    if len(self.errors) < 1024:
                        self.errors.append(type(error).__name__)
        finally:
            if peer is not None:
                peer.close()
            else:
                connection.close()
            current = threading.current_thread()
            with self._lock:
                self._connections.discard(connection)
                self._threads.discard(current)

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with self._lock:
            connections = list(self._connections)
            threads = list(self._threads)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self._accept_thread is not None and self._accept_thread is not threading.current_thread():
            self._accept_thread.join(timeout=3.0)
            self._accept_thread = None
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=3.0)

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
) -> NodeDescriptor:
    root = Path(state_dir)
    root.mkdir(parents=True, exist_ok=True)
    identity_path = root / NODE_IDENTITY_FILE
    if identity_path.exists():
        raise FileExistsError(f"node state already exists: {root}")
    identity = ServiceIdentity.generate()
    descriptor = NodeDescriptor.create(identity, endpoint, capabilities, policy)
    identity.save(identity_path)
    atomic_write_text(root / NODE_DESCRIPTOR_FILE, descriptor.to_json(), mode=0o644)
    return descriptor


def load_node(state_dir: Path, peers: tuple[NodeDescriptor, ...] = ()) -> WanNodeServer:
    root = Path(state_dir)
    identity = ServiceIdentity.load(root / NODE_IDENTITY_FILE)
    descriptor = NodeDescriptor.from_json((root / NODE_DESCRIPTOR_FILE).read_text(encoding="utf-8"))
    return WanNodeServer(identity, descriptor, root, known_peers=peers)


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

    run = subcommands.add_parser("run")
    run.add_argument("--state-dir", type=Path, required=True)
    run.add_argument("--ready-file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
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
            )
            print(descriptor.node_id)
            return 0
        node = load_node(options.state_dir)
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
                        "nodeId": node.descriptor.node_id,
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
