from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from granger_network.cells import MuxStream
from granger_network.circuit import BuiltCircuit, CircuitBuilder
from granger_network.errors import OverlayRoutingError, ProtocolError
from granger_network.identity import ServiceIdentity
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType, authenticate_server_stream
from granger_network.transport import RendezvousEndpoint


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanCircuitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-circuit-")
        self.root = Path(self.temporary.name)
        definitions = ("access", "entry", "middle", "rendezvous")
        self.identities = [ServiceIdentity.generate() for _ in definitions]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                (role,),
                RelayPolicy(
                    enabled=True,
                    max_circuits=16,
                    max_streams=16,
                    max_connections=32,
                    max_bandwidth_kib_per_second=64 * 1024,
                ),
                lifetime=3600,
            )
            for identity, role in zip(self.identities, definitions, strict=True)
        ]
        self.nodes = [
            WanNodeServer(identity, descriptor, self.root / f"node-{index}",
                          capture_path=self.root / f"node-{index}.capture")
            for index, (identity, descriptor) in enumerate(
                zip(self.identities, self.descriptors, strict=True)
            )
        ]
        for node in self.nodes:
            node.start_background()
        self.route = tuple(
            zip(self.descriptors, definitions, strict=True)
        )

    def tearDown(self) -> None:
        for node in self.nodes:
            node.stop()
        self.temporary.cleanup()

    def test_telescoped_real_socket_circuit_reaches_final_node(self) -> None:
        marker = b"GRANGER_APPLICATION_MARKER_MUST_STAY_OPAQUE"
        endpoint_identity = ServiceIdentity.generate()
        builder = CircuitBuilder(endpoint_identity, PeerRole.CLIENT, timeout=4.0)
        circuit = builder.open(self.route)
        try:
            response = circuit.endpoint.rpc.request(
                RpcType.PING,
                marker,
                expected=RpcType.PONG,
            )
            self.assertEqual(response.payload, marker)
            self.assertEqual(circuit.hop_count, 4)
            self.assertEqual(len(circuit.unique_node_ids), 4)
            self.assertEqual(len(set(circuit.circuit_ids)), len(circuit.circuit_ids))
            self.assertEqual(len(circuit.hop_authentication_keys), 4)
            self.assertEqual(len(set(circuit.hop_authentication_keys)), 4)
            self.assertNotIn(
                endpoint_identity.public_key_bytes,
                circuit.hop_authentication_keys,
            )
            self.assertTrue(circuit.all_cells_fixed_size)
            self.assertEqual(len(self.nodes[0].circuit_observations), 1)
            self.assertEqual(len(self.nodes[1].circuit_observations), 1)
            self.assertEqual(len(self.nodes[2].circuit_observations), 1)
            for node in self.nodes[:3]:
                observation = node.circuit_observations[0]
                self.assertGreater(observation.bytes_forwarded, 0)
                captured = node.capture_path.read_bytes()
                self.assertTrue(captured)
                self.assertNotIn(marker, captured)
                self.assertEqual(len(observation._sample), 0)
            self.assertEqual(self.nodes[0].circuit_observations[0].downstream, self.descriptors[1].node_id)
            self.assertEqual(self.nodes[1].circuit_observations[0].downstream, self.descriptors[2].node_id)
            self.assertEqual(self.nodes[2].circuit_observations[0].downstream, self.descriptors[3].node_id)
        finally:
            circuit.close()
        deadline = time.monotonic() + 5.0
        while any(node.runtime.active_circuits for node in self.nodes) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(all(node.runtime.active_circuits == 0 for node in self.nodes))

    def test_unreachable_middle_fails_closed_without_shorter_route(self) -> None:
        self.nodes[2].stop()
        builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=1.0)
        with self.assertRaises((OSError, ProtocolError, OverlayRoutingError)):
            builder.open(self.route)
        self.assertEqual(self.nodes[3].accepted_connections, 0)

    def test_nested_peer_handshake_inherits_build_timeout(self) -> None:
        observed_timeouts: list[float | None] = []

        def fail_nested_handshake(stream, *_args, **_kwargs):
            observed_timeouts.append(stream._timeout)
            raise TimeoutError("simulated nested handshake loss")

        builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=0.25)
        with patch(
            "granger_network.circuit.authenticate_client_stream",
            side_effect=fail_nested_handshake,
        ):
            with self.assertRaises(TimeoutError):
                builder.open(self.route[:2])
        self.assertEqual(observed_timeouts, [0.25])

    def test_silent_nested_peer_times_out_and_closes_partial_circuit(self) -> None:
        reached = threading.Event()
        release = threading.Event()
        results: list[BuiltCircuit | Exception] = []

        def silent_peer(connection, identity, descriptor, **kwargs):
            if isinstance(connection, MuxStream) and descriptor.node_id == self.descriptors[1].node_id:
                reached.set()
                release.wait(3.0)
                raise ProtocolError("controlled silent nested peer")
            return authenticate_server_stream(connection, identity, descriptor, **kwargs)

        def build() -> None:
            try:
                results.append(
                    CircuitBuilder(
                        ServiceIdentity.generate(), PeerRole.CLIENT, timeout=0.25
                    ).open(self.route[:2])
                )
            except Exception as error:
                results.append(error)

        worker = threading.Thread(target=build, daemon=True)
        with patch("granger_network.node.authenticate_server_stream", side_effect=silent_peer):
            try:
                worker.start()
                self.assertTrue(reached.wait(2.0))
                worker.join(timeout=1.0)
                self.assertFalse(worker.is_alive(), "nested handshake ignored the timeout")
                self.assertEqual(len(results), 1)
                self.assertIsInstance(results[0], TimeoutError)
            finally:
                release.set()
                worker.join(timeout=3.0)
                for result in results:
                    if not isinstance(result, Exception):
                        result.close()
        deadline = time.monotonic() + 3.0
        while any(node.runtime.active_circuits for node in self.nodes) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(all(node.runtime.active_circuits == 0 for node in self.nodes))

    def test_completed_circuit_does_not_inherit_build_timeout(self) -> None:
        circuit = CircuitBuilder(
            ServiceIdentity.generate(),
            PeerRole.CLIENT,
            timeout=0.2,
        ).open(self.route)
        try:
            time.sleep(0.35)
            response = circuit.endpoint.rpc.request(
                RpcType.PING,
                b"idle-circuit",
                expected=RpcType.PONG,
            )
            self.assertEqual(response.payload, b"idle-circuit")
        finally:
            circuit.close()

    def test_route_repetition_is_rejected_before_connect(self) -> None:
        builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=1.0)
        repeated = (
            (self.descriptors[0], "access"),
            (self.descriptors[0], "access"),
        )
        accepted_before = self.nodes[0].accepted_connections
        with self.assertRaisesRegex(OverlayRoutingError, "repeats"):
            builder.open(repeated)
        self.assertEqual(self.nodes[0].accepted_connections, accepted_before)


if __name__ == "__main__":
    unittest.main()
