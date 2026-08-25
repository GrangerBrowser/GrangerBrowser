from __future__ import annotations

import socket
import tempfile
import time
import unittest
from pathlib import Path

from granger_network.circuit import CircuitBuilder
from granger_network.errors import OverlayRoutingError, ProtocolError
from granger_network.identity import ServiceIdentity
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType
from granger_network.transport import RendezvousEndpoint


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanCircuitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-circuit-")
        self.root = Path(self.temporary.name)
        definitions = ("entry", "middle", "rendezvous")
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
            WanNodeServer(identity, descriptor, self.root / f"node-{index}")
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
        builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=4.0)
        circuit = builder.open(self.route)
        try:
            response = circuit.endpoint.rpc.request(
                RpcType.PING,
                marker,
                expected=RpcType.PONG,
            )
            self.assertEqual(response.payload, marker)
            self.assertEqual(circuit.hop_count, 3)
            self.assertEqual(len(circuit.unique_node_ids), 3)
            self.assertEqual(len(set(circuit.circuit_ids)), len(circuit.circuit_ids))
            self.assertTrue(circuit.all_cells_fixed_size)
            self.assertEqual(len(self.nodes[0].circuit_observations), 1)
            self.assertEqual(len(self.nodes[1].circuit_observations), 1)
            for node in self.nodes[:2]:
                observation = node.circuit_observations[0]
                self.assertGreater(observation.bytes_forwarded, 0)
                self.assertFalse(observation.contains(marker))
            self.assertEqual(self.nodes[0].circuit_observations[0].downstream, self.descriptors[1].node_id)
            self.assertEqual(self.nodes[1].circuit_observations[0].downstream, self.descriptors[2].node_id)
        finally:
            circuit.close()
        deadline = time.monotonic() + 5.0
        while any(node.runtime.active_circuits for node in self.nodes) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(all(node.runtime.active_circuits == 0 for node in self.nodes))

    def test_unreachable_middle_fails_closed_without_shorter_route(self) -> None:
        self.nodes[1].stop()
        builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=1.0)
        with self.assertRaises((OSError, ProtocolError, OverlayRoutingError)):
            builder.open(self.route)
        self.assertEqual(self.nodes[2].accepted_connections, 0)

    def test_route_repetition_is_rejected_before_connect(self) -> None:
        builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=1.0)
        repeated = (
            (self.descriptors[0], "entry"),
            (self.descriptors[0], "entry"),
        )
        accepted_before = self.nodes[0].accepted_connections
        with self.assertRaisesRegex(OverlayRoutingError, "repeats"):
            builder.open(repeated)
        self.assertEqual(self.nodes[0].accepted_connections, accepted_before)


if __name__ == "__main__":
    unittest.main()
