from __future__ import annotations

import json
import socket
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from granger_network.circuit import CircuitBuilder
from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import encode_record
from granger_network.errors import (
    ConnectionClosedError,
    DiscoveryError,
    ProtocolError,
    ReplayError,
    ResourceLimitError,
)
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor, IntroductionRegistry
from granger_network.node import WanCircuitObservation, WanNodeServer, initialize_node
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import (
    PeerRole,
    RpcType,
    connect_authenticated_peer,
)
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_control import RendezvousJoin
from granger_network.wan_discovery import PersistentRecordStore


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanResourceLimitTests(unittest.TestCase):
    def test_default_node_does_not_retain_connection_or_circuit_topology(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-metadata-retention-") as temporary:
            root = Path(temporary)
            identities = (ServiceIdentity.generate(), ServiceIdentity.generate())
            policy = RelayPolicy(
                enabled=True,
                max_circuits=8,
                max_streams=16,
                max_connections=16,
                max_bandwidth_kib_per_second=64 * 1024,
            )
            descriptors = (
                NodeDescriptor.create(
                    identities[0],
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    ("access",),
                    policy,
                    lifetime=600,
                ),
                NodeDescriptor.create(
                    identities[1],
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    ("rendezvous",),
                    policy,
                    lifetime=600,
                ),
            )
            nodes = tuple(
                WanNodeServer(identity, descriptor, root / f"node-{index}")
                for index, (identity, descriptor) in enumerate(
                    zip(identities, descriptors, strict=True)
                )
            )
            for node in nodes:
                node.start_background()
            try:
                with CircuitBuilder(
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=3.0,
                ).open(
                    (
                        (descriptors[0], "access"),
                        (descriptors[1], "rendezvous"),
                    )
                ) as circuit:
                    response = circuit.endpoint.rpc.request(
                        RpcType.PING,
                        b"metadata-retention-check",
                        expected=RpcType.PONG,
                    )
                    self.assertEqual(response.payload, b"metadata-retention-check")
                self.assertGreater(nodes[0].contribution_snapshot()["bytesRelayed"], 0)
                self.assertTrue(all(node.peer_addresses == [] for node in nodes))
                self.assertTrue(all(node.circuit_observations == [] for node in nodes))
            finally:
                for node in nodes:
                    node.stop()

    def test_runtime_diagnostics_record_categories_without_raw_error_details(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-diagnostic-redaction-") as temporary:
            root = Path(temporary)
            identity = ServiceIdentity.generate()
            descriptor = NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("discovery",),
                RelayPolicy(enabled=False),
                lifetime=600,
            )
            diagnostics = root / "runtime-diagnostics.jsonl"
            node = WanNodeServer(
                identity,
                descriptor,
                root / "node",
                diagnostics_path=diagnostics,
            )
            sensitive = "203.0.113.7:62441/service.granger?token=private"
            node._record_runtime_error(RuntimeError(sensitive))
            content = diagnostics.read_text(encoding="ascii")
            document = json.loads(content)

        self.assertEqual(node.errors, ["RuntimeError"])
        self.assertEqual(document["error"], "RuntimeError")
        self.assertNotIn(sensitive, content)

    def test_introduction_registry_fails_closed_at_bounded_capacity(self) -> None:
        now = int(time.time())
        node_identity = ServiceIdentity.generate()
        node_id = NodeDescriptor.create(
            node_identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("introduction",),
            RelayPolicy(enabled=True),
            issued_at=now,
            lifetime=600,
        ).node_id
        service_identities = (ServiceIdentity.generate(), ServiceIdentity.generate())
        services = tuple(
            ServiceDescriptor.create_remote(
                identity,
                f"bounded-{index}",
                issued_at=now,
                lifetime=600,
            )
            for index, identity in enumerate(service_identities)
        )
        introductions = tuple(
            IntroductionDescriptor.create(
                identity,
                service,
                [node_id],
                sequence=1,
                issued_at=now,
                lifetime=300,
            )
            for identity, service in zip(service_identities, services, strict=True)
        )
        registry = IntroductionRegistry(max_records=1, max_replay_entries=1)
        registry.install(introductions[0], services[0], now=now)
        with self.assertRaisesRegex(ResourceLimitError, "record limit"):
            registry.install(introductions[1], services[1], now=now)

        point = introductions[0].points[0]
        nonce = b"a" * 16
        registry.authorize(
            services[0].service_id,
            node_id,
            point.token,
            nonce,
            now=now,
        )
        with self.assertRaises(ReplayError):
            registry.authorize(
                services[0].service_id,
                node_id,
                point.token,
                nonce,
                now=now,
            )
        with self.assertRaisesRegex(ResourceLimitError, "replay state"):
            registry.authorize(
                services[0].service_id,
                node_id,
                point.token,
                b"b" * 16,
                now=now,
            )

    def test_default_observations_do_not_retain_relay_payload(self) -> None:
        payload = b"x" * (2 * 1024 * 1024)
        observations = [
            WanCircuitObservation(index.to_bytes(16, "big"), "middle", "upstream", "downstream")
            for index in range(32)
        ]
        for observation in observations:
            observation.record(payload)
            self.assertEqual(observation.bytes_forwarded, len(payload))
        self.assertEqual(sum(len(observation._sample) for observation in observations), 0)

    def test_explicit_observation_sample_is_bounded(self) -> None:
        observation = WanCircuitObservation(
            b"c" * 16, "middle", "upstream", "downstream", sample_limit=128,
        )
        observation.record(b"marker" + b"x" * 4096)
        self.assertTrue(observation.contains(b"marker"))
        self.assertEqual(len(observation._sample), 128)

    def test_node_initialization_applies_requested_descriptor_lifetime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-node-lifetime-") as temporary:
            descriptor = initialize_node(
                Path(temporary),
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("discovery",),
                RelayPolicy(enabled=False),
                descriptor_lifetime=24 * 60 * 60,
            )
            self.assertEqual(descriptor.expires_at - descriptor.issued_at, 24 * 60 * 60)

    def test_real_listener_rejects_connections_beyond_signed_policy(self) -> None:
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(
                enabled=False,
                max_connections=2,
                connection_timeout_seconds=2,
                max_bandwidth_kib_per_second=64 * 1024,
            ),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-node-limits-") as temporary:
            node = WanNodeServer(identity, descriptor, Path(temporary))
            node.start_background()
            connections: list[socket.socket] = []
            try:
                for _ in range(5):
                    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection.settimeout(2.0)
                    connection.connect(descriptor.endpoint.socket_address)
                    connections.append(connection)
                deadline = time.monotonic() + 3.0
                while node.rejected_connections < 3 and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(node.accepted_connections, 2)
                self.assertGreaterEqual(node.rejected_connections, 3)
            finally:
                for connection in connections:
                    connection.close()
                node.stop()
            self.assertEqual(node.runtime.active_circuits, 0)

    def test_single_source_cannot_consume_every_listener_slot(self) -> None:
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(
                enabled=False,
                max_connections=64,
                connection_timeout_seconds=2,
                max_bandwidth_kib_per_second=64 * 1024,
            ),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-source-connection-limit-") as temporary:
            node = WanNodeServer(identity, descriptor, Path(temporary))
            node.start_background()
            connections: list[socket.socket] = []
            try:
                for _ in range(40):
                    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection.settimeout(2.0)
                    connection.connect(descriptor.endpoint.socket_address)
                    connections.append(connection)
                deadline = time.monotonic() + 3.0
                while node.rejected_connections < 8 and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(node.accepted_connections, 32)
                self.assertGreaterEqual(node.rejected_connections, 8)
                self.assertLessEqual(len(node._active_sources), 1)
            finally:
                for connection in connections:
                    connection.close()
                node.stop()

    def test_partial_handshakes_expire_and_release_capacity_for_a_real_peer(self) -> None:
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(
                enabled=False,
                max_connections=2,
                connection_timeout_seconds=1,
                max_bandwidth_kib_per_second=64 * 1024,
            ),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-partial-handshake-") as temporary:
            node = WanNodeServer(identity, descriptor, Path(temporary))
            stalled: list[socket.socket] = []
            peer = None
            node.start_background()
            try:
                for _ in range(2):
                    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection.settimeout(2.0)
                    connection.connect(descriptor.endpoint.socket_address)
                    connection.sendall(b"\x03")
                    stalled.append(connection)

                deadline = time.monotonic() + 3.0
                while node.accepted_connections < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(node.accepted_connections, 2)

                deadline = time.monotonic() + 3.0
                while node._connections and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(len(node._connections), 0)
                self.assertEqual(len(node._active_sources), 0)

                peer = connect_authenticated_peer(
                    descriptor,
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=2.0,
                )
                response = peer.rpc.request(
                    RpcType.PING,
                    b"legitimate-after-slow-peer",
                    expected=RpcType.PONG,
                )
                self.assertEqual(response.payload, b"legitimate-after-slow-peer")
            finally:
                if peer is not None:
                    peer.close()
                for connection in stalled:
                    connection.close()
                node.stop()

    def test_repeated_start_stop_releases_listener_and_source_state(self) -> None:
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(
                enabled=False,
                max_connections=8,
                connection_timeout_seconds=1,
                max_bandwidth_kib_per_second=64 * 1024,
            ),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-start-stop-storm-") as temporary:
            node = WanNodeServer(identity, descriptor, Path(temporary))
            for iteration in range(8):
                node.start_background()
                peer = connect_authenticated_peer(
                    descriptor,
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=2.0,
                )
                try:
                    marker = f"iteration-{iteration}".encode("ascii")
                    self.assertEqual(
                        peer.rpc.request(
                            RpcType.PING,
                            marker,
                            expected=RpcType.PONG,
                        ).payload,
                        marker,
                    )
                finally:
                    peer.close()
                    node.stop()

                self.assertIsNone(node._listener)
                self.assertIsNone(node._accept_thread)
                self.assertEqual(len(node._connections), 0)
                self.assertEqual(len(node._connection_sources), 0)
                self.assertEqual(len(node._active_sources), 0)
                self.assertEqual(len(node._threads), 0)
                self.assertEqual(node.runtime.active_circuits, 0)
                self.assertEqual(node.descriptor.node_id, descriptor.node_id)

    def test_rpc_source_budget_survives_reconnects_without_storing_raw_ip(self) -> None:
        identity = ServiceIdentity.generate()
        client_identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(enabled=False, max_connections=16),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-rpc-source-limit-") as temporary:
            node = WanNodeServer(
                identity,
                descriptor,
                Path(temporary),
                max_rpc_requests_per_connection=2,
            )
            node._max_rpc_requests_per_source_window = 3
            node.start_background()
            first = connect_authenticated_peer(
                descriptor,
                client_identity,
                PeerRole.CLIENT,
                timeout=2.0,
            )
            try:
                for marker in (b"one", b"two"):
                    self.assertEqual(
                        first.rpc.request(RpcType.PING, marker, expected=RpcType.PONG).payload,
                        marker,
                    )
            finally:
                first.close()
            second = connect_authenticated_peer(
                descriptor,
                client_identity,
                PeerRole.CLIENT,
                timeout=2.0,
            )
            try:
                self.assertEqual(
                    second.rpc.request(RpcType.PING, b"three", expected=RpcType.PONG).payload,
                    b"three",
                )
                with self.assertRaises((ConnectionClosedError, OSError, ProtocolError)):
                    second.rpc.request(RpcType.PING, b"four", expected=RpcType.PONG)
            finally:
                second.close()
                node.stop()
            self.assertEqual(len(node._rpc_source_windows), 1)
            self.assertNotIn(b"127.0.0.1", tuple(node._rpc_source_windows))

    def test_authenticated_connection_closes_at_rpc_request_limit(self) -> None:
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(enabled=False),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-rpc-limit-") as temporary:
            node = WanNodeServer(
                identity,
                descriptor,
                Path(temporary),
                max_rpc_requests_per_connection=2,
            )
            node.start_background()
            peer = connect_authenticated_peer(
                descriptor,
                ServiceIdentity.generate(),
                PeerRole.CLIENT,
                timeout=3.0,
            )
            try:
                for marker in (b"first", b"second"):
                    response = peer.rpc.request(
                        RpcType.PING,
                        marker,
                        expected=RpcType.PONG,
                    )
                    self.assertEqual(response.payload, marker)
                with self.assertRaises((ConnectionClosedError, OSError, ProtocolError)):
                    peer.rpc.request(
                        RpcType.PING,
                        b"overflow",
                        expected=RpcType.PONG,
                    )
                deadline = time.monotonic() + 2.0
                while "ResourceLimitError" not in node.errors and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIn("ResourceLimitError", node.errors)
            finally:
                peer.close()
                node.stop()

    def test_rendezvous_replay_state_is_bounded_without_live_entry_eviction(self) -> None:
        now = int(time.time())
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("rendezvous",),
            RelayPolicy(enabled=True),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-rendezvous-replay-") as temporary:
            node = WanNodeServer(identity, descriptor, Path(temporary))
            node._max_rendezvous_replay_entries = 1
            cookie_tag = b"c" * 32
            slot = SimpleNamespace(
                registration=SimpleNamespace(expires_at=now + 60)
            )
            node._rendezvous_slots[cookie_tag] = slot

            missing = RendezvousJoin(b"m" * 32, b"x" * 16, b"0" * 16)
            self.assertIsNone(node._reserve_rendezvous_join(missing, now))
            self.assertEqual(node._used_rendezvous_joins, {})

            first = RendezvousJoin(cookie_tag, b"a" * 16, b"1" * 16)
            self.assertIs(node._reserve_rendezvous_join(first, now), slot)
            with self.assertRaisesRegex(ProtocolError, "replayed"):
                node._reserve_rendezvous_join(first, now)

            second = RendezvousJoin(cookie_tag, b"b" * 16, b"2" * 16)
            with self.assertRaisesRegex(ResourceLimitError, "replay state"):
                node._reserve_rendezvous_join(second, now)
            self.assertIn((cookie_tag, first.nonce), node._used_rendezvous_joins)

            self.assertIsNone(node._reserve_rendezvous_join(second, now + 60))
            self.assertEqual(node._used_rendezvous_joins, {})

    def test_persistent_dht_store_refuses_record_flood_past_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-record-limit-") as temporary:
            store = PersistentRecordStore(Path(temporary) / "records.json", maximum=1)
            first = ServiceDescriptor.create_remote(
                ServiceIdentity.generate(),
                "first",
                lifetime=600,
            )
            second = ServiceDescriptor.create_remote(
                ServiceIdentity.generate(),
                "second",
                lifetime=600,
            )
            store.store(encode_record(first))
            with self.assertRaisesRegex(DiscoveryError, "full"):
                store.store(encode_record(second))

    def test_expired_dht_records_release_capacity_without_restart(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory(prefix="granger-record-expiry-") as temporary:
            store = PersistentRecordStore(Path(temporary) / "records.json", maximum=1)
            expired = ServiceDescriptor.create_remote(
                ServiceIdentity.generate(),
                "expired",
                issued_at=now,
                lifetime=30,
            )
            fresh = ServiceDescriptor.create_remote(
                ServiceIdentity.generate(),
                "fresh",
                issued_at=now + 31,
                lifetime=30,
            )
            store.store(encode_record(expired, now=now), now=now)
            store.store(encode_record(fresh, now=now + 31), now=now + 31)

            self.assertIsNone(store.fetch("service", expired.service_id, now=now + 31))
            self.assertIsNotNone(store.fetch("service", fresh.service_id, now=now + 31))

    def test_in_memory_known_peers_follow_bounded_persistent_cache(self) -> None:
        identity = ServiceIdentity.generate()
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",),
            RelayPolicy(enabled=False),
            lifetime=600,
        )
        with tempfile.TemporaryDirectory(prefix="granger-known-peer-limit-") as temporary:
            node = WanNodeServer(identity, descriptor, Path(temporary))
            node.peer_cache.maximum = 2
            for _ in range(3):
                peer_identity = ServiceIdentity.generate()
                peer = NodeDescriptor.create(
                    peer_identity,
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    ("discovery",),
                    RelayPolicy(enabled=False),
                    lifetime=600,
                )
                node.add_known_peer(peer)

            self.assertEqual(len(node.peer_cache.load()), 2)
            self.assertLessEqual(len(node._known), 3)
            self.assertIn(descriptor.node_id, node._known)


if __name__ == "__main__":
    unittest.main()
