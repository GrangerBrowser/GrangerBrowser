from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from granger_network.bootstrap import BootstrapPool, BootstrapSet, PeerCache
from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import SERVICE_RECORD, RecordEnvelope, encode_record
from granger_network.errors import DiscoveryError, ProtocolError, ResolutionError
from granger_network.identity import ServiceIdentity
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType, connect_authenticated_peer
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_discovery import WanDiscoveryClient, encode_record_envelope
from granger_network.network_health import NetworkState


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-dht-")
        self.root = Path(self.temporary.name)
        self.now = int(time.time())
        self.authority = ServiceIdentity.generate()
        self.identities = [ServiceIdentity.generate() for _ in range(6)]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("access", "bootstrap", "discovery", "entry", "middle"),
                RelayPolicy(enabled=True, max_bandwidth_kib_per_second=64 * 1024),
                issued_at=self.now,
                lifetime=3600,
            )
            for identity in self.identities
        ]
        self.nodes = [
            WanNodeServer(
                identity,
                descriptor,
                self.root / f"node-{index}",
                known_peers=self.descriptors,
            )
            for index, (identity, descriptor) in enumerate(
                zip(self.identities, self.descriptors, strict=True)
            )
        ]
        for node in self.nodes:
            node.start_background()
        self.bootstrap = BootstrapSet.create(
            self.authority,
            self.descriptors,
            issued_at=self.now,
            lifetime=1800,
        )
        self.cache = PeerCache(self.root / "client-peers.json")
        self.client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(self.bootstrap, self.cache),
            cache=self.cache,
            timeout=2.0,
        )

    def tearDown(self) -> None:
        for node in self.nodes:
            node.stop()
        self.temporary.cleanup()

    def test_signed_record_replication_and_lookup_use_real_authenticated_sockets(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-overlay",
            issued_at=self.now,
            lifetime=1800,
        )
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
            patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
            patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS used")) as gethostbyname_ex,
        ):
            self.assertEqual(self.client.publish(service, now=self.now), 3)
            resolved = self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now)
        self.assertEqual(resolved, service)
        self.assertEqual(getaddrinfo.call_count, 0)
        self.assertEqual(gethostbyname.call_count, 0)
        self.assertEqual(gethostbyname_ex.call_count, 0)
        self.assertTrue(all(node.accepted_connections > 0 for node in self.nodes))
        self.assertTrue(all(node.rpc_requests > 0 for node in self.nodes))
        self.assertEqual(len(self.cache.load(now=self.now)), 6)
        health = self.client.health()
        self.assertEqual(health.state, NetworkState.CONNECTED)
        self.assertTrue(health.dht_ready)
        self.assertGreaterEqual(health.authenticated_peers, 2)

    def test_discovery_batch_workers_do_not_block_process_shutdown(self) -> None:
        daemon_states: list[bool] = []

        def request(*_args, **_kwargs) -> bytes:
            daemon_states.append(threading.current_thread().daemon)
            return b"response"

        with patch.object(self.client, "_request", side_effect=request):
            results = self.client._request_batch(
                list(self.descriptors[:3]),
                RpcType.FIND_NODE,
                b"request",
                RpcType.FIND_NODE,
            )
        self.assertEqual([content for _peer, content in results], [b"response"] * 3)
        self.assertEqual(daemon_states, [True] * 3)

    def test_one_bootstrap_failure_keeps_quorum_and_two_failures_close_route(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-failure",
            issued_at=self.now,
            lifetime=1800,
        )
        self.client.publish(service, now=self.now)
        replica_indexes = [
            index
            for index, node in enumerate(self.nodes)
            if node.records.fetch(SERVICE_RECORD, service.service_id) is not None
        ]
        self.assertEqual(len(replica_indexes), 3)
        self.nodes[replica_indexes[0]].stop()
        self.assertEqual(
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now),
            service,
        )
        self.nodes[replica_indexes[1]].stop()
        with self.assertRaises(ResolutionError):
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now)

    def test_unreachable_cache_entries_cannot_mask_signed_bootstrap_seeds(self) -> None:
        stale = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("discovery",),
                RelayPolicy(enabled=False),
                issued_at=self.now,
                lifetime=3600,
            )
            for _ in range(8)
        ]
        self.cache.ingest(stale, source="peer:stale", now=self.now)
        client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(self.bootstrap, self.cache),
            cache=self.cache,
            timeout=0.25,
        )
        health = client.join_network()
        self.assertEqual(health.state, NetworkState.JOINING)
        self.assertGreaterEqual(health.bootstrap_attempted, 2)
        self.assertGreaterEqual(health.authenticated_peers, 2)

    def test_private_discovery_retries_cover_guard_middle_pairs(self) -> None:
        role_nodes: dict[str, list[NodeDescriptor]] = {
            "access": [],
            "entry": [],
            "middle": [],
        }
        port = 45000
        for role in role_nodes:
            for index in range(2):
                role_nodes[role].append(
                    NodeDescriptor.create(
                        ServiceIdentity.generate(),
                        RendezvousEndpoint(f"127.{port - 44999}.0.{index + 1}", port),
                        ("bootstrap", role),
                        RelayPolicy(enabled=True),
                        issued_at=self.now,
                        lifetime=3600,
                    )
                )
                port += 1
        peer = NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint("127.7.0.1", port),
            ("bootstrap", "discovery"),
            RelayPolicy(enabled=True),
            issued_at=self.now,
            lifetime=3600,
        )
        bootstrap = BootstrapSet.create(
            self.authority,
            [node for nodes in role_nodes.values() for node in nodes] + [peer],
            issued_at=self.now,
            lifetime=1800,
        )
        client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(bootstrap, PeerCache(self.root / "route-peers.json")),
            timeout=0.1,
        )

        routes = client._private_route_candidates(peer, limit=4)
        self.assertEqual(len(routes), 4)
        self.assertEqual(
            {
                (route[1][0].node_id, route[2][0].node_id)
                for route in routes
            },
            {
                (guard.node_id, middle.node_id)
                for guard in role_nodes["entry"]
                for middle in role_nodes["middle"]
            },
        )
        for failed_guard in role_nodes["entry"]:
            for failed_middle in role_nodes["middle"]:
                self.assertTrue(
                    any(
                        route[1][0].node_id != failed_guard.node_id
                        and route[2][0].node_id != failed_middle.node_id
                        for route in routes
                    )
                )

    def test_malformed_signed_record_is_rejected_by_remote_store(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-poison",
            issued_at=self.now,
            lifetime=1800,
        )
        envelope = encode_record(service, now=self.now)
        document = json.loads(envelope.payload)
        document["serviceId"] = "a" * 52
        poisoned = RecordEnvelope(
            envelope.kind,
            envelope.key,
            envelope.sequence,
            envelope.expires_at,
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii"),
        )
        peer = connect_authenticated_peer(
            self.descriptors[0],
            ServiceIdentity.generate(),
            PeerRole.CLIENT,
            timeout=2.0,
        )
        try:
            with self.assertRaises(ProtocolError):
                peer.rpc.request(
                    RpcType.STORE_RECORD,
                    encode_record_envelope(poisoned),
                    expected=RpcType.STORE_RECORD,
                )
        finally:
            peer.close()
        self.assertIsNone(self.nodes[0].records.fetch(SERVICE_RECORD, service.service_id))

    def test_persistent_store_survives_node_restart(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-persist",
            issued_at=self.now,
            lifetime=1800,
        )
        self.client.publish(service, now=self.now)
        stored_index = next(
            index
            for index, node in enumerate(self.nodes)
            if node.records.fetch(SERVICE_RECORD, service.service_id) is not None
        )
        first = self.nodes[stored_index]
        first.stop()
        replacement = WanNodeServer(
            self.identities[stored_index],
            self.descriptors[stored_index],
            self.root / f"node-{stored_index}",
            known_peers=self.descriptors,
        )
        self.nodes[stored_index] = replacement
        self.assertEqual(
            replacement.records.fetch(SERVICE_RECORD, service.service_id),
            encode_record(service, now=self.now),
        )
        replacement.start_background()
        self.assertEqual(
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now),
            service,
        )


if __name__ == "__main__":
    unittest.main()
