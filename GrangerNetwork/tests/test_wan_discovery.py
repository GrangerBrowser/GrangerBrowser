from __future__ import annotations

import json
import socket
import tempfile
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
        self.identities = [ServiceIdentity.generate() for _ in range(3)]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("bootstrap", "discovery"),
                RelayPolicy(enabled=False, max_bandwidth_kib_per_second=64 * 1024),
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
        bootstrap = BootstrapSet.create(
            self.authority,
            self.descriptors,
            issued_at=self.now,
            lifetime=1800,
        )
        self.cache = PeerCache(self.root / "client-peers.json")
        self.client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(bootstrap, self.cache),
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
        self.assertEqual(len(self.cache.load(now=self.now)), 3)

    def test_one_bootstrap_failure_keeps_quorum_and_two_failures_close_route(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-failure",
            issued_at=self.now,
            lifetime=1800,
        )
        self.client.publish(service, now=self.now)
        self.nodes[0].stop()
        self.assertEqual(
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now),
            service,
        )
        self.nodes[1].stop()
        with self.assertRaises(ResolutionError):
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now)

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
        first = self.nodes[0]
        first.stop()
        replacement = WanNodeServer(
            self.identities[0],
            self.descriptors[0],
            self.root / "node-0",
            known_peers=self.descriptors,
        )
        self.nodes[0] = replacement
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
