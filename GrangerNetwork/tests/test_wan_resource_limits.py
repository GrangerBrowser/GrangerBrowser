from __future__ import annotations

import socket
import tempfile
import time
import unittest
from pathlib import Path

from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import encode_record
from granger_network.errors import DiscoveryError
from granger_network.identity import ServiceIdentity
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_discovery import PersistentRecordStore


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanResourceLimitTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
