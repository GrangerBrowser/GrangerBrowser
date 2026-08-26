from __future__ import annotations

import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from granger_network.bootstrap import (
    MAX_CACHE_PEERS_PER_NETWORK_GROUP,
    MAX_CACHE_PEERS_PER_SOURCE,
    BootstrapPool,
    BootstrapSet,
    PeerCache,
)
from granger_network.errors import DiscoveryError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint


class BootstrapResilienceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.authority = ServiceIdentity.generate()

    def descriptor(
        self,
        host: str,
        port: int,
        capabilities: tuple[str, ...] = ("discovery",),
        *,
        network_id: str = "granger-network-v0.4",
    ) -> NodeDescriptor:
        return NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint(host, port),
            capabilities,
            RelayPolicy(),
            issued_at=self.now,
            lifetime=3600,
            network_id=network_id,
        )

    def bootstrap_peers(self) -> list[NodeDescriptor]:
        return [
            self.descriptor(f"203.0.113.{index + 1}", 22000 + index, ("bootstrap", "discovery"))
            for index in range(3)
        ]

    def test_bootstrap_set_binds_network_protocol_and_generation(self) -> None:
        bundle = BootstrapSet.create(
            self.authority,
            [
                self.descriptor(
                    f"203.0.113.{index + 1}",
                    22000 + index,
                    ("bootstrap", "discovery"),
                    network_id="granger-development-v1",
                )
                for index in range(3)
            ],
            network_id="granger-development-v1",
            protocol_version=3,
            generation=7,
            issued_at=self.now,
            lifetime=600,
        )
        parsed = BootstrapSet.from_json(
            bundle.to_json(),
            self.authority.public_key_bytes,
            now=self.now,
            expected_network_id="granger-development-v1",
            expected_protocol_version=3,
        )
        self.assertEqual(parsed.generation, 7)
        with self.assertRaisesRegex(DiscoveryError, "different network"):
            BootstrapSet.from_json(
                bundle.to_json(),
                self.authority.public_key_bytes,
                now=self.now,
                expected_network_id="granger-network-v0.4",
            )

    def test_corrupt_cache_is_ignored_without_becoming_a_network_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "peer-cache.json"
            path.write_text("{not-json", encoding="utf-8")
            cache = PeerCache(path)
            self.assertEqual(cache.load(now=self.now), ())
            self.assertEqual(cache.last_load_error, "JSONDecodeError")

    def test_peer_ingestion_is_bounded_by_source_and_network_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_cache = PeerCache(Path(temporary) / "source.json")
            source_peers = [
                self.descriptor(f"198.18.{index}.1", 23000 + index)
                for index in range(80)
            ]
            self.assertEqual(
                source_cache.ingest(source_peers, source="peer:hostile", now=self.now),
                MAX_CACHE_PEERS_PER_SOURCE,
            )
            self.assertEqual(len(source_cache.load(now=self.now)), MAX_CACHE_PEERS_PER_SOURCE)

            group_cache = PeerCache(Path(temporary) / "group.json")
            group_peers = [
                self.descriptor(f"198.51.100.{index + 1}", 24000 + index)
                for index in range(40)
            ]
            self.assertEqual(
                group_cache.ingest(group_peers, source="peer:group", now=self.now),
                MAX_CACHE_PEERS_PER_NETWORK_GROUP,
            )
            self.assertEqual(len(group_cache.load(now=self.now)), MAX_CACHE_PEERS_PER_NETWORK_GROUP)

    def test_invalid_and_duplicate_endpoint_descriptors_do_not_poison_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = PeerCache(Path(temporary) / "cache.json")
            valid = self.descriptor("203.0.113.70", 25000)
            invalid = replace(valid, signature=b"\x00" * 64)
            duplicate_endpoint = self.descriptor("203.0.113.70", 25000)
            accepted = cache.ingest(
                (invalid, valid, duplicate_endpoint),
                source="peer:sample",
                now=self.now,
            )
            self.assertEqual(accepted, 1)
            self.assertEqual(cache.load(now=self.now), (valid,))

    def test_success_metadata_persists_and_cached_peers_are_tried_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = PeerCache(Path(temporary) / "cache.json")
            cached = self.descriptor("198.51.100.80", 26000)
            cache.add(cached, now=self.now, source="peer:trusted")
            cache.record_success(cached, now=self.now + 1)
            cache.record_failure(cached, now=self.now + 2)
            entry = cache.entries(now=self.now + 2)[0]
            self.assertEqual(entry.successful_connections, 1)
            self.assertEqual(entry.failed_connections, 1)
            self.assertEqual(entry.last_successful_connection, self.now + 1)
            bootstrap = BootstrapSet.create(
                self.authority,
                self.bootstrap_peers(),
                issued_at=self.now,
                lifetime=600,
            )
            pool = BootstrapPool(bootstrap, cache)
            self.assertEqual(pool.candidates("discovery", now=self.now + 2)[0].node_id, cached.node_id)


if __name__ == "__main__":
    unittest.main()
