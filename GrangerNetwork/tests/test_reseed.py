from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from granger_network.bootstrap import BootstrapSet
from granger_network.errors import DiscoveryError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.reseed import ReseedStore
from granger_network.transport import RendezvousEndpoint


class ReseedStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-reseed-")
        self.root = Path(self.temporary.name)
        self.now = int(time.time())
        self.authority = ServiceIdentity.generate()
        self.peers = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint(f"203.0.113.{index + 1}", 27000 + index),
                ("bootstrap", "discovery"),
                RelayPolicy(),
                issued_at=self.now,
                lifetime=3600,
            )
            for index in range(3)
        ]
        self.store = ReseedStore(self.root / "store", (self.authority.public_key_bytes,))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def bundle(self, generation: int, *, lifetime: int = 1800) -> BootstrapSet:
        return BootstrapSet.create(
            self.authority,
            self.peers,
            generation=generation,
            issued_at=self.now,
            lifetime=lifetime,
        )

    def test_import_is_atomic_idempotent_and_rotates_forward(self) -> None:
        first_bundle = self.bundle(1)
        first = self.store.import_content(first_bundle.to_json(), now=self.now)
        reformatted = json.dumps(json.loads(first_bundle.to_json()), separators=(",", ":"))
        repeated = self.store.import_content(reformatted, now=self.now)
        second = self.store.import_content(self.bundle(2).to_json(), now=self.now)
        self.assertTrue(first.installed)
        self.assertFalse(repeated.installed)
        self.assertTrue(second.installed)
        self.assertEqual(self.store.load_active(now=self.now)[0].generation, 2)
        self.assertEqual(self.store.diagnostics(now=self.now)["activeAuthorities"], 1)

    def test_rollback_and_same_generation_equivocation_are_rejected(self) -> None:
        self.store.import_content(self.bundle(2).to_json(), now=self.now)
        with self.assertRaisesRegex(DiscoveryError, "rollback"):
            self.store.import_content(self.bundle(1).to_json(), now=self.now)
        replacement_peers = list(self.peers)
        replacement_peers[-1] = NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint("198.51.100.99", 27999),
            ("bootstrap", "discovery"),
            RelayPolicy(),
            issued_at=self.now,
            lifetime=3600,
        )
        equivocation = BootstrapSet.create(
            self.authority,
            replacement_peers,
            generation=2,
            issued_at=self.now,
            lifetime=1800,
        )
        with self.assertRaisesRegex(DiscoveryError, "equivocation"):
            self.store.import_content(equivocation.to_json(), now=self.now)

    def test_wrong_authority_network_and_expired_sets_fail_closed(self) -> None:
        other = ServiceIdentity.generate()
        untrusted = BootstrapSet.create(
            other,
            self.peers,
            generation=1,
            issued_at=self.now,
            lifetime=600,
        )
        with self.assertRaisesRegex(DiscoveryError, "not trusted"):
            self.store.import_content(untrusted.to_json(), now=self.now)
        development_peers = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint(f"198.51.100.{index + 1}", 28000 + index),
                ("bootstrap", "discovery"),
                RelayPolicy(),
                issued_at=self.now,
                lifetime=3600,
                network_id="granger-development-v1",
            )
            for index in range(3)
        ]
        wrong_network = BootstrapSet.create(
            self.authority,
            development_peers,
            network_id="granger-development-v1",
            generation=1,
            issued_at=self.now,
            lifetime=600,
        )
        with self.assertRaisesRegex(DiscoveryError, "different network"):
            self.store.import_content(wrong_network.to_json(), now=self.now)
        self.store.import_content(self.bundle(1, lifetime=60).to_json(), now=self.now)
        self.assertEqual(self.store.load_active(now=self.now + 61), ())

    def test_multiple_trusted_authorities_and_export_are_supported(self) -> None:
        second_authority = ServiceIdentity.generate()
        second_bundle = BootstrapSet.create(
            second_authority,
            self.peers,
            generation=3,
            issued_at=self.now,
            lifetime=600,
        )
        store = ReseedStore(
            self.root / "multi",
            (self.authority.public_key_bytes, second_authority.public_key_bytes),
        )
        store.import_content(self.bundle(2).to_json(), source="bundled", now=self.now)
        store.import_content(second_bundle.to_json(), source="manual", now=self.now)
        self.assertEqual(len(store.load_active(now=self.now)), 2)
        exported = store.export_active(self.root / "export", now=self.now)
        self.assertEqual(len(exported), 2)
        self.assertTrue(all(path.is_file() for path in exported))


if __name__ == "__main__":
    unittest.main()
