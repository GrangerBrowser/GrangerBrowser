from __future__ import annotations

import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from granger_network._codec import encode_base64url
from granger_network.bootstrap import BootstrapSet, CachedPeerPool, PeerCache
from granger_network.errors import DiscoveryError, ProtocolError
from granger_network.identity import ServiceIdentity
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.reseed import (
    ReseedAdvertisement,
    ReseedStore,
    decode_reseed_advertisements,
    decode_reseed_chunk_request,
    decode_reseed_chunk_response,
    encode_reseed_advertisements,
    encode_reseed_chunk_request,
    encode_reseed_chunk_response,
)
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_discovery import WanDiscoveryClient
from granger_network.wan_config import load_discovery_runtime


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

    @staticmethod
    def _free_port() -> int:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])

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

    def test_transport_metadata_is_verified_before_high_water_changes(self) -> None:
        self.store.import_content(self.bundle(1).to_json(), now=self.now)
        bundle = self.bundle(2)
        advertisement = ReseedAdvertisement(
            bundle.authority_public_key, bundle.generation, bundle.sha256,
            bundle.expires_at, len(bundle.to_json().encode("ascii")),
        )
        for changes in (
            {"generation": 3}, {"sha256": "0" * 64},
            {"authority_public_key": ServiceIdentity.generate().public_key_bytes},
            {"expires_at": bundle.expires_at + 1}, {"size": advertisement.size + 1},
        ):
            with self.subTest(field=next(iter(changes))):
                with self.assertRaisesRegex(DiscoveryError, "signed bundle metadata"):
                    self.store.import_content(
                        bundle.to_json(), now=self.now,
                        expected_advertisement=replace(advertisement, **changes),
                    )
                self.assertEqual(self.store.load_active(now=self.now)[0].generation, 1)
                self.assertEqual(len(tuple(self.store.bundles_root.glob("*.json"))), 1)
        self.assertTrue(self.store.import_content(
            bundle.to_json(), now=self.now, expected_advertisement=advertisement,
        ).installed)

    def test_transport_rejects_tiny_chunks_without_unbounded_requests(self) -> None:
        bundle = self.bundle(1)
        advertisement = ReseedAdvertisement(
            bundle.authority_public_key, bundle.generation, bundle.sha256,
            bundle.expires_at, len(bundle.to_json().encode("ascii")),
        )
        cache = PeerCache(self.root / "chunk-peers.json")
        client = WanDiscoveryClient(
            ServiceIdentity.generate(), CachedPeerPool(cache), cache=cache,
            reseed_store=self.store,
        )
        payload = encode_reseed_chunk_response(
            advertisement.sha256, 0, advertisement.size, b"{",
        )
        with patch.object(client, "_request", return_value=payload) as request:
            with self.assertRaisesRegex(ProtocolError, "advertisement"):
                client._fetch_reseed_advertisement(
                    self.peers[0], advertisement, direct_first_contact=True,
                )
        self.assertEqual(request.call_count, 1)
        self.assertEqual(self.store.high_water_marks(), {})

    def test_refresh_precedes_embedded_descriptor_expiry(self) -> None:
        self.store.import_content(self.bundle(1, lifetime=7200).to_json(), now=self.now)
        cache = PeerCache(self.root / "expiry-peers.json")
        client = WanDiscoveryClient(
            ServiceIdentity.generate(), CachedPeerPool(cache), cache=cache,
            reseed_store=self.store,
        )
        with patch("granger_network.wan_discovery.time.time", return_value=self.now + 2800):
            with patch.object(client, "refresh_reseed", return_value=1) as refresh:
                self.assertEqual(client.maybe_refresh_reseed(), 1)
                refresh.assert_called_once()

    def test_reimport_repairs_missing_or_corrupt_accepted_bundle(self) -> None:
        bundle = self.bundle(1)
        imported = self.store.import_content(bundle.to_json(), now=self.now)
        destination = next(self.store.bundles_root.glob("*.json"))

        destination.write_text("corrupt", encoding="ascii")
        repaired = self.store.import_content(bundle.to_json(), now=self.now)
        self.assertFalse(repaired.installed)
        self.assertEqual(repaired.sha256, imported.sha256)
        self.assertEqual(self.store.load_active(now=self.now), (bundle,))

        destination.unlink()
        restored = self.store.import_content(bundle.to_json(), now=self.now)
        self.assertFalse(restored.installed)
        self.assertTrue(destination.is_file())
        self.assertEqual(self.store.load_active(now=self.now), (bundle,))

    def test_two_valid_generations_overlap_then_old_generation_expires(self) -> None:
        old = self.bundle(1, lifetime=60)
        newer = BootstrapSet.create(
            self.authority,
            self.peers,
            generation=2,
            issued_at=self.now + 30,
            lifetime=300,
        )
        self.store.import_content(old.to_json(), now=self.now)
        self.store.import_content(newer.to_json(), now=self.now + 30)

        self.assertEqual(
            [bundle.generation for bundle in self.store.load_active(now=self.now + 30)],
            [2, 1],
        )
        self.assertEqual(
            [bundle.generation for bundle in self.store.load_active(now=self.now + 61)],
            [2],
        )
        self.assertEqual(
            self.store.high_water_marks()[self.authority.public_key_bytes][0],
            2,
        )

    def test_expired_high_water_generation_never_falls_back_to_older_bundle(self) -> None:
        old = self.bundle(1, lifetime=1200)
        newer = BootstrapSet.create(
            self.authority,
            self.peers,
            generation=2,
            issued_at=self.now + 10,
            lifetime=60,
        )
        self.store.import_content(old.to_json(), now=self.now)
        self.store.import_content(newer.to_json(), now=self.now + 10)
        self.assertEqual(
            [bundle.generation for bundle in self.store.load_active(now=self.now + 10)],
            [2, 1],
        )
        self.assertEqual(self.store.load_active(now=self.now + 71), ())

    def test_failed_state_commit_keeps_previous_complete_generation(self) -> None:
        first = self.bundle(1)
        second = self.bundle(2)
        self.store.import_content(first.to_json(), now=self.now)
        from granger_network import reseed as reseed_module

        real_atomic_write = reseed_module.atomic_write_text

        def fail_state(path: Path, content: str, mode: int = 0o600) -> None:
            if Path(path) == self.store.state_path:
                raise OSError("simulated state commit failure")
            real_atomic_write(path, content, mode)

        with patch("granger_network.reseed.atomic_write_text", side_effect=fail_state):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.store.import_content(second.to_json(), now=self.now)

        restarted = ReseedStore(
            self.store.root,
            (self.authority.public_key_bytes,),
        )
        self.assertEqual(restarted.load_active(now=self.now)[0].generation, 1)
        self.assertEqual(
            restarted.high_water_marks()[self.authority.public_key_bytes][0],
            1,
        )

    def test_clock_skew_policy_is_bounded(self) -> None:
        within_skew = BootstrapSet.create(
            self.authority,
            self.peers,
            generation=1,
            issued_at=self.now + 120,
            lifetime=600,
        )
        outside_skew = BootstrapSet.create(
            self.authority,
            self.peers,
            generation=2,
            issued_at=self.now + 121,
            lifetime=600,
        )
        self.store.import_content(within_skew.to_json(), now=self.now)
        with self.assertRaisesRegex(DiscoveryError, "currently valid"):
            self.store.import_content(outside_skew.to_json(), now=self.now)

    def test_reseed_transport_codecs_are_bounded_and_canonical(self) -> None:
        advertisement = ReseedAdvertisement(
            self.authority.public_key_bytes,
            7,
            "ab" * 32,
            self.now + 600,
            1234,
        )
        self.assertEqual(
            decode_reseed_advertisements(
                encode_reseed_advertisements((advertisement,))
            ),
            (advertisement,),
        )
        request = encode_reseed_chunk_request(advertisement.sha256, 128)
        self.assertEqual(decode_reseed_chunk_request(request), (advertisement.sha256, 128))
        response = encode_reseed_chunk_response(
            advertisement.sha256,
            128,
            256,
            b"x" * 128,
        )
        self.assertEqual(
            decode_reseed_chunk_response(response),
            (advertisement.sha256, 128, 256, b"x" * 128),
        )
        with self.assertRaises(ProtocolError):
            decode_reseed_chunk_response(response + b"x")

    def test_authenticated_peer_transports_new_generation_without_becoming_authority(self) -> None:
        port = self._free_port()
        server_identity = ServiceIdentity.generate()
        server_descriptor = NodeDescriptor.create(
            server_identity,
            RendezvousEndpoint("127.0.0.1", port),
            ("bootstrap", "discovery"),
            RelayPolicy(),
            issued_at=self.now,
            lifetime=3600,
        )
        second_peer = NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint("127.0.0.1", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(),
            issued_at=self.now,
            lifetime=3600,
        )
        peers = (server_descriptor, second_peer)
        first = BootstrapSet.create(
            self.authority,
            peers,
            generation=1,
            issued_at=self.now,
            lifetime=600,
        )
        second = BootstrapSet.create(
            self.authority,
            peers,
            generation=2,
            issued_at=self.now,
            lifetime=1200,
        )
        source_store = ReseedStore(
            self.root / "source-store",
            (self.authority.public_key_bytes,),
        )
        source_store.import_content(first.to_json(), now=self.now)
        source_store.import_content(second.to_json(), now=self.now)
        destination_store = ReseedStore(
            self.root / "destination-store",
            (self.authority.public_key_bytes,),
        )
        destination_store.import_content(first.to_json(), now=self.now)
        cache = PeerCache(self.root / "client-cache.json")
        cache.add(server_descriptor, now=self.now, source="authenticated-peer")
        cache.record_success(server_descriptor, now=self.now)
        server = WanNodeServer(
            server_identity,
            server_descriptor,
            self.root / "server",
            reseed_store=source_store,
        )
        server.start_background()
        try:
            discovery = WanDiscoveryClient(
                ServiceIdentity.generate(),
                CachedPeerPool(cache),
                cache=cache,
                reseed_store=destination_store,
                timeout=1.0,
            )
            self.assertEqual(
                discovery.refresh_reseed(direct_first_contact=True),
                1,
            )
            self.assertEqual(
                [
                    bundle.generation
                    for bundle in destination_store.load_active(now=self.now)
                ],
                [2, 1],
            )
            self.assertEqual(
                destination_store.high_water_marks()[self.authority.public_key_bytes],
                (2, second.sha256),
            )
        finally:
            server.stop()

    def test_offline_client_recovers_across_expiry_from_authenticated_peer_cache(self) -> None:
        port = self._free_port()
        server_identity = ServiceIdentity.generate()
        server_descriptor = NodeDescriptor.create(
            server_identity,
            RendezvousEndpoint("127.0.0.1", port),
            ("bootstrap", "discovery"),
            RelayPolicy(),
            issued_at=self.now - 120,
            lifetime=3600,
        )
        second_peer = NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint("127.0.0.1", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(),
            issued_at=self.now - 120,
            lifetime=3600,
        )
        expired = BootstrapSet.create(
            self.authority,
            (server_descriptor, second_peer),
            generation=1,
            issued_at=self.now - 120,
            lifetime=60,
        )
        current = BootstrapSet.create(
            self.authority,
            (server_descriptor, second_peer),
            generation=2,
            issued_at=self.now,
            lifetime=1200,
        )
        source_store = ReseedStore(
            self.root / "wake-source",
            (self.authority.public_key_bytes,),
        )
        source_store.import_content(current.to_json(), now=self.now)
        server = WanNodeServer(
            server_identity,
            server_descriptor,
            self.root / "wake-server",
            reseed_store=source_store,
        )
        state = self.root / "wake-client"
        cache_path = state / "peer-cache.json"
        cache = PeerCache(cache_path)
        cache.add(server_descriptor, now=self.now - 30, source="authenticated-peer")
        cache.record_success(server_descriptor, now=self.now - 30)
        client_store = ReseedStore(
            state / "reseed",
            (self.authority.public_key_bytes,),
        )
        client_store.import_content(expired.to_json(), now=self.now - 120)
        bootstrap_path = state / "bootstrap.json"
        pin_path = state / "authority.pin"
        bootstrap_path.write_text(expired.to_json(), encoding="ascii")
        pin_path.write_text(
            encode_base64url(self.authority.public_key_bytes) + "\n",
            encoding="ascii",
        )
        identity_path = state / "client-identity.json"
        persistent_identity = ServiceIdentity.generate()
        persistent_identity.save(identity_path)

        with self.assertRaises(DiscoveryError):
            load_discovery_runtime(
                bootstrap_path,
                pin_path,
                cache_path,
                identity_path,
                timeout=1.0,
            )
        self.assertEqual(
            ServiceIdentity.load(identity_path).public_key_bytes,
            persistent_identity.public_key_bytes,
        )

        server.start_background()
        try:
            runtime = load_discovery_runtime(
                bootstrap_path,
                pin_path,
                cache_path,
                identity_path,
                timeout=1.0,
            )
            self.assertEqual(runtime.bootstrap.generation, 2)
            self.assertEqual(runtime.reseed.high_water_marks()[self.authority.public_key_bytes][0], 2)
            self.assertEqual(
                runtime.identity.public_key_bytes,
                persistent_identity.public_key_bytes,
            )
        finally:
            server.stop()

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

    def test_only_exact_previously_installed_expired_bundle_is_recognized(self) -> None:
        bundle = self.bundle(1, lifetime=60)
        source = self.root / "bootstrap.json"
        source.write_text(bundle.to_json(), encoding="utf-8")
        installed = self.store.import_path(source, now=self.now)

        expired = self.store.expired_installed_bundle(source, now=self.now + 61)
        self.assertIsNotNone(expired)
        assert expired is not None
        self.assertEqual(expired.sha256, installed.sha256)
        self.assertFalse(expired.installed)
        self.assertEqual(self.store.load_active(now=self.now + 61), ())

        changed = json.loads(bundle.to_json())
        changed["expiresAt"] += 1
        source.write_text(json.dumps(changed), encoding="utf-8")
        self.assertIsNone(
            self.store.expired_installed_bundle(source, now=self.now + 61)
        )
        with self.assertRaisesRegex(DiscoveryError, "not trusted"):
            self.store.import_path(source, now=self.now + 61)

    def test_installed_bundle_with_expired_embedded_descriptor_is_inactive(self) -> None:
        short_lived_peers = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint(f"198.51.100.{index + 10}", 28100 + index),
                ("bootstrap", "discovery"),
                RelayPolicy(),
                issued_at=self.now,
                lifetime=30,
            )
            for index in range(3)
        ]
        bundle = BootstrapSet.create(
            self.authority,
            short_lived_peers,
            generation=1,
            issued_at=self.now,
            lifetime=300,
        )
        source = self.root / "short-descriptor-bootstrap.json"
        source.write_text(bundle.to_json(), encoding="utf-8")
        self.store.import_path(source, now=self.now)

        self.assertIsNotNone(
            self.store.expired_installed_bundle(source, now=self.now + 31)
        )
        self.assertEqual(self.store.load_active(now=self.now + 31), ())

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
