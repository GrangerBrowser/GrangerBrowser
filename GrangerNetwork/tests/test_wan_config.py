from __future__ import annotations

import concurrent.futures
import json
import tempfile
import time
import unittest
from pathlib import Path

from granger_network.bootstrap import BootstrapSet
from granger_network.errors import DiscoveryError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_config import (
    SIGNED_CONFIG_NETWORK_ID,
    ensure_browser_wan_config,
    load_browser_wan_config,
    write_bootstrap_bundle,
    write_signed_browser_wan_config,
)


class SignedWanConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = int(time.time())
        self.bootstrap_authority = ServiceIdentity.generate()
        peers = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint("127.0.0.1", 28000 + index),
                ("bootstrap", "discovery"),
                RelayPolicy(),
                issued_at=self.now,
                lifetime=3600,
            )
            for index in range(3)
        ]
        bootstrap = BootstrapSet.create(
            self.bootstrap_authority,
            peers,
            issued_at=self.now,
            lifetime=3600,
        )
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.bootstrap_path = self.bundle / "bootstrap-set.json"
        self.bootstrap_pin_path = self.bundle / "bootstrap-authority.pin"
        write_bootstrap_bundle(
            bootstrap,
            self.bootstrap_path,
            self.bootstrap_pin_path,
        )
        self.config_authority = ServiceIdentity.generate()
        self.config_path = self.bundle / "browser-wan.json"
        self.trust_anchor = self.bundle / "config-authority.pin"
        self.install_root = self.root / "installed"
        self.rollback_state = self.root / "state" / "wan-rollback.json"
        self.write_config(1)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, generation: int, **policy: object) -> None:
        write_signed_browser_wan_config(
            self.config_path,
            self.config_authority,
            self.bootstrap_path,
            self.bootstrap_pin_path,
            generation=generation,
            issued_at=self.now,
            expires_at=self.now + 3500,
            **policy,
        )

    def test_signed_config_verifies_schema_protocol_files_and_signature(self) -> None:
        config = load_browser_wan_config(
            self.config_path,
            trust_anchor_path=self.trust_anchor,
            now=self.now,
            allow_legacy=False,
        )
        self.assertEqual(config.version, 2)
        self.assertEqual(config.network_id, SIGNED_CONFIG_NETWORK_ID)
        self.assertEqual(config.protocol_version, 3)
        self.assertEqual(config.generation, 1)
        self.assertEqual(config.bootstrap_path, self.bootstrap_path)
        self.assertEqual(config.authority_pin_path, self.bootstrap_pin_path)

    def test_unsigned_config_is_rejected_in_packaged_mode(self) -> None:
        legacy = self.bundle / "legacy.json"
        legacy.write_text(
            json.dumps(
                {
                    "aliasPins": {},
                    "authorityPin": self.bootstrap_pin_path.name,
                    "bootstrap": self.bootstrap_path.name,
                    "minimumReplicas": 2,
                    "replicationFactor": 3,
                    "routeAttempts": 3,
                    "timeoutSeconds": 5,
                    "version": 1,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(DiscoveryError, "unsigned"):
            load_browser_wan_config(
                legacy,
                trust_anchor_path=self.trust_anchor,
                now=self.now,
                allow_legacy=False,
            )
        self.assertEqual(load_browser_wan_config(legacy).version, 1)

    def test_tampered_config_and_bootstrap_are_rejected(self) -> None:
        document = json.loads(self.config_path.read_text(encoding="utf-8"))
        document["routeAttempts"] = 5
        self.config_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(DiscoveryError, "signature"):
            load_browser_wan_config(
                self.config_path,
                trust_anchor_path=self.trust_anchor,
                now=self.now,
                allow_legacy=False,
            )

        self.write_config(1)
        self.bootstrap_path.write_bytes(self.bootstrap_path.read_bytes() + b" ")
        with self.assertRaisesRegex(DiscoveryError, "digest"):
            load_browser_wan_config(
                self.config_path,
                trust_anchor_path=self.trust_anchor,
                now=self.now,
                allow_legacy=False,
            )

    def test_expired_config_is_rejected(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "currently valid"):
            load_browser_wan_config(
                self.config_path,
                trust_anchor_path=self.trust_anchor,
                now=self.now + 3500,
                allow_legacy=False,
            )

    def test_missing_config_is_provisioned_atomically_and_idempotently(self) -> None:
        installed = ensure_browser_wan_config(
            self.config_path,
            self.trust_anchor,
            self.install_root,
            self.rollback_state,
            now=self.now,
        )
        self.assertTrue(installed.is_file())
        self.assertTrue((self.install_root / "active.json").is_file())
        self.assertTrue(self.rollback_state.is_file())
        self.assertEqual(
            installed,
            ensure_browser_wan_config(
                self.config_path,
                self.trust_anchor,
                self.install_root,
                self.rollback_state,
                now=self.now,
            ),
        )
        self.assertFalse(any(self.install_root.rglob("*private*")))

    def test_tampered_installed_config_is_rejected_without_silent_repair(self) -> None:
        installed = ensure_browser_wan_config(
            self.config_path,
            self.trust_anchor,
            self.install_root,
            self.rollback_state,
            now=self.now,
        )
        document = json.loads(installed.read_text(encoding="utf-8"))
        document["timeoutSeconds"] = 4
        installed.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(DiscoveryError):
            ensure_browser_wan_config(
                self.config_path,
                self.trust_anchor,
                self.install_root,
                self.rollback_state,
                now=self.now,
            )

    def test_older_generation_and_same_generation_equivocation_are_rejected(self) -> None:
        self.write_config(2)
        ensure_browser_wan_config(
            self.config_path,
            self.trust_anchor,
            self.install_root,
            self.rollback_state,
            now=self.now,
        )
        self.write_config(1)
        with self.assertRaisesRegex(DiscoveryError, "rollback"):
            ensure_browser_wan_config(
                self.config_path,
                self.trust_anchor,
                self.install_root,
                self.rollback_state,
                now=self.now,
            )

        self.write_config(2, timeout_seconds=7.0)
        with self.assertRaisesRegex(DiscoveryError, "equivocation"):
            ensure_browser_wan_config(
                self.config_path,
                self.trust_anchor,
                self.install_root,
                self.rollback_state,
                now=self.now,
            )

    def test_newer_generation_replaces_active_config_and_prunes_old_bundle(self) -> None:
        first = ensure_browser_wan_config(
            self.config_path,
            self.trust_anchor,
            self.install_root,
            self.rollback_state,
            now=self.now,
        )
        self.write_config(2, timeout_seconds=7.0)
        second = ensure_browser_wan_config(
            self.config_path,
            self.trust_anchor,
            self.install_root,
            self.rollback_state,
            now=self.now,
        )
        self.assertNotEqual(first, second)
        self.assertFalse(first.exists())
        self.assertEqual(
            load_browser_wan_config(
                second,
                trust_anchor_path=self.trust_anchor,
                rollback_state_path=self.rollback_state,
                now=self.now,
                allow_legacy=False,
            ).generation,
            2,
        )

    def test_concurrent_first_start_converges_on_one_active_config(self) -> None:
        def provision() -> Path:
            return ensure_browser_wan_config(
                self.config_path,
                self.trust_anchor,
                self.install_root,
                self.rollback_state,
                now=self.now,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            paths = list(executor.map(lambda _index: provision(), range(12)))
        self.assertEqual(len(set(paths)), 1)
        self.assertEqual(len(list((self.install_root / "bundles").iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
