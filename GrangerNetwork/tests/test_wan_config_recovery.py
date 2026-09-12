from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from pathlib import Path
from unittest import mock

from granger_network._codec import canonical_json, decode_base64url, encode_base64url
from granger_network.bootstrap import BootstrapSet
from granger_network.errors import DiscoveryError, ProtocolError
from granger_network.identity import ServiceIdentity
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType, connect_authenticated_peer, connect_config_recovery
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_config import (
    SIGNED_CONFIG_SIGNATURE_DOMAIN, ensure_browser_wan_config, load_browser_wan_config,
    write_signed_browser_wan_config,
)
from granger_network.wan_config_recovery import WanConfigPublisher, WanConfigRecovery, export_public_config


class WanConfigRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.now = int(time.time())
        self.authority = ServiceIdentity.generate()
        self.config_authority = ServiceIdentity.generate()
        self.node_identity = ServiceIdentity.generate()
        self.spare_identity = ServiceIdentity.generate()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.endpoint = RendezvousEndpoint("127.0.0.1", sock.getsockname()[1])
        self.old = self.bundle(1, self.now - 7200)
        self.new = self.bundle(2, self.now)
        self.pin = self.old.parent / "config-authority.pin"
        self.install_root = self.root / "installed"
        self.rollback = self.root / "rollback.json"
        self.recovery = WanConfigRecovery(self.old, self.pin, self.install_root, self.rollback)

    def bundle(self, generation, issued_at, *, authority=None):
        root = self.root / f"bundle-{generation}-{issued_at}"
        root.mkdir(exist_ok=True)
        peer = NodeDescriptor.create(
            self.node_identity, self.endpoint, ("bootstrap", "discovery"), RelayPolicy(),
            issued_at=issued_at, lifetime=3600,
        )
        spare = NodeDescriptor.create(
            self.spare_identity, RendezvousEndpoint("127.0.0.1", 1),
            ("bootstrap", "discovery"), RelayPolicy(), issued_at=issued_at, lifetime=3600,
        )
        bootstrap = BootstrapSet.create(
            authority or self.authority, [peer, spare], generation=generation,
            issued_at=issued_at, lifetime=3600,
        )
        bootstrap_path = root / "bootstrap-set.json"
        bootstrap_path.write_text(bootstrap.to_json(), encoding="utf-8")
        pin = root / "bootstrap-authority.pin"
        pin.write_text(encode_base64url(bootstrap.authority_public_key) + "\n", encoding="ascii")
        config = root / "browser-wan.json"
        write_signed_browser_wan_config(
            config, self.config_authority, bootstrap_path, pin,
            generation=generation, issued_at=issued_at, expires_at=issued_at + 3500,
        )
        return config

    def payload(self, path=None):
        return export_public_config(path or self.new, self.pin, now=self.now)

    def mutate(self, payload, **changes):
        envelope = json.loads(payload)
        config = json.loads(decode_base64url(envelope["config"]))
        config.update(changes)
        config.pop("signature")
        config["signature"] = encode_base64url(self.config_authority.sign(
            SIGNED_CONFIG_SIGNATURE_DOMAIN + canonical_json(config)))
        envelope["config"] = encode_base64url(canonical_json(config))
        return canonical_json(envelope)

    def server(self):
        peer = NodeDescriptor.create(
            self.node_identity, self.endpoint, ("bootstrap", "discovery"), RelayPolicy(),
            issued_at=self.now, lifetime=3600,
        )
        server = WanNodeServer(self.node_identity, peer, self.root / "node")
        server.wan_config_publisher = WanConfigPublisher(self.new, self.pin)
        server.start_background()
        self.addCleanup(server.stop)
        return server

    def test_expired_config_never_becomes_routing_config(self):
        with self.assertRaisesRegex(DiscoveryError, "CONFIG_EXPIRED"):
            self.recovery.current(now=self.now)
        contacts = self.recovery.contacts(now=self.now)
        self.assertEqual(len(contacts), 2)
        self.assertIn(self.node_identity.public_key_bytes, [contact.public_key for contact in contacts])
        self.assertFalse(self.rollback.exists())

    def test_hosting_recovery_preserves_identity_and_uses_its_peer_cache(self):
        from granger_network.hosting import _recover_hosting_config
        from granger_network.wan_config import load_or_create_identity
        root = self.root / "host"
        original = load_or_create_identity(root / "identity/network-identity.json")
        recovery = mock.Mock()
        recovery.current.side_effect = DiscoveryError("expired")
        recovery.refresh.return_value = self.new
        with mock.patch("granger_network.hosting._write_status"):
            self.assertEqual(_recover_hosting_config(root, mock.Mock(), recovery), self.new)
        args, kwargs = recovery.refresh.call_args
        self.assertEqual(args[0].public_key_bytes, original.public_key_bytes)
        self.assertEqual(kwargs["cache"].path, root / "metadata/peer-cache.json")
        self.assertFalse(kwargs["cache"].path.exists())

    def test_offline_across_expiry_recovers_over_authenticated_wire3_without_dns(self):
        server = self.server()
        identity = ServiceIdentity.generate()
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            path = self.recovery.refresh(identity)
        self.assertIsNotNone(path)
        config = load_browser_wan_config(path, trust_anchor_path=self.pin, allow_legacy=False)
        self.assertEqual(config.generation, 2)
        self.assertGreater(server.rpc_requests, 0)
        self.assertEqual(self.recovery.current(), path)
        self.assertEqual(WanConfigRecovery(self.old, self.pin, self.install_root, self.rollback).current(), path)

    def test_recovery_role_cannot_issue_data_or_discovery_rpc(self):
        self.server()
        for operation in (RpcType.OPEN_CIRCUIT, RpcType.FIND_NODE, RpcType.STORE_RECORD, RpcType.INTRO_REGISTER):
            with self.subTest(operation=operation):
                contact = next(c for c in self.recovery.contacts() if c.public_key == self.node_identity.public_key_bytes)
                peer = connect_config_recovery(contact, ServiceIdentity.generate())
                try:
                    with self.assertRaisesRegex(ProtocolError, "CONFIG_RECOVERY_ONLY"):
                        peer.rpc.request(operation, expected=operation)
                finally:
                    peer.close()

    def test_normal_peer_connector_still_rejects_expired_descriptor(self):
        old = BootstrapSet.from_json(
            (self.old.parent / "bootstrap-set.json").read_text(), self.authority.public_key_bytes,
            now=self.now - 7200,
        ).peers[0]
        with mock.patch("socket.socket", side_effect=AssertionError("must not dial")):
            with self.assertRaises(Exception) as caught:
                connect_authenticated_peer(old, ServiceIdentity.generate(), PeerRole.CLIENT)
        self.assertNotIsInstance(caught.exception, AssertionError)

    def test_signed_candidate_checks_reject_without_changing_state(self):
        installed = self.recovery.install(self.payload())
        pointer = (self.install_root / "active.json").read_bytes()
        rollback = self.rollback.read_bytes()
        cases = [
            ("rollback", {"generation": 1}),
            ("equivocation", {"timeoutSeconds": 7}),
            ("network", {"generation": 3, "networkId": "other-network"}),
            ("protocol", {"generation": 3, "protocolVersion": 999}),
            ("NOT_YET_VALID", {"generation": 3, "issuedAt": self.now + 121}),
            ("EXPIRED", {"generation": 3, "issuedAt": self.now - 3600, "expiresAt": self.now}),
            ("authority", {"configAuthorityKey": encode_base64url(ServiceIdentity.generate().public_key_bytes)}),
        ]
        for reason, changes in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(DiscoveryError, reason):
                    self.recovery.install(self.mutate(self.payload(), **changes), now=self.now)
                self.assertEqual(pointer, (self.install_root / "active.json").read_bytes())
                self.assertEqual(rollback, self.rollback.read_bytes())
                self.assertTrue(installed.exists())

    def test_bad_signature_and_corrupt_transfer_do_not_advance_state(self):
        payload = self.payload()
        envelope = json.loads(payload)
        config = json.loads(decode_base64url(envelope["config"]))
        config["routeAttempts"] = 5
        envelope["config"] = encode_base64url(canonical_json(config))
        for bad in (canonical_json(envelope), payload[:-1], b"[]", b"{" * 2000):
            with self.subTest(size=len(bad)):
                with self.assertRaises(DiscoveryError):
                    self.recovery.install(bad)
                self.assertFalse(self.rollback.exists())
                self.assertFalse((self.install_root / "active.json").exists())

    def test_bootstrap_authority_cannot_be_replaced_by_config_recovery(self):
        other = self.bundle(3, self.now, authority=ServiceIdentity.generate())
        with self.assertRaisesRegex(DiscoveryError, "cannot replace"):
            self.recovery.install(self.payload(other))
        self.assertFalse(self.rollback.exists())

    def test_advertised_fast_forward_does_not_poison_high_water(self):
        publisher = WanConfigPublisher(self.new, self.pin)
        ad = publisher.advertisements()[0]
        from dataclasses import replace
        with self.assertRaisesRegex(DiscoveryError, "advertised generation"):
            self.recovery.install(self.payload(), advertisement=replace(ad, generation=2**63-1))
        self.assertFalse(self.rollback.exists())

    def test_clock_skew_and_expiry_are_checked_on_every_load(self):
        path = self.recovery.install(self.payload(), now=self.now - 120)
        for current, message in ((self.now - 121, "NOT_YET_VALID"), (self.now + 3500, "EXPIRED")):
            with self.assertRaisesRegex(DiscoveryError, message):
                load_browser_wan_config(path, trust_anchor_path=self.pin, now=current, allow_legacy=False)
        self.assertEqual(self.recovery.current(now=self.now + 60), path)

    def test_crash_after_high_water_before_pointer_recovers_exact_generation(self):
        from granger_network import wan_config
        write = wan_config.atomic_write_text
        def interrupt(path, content, mode=0o600):
            if Path(path).name == "active.json":
                raise OSError("injected crash")
            return write(path, content, mode)
        with mock.patch.object(wan_config, "atomic_write_text", side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "injected crash"):
                self.recovery.install(self.payload())
        self.assertEqual(json.loads(self.rollback.read_text())["generation"], 2)
        path = self.recovery.current()
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), json.loads(self.rollback.read_text())["configSha256"])

    def test_unavailable_sources_back_off_without_looping(self):
        identity = ServiceIdentity.generate()
        with mock.patch("granger_network.wan_config_recovery.connect_config_recovery", side_effect=OSError("offline")) as connect:
            self.assertIsNone(self.recovery.refresh(identity))
            count = connect.call_count
            for _ in range(100):
                self.assertIsNone(self.recovery.refresh(identity))
            self.assertEqual(count, connect.call_count)
            self.assertEqual(count, 2)
        self.assertGreater(self.recovery.snapshot()["retryInSeconds"], 0)
        self.assertLessEqual(self.recovery.snapshot()["retryInSeconds"], 36)

    def test_later_source_availability_recovers_after_retry_deadline(self):
        with mock.patch("granger_network.wan_config_recovery.connect_config_recovery", side_effect=OSError()):
            self.recovery.refresh(ServiceIdentity.generate())
        self.server()
        self.recovery._next_attempt = 0
        self.assertIsNotNone(self.recovery.refresh(ServiceIdentity.generate()))

    def test_managed_gateway_recovers_and_preserves_identity(self):
        from granger_network.browser_gateway import _ManagedWanGateway
        from granger_network.wan_config import load_or_create_identity
        self.server()
        state = self.root / "browser"
        identity = load_or_create_identity(state / "client-identity.json")
        created = threading.Event()
        def gateway(path, state_dir, **kwargs):
            result = mock.Mock()
            result._config = load_browser_wan_config(path, trust_anchor_path=self.pin, allow_legacy=False)
            result.network_health.return_value = {"state": "JOINING", "dhtReady": False}
            created.set()
            return result
        with mock.patch("granger_network.browser_gateway._WanGateway", side_effect=gateway), \
             mock.patch("granger_network.browser_gateway._write"):
            managed = _ManagedWanGateway(self.recovery, state)
            try:
                self.assertTrue(created.wait(10))
                self.assertTrue(managed._available.wait(3))
                self.assertEqual(managed.network_health()["configRecovery"]["generation"], 2)
                self.assertFalse(managed.network_health()["dhtReady"])
            finally:
                managed.close()
            self.assertFalse(managed._thread.is_alive())
        self.assertEqual(load_or_create_identity(state / "client-identity.json").public_key_bytes, identity.public_key_bytes)

    def test_post_join_config_fetch_never_uses_direct_contact(self):
        discovery = mock.Mock()
        discovery.pool.candidates.return_value = [mock.sentinel.carrier]
        discovery._private_route_candidates.return_value = []
        with mock.patch("granger_network.wan_config_recovery.connect_config_recovery", side_effect=AssertionError("direct forbidden")):
            self.assertIsNone(self.recovery.refresh(ServiceIdentity.generate(), discovery=discovery))
        discovery._private_route_candidates.assert_called_once()

    def test_peer_health_reaches_browser_before_config_refresh_deadline(self):
        from granger_network.browser_gateway import _ManagedWanGateway
        self.recovery.install(self.payload())
        ready = threading.Event()
        emitted = threading.Event()
        callbacks = []
        gateway = mock.Mock()
        gateway._config = load_browser_wan_config(self.new, trust_anchor_path=self.pin, allow_legacy=False)
        gateway.network_health.return_value = {'state': 'JOINING', 'dhtReady': False}

        def create(*args, **kwargs):
            callbacks.append(kwargs.get('on_health_changed'))
            ready.set()
            return gateway

        def write(document):
            if document.get('networkHealth', {}).get('state') == 'CONNECTED':
                emitted.set()

        with mock.patch('granger_network.browser_gateway._WanGateway', side_effect=create), \
                mock.patch('granger_network.browser_gateway._write', side_effect=write), \
                mock.patch.object(self.recovery, 'current', wraps=self.recovery.current) as current:
            managed = _ManagedWanGateway(self.recovery, self.root / 'health-client')
            try:
                self.assertTrue(ready.wait(3))
                self.assertTrue(managed._available.wait(3))
                deadline = time.monotonic() + 2
                while not managed._retry_at and time.monotonic() < deadline:
                    time.sleep(.01)
                retry_at = managed._retry_at
                calls = current.call_count
                self.assertGreater(retry_at - time.monotonic(), 30)
                self.assertTrue(callable(callbacks[0]), 'BrowserPeer has no health notification')
                gateway.network_health.return_value = {'state': 'CONNECTED', 'dhtReady': True}
                callbacks[0]()
                self.assertTrue(emitted.wait(2), 'Connected health waited for config renewal')
                self.assertEqual(managed._retry_at, retry_at)
                self.assertEqual(current.call_count, calls, 'Health triggered control/network polling')
            finally:
                managed.close()
            self.assertFalse(managed._thread.is_alive())

    def test_live_renewal_uses_real_four_hop_protected_circuit(self):
        self.recovery.install(self.payload())
        self.recovery.current()
        newer = self.bundle(3, self.now)
        identities = [ServiceIdentity.generate() for _ in range(3)] + [self.node_identity]
        peers = []
        for index, identity in enumerate(identities):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                endpoint = RendezvousEndpoint("127.0.0.1", probe.getsockname()[1])
            if index == 3:
                endpoint = self.endpoint
            peers.append(NodeDescriptor.create(
                identity, endpoint, ("access", "entry", "middle", "discovery"), RelayPolicy(enabled=True),
                issued_at=self.now, lifetime=3600))
        nodes = []
        for index, (identity, peer) in enumerate(zip(identities, peers)):
            node = WanNodeServer(identity, peer, self.root / f"warm-node-{index}", known_peers=tuple(peers))
            if index == 3:
                node.wan_config_publisher = WanConfigPublisher(newer, self.pin)
            node.start_background()
            self.addCleanup(node.stop)
            nodes.append(node)
        discovery = mock.Mock()
        discovery.pool.candidates.return_value = (peers[3],)
        discovery._private_route_candidates.return_value = (tuple(zip(peers, ("access", "entry", "middle", "discovery"))),)
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             mock.patch("granger_network.wan_config_recovery.connect_config_recovery", side_effect=AssertionError("direct forbidden")):
            self.assertIsNotNone(self.recovery.refresh(ServiceIdentity.generate(), discovery=discovery))
        self.assertEqual(self.recovery.generation, 3)
        self.assertTrue(all(node.rpc_requests > 0 for node in nodes))

    def test_disk_failure_before_snapshot_commit_keeps_existing_generation(self):
        path = self.recovery.install(self.payload())
        before = self.rollback.read_bytes()
        new = self.bundle(3, self.now)
        from granger_network import wan_config
        write = wan_config.atomic_write_bytes
        def fail(path, content, mode=0o600):
            if Path(path).name == "browser-wan.json":
                raise OSError("disk unavailable")
            return write(path, content, mode)
        with mock.patch.object(wan_config, "atomic_write_bytes", side_effect=fail):
            with self.assertRaisesRegex(OSError, "disk unavailable"):
                self.recovery.install(self.payload(new))
        self.assertEqual(self.rollback.read_bytes(), before)
        self.assertEqual(self.recovery.current(), path)

    def test_member_traversal_and_extra_files_are_rejected(self):
        envelope = json.loads(self.payload())
        envelope["members"]["../private.json"] = encode_base64url(b"not-a-key")
        with self.assertRaisesRegex(DiscoveryError, "malformed"):
            self.recovery.install(canonical_json(envelope))
        self.assertFalse(self.rollback.exists())

    def test_clock_jump_cannot_steal_a_live_provision_lock(self):
        from granger_network.wan_config import _ProvisionLock
        lock = self.root / "provision.lock"
        with _ProvisionLock(lock):
            with mock.patch("time.time", return_value=self.now + 100000):
                with self.assertRaisesRegex(DiscoveryError, "lock timed out"):
                    with _ProvisionLock(lock, timeout=0.1):
                        self.fail("live lock stolen")

    def test_process_death_releases_provision_lock_without_deleting_state(self):
        from granger_network.wan_config import _ProvisionLock
        lock = self.root / "provision.lock"
        command = "from pathlib import Path; import sys,time; from granger_network.wan_config import _ProvisionLock; lock=_ProvisionLock(Path(sys.argv[1])); lock.__enter__(); print('LOCKED', flush=True); time.sleep(30)"
        process = subprocess.Popen([sys.executable, "-c", command, str(lock)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.stdout.readline().strip(), b"LOCKED")
            process.kill()
            process.wait(timeout=5)
            with _ProvisionLock(lock, timeout=1):
                self.assertTrue(lock.is_file())
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
