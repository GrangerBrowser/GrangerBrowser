from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from granger_network.bootstrap import BootstrapSet, PeerCache
from granger_network.errors import DiscoveryError
from granger_network.identity import ServiceIdentity
from granger_network.node import NodeListenerEndpoint, initialize_node, load_node
from granger_network.operator import (
    DISCOVERY_CAPABILITIES,
    NODE_DESCRIPTOR_REPUBLISH_INTERVAL_SECONDS,
    OPERATOR_TERMINAL_EXIT_CODE,
    _BootstrapLoadResult,
    _DiscoverySupervisor,
    _PersistentPeerPool,
    _descriptor_publication_due,
    _discovery_capability,
    _discovery_wait_seconds,
    _load_bootstrap_sets,
    _persistent_router_peers,
    _stopped_status_document,
    load_operator_config,
    main as operator_main,
    prepare_node,
    run_operator,
)
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_config import write_bootstrap_bundle


class OperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-operator-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _free_port(self) -> int:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
        listener.close()
        return port

    def _config(self, *, port: int | None = None) -> Path:
        selected_port = port or self._free_port()
        path = self.root / "config.json"
        path.write_text(
            json.dumps(
                {
                    "advertise": {"host": "203.0.113.90", "port": selected_port},
                    "bootstrap": {"authorityPins": [], "bundles": []},
                    "capabilities": [
                        "access",
                        "bootstrap",
                        "discovery",
                        "entry",
                        "introduction",
                        "middle",
                        "rendezvous",
                        "service-relay",
                    ],
                    "descriptorLifetimeSeconds": 86400,
                    "discoveryIntervalSeconds": 300,
                    "listen": {"host": "127.0.0.1", "port": selected_port},
                    "peerDescriptors": [],
                    "relayPolicy": {
                        "burstKiB": 4096,
                        "connectionTimeoutSeconds": 10,
                        "enabled": True,
                        "idleTimeoutSeconds": 120,
                        "maxBandwidthKiBPerSecond": 2048,
                        "maxBytesPerCircuit": 67108864,
                        "maxCircuits": 48,
                        "maxConnections": 96,
                        "maxStreams": 128,
                        "memoryBudgetKiB": 131072,
                    },
                    "renewBeforeSeconds": 21600,
                    "version": 1,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def _bootstrap_peers(
        self,
        now: int,
        *,
        lifetime: int = 3600,
    ) -> list[NodeDescriptor]:
        return [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint(f"203.0.113.{index + 110}", 62500 + index),
                (
                    "access",
                    "bootstrap",
                    "discovery",
                    "entry",
                    "middle",
                ),
                RelayPolicy(enabled=True),
                issued_at=now,
                lifetime=lifetime,
            )
            for index in range(3)
        ]

    def _signed_config(
        self,
        bundle: BootstrapSet,
    ) -> tuple[Path, Path]:
        config_path = self._config()
        bundle_path = self.root / "bootstrap.json"
        authority_pin = self.root / "bootstrap-authority.pin"
        write_bootstrap_bundle(bundle, bundle_path, authority_pin)
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["bootstrap"] = {
            "authorityPins": [authority_pin.name],
            "bundles": [bundle_path.name],
        }
        config_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return config_path, bundle_path

    def test_discovery_schedule_is_bounded_and_identity_staggered(self) -> None:
        node_ids = (
            "steapuncu4l3k2zf3p6vt5rsgbcpl2cretfs3ul3lweedprwp3ya",
            "xciuusikp4jkcaynnqem2yqxt32pgvs2ftrn3issvpcdtaxpfoea",
            "2zuojanfgtf25ggpiclkhxxq3opt6dt3vekx4jznnfjrnka5xjfq",
            "5scqnjvqgbkslcuthre47tfsn7gqrzmibzvbgtsqpkiw7hdk4rmq",
        )
        initial = {
            _discovery_wait_seconds(node_id, 60, 0, initial=True)
            for node_id in node_ids
        }
        recurring = {
            _discovery_wait_seconds(node_id, 60, 1, initial=False)
            for node_id in node_ids
        }

        self.assertTrue(all(0 <= delay <= 60 for delay in initial))
        self.assertTrue(all(60 <= delay <= 120 for delay in recurring))
        self.assertGreater(len(initial), 1)
        self.assertGreater(len(recurring), 1)

    def test_discovery_capability_rotates_without_bursting_all_roles(self) -> None:
        node_id = "steapuncu4l3k2zf3p6vt5rsgbcpl2cretfs3ul3lweedprwp3ya"
        sequence = tuple(
            _discovery_capability(node_id, cycle)
            for cycle in range(len(DISCOVERY_CAPABILITIES))
        )

        self.assertEqual(set(sequence), set(DISCOVERY_CAPABILITIES))
        self.assertEqual(len(sequence), len(set(sequence)))
        self.assertEqual(
            _discovery_capability(node_id, len(DISCOVERY_CAPABILITIES)),
            sequence[0],
        )

    def test_node_descriptor_publication_is_initial_and_bounded(self) -> None:
        interval = NODE_DESCRIPTOR_REPUBLISH_INTERVAL_SECONDS

        self.assertTrue(_descriptor_publication_due(None, 100.0))
        self.assertFalse(_descriptor_publication_due(100.0, 100.0 + interval - 0.001))
        self.assertTrue(_descriptor_publication_due(100.0, 100.0 + interval))
        with self.assertRaisesRegex(ValueError, "publication time"):
            _descriptor_publication_due(100.0, -1.0)

    def test_prepare_keeps_identity_and_exports_only_public_descriptor(self) -> None:
        config = load_operator_config(self._config())
        state = self.root / "state"
        public = self.root / "public"
        now = int(time.time())
        first, created = prepare_node(config, state, public, now=now)
        identity_content = (state / "node-identity.json").read_text(encoding="utf-8")
        second, repeated = prepare_node(config, state, public, now=now + 1)
        renewed, rotated = prepare_node(
            config,
            state,
            public,
            now=first.expires_at - config.renew_before + 1,
        )
        self.assertTrue(created)
        self.assertFalse(repeated)
        self.assertTrue(rotated)
        self.assertEqual(first.node_id, second.node_id)
        self.assertEqual(first.node_id, renewed.node_id)
        self.assertGreater(renewed.expires_at, first.expires_at)
        self.assertEqual(
            identity_content,
            (state / "node-identity.json").read_text(encoding="utf-8"),
        )
        public_content = (public / "node-descriptor.json").read_text(encoding="utf-8")
        self.assertNotIn("privateKey", public_content)
        NodeDescriptor.from_json(public_content, now=first.expires_at - config.renew_before + 1)

    def test_listener_can_bind_separately_from_advertised_endpoint(self) -> None:
        port = self._free_port()
        state = self.root / "node"
        descriptor = initialize_node(
            state,
            RendezvousEndpoint("203.0.113.91", port),
            ("bootstrap", "discovery"),
            RelayPolicy(max_connections=8),
        )
        node = load_node(
            state,
            listener_endpoint=NodeListenerEndpoint("127.0.0.1", port),
        )
        try:
            node.start_background()
            connection = socket.create_connection(("127.0.0.1", port), timeout=2.0)
            connection.close()
            self.assertEqual(descriptor.endpoint.host, "203.0.113.91")
            self.assertEqual(node.listener_endpoint.host, "127.0.0.1")
        finally:
            node.stop()

    def test_authenticated_peer_cache_survives_node_reload(self) -> None:
        first_state = self.root / "first"
        second_state = self.root / "second"
        first = initialize_node(
            first_state,
            RendezvousEndpoint("203.0.113.92", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(),
        )
        second = initialize_node(
            second_state,
            RendezvousEndpoint("198.51.100.92", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(),
        )
        initial = load_node(first_state, (second,))
        initial.stop()
        reloaded = load_node(first_state)
        try:
            known = {peer.node_id for peer in reloaded._known_peers()}
            self.assertIn(first.node_id, known)
            self.assertIn(second.node_id, known)
        finally:
            reloaded.stop()

    def test_expired_installed_reseed_is_not_returned_as_bootstrap(self) -> None:
        now = int(time.time())
        authority = ServiceIdentity.generate()
        bundle = BootstrapSet.create(
            authority,
            self._bootstrap_peers(now),
            generation=1,
            issued_at=now,
            lifetime=60,
        )
        config_path, _bundle_path = self._signed_config(bundle)
        config = load_operator_config(config_path)
        state = self.root / "expired-reseed-state"

        active = _load_bootstrap_sets(config, state, now=now)
        expired = _load_bootstrap_sets(config, state, now=now + 61)

        self.assertEqual(active.bootstrap_sets[0].generation, 1)
        self.assertEqual(active.failure_reason, "")
        self.assertEqual(expired.bootstrap_sets, ())
        self.assertEqual(expired.failure_reason, "RESEED_EXPIRED")

    def test_fresh_router_rejects_expired_reseed_without_creating_identity(self) -> None:
        config = load_operator_config(self._config())
        state = self.root / "fresh-expired-state"
        with patch(
            "granger_network.operator._load_bootstrap_sets",
            return_value=_BootstrapLoadResult((), "RESEED_EXPIRED"),
        ):
            with self.assertRaisesRegex(DiscoveryError, "fresh router"):
                run_operator(
                    config,
                    state,
                    self.root / "fresh-public",
                    self.root / "fresh.pid",
                    self.root / "fresh-ready.json",
                    self.root / "fresh-status.json",
                    self.root / "fresh-diagnostics.jsonl",
                )
        self.assertFalse((state / "node-identity.json").exists())

    def test_joined_router_requires_recent_authenticated_peer_state(self) -> None:
        now = int(time.time())
        config = load_operator_config(self._config())
        state = self.root / "joined-state"
        public = self.root / "joined-public"
        descriptor, _created = prepare_node(config, state, public, now=now)
        peers = self._bootstrap_peers(now)
        cache = PeerCache(state / "peer-cache.json")
        for peer in peers:
            cache.record_success(peer, now=now)

        persistent = _persistent_router_peers(
            state,
            descriptor.node_id,
            now=now + 1,
        )
        self.assertEqual(len(persistent), 3)
        pool = _PersistentPeerPool(persistent)
        self.assertEqual(len(pool.seed_candidates("discovery", now=now + 1)), 3)

        node = load_node(state, persistent)
        supervisor = _DiscoverySupervisor(
            node,
            ServiceIdentity.load(state / "node-identity.json"),
            (),
            300,
            startup_failure_reason="RESEED_EXPIRED",
            persistent_peers=persistent,
        )
        try:
            self.assertIsNotNone(supervisor.discovery)
            self.assertEqual(supervisor.status()["authenticatedPeers"], 0)
            self.assertEqual(supervisor.status()["state"], "DEGRADED")
            recovered = supervisor._with_reseed_status(
                {
                    "authenticatedPeers": 3,
                    "dhtReady": True,
                    "failureReason": "",
                    "state": "CONNECTED",
                }
            )
            self.assertTrue(recovered["dhtReady"])
            self.assertEqual(recovered["failureReason"], "RESEED_EXPIRED")
            self.assertEqual(recovered["state"], "DEGRADED")
            self.assertTrue(recovered["refreshRequired"])
        finally:
            node.stop()

    def test_joined_router_without_recent_peer_state_fails_closed(self) -> None:
        config = load_operator_config(self._config())
        state = self.root / "joined-empty-state"
        prepare_node(config, state, self.root / "joined-empty-public")
        with patch(
            "granger_network.operator._load_bootstrap_sets",
            return_value=_BootstrapLoadResult((), "RESEED_EXPIRED"),
        ):
            with self.assertRaisesRegex(DiscoveryError, "insufficient"):
                run_operator(
                    config,
                    state,
                    self.root / "joined-empty-public",
                    self.root / "joined-empty.pid",
                    self.root / "joined-empty-ready.json",
                    self.root / "joined-empty-status.json",
                    self.root / "joined-empty-diagnostics.jsonl",
                )

    def test_fresh_reseed_generation_recovers_after_expiry(self) -> None:
        now = int(time.time())
        authority = ServiceIdentity.generate()
        peers = self._bootstrap_peers(now, lifetime=3600)
        first = BootstrapSet.create(
            authority,
            peers,
            generation=1,
            issued_at=now,
            lifetime=60,
        )
        config_path, bundle_path = self._signed_config(first)
        config = load_operator_config(config_path)
        state = self.root / "reseed-recovery-state"
        _load_bootstrap_sets(config, state, now=now)
        self.assertEqual(
            _load_bootstrap_sets(config, state, now=now + 61).failure_reason,
            "RESEED_EXPIRED",
        )

        second = BootstrapSet.create(
            authority,
            peers,
            generation=2,
            issued_at=now + 61,
            lifetime=600,
        )
        bundle_path.write_text(second.to_json(), encoding="utf-8")
        recovered = _load_bootstrap_sets(config, state, now=now + 61)
        self.assertEqual(recovered.failure_reason, "")
        self.assertEqual(recovered.bootstrap_sets[0].generation, 2)

    def test_signed_topology_rejection_is_terminal_for_systemd(self) -> None:
        config_path = self._config()
        status_path = self.root / "terminal-status.json"
        with patch(
            "granger_network.operator.run_operator",
            side_effect=DiscoveryError("bootstrap set signature is invalid"),
        ):
            result = operator_main(
                [
                    "run",
                    "--config",
                    str(config_path),
                    "--state-dir",
                    str(self.root / "terminal-state"),
                    "--public-dir",
                    str(self.root / "terminal-public"),
                    "--pid-file",
                    str(self.root / "terminal.pid"),
                    "--ready-file",
                    str(self.root / "terminal-ready.json"),
                    "--status-file",
                    str(status_path),
                    "--diagnostics",
                    str(self.root / "terminal-diagnostics.jsonl"),
                ]
            )
        self.assertEqual(result, OPERATOR_TERMINAL_EXIT_CODE)
        status = json.loads(status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["network"]["failureReason"], "SIGNED_TOPOLOGY_REJECTED")

    def test_config_rejects_unpaired_reseed_material(self) -> None:
        path = self._config()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["bootstrap"]["authorityPins"] = ["bootstrap-authority.pin"]
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "configured together"):
            load_operator_config(path)

    def test_public_bundle_tool_keeps_authority_keys_private(self) -> None:
        descriptors: list[Path] = []
        for index, host in enumerate(("203.0.113.101", "198.51.100.101"), start=1):
            state = self.root / f"seed-{index}"
            initialize_node(
                state,
                RendezvousEndpoint(host, 62000 + index),
                ("bootstrap", "discovery"),
                RelayPolicy(),
                descriptor_lifetime=3600,
            )
            descriptors.append(state / "node-descriptor.json")
        private = self.root / "private"
        public = self.root / "public"
        tool = Path(__file__).resolve().parents[1] / "tools" / "operator_bundle.py"
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        command = [
            sys.executable,
            str(tool),
            "create",
            "--private-root",
            str(private),
            "--public-root",
            str(public),
            "--generation",
            "1",
            "--lifetime",
            "600",
        ]
        for descriptor in descriptors:
            command.extend(("--descriptor", str(descriptor)))
        created = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        verified = subprocess.run(
            [
                sys.executable,
                str(tool),
                "verify",
                "--public-root",
                str(public),
            ],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertTrue((private / "bootstrap-authority.json").is_file())
        self.assertTrue((private / "config-authority.json").is_file())
        self.assertFalse(any(b'"privateKey"' in path.read_bytes() for path in public.iterdir()))
        self.assertTrue(json.loads(verified.stdout)["ok"])

    def test_linux_systemd_deployment_is_bounded_and_unprivileged(self) -> None:
        operator_root = Path(__file__).resolve().parents[1] / "operator" / "linux"
        service = (operator_root / "systemd" / "granger-node@.service").read_text(
            encoding="utf-8"
        )
        installer = (operator_root / "install-public-test-topology.sh").read_text(
            encoding="utf-8"
        )
        distributed_installer = (operator_root / "install-public-router.sh").read_text(
            encoding="utf-8"
        )
        firewall_installer = (operator_root / "install-granger-firewall.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("User=granger", service)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("RestartPreventExitStatus=78", service)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("MemoryMax=160M", service)
        self.assertIn("TasksMax=256", service)
        self.assertIn("TimeoutStopSec=120s", service)
        self.assertIn("RuntimeDirectory=granger-node/%i", service)
        self.assertIn("/run/granger-node/%i/status.json", service)
        self.assertNotIn("217.60.10.122", service)
        self.assertNotIn("217.60.10.122", installer)
        self.assertIn("--public-ip", installer)
        self.assertIn('STATE_ROOT="/var/lib/granger-node"', installer)
        self.assertIn('$STATE_ROOT/private/authorities', installer)
        self.assertNotIn("privateKey", installer)
        self.assertIn("--public-ip", distributed_installer)
        self.assertIn("--public-bootstrap", distributed_installer)
        self.assertIn('STATE_ROOT="/var/lib/granger-node"', distributed_installer)
        self.assertIn('CONFIG_ROOT="/etc/granger-node"', distributed_installer)
        self.assertIn("operator_bundle.py\" verify", distributed_installer)
        self.assertIn('systemctl enable "granger-node@$NODE_NAME.service"', distributed_installer)
        self.assertNotIn("217.60.10.122", distributed_installer)
        self.assertNotIn('operator_bundle.py" create', distributed_installer)
        self.assertNotIn("private/authorities", distributed_installer)
        self.assertIn("--persist", firewall_installer)
        self.assertIn('nft -c -f "$NFTABLES_CONFIG"', firewall_installer)
        self.assertIn("systemctl enable nftables.service", firewall_installer)

    def test_node_shutdown_uses_one_shared_thread_join_deadline(self) -> None:
        state = self.root / "shutdown-node"
        initialize_node(
            state,
            RendezvousEndpoint("203.0.113.95", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(max_connections=8),
        )
        node = load_node(state)

        class WaitingThread:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def join(self, timeout: float | None = None) -> None:
                assert timeout is not None
                self.timeouts.append(timeout)

        workers = [WaitingThread(), WaitingThread(), WaitingThread()]
        node._threads = set(workers)  # type: ignore[assignment]
        with patch(
            "granger_network.node.time.monotonic",
            side_effect=(100.0, 100.5, 102.75, 103.1),
        ):
            node.stop()
        observed = [timeout for worker in workers for timeout in worker.timeouts]
        self.assertEqual(len(observed), 2)
        self.assertCountEqual(observed, (2.5, 0.25))

    def test_node_shutdown_does_not_wait_indefinitely_for_runtime_lock(self) -> None:
        state = self.root / "locked-shutdown-node"
        initialize_node(
            state,
            RendezvousEndpoint("203.0.113.96", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(max_connections=8),
        )
        node = load_node(state)
        locked = threading.Event()
        release = threading.Event()

        def hold_runtime_lock() -> None:
            with node._lock:
                locked.set()
                release.wait(5.0)

        holder = threading.Thread(target=hold_runtime_lock, daemon=True)
        holder.start()
        self.assertTrue(locked.wait(1.0))
        started = time.monotonic()
        node.stop()
        elapsed = time.monotonic() - started
        release.set()
        holder.join(timeout=1.0)
        self.assertLess(elapsed, 2.0)

    def test_stopped_status_reuses_snapshot_without_runtime_locks(self) -> None:
        state = self.root / "locked-status-node"
        initialize_node(
            state,
            RendezvousEndpoint("203.0.113.97", self._free_port()),
            ("bootstrap", "discovery"),
            RelayPolicy(max_connections=8),
        )
        node = load_node(state)
        status_file = self.root / "status.json"
        status_file.write_text(
            json.dumps(
                {
                    "activeCircuits": 3,
                    "network": {"dhtReady": True, "state": "CONNECTED"},
                    "peerCache": {"peers": 4, "version": 2},
                    "state": "RUNNING",
                    "version": 1,
                }
            ),
            encoding="utf-8",
        )
        with node.runtime._lock, node.peer_cache._lock:
            started = time.monotonic()
            document = _stopped_status_document(node, status_file, started_at=123)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.25)
        self.assertEqual(document["state"], "STOPPED")
        self.assertEqual(document["activeCircuits"], 0)
        self.assertEqual(document["startedAt"], 123)
        self.assertEqual(document["peerCache"], {"peers": 4, "version": 2})


if __name__ == "__main__":
    unittest.main()
