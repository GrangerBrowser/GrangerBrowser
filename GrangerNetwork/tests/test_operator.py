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

from granger_network.identity import ServiceIdentity
from granger_network.node import NodeListenerEndpoint, initialize_node, load_node
from granger_network.operator import load_operator_config, prepare_node
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint


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
        self.assertIn("User=granger", service)
        self.assertIn("Restart=on-failure", service)
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


if __name__ == "__main__":
    unittest.main()
