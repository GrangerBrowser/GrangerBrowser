from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from granger_network.circuit import CircuitBuilder
from granger_network.browser_peer import BrowserPeerPolicy, BrowserPeerRuntime
from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import (
    DescriptorError,
    OverlayRoutingError,
    ProtocolError,
    TransportPolicyError,
)
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import MAX_CONNECTIONS_PER_SOURCE, WanNodeServer
from granger_network.peer import (
    ADJACENT_NODE_DESCRIPTOR_VERSION,
    NodeDescriptor,
    RelayPolicy,
)
from granger_network.peer_rpc import (
    PeerRole,
    RpcType,
    connect_authenticated_peer,
)
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_routing import WanRouteSelector
from granger_network.wan_service import WanServiceClient, WanServiceHost
from granger_network.wan_discovery import (
    decode_node_list,
    encode_peer_sample,
)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def relay_policy() -> RelayPolicy:
    return RelayPolicy(
        enabled=True,
        max_circuits=16,
        max_streams=16,
        max_connections=16,
        max_bytes_per_circuit=8 * 1024 * 1024,
        max_bandwidth_kib_per_second=64 * 1024,
        connection_timeout_seconds=3,
        idle_timeout_seconds=30,
    )


def reachable_descriptor(
    identity: ServiceIdentity,
    capabilities: tuple[str, ...],
) -> NodeDescriptor:
    return NodeDescriptor.create(
        identity,
        RendezvousEndpoint("127.0.0.1", available_port()),
        capabilities,
        relay_policy(),
        lifetime=3600,
    )


def adjacent_descriptor(
    identity: ServiceIdentity,
    anchor: NodeDescriptor,
) -> NodeDescriptor:
    return NodeDescriptor.create(
        identity,
        anchor.endpoint,
        ("middle",),
        relay_policy(),
        lifetime=600,
        reachability="adjacent",
        version=ADJACENT_NODE_DESCRIPTOR_VERSION,
        via_node_id=anchor.node_id,
    )


class _RestrictedHostingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    body = b"restricted browser hosting over granger"

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _StaticDiscovery:
    def __init__(self, candidates: dict[str, tuple[NodeDescriptor, ...]]) -> None:
        self.candidates = candidates
        self._lock = threading.Lock()

    def find_nodes(self, _target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        with self._lock:
            return self.candidates.get(capability, ())

    def route_candidates(self, _target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        with self._lock:
            return self.candidates.get(capability, ())

    def publish(self, record) -> int:
        if not isinstance(record, NodeDescriptor):
            return 0
        with self._lock:
            for capability in record.capabilities:
                current = {
                    descriptor.node_id: descriptor
                    for descriptor in self.candidates.get(capability, ())
                }
                current[record.node_id] = record
                self.candidates[capability] = tuple(current.values())
        return 3


class ReverseAdjacencyTests(unittest.TestCase):
    def test_stopping_supervisor_cannot_be_replaced_while_alive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-peer-stop-") as temporary:
            browser = BrowserPeerRuntime(
                ServiceIdentity.generate(), _StaticDiscovery({}), Path(temporary),
            )
            supervisor = Mock()
            supervisor.is_alive.return_value = True
            browser._thread = supervisor
            browser._joined.set()
            browser.stop()
            self.assertIs(browser._thread, supervisor)
            self.assertFalse(browser.wait_until_joined(0.0))
            browser.start()
            self.assertIs(browser._thread, supervisor)
            self.assertTrue(browser._stop.is_set())
            supervisor.is_alive.return_value = False
            browser.stop()
            self.assertIsNone(browser._thread)

    def test_browser_peer_advertises_reachable_only_after_callback_quorum(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-public-browser-peer-") as temporary:
            root = Path(temporary)
            probe_pairs = []
            for index in range(2):
                identity = ServiceIdentity.generate()
                descriptor = reachable_descriptor(identity, ("discovery", "entry"))
                probe_pairs.append(
                    (
                        descriptor,
                        WanNodeServer(identity, descriptor, root / f"probe-{index}"),
                    )
                )
            discovery = _StaticDiscovery(
                {
                    "discovery": tuple(item[0] for item in probe_pairs),
                    "entry": tuple(item[0] for item in probe_pairs),
                }
            )
            browser = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                discovery,
                root / "browser",
                relay_policy=relay_policy(),
                lifecycle_policy=BrowserPeerPolicy(
                    target_adjacencies=1,
                    descriptor_lifetime_seconds=120,
                    renewal_margin_seconds=119,
                    reconnect_floor_seconds=0.05,
                    reconnect_ceiling_seconds=0.25,
                    public_listener_port=available_port(),
                    reachability_quorum=2,
                    public_reprobe_seconds=1.0,
                    public_retry_seconds=30.0,
                ),
            )
            for _descriptor, node in probe_pairs:
                node.start_background()
            browser.start()
            peer = None
            try:
                self.assertTrue(browser.wait_until_joined(8.0))
                descriptor = browser.current_descriptor()
                self.assertIsNotNone(descriptor)
                assert descriptor is not None
                self.assertEqual(descriptor.reachability, "reachable")
                self.assertIn("discovery", descriptor.capabilities)
                self.assertIn("entry", descriptor.capabilities)
                metrics = browser.contribution_snapshot()
                self.assertEqual(metrics["contributionState"], "public-relay")
                self.assertGreaterEqual(metrics["publicProbes"], 2)
                self.assertEqual(metrics["activeAdjacencies"], 0)
                self.assertTrue(
                    all(node.reachability_probes >= 1 for _descriptor, node in probe_pairs)
                )
                self.assertNotIn(
                    descriptor.node_id,
                    {candidate.node_id for candidate in browser._public_candidates()},
                )

                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline:
                    renewed = browser.current_descriptor()
                    if renewed is not None and renewed.issued_at > descriptor.issued_at:
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(renewed)
                self.assertEqual(renewed.reachability, "reachable")
                self.assertGreater(renewed.issued_at, descriptor.issued_at)
                self.assertEqual(renewed.node_id, descriptor.node_id)
                self.assertGreaterEqual(browser.contribution_snapshot()["publicProbes"], 4)
                descriptor = renewed

                for _descriptor, node in probe_pairs:
                    node.stop()
                peer = connect_authenticated_peer(
                    descriptor,
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=2.0,
                )
                response = peer.rpc.request(
                    RpcType.PING,
                    b"new-activity-after-seed-shutdown",
                    expected=RpcType.PONG,
                )
                self.assertEqual(response.payload, b"new-activity-after-seed-shutdown")
            finally:
                if peer is not None:
                    peer.close()
                browser.stop()
                self.assertFalse(browser.wait_until_joined(0.0))
                for _descriptor, node in probe_pairs:
                    node.stop()

    def test_failed_public_probe_falls_back_to_restricted_relay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-public-fallback-") as temporary:
            root = Path(temporary)
            anchor_identity = ServiceIdentity.generate()
            anchor = reachable_descriptor(anchor_identity, ("discovery", "entry"))
            anchor_node = WanNodeServer(anchor_identity, anchor, root / "anchor")
            second_identity = ServiceIdentity.generate()
            second = reachable_descriptor(second_identity, ("discovery", "entry"))
            second_node = WanNodeServer(second_identity, second, root / "second")
            browser = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"discovery": (anchor,), "entry": (anchor,)}),
                root / "browser",
                relay_policy=relay_policy(),
                lifecycle_policy=BrowserPeerPolicy(
                    target_adjacencies=1,
                    descriptor_lifetime_seconds=120,
                    renewal_margin_seconds=30,
                    reconnect_floor_seconds=0.05,
                    reconnect_ceiling_seconds=0.25,
                    public_listener_port=available_port(),
                    reachability_quorum=2,
                    public_reprobe_seconds=30.0,
                    public_retry_seconds=1.0,
                ),
            )
            anchor_node.start_background()
            browser.start()
            try:
                self.assertTrue(browser.wait_until_joined(8.0))
                descriptor = browser.current_descriptor()
                self.assertIsNotNone(descriptor)
                assert descriptor is not None
                self.assertEqual(descriptor.reachability, "adjacent")
                self.assertEqual(descriptor.via_node_id, anchor.node_id)
                self.assertGreaterEqual(
                    browser.contribution_snapshot()["activeAdjacencies"],
                    1,
                )
                second_node.start_background()
                browser.discovery.publish(second)
                deadline = time.monotonic() + 8.0
                while time.monotonic() < deadline:
                    promoted = browser.current_descriptor()
                    if promoted is not None and promoted.reachability == "reachable":
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(promoted)
                self.assertEqual(promoted.reachability, "reachable")
                self.assertEqual(promoted.node_id, descriptor.node_id)
                self.assertNotEqual(browser._select_anchor(set()).node_id, promoted.node_id)
            finally:
                browser.stop()
                anchor_node.stop()
                second_node.stop()

    def test_reachability_probe_cannot_target_a_different_source_address(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-public-probe-policy-") as temporary:
            root = Path(temporary)
            verifier_identity = ServiceIdentity.generate()
            verifier = reachable_descriptor(
                verifier_identity,
                ("discovery", "entry"),
            )
            verifier_node = WanNodeServer(verifier_identity, verifier, root / "verifier")

            candidate_identity = ServiceIdentity.generate()
            candidate = NodeDescriptor.create(
                candidate_identity,
                RendezvousEndpoint("127.0.0.2", available_port()),
                ("discovery", "entry"),
                relay_policy(),
                lifetime=3600,
            )
            peer = None
            verifier_node.start_background()
            try:
                peer = connect_authenticated_peer(
                    verifier,
                    candidate_identity,
                    PeerRole.RELAY,
                    local_descriptor=candidate,
                    timeout=2.0,
                )
                with self.assertRaisesRegex(
                    ProtocolError,
                    "REACHABILITY_POLICY_REJECTED",
                ):
                    peer.rpc.request(
                        RpcType.REACHABILITY_PROBE,
                        expected=RpcType.REACHABILITY_PROBE,
                    )
                self.assertEqual(verifier_node.reachability_probes, 0)
                self.assertTrue(
                    all(
                        descriptor.node_id != candidate.node_id
                        for descriptor in verifier_node._known_peers()
                    )
                )
            finally:
                if peer is not None:
                    peer.close()
                verifier_node.stop()

    def test_idle_adjacency_outlives_the_connection_handshake_timeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-browser-idle-") as temporary:
            root = Path(temporary)
            anchor_identity = ServiceIdentity.generate()
            anchor = reachable_descriptor(
                anchor_identity,
                ("discovery", "entry"),
            )
            anchor_node = WanNodeServer(anchor_identity, anchor, root / "anchor")
            browser_policy = RelayPolicy(
                enabled=True,
                max_circuits=4,
                max_streams=8,
                max_connections=4,
                max_bandwidth_kib_per_second=1024,
                connection_timeout_seconds=1,
                idle_timeout_seconds=30,
            )
            runtime = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"entry": (anchor,)}),
                root / "browser",
                relay_policy=browser_policy,
                lifecycle_policy=BrowserPeerPolicy(
                    target_adjacencies=1,
                    descriptor_lifetime_seconds=120,
                    renewal_margin_seconds=30,
                    reconnect_floor_seconds=0.05,
                    reconnect_ceiling_seconds=0.2,
                ),
            )
            anchor_node.start_background()
            runtime.start()
            try:
                self.assertTrue(runtime.wait_until_joined(3.0))
                time.sleep(1.25)
                metrics = runtime.contribution_snapshot()
                self.assertEqual(metrics["activeAdjacencies"], 1)
                self.assertEqual(metrics["connectionFailures"], 0)
                self.assertEqual(metrics["registrations"], 1)
            finally:
                runtime.stop()
                anchor_node.stop()

    def test_browser_peer_requires_an_anchor_that_can_advertise_live_slots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-browser-anchor-") as temporary:
            anchor = reachable_descriptor(ServiceIdentity.generate(), ("entry",))
            runtime = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"entry": (anchor,)}),
                Path(temporary),
                relay_policy=relay_policy(),
            )
            with self.assertRaisesRegex(OverlayRoutingError, "no reachable"):
                runtime._select_anchor(set())

    def test_browser_peer_reconnects_use_bounded_backoff(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-browser-backoff-") as temporary:
            anchor = reachable_descriptor(
                ServiceIdentity.generate(),
                ("discovery", "entry"),
            )
            attempts: list[float] = []

            def reject_connection(*_args, **_kwargs):
                attempts.append(time.monotonic())
                raise OSError("synthetic anchor refusal")

            runtime = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"entry": (anchor,)}),
                Path(temporary),
                relay_policy=relay_policy(),
                lifecycle_policy=BrowserPeerPolicy(
                    target_adjacencies=1,
                    descriptor_lifetime_seconds=120,
                    renewal_margin_seconds=30,
                    reconnect_floor_seconds=0.05,
                    reconnect_ceiling_seconds=0.2,
                ),
                connector=reject_connection,
            )
            runtime.start()
            try:
                time.sleep(0.42)
            finally:
                runtime.stop()
            self.assertGreaterEqual(len(attempts), 2)
            self.assertLessEqual(len(attempts), 4)
            self.assertGreaterEqual(attempts[1] - attempts[0], 0.04)
            if len(attempts) >= 3:
                self.assertGreaterEqual(attempts[2] - attempts[1], 0.08)

    def test_listener_free_descriptor_renewal_is_not_persisted_as_dht_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-browser-renewal-") as temporary:
            anchor = reachable_descriptor(ServiceIdentity.generate(), ("entry",))
            runtime = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"entry": (anchor,)}),
                Path(temporary),
                relay_policy=relay_policy(),
            )
            descriptor, server = runtime._create_server(anchor)
            renewed = runtime._create_descriptor(
                anchor,
                issued_after=descriptor.issued_at,
            )
            server.replace_descriptor(renewed, now=renewed.issued_at)
            self.assertEqual(server.descriptor, renewed)
            self.assertIsNone(server.records.fetch("node", renewed.node_id))

    def test_signed_adjacent_descriptor_is_explicit_and_direct_dial_is_forbidden(self) -> None:
        anchor_identity = ServiceIdentity.generate()
        anchor = reachable_descriptor(anchor_identity, ("entry",))
        identity = ServiceIdentity.generate()
        descriptor = adjacent_descriptor(identity, anchor)

        document = json.loads(descriptor.to_json())
        self.assertEqual(document["version"], ADJACENT_NODE_DESCRIPTOR_VERSION)
        self.assertEqual(document["reachability"], "adjacent")
        self.assertEqual(document["viaNodeId"], anchor.node_id)
        self.assertEqual(document["capabilities"], ["middle"])
        self.assertEqual(NodeDescriptor.from_json(descriptor.to_json()), descriptor)

        with self.assertRaisesRegex(TransportPolicyError, "direct peer"):
            connect_authenticated_peer(
                descriptor,
                ServiceIdentity.generate(),
                PeerRole.CLIENT,
            )
        with self.assertRaisesRegex(DescriptorError, "middle relay role"):
            NodeDescriptor.create(
                identity,
                anchor.endpoint,
                ("entry", "middle"),
                relay_policy(),
                reachability="adjacent",
                version=ADJACENT_NODE_DESCRIPTOR_VERSION,
                via_node_id=anchor.node_id,
            )
        with self.assertRaisesRegex(DescriptorError, "version 4"):
            NodeDescriptor.create(
                identity,
                anchor.endpoint,
                ("middle",),
                relay_policy(),
                reachability="adjacent",
                via_node_id=None,
            )

    def test_route_selector_places_adjacent_middle_after_its_anchor(self) -> None:
        access = reachable_descriptor(ServiceIdentity.generate(), ("access",))
        anchor = reachable_descriptor(ServiceIdentity.generate(), ("entry",))
        other_entry = reachable_descriptor(ServiceIdentity.generate(), ("entry",))
        restricted = adjacent_descriptor(ServiceIdentity.generate(), anchor)
        selector = WanRouteSelector(
            _StaticDiscovery(
                {
                    "access": (access,),
                    "entry": (other_entry, anchor),
                    "middle": (restricted,),
                }
            ),
            guard_seed=b"g" * 32,
        )

        selected = selector.client_prefix("a" * 52)
        self.assertEqual(selected.route[1][0].node_id, anchor.node_id)
        self.assertEqual(selected.route[2][0].node_id, restricted.node_id)
        self.assertEqual(selected.route[2][0].via_node_id, selected.route[1][0].node_id)

    def test_reverse_adjacency_slots_are_bounded_per_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-reverse-bounds-") as temporary:
            root = Path(temporary)
            anchor_identity = ServiceIdentity.generate()
            restricted_identity = ServiceIdentity.generate()
            anchor = reachable_descriptor(
                anchor_identity,
                ("discovery", "entry"),
            )
            restricted = adjacent_descriptor(restricted_identity, anchor)
            anchor_node = WanNodeServer(anchor_identity, anchor, root / "anchor")
            offered = []
            anchor_node.start_background()
            try:
                for _ in range(4):
                    peer = connect_authenticated_peer(
                        anchor,
                        restricted_identity,
                        PeerRole.RELAY,
                        local_descriptor=restricted,
                        timeout=3.0,
                    )
                    peer.rpc.request(
                        RpcType.REVERSE_REGISTER,
                        expected=RpcType.REVERSE_REGISTER,
                    )
                    offered.append(peer)
                overflow = connect_authenticated_peer(
                    anchor,
                    restricted_identity,
                    PeerRole.RELAY,
                    local_descriptor=restricted,
                    timeout=3.0,
                )
                try:
                    with self.assertRaisesRegex(ProtocolError, "REVERSE_CAPACITY"):
                        overflow.rpc.request(
                            RpcType.REVERSE_REGISTER,
                            expected=RpcType.REVERSE_REGISTER,
                        )
                finally:
                    overflow.close()
                metrics = anchor_node.contribution_snapshot()["reverseAdjacency"]
                self.assertEqual(metrics["activePeers"], 1)
                self.assertEqual(metrics["activeSlots"], 4)
                self.assertEqual(metrics["rejectedRegistrations"], 1)
            finally:
                anchor_node.stop()
                for peer in offered:
                    peer.close()

    def test_real_circuit_uses_outbound_only_peer_as_middle_relay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-reverse-adjacency-") as temporary:
            root = Path(temporary)
            anchor_identity = ServiceIdentity.generate()
            final_identity = ServiceIdentity.generate()
            restricted_identity = ServiceIdentity.generate()
            anchor = reachable_descriptor(
                anchor_identity,
                ("discovery", "entry"),
            )
            final = reachable_descriptor(final_identity, ("rendezvous",))
            restricted = adjacent_descriptor(restricted_identity, anchor)
            anchor_node = WanNodeServer(anchor_identity, anchor, root / "anchor")
            final_node = WanNodeServer(final_identity, final, root / "final")
            restricted_node = WanNodeServer(
                restricted_identity,
                restricted,
                root / "restricted",
                capture_path=root / "restricted.capture",
                enable_listener=False,
            )
            reverse_thread: threading.Thread | None = None
            circuit = None
            anchor_node.start_background()
            final_node.start_background()
            try:
                with self.assertRaises(TransportPolicyError):
                    connect_authenticated_peer(
                        restricted,
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                    )

                offered = connect_authenticated_peer(
                    anchor,
                    restricted_identity,
                    PeerRole.RELAY,
                    local_descriptor=restricted,
                    timeout=3.0,
                )
                registered = offered.rpc.request(
                    RpcType.REVERSE_REGISTER,
                    expected=RpcType.REVERSE_REGISTER,
                )
                self.assertEqual(registered.payload, b"")
                reverse_thread = threading.Thread(
                    target=restricted_node.serve_reverse_adjacency,
                    args=(offered, anchor),
                    daemon=True,
                )
                reverse_thread.start()

                reverse_metrics = anchor_node.contribution_snapshot()["reverseAdjacency"]
                self.assertEqual(reverse_metrics["activePeers"], 1)
                self.assertEqual(reverse_metrics["activeSlots"], 1)

                circuit = CircuitBuilder(
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=4.0,
                ).open(
                    (
                        (anchor, "entry"),
                        (restricted, "middle"),
                        (final, "rendezvous"),
                    )
                )
                response = circuit.endpoint.rpc.request(
                    RpcType.PING,
                    b"restricted-relay-proof",
                    expected=RpcType.PONG,
                )
                self.assertEqual(response.payload, b"restricted-relay-proof")

                deadline = time.monotonic() + 3.0
                contribution = restricted_node.contribution_snapshot()
                while contribution["bytesRelayed"] == 0 and time.monotonic() < deadline:
                    time.sleep(0.02)
                    contribution = restricted_node.contribution_snapshot()
                self.assertGreaterEqual(contribution["circuitsStarted"], 1)
                self.assertGreater(contribution["bytesRelayed"], 0)
                self.assertGreaterEqual(len(restricted_node.circuit_observations), 1)
                self.assertEqual(
                    restricted_node.circuit_observations[0].downstream,
                    final.node_id,
                )
                consumed = anchor_node.contribution_snapshot()["reverseAdjacency"]
                self.assertEqual(consumed["activeSlots"], 0)
                self.assertEqual(consumed["acquiredSlots"], 1)
                discovery_peer = connect_authenticated_peer(
                    anchor,
                    ServiceIdentity.generate(),
                    PeerRole.CLIENT,
                    timeout=3.0,
                )
                try:
                    sample = discovery_peer.rpc.request(
                        RpcType.PEER_SAMPLE,
                        encode_peer_sample("middle", 8),
                        expected=RpcType.PEER_SAMPLE,
                    )
                    available = decode_node_list(
                        sample.payload,
                        expected_network_id=anchor.network_id,
                        expected_protocol_version=anchor.protocol_version,
                    )
                finally:
                    discovery_peer.close()
                self.assertNotIn(
                    restricted.node_id,
                    {descriptor.node_id for descriptor in available},
                )
            finally:
                if circuit is not None:
                    circuit.close()
                restricted_node.stop()
                anchor_node.stop()
                final_node.stop()
                if reverse_thread is not None:
                    reverse_thread.join(timeout=3.0)
                    self.assertFalse(reverse_thread.is_alive())

    def test_two_browser_peer_runtimes_join_and_one_relays_for_the_other(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-browser-peers-") as temporary:
            root = Path(temporary)
            anchor_identity = ServiceIdentity.generate()
            final_identity = ServiceIdentity.generate()
            browser_a_identity = ServiceIdentity.generate()
            browser_b_identity = ServiceIdentity.generate()
            discovery_access_identity = ServiceIdentity.generate()
            anchor = reachable_descriptor(
                anchor_identity,
                ("discovery", "entry"),
            )
            discovery_access = reachable_descriptor(
                discovery_access_identity,
                ("access",),
            )
            final = reachable_descriptor(final_identity, ("rendezvous",))
            anchor_node = WanNodeServer(anchor_identity, anchor, root / "anchor")
            discovery_access_node = WanNodeServer(
                discovery_access_identity,
                discovery_access,
                root / "discovery-access",
            )
            final_node = WanNodeServer(final_identity, final, root / "final")
            discovery = _StaticDiscovery({"entry": (anchor,)})
            lifecycle = BrowserPeerPolicy(
                target_adjacencies=1,
                descriptor_lifetime_seconds=120,
                renewal_margin_seconds=30,
                reconnect_floor_seconds=0.05,
                reconnect_ceiling_seconds=0.25,
            )
            browser_a = BrowserPeerRuntime(
                browser_a_identity,
                discovery,
                root / "browser-a",
                relay_policy=relay_policy(),
                lifecycle_policy=lifecycle,
            )
            browser_b = BrowserPeerRuntime(
                browser_b_identity,
                discovery,
                root / "browser-b",
                relay_policy=relay_policy(),
                lifecycle_policy=lifecycle,
            )
            circuit = None
            anchor_node.start_background()
            discovery_access_node.start_background()
            final_node.start_background()
            browser_a.start()
            browser_b.start()
            try:
                self.assertTrue(browser_a.wait_until_joined(4.0))
                self.assertTrue(browser_b.wait_until_joined(4.0))
                descriptor_a = browser_a.current_descriptor()
                descriptor_b = browser_b.current_descriptor()
                self.assertIsNotNone(descriptor_a)
                self.assertIsNotNone(descriptor_b)
                assert descriptor_a is not None and descriptor_b is not None

                direct_discovery_peer = connect_authenticated_peer(
                    anchor,
                    browser_b_identity,
                    PeerRole.CLIENT,
                    timeout=3.0,
                )
                try:
                    direct_sample = direct_discovery_peer.rpc.request(
                        RpcType.PEER_SAMPLE,
                        encode_peer_sample("middle", 8),
                        expected=RpcType.PEER_SAMPLE,
                    )
                    direct_learned = decode_node_list(
                        direct_sample.payload,
                        expected_network_id=anchor.network_id,
                        expected_protocol_version=anchor.protocol_version,
                    )
                finally:
                    direct_discovery_peer.close()
                direct_ids = {descriptor.node_id for descriptor in direct_learned}
                self.assertNotIn(descriptor_a.node_id, direct_ids)
                self.assertNotIn(descriptor_b.node_id, direct_ids)

                with CircuitBuilder(
                    browser_b_identity,
                    PeerRole.CLIENT,
                    timeout=4.0,
                ).open(
                    (
                        (discovery_access, "access"),
                        (anchor, "discovery"),
                    )
                ) as discovery_circuit:
                    sample = discovery_circuit.endpoint.rpc.request(
                        RpcType.PEER_SAMPLE,
                        encode_peer_sample("middle", 8),
                        expected=RpcType.PEER_SAMPLE,
                    )
                    learned = decode_node_list(
                        sample.payload,
                        expected_network_id=anchor.network_id,
                        expected_protocol_version=anchor.protocol_version,
                    )
                learned_ids = {descriptor.node_id for descriptor in learned}
                self.assertIn(descriptor_a.node_id, learned_ids)
                self.assertIn(descriptor_b.node_id, learned_ids)

                circuit = CircuitBuilder(
                    browser_b_identity,
                    PeerRole.CLIENT,
                    timeout=4.0,
                ).open(
                    (
                        (anchor, "entry"),
                        (descriptor_a, "middle"),
                        (final, "rendezvous"),
                    )
                )
                response = circuit.endpoint.rpc.request(
                    RpcType.PING,
                    b"browser-to-browser-relay",
                    expected=RpcType.PONG,
                )
                self.assertEqual(response.payload, b"browser-to-browser-relay")
                deadline = time.monotonic() + 3.0
                metrics = browser_a.contribution_snapshot()
                while metrics["bytesRelayed"] == 0 and time.monotonic() < deadline:
                    time.sleep(0.02)
                    metrics = browser_a.contribution_snapshot()
                self.assertGreater(metrics["bytesRelayed"], 0)
                self.assertGreaterEqual(metrics["circuitsRelayed"], 1)

                circuit.close()
                circuit = None
                deadline = time.monotonic() + 4.0
                metrics = browser_a.contribution_snapshot()
                while (
                    (
                        metrics["activeAdjacencies"] < 1
                        or metrics["registrations"] < 2
                    )
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                    metrics = browser_a.contribution_snapshot()
                self.assertGreaterEqual(metrics["activeAdjacencies"], 1)
                self.assertGreaterEqual(metrics["registrations"], 2)
                renewed = browser_a.current_descriptor()
                self.assertIsNotNone(renewed)
                assert renewed is not None
                self.assertEqual(renewed.node_id, descriptor_a.node_id)

                circuit = CircuitBuilder(
                    browser_b_identity,
                    PeerRole.CLIENT,
                    timeout=4.0,
                ).open(
                    (
                        (anchor, "entry"),
                        (renewed, "middle"),
                        (final, "rendezvous"),
                    )
                )
                rebuilt = circuit.endpoint.rpc.request(
                    RpcType.PING,
                    b"browser-relay-rebuilt",
                    expected=RpcType.PONG,
                )
                self.assertEqual(rebuilt.payload, b"browser-relay-rebuilt")
            finally:
                if circuit is not None:
                    circuit.close()
                browser_a.stop()
                browser_b.stop()
                anchor_node.stop()
                discovery_access_node.stop()
                final_node.stop()

    def test_restricted_service_host_uses_browser_peers_on_both_route_halves(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-restricted-hosting-") as temporary:
            root = Path(temporary)
            backend = ThreadingHTTPServer(("127.0.0.1", 0), _RestrictedHostingHandler)
            backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
            backend_thread.start()

            definitions = (
                (("access",), "client-access"),
                (("discovery", "entry"), "client-anchor"),
                (("access",), "service-access"),
                (("discovery", "entry", "service-relay"), "service-anchor"),
                (("introduction",), "introduction"),
                (("rendezvous",), "rendezvous"),
            )
            infrastructure = []
            for capabilities, name in definitions:
                identity = ServiceIdentity.generate()
                descriptor = reachable_descriptor(identity, capabilities)
                infrastructure.append(
                    (
                        descriptor,
                        WanNodeServer(identity, descriptor, root / name),
                    )
                )
            (
                (client_access, _client_access_node),
                (client_anchor, _client_anchor_node),
                (service_access, _service_access_node),
                (service_anchor, _service_anchor_node),
                (introduction_node, _introduction_server),
                (rendezvous_node, _rendezvous_server),
            ) = infrastructure
            lifecycle = BrowserPeerPolicy(
                target_adjacencies=2,
                descriptor_lifetime_seconds=120,
                renewal_margin_seconds=30,
                reconnect_floor_seconds=0.05,
                reconnect_ceiling_seconds=0.25,
            )
            client_browser = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"entry": (client_anchor,)}),
                root / "client-browser",
                relay_policy=relay_policy(),
                lifecycle_policy=lifecycle,
            )
            service_browser = BrowserPeerRuntime(
                ServiceIdentity.generate(),
                _StaticDiscovery({"entry": (service_anchor,)}),
                root / "service-browser",
                relay_policy=relay_policy(),
                lifecycle_policy=lifecycle,
            )
            service_identity = ServiceIdentity.generate()
            service = ServiceDescriptor.create_remote(
                service_identity,
                "restricted-hosting",
                lifetime=1800,
            )
            introduction = IntroductionDescriptor.create(
                service_identity,
                service,
                [introduction_node.node_id],
                sequence=1,
                lifetime=900,
            )
            host = None
            session = None
            for _descriptor, node in infrastructure:
                node.start_background()
            client_browser.start()
            service_browser.start()
            try:
                self.assertTrue(client_browser.wait_until_joined(5.0))
                self.assertTrue(service_browser.wait_until_joined(5.0))
                client_middle = client_browser.current_descriptor()
                service_middle = service_browser.current_descriptor()
                self.assertIsNotNone(client_middle)
                self.assertIsNotNone(service_middle)
                assert client_middle is not None and service_middle is not None

                host = WanServiceHost(
                    service_identity,
                    service,
                    introduction,
                    (
                        (service_access, "access"),
                        (service_anchor, "service-relay"),
                        (service_middle, "middle"),
                        (introduction_node, "introduction"),
                    ),
                    (
                        (service_access, "access"),
                        (service_anchor, "service-relay"),
                        (service_middle, "middle"),
                        (rendezvous_node, "rendezvous"),
                    ),
                    LoopbackHttpBridge(
                        LoopbackHttpTarget(
                            "127.0.0.1",
                            int(backend.server_address[1]),
                        )
                    ),
                    timeout=4.0,
                    rendezvous_lifetime=120,
                )
                client = WanServiceClient(
                    ServiceIdentity.generate(),
                    service,
                    introduction,
                    (
                        (client_access, "access"),
                        (client_anchor, "entry"),
                        (client_middle, "middle"),
                    ),
                    timeout=4.0,
                )
                with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                    host.start_background()
                    host.wait_ready(20.0)
                    session = client.connect(introduction_node)
                    response = session.fetch("/")
                self.assertEqual(response.status, 200)
                self.assertEqual(response.body, _RestrictedHostingHandler.body)
                self.assertIsNone(service.endpoint)
                client_metrics = client_browser.contribution_snapshot()
                service_metrics = service_browser.contribution_snapshot()
                self.assertGreater(client_metrics["bytesRelayed"], 0)
                self.assertGreater(service_metrics["bytesRelayed"], 0)
                self.assertGreaterEqual(client_metrics["circuitsRelayed"], 1)
                self.assertGreaterEqual(service_metrics["circuitsRelayed"], 2)
            finally:
                if session is not None:
                    session.close()
                if host is not None:
                    host.stop()
                client_browser.stop()
                service_browser.stop()
                for _descriptor, node in infrastructure:
                    node.stop()
                backend.shutdown()
                backend.server_close()
                backend_thread.join(timeout=2.0)

    def test_restricted_browser_peers_survive_single_anchor_churn(self) -> None:
        peer_count = int(os.environ.get("GRANGER_TEST_BROWSER_PEERS", "30"))
        self.assertGreaterEqual(peer_count, 30)
        self.assertLessEqual(peer_count, 100)
        with tempfile.TemporaryDirectory(prefix="granger-browser-peer-scale-") as temporary:
            root = Path(temporary)
            anchor_pairs = []
            # All test clients share one loopback source. Retain capacity after
            # one anchor loss without bypassing the production per-source limit.
            clients_per_anchor = MAX_CONNECTIONS_PER_SOURCE // 2
            anchor_count = max(4, (peer_count + clients_per_anchor - 1) // clients_per_anchor + 1)
            for index in range(anchor_count):
                identity = ServiceIdentity.generate()
                descriptor = NodeDescriptor.create(
                    identity,
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    ("discovery", "entry"),
                    RelayPolicy(
                        enabled=True,
                        max_circuits=64,
                        max_streams=64,
                        max_connections=128,
                        max_bandwidth_kib_per_second=64 * 1024,
                    ),
                    lifetime=3600,
                )
                anchor_pairs.append(
                    (
                        descriptor,
                        WanNodeServer(identity, descriptor, root / f"anchor-{index}"),
                    )
                )
            final_identity = ServiceIdentity.generate()
            final = NodeDescriptor.create(
                final_identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("rendezvous",),
                RelayPolicy(
                    enabled=True,
                    max_circuits=64,
                    max_streams=64,
                    max_connections=128,
                    max_bandwidth_kib_per_second=64 * 1024,
                ),
                lifetime=3600,
            )
            final_node = WanNodeServer(final_identity, final, root / "final")
            discovery = _StaticDiscovery(
                {"entry": tuple(descriptor for descriptor, _node in anchor_pairs)}
            )
            lifecycle = BrowserPeerPolicy(
                target_adjacencies=1,
                descriptor_lifetime_seconds=120,
                renewal_margin_seconds=30,
                reconnect_floor_seconds=0.05,
                reconnect_ceiling_seconds=0.25,
            )
            browsers = [
                BrowserPeerRuntime(
                    ServiceIdentity.generate(),
                    discovery,
                    root / f"browser-{index}",
                    relay_policy=relay_policy(),
                    lifecycle_policy=lifecycle,
                )
                for index in range(peer_count)
            ]
            for _descriptor, node in anchor_pairs:
                node.start_background()
            final_node.start_background()
            for browser in browsers:
                browser.start()
            try:
                self.assertTrue(all(browser.wait_until_joined(8.0) for browser in browsers))
                descriptors = [browser.current_descriptor() for browser in browsers]
                self.assertTrue(all(descriptor is not None for descriptor in descriptors))
                typed_descriptors = [descriptor for descriptor in descriptors if descriptor is not None]
                self.assertEqual(len({item.node_id for item in typed_descriptors}), peer_count)
                initial_node_ids = {
                    browser: descriptor.node_id
                    for browser, descriptor in zip(browsers, typed_descriptors, strict=True)
                }
                self.assertEqual(
                    sum(
                        node.contribution_snapshot()["reverseAdjacency"]["activeSlots"]
                        for _descriptor, node in anchor_pairs
                    ),
                    peer_count,
                )

                relayed = 0
                for descriptor in typed_descriptors[:8]:
                    anchor = next(
                        candidate
                        for candidate, _node in anchor_pairs
                        if candidate.node_id == descriptor.via_node_id
                    )
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=4.0,
                    ).open(
                        (
                            (anchor, "entry"),
                            (descriptor, "middle"),
                            (final, "rendezvous"),
                        )
                    ) as circuit:
                        response = circuit.endpoint.rpc.request(
                            RpcType.PING,
                            b"scale-relay",
                            expected=RpcType.PONG,
                        )
                        self.assertEqual(response.payload, b"scale-relay")
                    relayed += 1
                self.assertEqual(relayed, 8)

                failed_anchor, failed_node = anchor_pairs[0]
                affected = [
                    browser
                    for browser in browsers
                    if (
                        browser.current_descriptor() is not None
                        and browser.current_descriptor().via_node_id == failed_anchor.node_id
                    )
                ]
                self.assertGreater(len(affected), 0)
                failed_node.stop()
                deadline = time.monotonic() + 8.0
                while time.monotonic() < deadline:
                    migrated = [
                        browser
                        for browser in affected
                        if (
                            browser.current_descriptor() is not None
                            and browser.current_descriptor().via_node_id != failed_anchor.node_id
                            and browser.contribution_snapshot()["activeAdjacencies"] >= 1
                        )
                    ]
                    if len(migrated) == len(affected):
                        break
                    time.sleep(0.05)
                self.assertEqual(len(migrated), len(affected))
                for browser in affected:
                    descriptor = browser.current_descriptor()
                    self.assertIsNotNone(descriptor)
                    assert descriptor is not None
                    self.assertEqual(descriptor.node_id, initial_node_ids[browser])
                    self.assertGreaterEqual(
                        browser.contribution_snapshot()["anchorChanges"],
                        1,
                    )
                    anchor = next(
                        candidate
                        for candidate, _node in anchor_pairs[1:]
                        if candidate.node_id == descriptor.via_node_id
                    )
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=4.0,
                    ).open(
                        (
                            (anchor, "entry"),
                            (descriptor, "middle"),
                            (final, "rendezvous"),
                        )
                    ) as circuit:
                        response = circuit.endpoint.rpc.request(
                            RpcType.PING,
                            b"post-anchor-churn",
                            expected=RpcType.PONG,
                        )
                        self.assertEqual(response.payload, b"post-anchor-churn")
            finally:
                for browser in browsers:
                    browser.stop()
                for _descriptor, node in anchor_pairs:
                    node.stop()
                final_node.stop()


if __name__ == "__main__":
    unittest.main()
