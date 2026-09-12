from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from granger_network.bootstrap import BootstrapPool, BootstrapSet, CachedPeerPool, PeerCache
from granger_network.browser_peer import BrowserPeerPolicy, BrowserPeerRuntime
from granger_network.circuit import CircuitBuilder
from granger_network.descriptor import ServiceDescriptor
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_discovery import WanDiscoveryClient
from granger_network.wan_service import WanServiceClient, WanServiceHost


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def relay_policy() -> RelayPolicy:
    return RelayPolicy(
        enabled=True,
        max_circuits=128,
        max_streams=256,
        max_connections=256,
        max_bytes_per_circuit=32 * 1024 * 1024,
        max_bandwidth_kib_per_second=64 * 1024,
        connection_timeout_seconds=3,
        idle_timeout_seconds=30,
    )


class _Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply(b"self-sustaining-get")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self._reply(b"post:" + self.rfile.read(length))

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _RestrictedDiscovery:
    def __init__(self, anchors: tuple[NodeDescriptor, ...]) -> None:
        self.anchors = anchors

    def route_candidates(self, _target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        return self.anchors if capability == "entry" else ()


class _MutableDiscovery:
    def __init__(self, candidates: dict[str, tuple[NodeDescriptor, ...]]) -> None:
        self.candidates = candidates
        self._lock = threading.Lock()

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

    def remove(self, node_ids: set[str]) -> None:
        with self._lock:
            for capability, descriptors in tuple(self.candidates.items()):
                self.candidates[capability] = tuple(
                    descriptor
                    for descriptor in descriptors
                    if descriptor.node_id not in node_ids
                )


def service_roundtrip(
    nodes: list[NodeDescriptor],
    backend_port: int,
    name: str,
) -> None:
    if len(nodes) < 6:
        raise AssertionError("service roundtrip requires six reachable relays")
    identity = ServiceIdentity.generate()
    service = ServiceDescriptor.create_remote(identity, name, lifetime=1800)
    introduction = IntroductionDescriptor.create(
        identity,
        service,
        [nodes[3].node_id],
        sequence=1,
        lifetime=900,
    )
    host = WanServiceHost(
        identity,
        service,
        introduction,
        (
            (nodes[0], "access"),
            (nodes[1], "service-relay"),
            (nodes[2], "middle"),
            (nodes[3], "introduction"),
        ),
        (
            (nodes[0], "access"),
            (nodes[1], "service-relay"),
            (nodes[2], "middle"),
            (nodes[4], "rendezvous"),
        ),
        LoopbackHttpBridge(LoopbackHttpTarget("127.0.0.1", backend_port)),
        timeout=4.0,
        rendezvous_lifetime=120,
    )
    session = None
    try:
        host.start_background()
        host.wait_ready(20.0)
        client = WanServiceClient(
            ServiceIdentity.generate(),
            service,
            introduction,
            (
                (nodes[5], "access"),
                (nodes[0], "entry"),
                (nodes[1], "middle"),
            ),
            timeout=4.0,
        )
        session = client.connect(nodes[3])
        if session.fetch("/").body != b"self-sustaining-get":
            raise AssertionError("service GET response changed")
        if session.fetch("/submit", method="POST", body=b"scale").body != b"post:scale":
            raise AssertionError("service POST response changed")
    finally:
        if session is not None:
            session.close()
        host.stop()


class SelfSustainingOverlayTests(unittest.TestCase):
    def test_formed_overlay_survives_partial_reachable_peer_loss_matrix(self) -> None:
        peer_count = 20
        cases = ((10, 2), (25, 5), (50, 10), (75, 15))
        requested = os.environ.get("GRANGER_TEST_LOSS_PERCENT", "").strip()
        if requested:
            cases = tuple(case for case in cases if case[0] == int(requested, 10))
            self.assertTrue(cases, "requested peer-loss percentage is unsupported")
        for loss_percent, lost_count in cases:
            with self.subTest(lossPercent=loss_percent), tempfile.TemporaryDirectory(
                prefix=f"granger-peer-loss-{loss_percent}-"
            ) as temporary:
                root = Path(temporary)
                policy = relay_policy()
                pairs = []
                for index in range(peer_count):
                    identity = ServiceIdentity.generate()
                    descriptor = NodeDescriptor.create(
                        identity,
                        RendezvousEndpoint("127.0.0.1", available_port()),
                        (
                            "access",
                            "discovery",
                            "entry",
                            "middle",
                            "rendezvous",
                        ),
                        policy,
                        lifetime=3600,
                    )
                    pairs.append((descriptor, identity))
                descriptors = tuple(descriptor for descriptor, _identity in pairs)
                nodes = [
                    WanNodeServer(
                        identity,
                        descriptor,
                        root / f"node-{index}",
                        known_peers=tuple(
                            candidate
                            for candidate in descriptors
                            if candidate.node_id != descriptor.node_id
                        ),
                    )
                    for index, (descriptor, identity) in enumerate(pairs)
                ]
                cache = PeerCache(root / "peer-cache.json")
                current = int(time.time())
                cache.ingest(
                    descriptors,
                    source="authenticated-formed-overlay",
                    now=current,
                )
                for descriptor in descriptors:
                    cache.record_success(descriptor, now=current)
                ranked = cache.ranked("discovery", now=current)
                survivor_count = peer_count - lost_count
                survivor_ids = {
                    ranked[round(index * (peer_count - 1) / (survivor_count - 1))].node_id
                    for index in range(survivor_count)
                }
                self.assertEqual(len(survivor_ids), survivor_count)

                for node in nodes:
                    node.start_background()
                try:
                    for descriptor, node in zip(descriptors, nodes, strict=True):
                        if descriptor.node_id not in survivor_ids:
                            node.stop()
                    recovery = WanDiscoveryClient(
                        ServiceIdentity.generate(),
                        CachedPeerPool(cache),
                        cache=cache,
                        timeout=1.0,
                    )
                    started = time.monotonic()
                    with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                        self.assertNotEqual(
                            recovery.join_network().state.value,
                            "OFFLINE",
                        )
                        available = recovery.find_nodes(
                            loss_percent.to_bytes(32, "big"),
                            "discovery",
                        )
                        live = [
                            descriptor
                            for descriptor in available
                            if descriptor.node_id in survivor_ids
                        ]
                        self.assertGreaterEqual(len(live), 4)
                        identity = ServiceIdentity.generate()
                        record = ServiceDescriptor.create_remote(
                            identity,
                            f"peer-loss-{loss_percent}",
                            lifetime=900,
                        )
                        self.assertGreaterEqual(recovery.publish(record), 2)
                        self.assertEqual(
                            recovery.lookup("service", record.service_id),
                            record,
                        )
                        with CircuitBuilder(
                            ServiceIdentity.generate(),
                            PeerRole.CLIENT,
                            timeout=3.0,
                        ).open(
                            (
                                (live[0], "access"),
                                (live[1], "entry"),
                                (live[2], "middle"),
                                (live[3], "rendezvous"),
                            )
                        ) as circuit:
                            marker = f"loss-{loss_percent}".encode("ascii")
                            self.assertEqual(
                                circuit.endpoint.rpc.request(
                                    RpcType.PING,
                                    marker,
                                    expected=RpcType.PONG,
                                ).payload,
                                marker,
                            )
                    self.assertLess(time.monotonic() - started, 90.0)
                finally:
                    for node in nodes:
                        node.stop()

    def test_new_overlay_activity_survives_initial_seed_shutdown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-self-sustaining-") as temporary:
            root = Path(temporary)
            policy = relay_policy()
            ordinary_capabilities = (
                "access",
                "discovery",
                "entry",
                "introduction",
                "middle",
                "rendezvous",
                "service-relay",
            )
            seed_pairs = []
            ordinary_pairs = []
            for index in range(4):
                identity = ServiceIdentity.generate()
                descriptor = NodeDescriptor.create(
                    identity,
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    ("bootstrap", *ordinary_capabilities),
                    policy,
                    lifetime=3600,
                )
                seed_pairs.append((descriptor, identity))
            for index in range(10):
                identity = ServiceIdentity.generate()
                descriptor = NodeDescriptor.create(
                    identity,
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    ordinary_capabilities,
                    policy,
                    lifetime=3600,
                )
                ordinary_pairs.append((descriptor, identity))
            all_descriptors = tuple(
                descriptor for descriptor, _identity in (*seed_pairs, *ordinary_pairs)
            )
            seed_nodes = [
                WanNodeServer(
                    identity,
                    descriptor,
                    root / f"seed-{index}",
                    known_peers=tuple(
                        peer for peer in all_descriptors if peer.node_id != descriptor.node_id
                    ),
                )
                for index, (descriptor, identity) in enumerate(seed_pairs)
            ]
            ordinary_nodes = [
                WanNodeServer(
                    identity,
                    descriptor,
                    root / f"ordinary-{index}",
                    known_peers=tuple(
                        peer for peer in all_descriptors if peer.node_id != descriptor.node_id
                    ),
                )
                for index, (descriptor, identity) in enumerate(ordinary_pairs)
            ]
            authority = ServiceIdentity.generate()
            bootstrap = BootstrapSet.create(
                authority,
                [descriptor for descriptor, _identity in seed_pairs],
                generation=1,
                lifetime=1800,
            )
            cache = PeerCache(root / "client-cache.json")
            initial = WanDiscoveryClient(
                ServiceIdentity.generate(),
                BootstrapPool(bootstrap, cache),
                cache=cache,
                timeout=2.0,
            )
            backend = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
            backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
            backend_thread.start()
            restricted = None
            host = None
            session = None
            for node in (*seed_nodes, *ordinary_nodes):
                node.start_background()
            try:
                initial_health = initial.join_network()
                self.assertNotEqual(initial_health.state.value, "OFFLINE")
                initial.find_nodes(b"i" * 32, "discovery")
                cached_ordinary = {
                    descriptor.node_id
                    for descriptor in cache.load()
                    if "bootstrap" not in descriptor.capabilities
                }
                self.assertGreaterEqual(len(cached_ordinary), 8)

                for node in seed_nodes:
                    node.stop()

                recovery = WanDiscoveryClient(
                    ServiceIdentity.generate(),
                    BootstrapPool(bootstrap, cache),
                    cache=cache,
                    timeout=1.0,
                )
                with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                    recovered_health = recovery.join_network()
                    self.assertNotEqual(recovered_health.state.value, "OFFLINE")
                    new_nodes = recovery.find_nodes(b"n" * 32, "rendezvous")
                    self.assertGreaterEqual(len(new_nodes), 3)
                    self.assertTrue(
                        all("bootstrap" not in node.capabilities for node in new_nodes[:3])
                    )

                    service_identity = ServiceIdentity.generate()
                    dht_service = ServiceDescriptor.create_remote(
                        service_identity,
                        "after-seed-shutdown-dht",
                        lifetime=900,
                    )
                    self.assertGreaterEqual(recovery.publish(dht_service), 2)
                    resolved = recovery.lookup("service", dht_service.service_id)
                    self.assertEqual(resolved, dht_service)

                    ordinary = [descriptor for descriptor, _identity in ordinary_pairs]
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=3.0,
                    ).open(
                        (
                            (ordinary[0], "access"),
                            (ordinary[1], "entry"),
                            (ordinary[2], "middle"),
                            (ordinary[3], "rendezvous"),
                        )
                    ) as circuit:
                        response = circuit.endpoint.rpc.request(
                            RpcType.PING,
                            b"fresh-circuit-after-seed-shutdown",
                            expected=RpcType.PONG,
                        )
                        self.assertEqual(
                            response.payload,
                            b"fresh-circuit-after-seed-shutdown",
                        )

                    restricted = BrowserPeerRuntime(
                        ServiceIdentity.generate(),
                        _RestrictedDiscovery((ordinary[1], ordinary[4])),
                        root / "restricted-browser",
                        relay_policy=policy,
                        lifecycle_policy=BrowserPeerPolicy(
                            target_adjacencies=1,
                            descriptor_lifetime_seconds=120,
                            renewal_margin_seconds=30,
                            reconnect_floor_seconds=0.05,
                            reconnect_ceiling_seconds=0.25,
                        ),
                    )
                    restricted.start()
                    self.assertTrue(restricted.wait_until_joined(5.0))
                    restricted_descriptor = restricted.current_descriptor()
                    self.assertIsNotNone(restricted_descriptor)
                    assert restricted_descriptor is not None
                    restricted_anchor = next(
                        descriptor
                        for descriptor in ordinary
                        if descriptor.node_id == restricted_descriptor.via_node_id
                    )
                    restricted_exit = next(
                        descriptor
                        for descriptor in ordinary
                        if descriptor.node_id
                        not in {restricted_anchor.node_id, restricted_descriptor.node_id}
                    )
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=3.0,
                    ).open(
                        (
                            (restricted_anchor, "entry"),
                            (restricted_descriptor, "middle"),
                            (restricted_exit, "rendezvous"),
                        )
                    ) as circuit:
                        response = circuit.endpoint.rpc.request(
                            RpcType.PING,
                            b"restricted-after-seed-shutdown",
                            expected=RpcType.PONG,
                        )
                        self.assertEqual(response.payload, b"restricted-after-seed-shutdown")

                    hosted_service = ServiceDescriptor.create_remote(
                        service_identity,
                        "new-host-after-seed-shutdown",
                        lifetime=1800,
                    )
                    introduction = IntroductionDescriptor.create(
                        service_identity,
                        hosted_service,
                        [ordinary[6].node_id],
                        sequence=1,
                        lifetime=900,
                    )
                    host = WanServiceHost(
                        service_identity,
                        hosted_service,
                        introduction,
                        (
                            (ordinary[0], "access"),
                            (ordinary[1], "service-relay"),
                            (ordinary[2], "middle"),
                            (ordinary[6], "introduction"),
                        ),
                        (
                            (ordinary[0], "access"),
                            (ordinary[1], "service-relay"),
                            (ordinary[2], "middle"),
                            (ordinary[7], "rendezvous"),
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
                    host.start_background()
                    host.wait_ready(20.0)
                    client = WanServiceClient(
                        ServiceIdentity.generate(),
                        hosted_service,
                        introduction,
                        (
                            (ordinary[3], "access"),
                            (ordinary[4], "entry"),
                            (ordinary[5], "middle"),
                        ),
                        timeout=4.0,
                    )
                    session = client.connect(ordinary[6])
                    get_response = session.fetch("/")
                    post_response = session.fetch("/submit", method="POST", body=b"payload")
                    self.assertEqual(get_response.body, b"self-sustaining-get")
                    self.assertEqual(post_response.body, b"post:payload")

                    session.close()
                    session = None
                    host.stop()
                    host = None

                    alternate_anchor = next(
                        descriptor
                        for descriptor in (ordinary[1], ordinary[4])
                        if descriptor.node_id != restricted_anchor.node_id
                    )
                    loss = [restricted_anchor]
                    loss.extend(
                        descriptor
                        for descriptor in ordinary
                        if descriptor.node_id
                        not in {restricted_anchor.node_id, alternate_anchor.node_id}
                    )
                    loss = loss[:3]
                    lost_ids = {descriptor.node_id for descriptor in loss}
                    for descriptor, node in zip(ordinary, ordinary_nodes, strict=True):
                        if descriptor.node_id in lost_ids:
                            node.stop()

                    deadline = time.monotonic() + 8.0
                    migrated_descriptor = restricted.current_descriptor()
                    while time.monotonic() < deadline:
                        migrated_descriptor = restricted.current_descriptor()
                        metrics = restricted.contribution_snapshot()
                        if (
                            migrated_descriptor is not None
                            and migrated_descriptor.via_node_id == alternate_anchor.node_id
                            and metrics["activeAdjacencies"] >= 1
                        ):
                            break
                        time.sleep(0.05)
                    self.assertIsNotNone(migrated_descriptor)
                    assert migrated_descriptor is not None
                    self.assertEqual(
                        migrated_descriptor.via_node_id,
                        alternate_anchor.node_id,
                    )
                    self.assertGreaterEqual(
                        restricted.contribution_snapshot()["anchorChanges"],
                        1,
                    )

                    survivors = [
                        descriptor
                        for descriptor in ordinary
                        if descriptor.node_id not in lost_ids
                    ]
                    post_churn_exit = next(
                        descriptor
                        for descriptor in survivors
                        if descriptor.node_id != alternate_anchor.node_id
                    )
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=3.0,
                    ).open(
                        (
                            (alternate_anchor, "entry"),
                            (migrated_descriptor, "middle"),
                            (post_churn_exit, "rendezvous"),
                        )
                    ) as circuit:
                        response = circuit.endpoint.rpc.request(
                            RpcType.PING,
                            b"fresh-circuit-after-ordinary-churn",
                            expected=RpcType.PONG,
                        )
                        self.assertEqual(
                            response.payload,
                            b"fresh-circuit-after-ordinary-churn",
                        )

                    post_churn_identity = ServiceIdentity.generate()
                    post_churn_dht = ServiceDescriptor.create_remote(
                        post_churn_identity,
                        "post-churn-dht",
                        lifetime=900,
                    )
                    self.assertGreaterEqual(recovery.publish(post_churn_dht), 2)
                    self.assertEqual(
                        recovery.lookup("service", post_churn_dht.service_id),
                        post_churn_dht,
                    )

                    hosted_service = ServiceDescriptor.create_remote(
                        post_churn_identity,
                        "new-host-after-ordinary-churn",
                        lifetime=1800,
                    )
                    introduction = IntroductionDescriptor.create(
                        post_churn_identity,
                        hosted_service,
                        [survivors[3].node_id],
                        sequence=1,
                        lifetime=900,
                    )
                    host = WanServiceHost(
                        post_churn_identity,
                        hosted_service,
                        introduction,
                        (
                            (survivors[0], "access"),
                            (survivors[1], "service-relay"),
                            (survivors[2], "middle"),
                            (survivors[3], "introduction"),
                        ),
                        (
                            (survivors[0], "access"),
                            (survivors[1], "service-relay"),
                            (survivors[2], "middle"),
                            (survivors[4], "rendezvous"),
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
                    host.start_background()
                    host.wait_ready(20.0)
                    client = WanServiceClient(
                        ServiceIdentity.generate(),
                        hosted_service,
                        introduction,
                        (
                            (survivors[5], "access"),
                            (survivors[6], "entry"),
                            (survivors[0], "middle"),
                        ),
                        timeout=4.0,
                    )
                    session = client.connect(survivors[3])
                    self.assertEqual(session.fetch("/").body, b"self-sustaining-get")
                    self.assertEqual(
                        session.fetch("/submit", method="POST", body=b"churn").body,
                        b"post:churn",
                    )
            finally:
                if session is not None:
                    session.close()
                if host is not None:
                    host.stop()
                if restricted is not None:
                    restricted.stop()
                for node in (*seed_nodes, *ordinary_nodes):
                    node.stop()
                backend.shutdown()
                backend.server_close()
                backend_thread.join(timeout=2.0)

    @unittest.skipUnless(
        os.environ.get("GRANGER_RUN_100_PEER_ACCEPTANCE") == "1",
        "set GRANGER_RUN_100_PEER_ACCEPTANCE=1 for the controlled scale test",
    )
    def test_hundred_browser_peers_replace_initial_seed_backbone(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-self-sustaining-100-") as temporary:
            root = Path(temporary)
            policy = relay_policy()
            capabilities = (
                "access",
                "bootstrap",
                "discovery",
                "entry",
                "introduction",
                "middle",
                "rendezvous",
                "service-relay",
            )
            seed_pairs = []
            for index in range(4):
                identity = ServiceIdentity.generate()
                descriptor = NodeDescriptor.create(
                    identity,
                    RendezvousEndpoint("127.0.0.1", available_port()),
                    capabilities,
                    policy,
                    lifetime=3600,
                )
                seed_pairs.append(
                    (
                        descriptor,
                        WanNodeServer(identity, descriptor, root / f"seed-{index}"),
                    )
                )
            seed_descriptors = tuple(descriptor for descriptor, _node in seed_pairs)
            for descriptor, node in seed_pairs:
                for peer in seed_descriptors:
                    if peer.node_id != descriptor.node_id:
                        node.add_known_peer(peer, source="formed-overlay")

            discovery = _MutableDiscovery(
                {
                    "discovery": seed_descriptors,
                    "entry": seed_descriptors,
                }
            )
            public_browsers = [
                BrowserPeerRuntime(
                    ServiceIdentity.generate(),
                    discovery,
                    root / f"public-{index}",
                    relay_policy=policy,
                    lifecycle_policy=BrowserPeerPolicy(
                        target_adjacencies=1,
                        descriptor_lifetime_seconds=300,
                        renewal_margin_seconds=60,
                        reconnect_floor_seconds=0.05,
                        reconnect_ceiling_seconds=0.5,
                        public_listener_port=available_port(),
                        reachability_quorum=2,
                        public_reprobe_seconds=300.0,
                        public_retry_seconds=1.0,
                    ),
                )
                for index in range(8)
            ]
            restricted_browsers: list[BrowserPeerRuntime] = []
            backend = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
            backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
            backend_thread.start()
            for _descriptor, node in seed_pairs:
                node.start_background()
            try:
                for browser in public_browsers:
                    browser.start()
                    self.assertTrue(browser.wait_until_joined(10.0))
                    descriptor = browser.current_descriptor()
                    self.assertIsNotNone(descriptor)
                    assert descriptor is not None
                    self.assertEqual(descriptor.reachability, "reachable")

                public_descriptors = [
                    descriptor
                    for browser in public_browsers
                    if (descriptor := browser.current_descriptor()) is not None
                ]
                self.assertEqual(len(public_descriptors), 8)
                self.assertEqual(len({item.node_id for item in public_descriptors}), 8)

                for browser in public_browsers:
                    server = browser._server
                    self.assertIsNotNone(server)
                    assert server is not None
                    for descriptor in public_descriptors:
                        if descriptor.node_id != server.descriptor.node_id:
                            server.add_known_peer(descriptor, source="formed-overlay")

                restricted_policy = BrowserPeerPolicy(
                    target_adjacencies=1,
                    descriptor_lifetime_seconds=300,
                    renewal_margin_seconds=60,
                    reconnect_floor_seconds=0.05,
                    reconnect_ceiling_seconds=0.5,
                )
                restricted_browsers = [
                    BrowserPeerRuntime(
                        ServiceIdentity.generate(),
                        discovery,
                        root / f"restricted-{index}",
                        relay_policy=policy,
                        lifecycle_policy=restricted_policy,
                    )
                    for index in range(92)
                ]
                for browser in restricted_browsers:
                    browser.start()
                self.assertTrue(
                    all(browser.wait_until_joined(15.0) for browser in restricted_browsers)
                )
                self.assertEqual(len(public_browsers) + len(restricted_browsers), 100)

                seed_ids = {descriptor.node_id for descriptor in seed_descriptors}
                for _descriptor, node in seed_pairs:
                    node.stop()
                discovery.remove(seed_ids)

                public_ids = {descriptor.node_id for descriptor in public_descriptors}
                deadline = time.monotonic() + 15.0
                migrated: list[NodeDescriptor] = []
                while time.monotonic() < deadline:
                    migrated = [
                        descriptor
                        for browser in restricted_browsers
                        if (descriptor := browser.current_descriptor()) is not None
                        and descriptor.via_node_id in public_ids
                        and browser.contribution_snapshot()["activeAdjacencies"] >= 1
                    ]
                    if len(migrated) == len(restricted_browsers):
                        break
                    time.sleep(0.05)
                self.assertEqual(len(migrated), len(restricted_browsers))
                self.assertGreaterEqual(len({item.via_node_id for item in migrated}), 6)

                cache = PeerCache(root / "post-seed-cache.json")
                current = int(time.time())
                for descriptor in public_descriptors:
                    cache.add(descriptor, source="authenticated-formed-overlay", now=current)
                    cache.record_success(descriptor, now=current)
                recovery = WanDiscoveryClient(
                    ServiceIdentity.generate(),
                    CachedPeerPool(cache),
                    cache=cache,
                    timeout=2.0,
                )

                with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                    self.assertNotEqual(recovery.join_network().state.value, "OFFLINE")
                    self.assertGreaterEqual(
                        len(recovery.find_nodes(b"s" * 32, "discovery")),
                        6,
                    )
                    record_identity = ServiceIdentity.generate()
                    record = ServiceDescriptor.create_remote(
                        record_identity,
                        "scale-after-seed-shutdown",
                        lifetime=900,
                    )
                    self.assertGreaterEqual(recovery.publish(record), 2)
                    self.assertEqual(recovery.lookup("service", record.service_id), record)

                    relay_descriptor = migrated[0]
                    relay_anchor = next(
                        descriptor
                        for descriptor in public_descriptors
                        if descriptor.node_id == relay_descriptor.via_node_id
                    )
                    relay_exit = next(
                        descriptor
                        for descriptor in public_descriptors
                        if descriptor.node_id != relay_anchor.node_id
                    )
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=4.0,
                    ).open(
                        (
                            (relay_anchor, "entry"),
                            (relay_descriptor, "middle"),
                            (relay_exit, "rendezvous"),
                        )
                    ) as circuit:
                        self.assertEqual(
                            circuit.endpoint.rpc.request(
                                RpcType.PING,
                                b"after-all-seeds-stopped",
                                expected=RpcType.PONG,
                            ).payload,
                            b"after-all-seeds-stopped",
                        )
                    service_roundtrip(
                        public_descriptors,
                        int(backend.server_address[1]),
                        "scale-before-ordinary-loss",
                    )

                    anchor_counts = {
                        descriptor.node_id: sum(
                            item.via_node_id == descriptor.node_id for item in migrated
                        )
                        for descriptor in public_descriptors
                    }
                    victim_ids = {
                        node_id
                        for node_id, _count in sorted(
                            anchor_counts.items(),
                            key=lambda item: (-item[1], item[0]),
                        )[:2]
                    }
                    affected = [
                        browser
                        for browser in restricted_browsers
                        if (
                            browser.current_descriptor() is not None
                            and browser.current_descriptor().via_node_id in victim_ids
                        )
                    ]
                    self.assertTrue(affected)
                    for browser, descriptor in zip(
                        public_browsers,
                        public_descriptors,
                        strict=True,
                    ):
                        if descriptor.node_id in victim_ids:
                            browser.stop()
                    discovery.remove(victim_ids)

                    survivor_descriptors = [
                        descriptor
                        for descriptor in public_descriptors
                        if descriptor.node_id not in victim_ids
                    ]
                    survivor_ids = {descriptor.node_id for descriptor in survivor_descriptors}
                    deadline = time.monotonic() + 15.0
                    remigrated: list[NodeDescriptor] = []
                    while time.monotonic() < deadline:
                        remigrated = [
                            descriptor
                            for browser in affected
                            if (descriptor := browser.current_descriptor()) is not None
                            and descriptor.via_node_id in survivor_ids
                            and browser.contribution_snapshot()["activeAdjacencies"] >= 1
                        ]
                        if len(remigrated) == len(affected):
                            break
                        time.sleep(0.05)
                    self.assertEqual(len(remigrated), len(affected))

                    migrated_relay = remigrated[0]
                    migrated_anchor = next(
                        descriptor
                        for descriptor in survivor_descriptors
                        if descriptor.node_id == migrated_relay.via_node_id
                    )
                    migrated_exit = next(
                        descriptor
                        for descriptor in survivor_descriptors
                        if descriptor.node_id != migrated_anchor.node_id
                    )
                    with CircuitBuilder(
                        ServiceIdentity.generate(),
                        PeerRole.CLIENT,
                        timeout=4.0,
                    ).open(
                        (
                            (migrated_anchor, "entry"),
                            (migrated_relay, "middle"),
                            (migrated_exit, "rendezvous"),
                        )
                    ) as circuit:
                        self.assertEqual(
                            circuit.endpoint.rpc.request(
                                RpcType.PING,
                                b"after-public-peer-loss",
                                expected=RpcType.PONG,
                            ).payload,
                            b"after-public-peer-loss",
                        )
                    post_loss = ServiceDescriptor.create_remote(
                        ServiceIdentity.generate(),
                        "scale-after-ordinary-loss",
                        lifetime=900,
                    )
                    self.assertGreaterEqual(recovery.publish(post_loss), 2)
                    self.assertEqual(
                        recovery.lookup("service", post_loss.service_id),
                        post_loss,
                    )
                    service_roundtrip(
                        survivor_descriptors,
                        int(backend.server_address[1]),
                        "scale-after-ordinary-loss-hosting",
                    )
            finally:
                for browser in restricted_browsers:
                    browser.stop()
                for browser in public_browsers:
                    browser.stop()
                for _descriptor, node in seed_pairs:
                    node.stop()
                backend.shutdown()
                backend.server_close()
                backend_thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
