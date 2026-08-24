from __future__ import annotations

import json
import secrets
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import (
    INTRODUCTION_RECORD,
    SERVICE_RECORD,
    DiscoveryPeer,
    DistributedDiscoveryNetwork,
    DistributedResolver,
    RecordEnvelope,
)
from granger_network.errors import (
    DescriptorError,
    DiscoveryError,
    OverlayRoutingError,
    ReplayError,
    ResolutionError,
    ResourceLimitError,
)
from granger_network.identity import ServiceIdentity
from granger_network.introduction import (
    AliasRecord,
    IntroductionDescriptor,
    IntroductionRegistry,
)
from granger_network.multihop import MultiHopCircuit, OverlayRoutePlanner
from granger_network.peer import (
    RELAY_CAPABILITIES,
    GrangerNode,
    NodeDescriptor,
    RelayPolicy,
)
from granger_network.transport import RendezvousEndpoint


class DistributedOverlayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.service_identity = ServiceIdentity.generate()
        self.service = ServiceDescriptor.create_remote(
            self.service_identity,
            "distributed-overlay",
            metadata={"contentType": "text/html", "title": "Distributed service"},
            issued_at=self.now,
            lifetime=3600,
        )
        self.nodes: dict[str, tuple[ServiceIdentity, NodeDescriptor]] = {}
        self.runtimes: dict[str, GrangerNode] = {}
        definitions = (
            ("entry", ("discovery", "entry")),
            ("client-middle", ("discovery", "middle")),
            ("introduction", ("discovery", "introduction")),
            ("host-middle", ("discovery", "middle")),
            ("service-relay", ("discovery", "service-relay")),
            ("directory-a", ("discovery",)),
            ("directory-b", ("discovery",)),
        )
        peers: list[DiscoveryPeer] = []
        for index, (name, capabilities) in enumerate(definitions, start=10):
            identity = ServiceIdentity.generate()
            enabled = bool(set(capabilities) & RELAY_CAPABILITIES)
            policy = RelayPolicy(
                enabled=enabled,
                max_circuits=8,
                max_bytes_per_circuit=8 * 1024 * 1024,
                max_bandwidth_kib_per_second=4096,
            )
            descriptor = NodeDescriptor.create(
                identity,
                RendezvousEndpoint(f"203.0.113.{index}", 23000 + index),
                capabilities,
                policy,
                issued_at=self.now,
                lifetime=3600,
            )
            self.nodes[name] = (identity, descriptor)
            peers.append(DiscoveryPeer(descriptor))
            if enabled:
                self.runtimes[descriptor.node_id] = GrangerNode(
                    identity,
                    descriptor,
                    policy,
                )
        self.peers = peers
        self.peers_by_id = {peer.descriptor.node_id: peer for peer in peers}
        self.network = DistributedDiscoveryNetwork(
            peers,
            replication_factor=3,
            minimum_replicas=2,
        )
        for _identity, descriptor in self.nodes.values():
            self.assertEqual(self.network.publish(descriptor, now=self.now), 3)
        self.assertEqual(self.network.publish(self.service, now=self.now), 3)
        intro_id = self.nodes["introduction"][1].node_id
        self.introductions = IntroductionDescriptor.create(
            self.service_identity,
            self.service,
            [intro_id],
            sequence=1,
            issued_at=self.now,
            lifetime=900,
        )
        self.alias = AliasRecord.create(
            self.service_identity,
            "forum.granger",
            sequence=1,
            issued_at=self.now,
            lifetime=1800,
        )
        self.assertEqual(self.network.publish(self.introductions, now=self.now), 3)
        self.assertEqual(self.network.publish(self.alias, now=self.now), 3)
        self.resolver = DistributedResolver(
            self.network,
            {"forum.granger": self.service.service_id},
        )

    @staticmethod
    def choose_first(sequence):
        def key(value):
            if isinstance(value, tuple):
                return value[1].node_id
            return value.node_id

        return sorted(sequence, key=key)[0]

    def route(self):
        return OverlayRoutePlanner(
            self.resolver,
            chooser=self.choose_first,
        ).plan("forum.granger", now=self.now)

    def test_node_descriptors_require_opt_in_and_enforce_limits(self) -> None:
        identity = ServiceIdentity.generate()
        with self.assertRaisesRegex(DescriptorError, "explicit opt-in"):
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("203.0.113.90", 24090),
                ("entry",),
                RelayPolicy(enabled=False),
                issued_at=self.now,
                lifetime=600,
            )

        policy = RelayPolicy(
            enabled=True,
            max_circuits=1,
            max_bytes_per_circuit=128 * 1024,
            max_bandwidth_kib_per_second=64,
        )
        monotonic_time = [100.0]
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("203.0.113.91", 24091),
            ("entry",),
            policy,
            issued_at=self.now,
            lifetime=600,
        )
        node = GrangerNode(
            identity,
            descriptor,
            policy,
            monotonic=lambda: monotonic_time[0],
        )
        first = secrets.token_bytes(16)
        node.begin_circuit(first, "entry")
        with self.assertRaises(ResourceLimitError):
            node.begin_circuit(secrets.token_bytes(16), "entry")
        node.account_bytes(first, 64 * 1024)
        with self.assertRaisesRegex(ResourceLimitError, "bandwidth"):
            node.account_bytes(first, 1)
        monotonic_time[0] += 1.0
        node.account_bytes(first, 64 * 1024)
        monotonic_time[0] += 1.0
        with self.assertRaisesRegex(ResourceLimitError, "per-circuit"):
            node.account_bytes(first, 1)
        node.end_circuit(first)
        self.assertEqual(node.active_circuits, 0)

        expiring_descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint("203.0.113.92", 24092),
            ("entry",),
            policy,
            issued_at=self.now,
            lifetime=1,
        )
        expiring_node = GrangerNode(
            identity,
            expiring_descriptor,
            policy,
            monotonic=lambda: monotonic_time[0],
        )
        with (
            patch("granger_network.peer.time.time", return_value=self.now + 2),
            self.assertRaisesRegex(DescriptorError, "expired"),
        ):
            expiring_node.begin_circuit(secrets.token_bytes(16), "entry")
        self.assertEqual(expiring_node.active_circuits, 0)

        document = json.loads(descriptor.to_json())
        document["capabilities"] = ["entry", "unknown"]
        with self.assertRaises(DescriptorError):
            NodeDescriptor.from_json(json.dumps(document), now=self.now)

    def test_discovery_resolves_signed_alias_and_introductions_without_dns(self) -> None:
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
            patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
            patch(
                "socket.gethostbyname_ex",
                side_effect=AssertionError("DNS used"),
            ) as gethostbyname_ex,
            patch(
                "socket.create_connection",
                side_effect=AssertionError("direct connection used"),
            ) as create_connection,
            patch(
                "socket.socket.connect",
                side_effect=AssertionError("direct socket connect used"),
            ) as socket_connect,
        ):
            descriptor = self.resolver.resolve("forum.granger")
            introductions = self.resolver.resolve_introduction(
                descriptor,
                now=self.now,
            )
            plan = self.route()
        self.assertEqual(getaddrinfo.call_count, 0)
        self.assertEqual(gethostbyname.call_count, 0)
        self.assertEqual(gethostbyname_ex.call_count, 0)
        self.assertEqual(create_connection.call_count, 0)
        self.assertEqual(socket_connect.call_count, 0)
        self.assertEqual(descriptor.service_id, self.service.service_id)
        self.assertEqual(introductions.service_id, self.service.service_id)
        self.assertIsNone(descriptor.endpoint)
        self.assertEqual(plan.introduction.node_id, introductions.points[0].node_id)
        self.assertEqual(
            len(
                self.network.replica_node_ids(
                    SERVICE_RECORD,
                    self.service.service_id,
                    now=self.now,
                )
            ),
            3,
        )
        serialized = introductions.to_json()
        self.assertNotIn("198.51.100.", serialized)
        self.assertNotIn('"host"', serialized)

        unpinned = DistributedResolver(self.network)
        with self.assertRaisesRegex(ResolutionError, "identity pin"):
            unpinned.resolve("forum.granger")

    def test_single_malicious_discovery_peer_cannot_forge_service(self) -> None:
        replica_ids = self.network.replica_node_ids(
            SERVICE_RECORD,
            self.service.service_id,
            now=self.now,
        )
        first_peer = self.peers_by_id[replica_ids[0]]
        envelope = first_peer.fetch(SERVICE_RECORD, self.service.service_id)
        self.assertIsNotNone(envelope)
        assert envelope is not None
        document = json.loads(envelope.payload.decode("ascii"))
        document["metadata"]["title"] = "Forged title"
        forged_payload = (
            json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        forged = replace(envelope, payload=forged_payload)
        first_peer._records[(SERVICE_RECORD, self.service.service_id)] = forged

        resolved = self.resolver.resolve(self.service.canonical_name)
        self.assertEqual(resolved.metadata["title"], "Distributed service")

        for node_id in replica_ids:
            peer = self.peers_by_id[node_id]
            peer._records[(SERVICE_RECORD, self.service.service_id)] = forged
        with self.assertRaises(ResolutionError):
            self.resolver.resolve(self.service.canonical_name)

    def test_introduction_tampering_identity_spoofing_and_replay_fail(self) -> None:
        document = json.loads(self.introductions.to_json())
        document["points"][0]["token"] = document["points"][0]["token"][::-1]
        with self.assertRaises(DescriptorError):
            IntroductionDescriptor.from_json(json.dumps(document), now=self.now)

        attacker = ServiceIdentity.generate()
        attacker_service = ServiceDescriptor.create_remote(
            attacker,
            "distributed-overlay",
            issued_at=self.now,
            lifetime=3600,
        )
        attacker_introduction = IntroductionDescriptor.create(
            attacker,
            attacker_service,
            [self.nodes["introduction"][1].node_id],
            sequence=1,
            issued_at=self.now,
            lifetime=600,
        )
        with self.assertRaises(DescriptorError):
            attacker_introduction.verify_for(self.service, now=self.now)

        newer = IntroductionDescriptor.create(
            self.service_identity,
            self.service,
            [self.nodes["introduction"][1].node_id],
            sequence=2,
            issued_at=self.now + 1,
            lifetime=600,
        )
        self.assertEqual(self.network.publish(newer, now=self.now + 1), 3)
        with self.assertRaises(ReplayError):
            self.network.publish(self.introductions, now=self.now + 1)

        registry = IntroductionRegistry()
        registry.install(newer, self.service, now=self.now + 1)
        with self.assertRaises(ReplayError):
            registry.install(self.introductions, self.service, now=self.now + 1)
        request_nonce = secrets.token_bytes(16)
        point = newer.points[0]
        registry.authorize(
            self.service.service_id,
            point.node_id,
            point.token,
            request_nonce,
            now=self.now + 1,
        )
        with self.assertRaises(ReplayError):
            registry.authorize(
                self.service.service_id,
                point.node_id,
                point.token,
                request_nonce,
                now=self.now + 1,
            )

    def test_multi_hop_circuit_separates_endpoints_keys_and_plaintext(self) -> None:
        route = self.route()
        registry = IntroductionRegistry()
        request_marker = b"private-multihop-request-marker"
        response_marker = b"private-multihop-response-marker"
        circuit: MultiHopCircuit | None = None
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
            patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
            patch(
                "socket.gethostbyname_ex",
                side_effect=AssertionError("DNS used"),
            ) as gethostbyname_ex,
        ):
            try:
                circuit = MultiHopCircuit.open(
                    route,
                    self.runtimes,
                    self.service_identity,
                    registry,
                )
                circuit.client_channel.send_json(
                    {"marker": request_marker.decode("ascii"), "type": "request"}
                )
                self.assertEqual(
                    circuit.service_channel.receive_json(),
                    {"marker": request_marker.decode("ascii"), "type": "request"},
                )
                circuit.client_channel.send_bytes(request_marker)
                self.assertEqual(
                    circuit.service_channel.receive_bytes(),
                    request_marker,
                )
                circuit.service_channel.send_json(
                    {"marker": response_marker.decode("ascii"), "type": "response"}
                )
                self.assertEqual(
                    circuit.client_channel.receive_json(),
                    {"marker": response_marker.decode("ascii"), "type": "response"},
                )
                circuit.service_channel.send_bytes(response_marker)
                self.assertEqual(
                    circuit.client_channel.receive_bytes(),
                    response_marker,
                )
                circuit.assert_healthy()
                self.assertTrue(circuit.all_sessions_use_wire_v3)
                self.assertEqual(circuit.session_count, 11)
                self.assertEqual(circuit.hop_session_count, 10)
                self.assertEqual(len(circuit.unique_session_bindings), 11)
                self.assertEqual(len(circuit.observations), 5)
                self.assertTrue(
                    all(
                        observation.bytes_forwarded > 0
                        for observation in circuit.observations.values()
                    )
                )
                self.assertFalse(circuit.plaintext_observed(request_marker))
                self.assertFalse(circuit.plaintext_observed(response_marker))
                self.assertNotIn(
                    circuit.host_address,
                    circuit.client_visible_addresses,
                )
                self.assertNotIn(
                    circuit.client_address,
                    circuit.host_visible_addresses,
                )
                self.assertFalse(circuit.single_relay_sees_both_endpoints())
                self.assertEqual(circuit.direct_client_host_connections, 0)
            finally:
                if circuit is not None:
                    circuit.close()
        self.assertEqual(getaddrinfo.call_count, 0)
        self.assertEqual(gethostbyname.call_count, 0)
        self.assertEqual(gethostbyname_ex.call_count, 0)
        self.assertTrue(all(node.active_circuits == 0 for node in self.runtimes.values()))

    def test_failed_hop_fails_closed_without_alternate_route(self) -> None:
        route = self.route()
        missing = dict(self.runtimes)
        missing.pop(route.client_middle.node_id)
        with self.assertRaises(OverlayRoutingError):
            MultiHopCircuit.open(
                route,
                missing,
                self.service_identity,
                IntroductionRegistry(),
            )
        self.assertTrue(all(node.active_circuits == 0 for node in self.runtimes.values()))
        with self.assertRaises(DiscoveryError):
            self.resolver.resolve_rendezvous("distributed-overlay")

    def test_discovery_rejects_record_equivocation(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "ASCII"):
            self.network.lookup(SERVICE_RECORD, "invalid-\N{SNOWMAN}", now=self.now)
        replica_id = self.network.replica_node_ids(
            INTRODUCTION_RECORD,
            self.service.service_id,
            now=self.now,
        )[0]
        peer = self.peers_by_id[replica_id]
        envelope = peer.fetch(INTRODUCTION_RECORD, self.service.service_id)
        self.assertIsNotNone(envelope)
        assert envelope is not None
        conflicting = RecordEnvelope(
            envelope.kind,
            envelope.key,
            envelope.sequence,
            envelope.expires_at,
            envelope.payload + b" ",
        )
        with self.assertRaises(DiscoveryError):
            peer.store(conflicting, now=self.now)


if __name__ == "__main__":
    unittest.main()
