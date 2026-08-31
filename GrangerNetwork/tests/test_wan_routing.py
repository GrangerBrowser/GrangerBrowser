from __future__ import annotations

import unittest

from granger_network.errors import OverlayRoutingError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_routing import WanRouteSelector, select_service_route_set


class _StaticDiscovery:
    def __init__(self, nodes: dict[str, tuple[NodeDescriptor, ...]]) -> None:
        self.nodes = nodes

    def find_nodes(self, _target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        return self.nodes[capability]


class _RouteCandidateDiscovery(_StaticDiscovery):
    def __init__(self, nodes: dict[str, tuple[NodeDescriptor, ...]]) -> None:
        super().__init__(nodes)
        self.route_candidate_calls = 0

    def find_nodes(self, _target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        raise AssertionError(f"DHT lookup was repeated for {capability}")

    def route_candidates(
        self,
        _target: bytes,
        capability: str,
    ) -> tuple[NodeDescriptor, ...]:
        self.route_candidate_calls += 1
        return self.nodes[capability]


def _descriptors(role: str, count: int, port: int) -> tuple[NodeDescriptor, ...]:
    return tuple(
        NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint(f"127.{index + 1}.0.1", port + index),
            (role,),
            RelayPolicy(enabled=True),
            lifetime=3600,
        )
        for index in range(count)
    )


def _service_descriptors() -> tuple[NodeDescriptor, ...]:
    capabilities = (
        "access",
        "introduction",
        "middle",
        "rendezvous",
        "service-relay",
    )
    return tuple(
        NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint(host, 44000 + index),
            capabilities,
            RelayPolicy(enabled=True),
            lifetime=3600,
        )
        for index, host in enumerate(
            ("10.1.0.1", "10.2.0.1", "10.3.0.1", "10.4.0.1")
        )
    )


class WanRouteSelectionTests(unittest.TestCase):
    def test_verified_route_candidate_provider_avoids_repeated_dht_lookups(self) -> None:
        discovery = _RouteCandidateDiscovery(
            {
                "access": _descriptors("access", 2, 40000),
                "entry": _descriptors("entry", 2, 40100),
                "middle": _descriptors("middle", 2, 40200),
            }
        )
        selector = WanRouteSelector(discovery, guard_seed=b"r" * 32)

        candidate = selector.client_prefix("b" * 52)

        self.assertEqual(len(candidate.route), 3)
        self.assertEqual(discovery.route_candidate_calls, 3)

    def test_retry_candidates_keep_stable_primary_guard_and_include_backup(self) -> None:
        accesses = _descriptors("access", 3, 41000)
        entries = _descriptors("entry", 2, 42000)
        middles = _descriptors("middle", 3, 43000)
        selector = WanRouteSelector(
            _StaticDiscovery(
                {
                    "access": accesses,
                    "entry": entries,
                    "middle": middles,
                }
            ),
            guard_seed=b"g" * 32,
        )

        candidates = selector.client_candidates("a" * 52, limit=6)
        preferred_guard = selector._guard_order(list(entries))[0]
        self.assertEqual(candidates[0].route[1][0], preferred_guard)
        self.assertNotEqual(candidates[1].route[1][0], preferred_guard)
        self.assertEqual(
            {candidate.route[1][0].node_id for candidate in candidates},
            {entry.node_id for entry in entries},
        )
        self.assertEqual(
            {
                (candidate.route[1][0].node_id, candidate.route[2][0].node_id)
                for candidate in candidates
            },
            {
                (entry.node_id, middle.node_id)
                for entry in entries
                for middle in middles
            },
        )

    def test_service_middle_exclusion_preserves_four_node_route(self) -> None:
        nodes = _service_descriptors()
        discovery = _StaticDiscovery(
            {capability: nodes for capability in nodes[0].capabilities}
        )
        selector = WanRouteSelector(discovery, guard_seed=b"s" * 32)
        final_node = nodes[0]
        failed_middle = nodes[1]

        selection = selector.service_route(
            "c" * 52,
            final_node,
            "introduction",
            excluded_middle_ids={failed_middle.node_id},
        )

        self.assertEqual(len(selection.route), 4)
        self.assertEqual(len({node.node_id for node, _role in selection.route}), 4)
        self.assertNotEqual(selection.route[2][0].node_id, failed_middle.node_id)
        self.assertIn(
            failed_middle.node_id,
            {node.node_id for node, _role in selection.route},
        )

    def test_exhausted_temporary_middle_exclusions_retry_required_routes(self) -> None:
        nodes = _service_descriptors()
        selector = WanRouteSelector(
            _StaticDiscovery(
                {capability: nodes for capability in nodes[0].capabilities}
            ),
            guard_seed=b"m" * 32,
        )

        introductions, rendezvous, retried = select_service_route_set(
            selector,
            "e" * 52,
            nodes[:2],
            nodes[2],
            failed_middle_ids={node.node_id for node in nodes},
        )

        self.assertTrue(retried)
        self.assertEqual(len(introductions), 2)
        for selection in (*introductions, rendezvous):
            self.assertEqual(len(selection.route), 4)
            self.assertEqual(
                len({node.node_id for node, _role in selection.route}),
                4,
            )

    def test_exhausted_temporary_route_exclusions_retry_required_routes(self) -> None:
        nodes = _service_descriptors()
        selector = WanRouteSelector(
            _StaticDiscovery(
                {capability: nodes for capability in nodes[0].capabilities}
            ),
            guard_seed=b"x" * 32,
        )

        introductions, rendezvous, retried = select_service_route_set(
            selector,
            "f" * 52,
            nodes[:2],
            nodes[2],
            failed_route_ids={node.node_id for node in nodes},
        )

        self.assertTrue(retried)
        self.assertEqual(len(introductions), 2)
        self.assertEqual(len(rendezvous.route), 4)

    def test_temporary_failure_retry_cannot_create_a_three_node_route(self) -> None:
        nodes = _service_descriptors()[:3]
        selector = WanRouteSelector(
            _StaticDiscovery(
                {capability: nodes for capability in nodes[0].capabilities}
            ),
            guard_seed=b"z" * 32,
        )
        with self.assertRaisesRegex(OverlayRoutingError, "no complete service relay route"):
            select_service_route_set(
                selector,
                "g" * 52,
                nodes[:2],
                nodes[2],
                failed_route_ids={node.node_id for node in nodes},
            )

    def test_service_route_separates_relays_from_the_same_network_group(self) -> None:
        capabilities = (
            "access",
            "introduction",
            "middle",
            "rendezvous",
            "service-relay",
        )
        nodes = tuple(
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint(host, 45000 + index),
                capabilities,
                RelayPolicy(enabled=True),
                lifetime=3600,
            )
            for index, host in enumerate(
                ("10.1.0.1", "10.2.0.1", "10.3.10.1", "10.3.20.1")
            )
        )
        selector = WanRouteSelector(
            _StaticDiscovery({capability: nodes for capability in capabilities}),
            guard_seed=b"n" * 32,
        )

        selection = selector.service_route(
            "d" * 52,
            nodes[0],
            "introduction",
        )

        positions = {
            node.node_id: index for index, (node, _role) in enumerate(selection.route)
        }
        self.assertTrue(selection.diversity_relaxed)
        self.assertGreater(
            abs(positions[nodes[2].node_id] - positions[nodes[3].node_id]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
