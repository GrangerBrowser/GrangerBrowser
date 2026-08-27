from __future__ import annotations

import unittest

from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_routing import WanRouteSelector


class _StaticDiscovery:
    def __init__(self, nodes: dict[str, tuple[NodeDescriptor, ...]]) -> None:
        self.nodes = nodes

    def find_nodes(self, _target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
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


class WanRouteSelectionTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
