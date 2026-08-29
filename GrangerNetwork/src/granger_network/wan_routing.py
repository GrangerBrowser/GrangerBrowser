from __future__ import annotations

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass
from typing import Protocol

from .errors import OverlayRoutingError
from .peer import NodeDescriptor, validate_node_id


ROUTE_SELECTION_DOMAIN = b"granger-network-v0.4/route-selection\x00"
GUARD_SELECTION_DOMAIN = b"granger-network-v0.5/guard-selection\x00"


class _Discovery(Protocol):
    def find_nodes(self, target: bytes, capability: str) -> tuple[NodeDescriptor, ...]: ...


def _selection_target(context: bytes, capability: str) -> bytes:
    if not isinstance(context, bytes) or not isinstance(capability, str):
        raise OverlayRoutingError("route selection context is invalid")
    return hashlib.sha256(
        ROUTE_SELECTION_DOMAIN
        + context
        + b"\x00"
        + capability.encode("ascii")
        + secrets.token_bytes(32)
    ).digest()


def _network_group(descriptor: NodeDescriptor) -> tuple[int, int]:
    address = ipaddress.ip_address(descriptor.endpoint.host)
    prefix = 16 if address.version == 4 else 32
    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    return address.version, int(network.network_address)


def _adjacent_network_group_conflicts(nodes: tuple[NodeDescriptor, ...]) -> int:
    return sum(
        _network_group(current) == _network_group(following)
        for current, following in zip(nodes, nodes[1:])
    )


@dataclass(frozen=True)
class WanRouteSelection:
    route: tuple[tuple[NodeDescriptor, str], ...]
    diversity_relaxed: bool


RelayCombination = tuple[
    int,
    int,
    int,
    NodeDescriptor,
    NodeDescriptor,
    NodeDescriptor,
]


def order_diverse_relay_combinations(
    combinations: list[RelayCombination],
    *,
    limit: int,
) -> tuple[RelayCombination, ...]:
    combinations.sort(key=lambda item: item[:3])
    remaining = list(enumerate(combinations))
    node_use: dict[str, int] = {}
    pair_use: dict[tuple[str, str], int] = {}
    ordered: list[RelayCombination] = []

    def pair_keys(combination: RelayCombination) -> tuple[tuple[str, str], ...]:
        nodes = combination[3:]
        return tuple(
            (nodes[left].node_id, nodes[right].node_id)
            for left in range(len(nodes))
            for right in range(left + 1, len(nodes))
        )

    while remaining and len(ordered) < limit:
        selected_index, selected = min(
            remaining,
            key=lambda item: (
                max(pair_use.get(pair, 0) for pair in pair_keys(item[1])),
                sum(pair_use.get(pair, 0) for pair in pair_keys(item[1])),
                max(node_use.get(node.node_id, 0) for node in item[1][3:]),
                sum(node_use.get(node.node_id, 0) for node in item[1][3:]),
                item[0],
            ),
        )
        ordered.append(selected)
        for node in selected[3:]:
            node_use[node.node_id] = node_use.get(node.node_id, 0) + 1
        for pair in pair_keys(selected):
            pair_use[pair] = pair_use.get(pair, 0) + 1
        remaining = [item for item in remaining if item[0] != selected_index]
    return tuple(ordered)


class WanRouteSelector:
    def __init__(self, discovery: _Discovery, *, guard_seed: bytes | None = None) -> None:
        self.discovery = discovery
        seed = secrets.token_bytes(32) if guard_seed is None else guard_seed
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise OverlayRoutingError("guard selection seed must contain 32 bytes")
        self.guard_seed = seed

    def _candidates(self, target: bytes, capability: str) -> tuple[NodeDescriptor, ...]:
        route_candidates = getattr(self.discovery, "route_candidates", None)
        if callable(route_candidates):
            return route_candidates(target, capability)
        return self.discovery.find_nodes(target, capability)

    def _guard_order(self, candidates: list[NodeDescriptor]) -> list[NodeDescriptor]:
        return sorted(
            candidates,
            key=lambda candidate: hashlib.sha256(
                GUARD_SELECTION_DOMAIN
                + self.guard_seed
                + candidate.node_id.encode("ascii")
            ).digest(),
        )

    def client_prefix(
        self,
        service_id: str,
        *,
        excluded_ids: set[str] | None = None,
    ) -> WanRouteSelection:
        return self.client_candidates(
            service_id,
            excluded_ids=excluded_ids,
            limit=1,
        )[0]

    def client_candidates(
        self,
        service_id: str,
        *,
        excluded_ids: set[str] | None = None,
        limit: int = 8,
    ) -> tuple[WanRouteSelection, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 64:
            raise OverlayRoutingError("route candidate limit is invalid")
        context = service_id.encode("ascii")
        used = {validate_node_id(node_id) for node_id in (excluded_ids or ())}
        accesses = [
            node
            for node in self._candidates(
                _selection_target(context, "access"),
                "access",
            )
            if node.node_id not in used
        ]
        entries = self._guard_order([
            node
            for node in self._candidates(
                _selection_target(context, "entry"),
                "entry",
            )
            if node.node_id not in used
        ])
        middles = [
            node
            for node in self._candidates(
                _selection_target(context, "middle"),
                "middle",
            )
            if node.node_id not in used
        ]
        if not accesses or not entries or not middles:
            raise OverlayRoutingError("no complete client relay route is available")
        result: list[WanRouteSelection] = []
        seen: set[tuple[str, str, str]] = set()
        combinations: list[
            tuple[int, int, int, NodeDescriptor, NodeDescriptor, NodeDescriptor]
        ] = []
        for guard_index, entry in enumerate(entries):
            for access_index, access in enumerate(accesses):
                for middle_index, middle in enumerate(middles):
                    identities = {access.node_id, entry.node_id, middle.node_id}
                    if len(identities) != 3:
                        continue
                    groups = {
                        _network_group(access),
                        _network_group(entry),
                        _network_group(middle),
                    }
                    combinations.append(
                        (
                            3 - len(groups),
                            guard_index,
                            access_index + middle_index,
                            access,
                            entry,
                            middle,
                        )
                    )
        ordered_combinations = order_diverse_relay_combinations(
            combinations,
            limit=limit,
        )
        for relaxation, _guard_index, _offset, access, entry, middle in ordered_combinations:
            route_ids = (access.node_id, entry.node_id, middle.node_id)
            if route_ids in seen:
                continue
            seen.add(route_ids)
            result.append(
                WanRouteSelection(
                    (
                        (access, "access"),
                        (entry, "entry"),
                        (middle, "middle"),
                    ),
                    relaxation > 0,
                )
            )
            if len(result) >= limit:
                break
        if not result:
            raise OverlayRoutingError("no complete client relay route is available")
        return tuple(result)

    def service_route(
        self,
        service_id: str,
        final_node: NodeDescriptor,
        final_role: str,
        *,
        excluded_ids: set[str] | None = None,
        excluded_middle_ids: set[str] | None = None,
    ) -> WanRouteSelection:
        if final_role not in {"introduction", "rendezvous"}:
            raise OverlayRoutingError("service route final role is invalid")
        final_node.verify()
        if final_role not in final_node.capabilities:
            raise OverlayRoutingError("service route final node lacks its role")
        context = service_id.encode("ascii") + final_node.node_id.encode("ascii")
        used = {
            validate_node_id(node_id) for node_id in (excluded_ids or ())
        } | {final_node.node_id}
        blocked_middles = used | {
            validate_node_id(node_id) for node_id in (excluded_middle_ids or ())
        }
        accesses = [
            node
            for node in self._candidates(
                _selection_target(context, "access"), "access"
            )
            if node.node_id not in used
        ]
        guards = self._guard_order([
            node
            for node in self._candidates(
                _selection_target(context, "service-relay"), "service-relay"
            )
            if node.node_id not in used
        ])
        middles = [
            node
            for node in self._candidates(
                _selection_target(context, "middle"), "middle"
            )
            if node.node_id not in blocked_middles
        ]
        choices: list[
            tuple[int, int, int, int, NodeDescriptor, NodeDescriptor, NodeDescriptor]
        ] = []
        for guard_index, guard in enumerate(guards):
            for access_index, access in enumerate(accesses):
                for middle_index, middle in enumerate(middles):
                    nodes = (access, guard, middle, final_node)
                    if len({node.node_id for node in nodes}) != len(nodes):
                        continue
                    groups = {_network_group(node) for node in nodes}
                    choices.append(
                        (
                            len(nodes) - len(groups),
                            _adjacent_network_group_conflicts(nodes),
                            guard_index,
                            access_index + middle_index,
                            access,
                            guard,
                            middle,
                        )
                    )
        if not choices:
            raise OverlayRoutingError("no complete service relay route is available")
        choices.sort(key=lambda item: item[:4])
        relaxation, _adjacency, _guard_index, _offset, access, entry, middle = choices[0]
        return WanRouteSelection(
            (
                (access, "access"),
                (entry, "service-relay"),
                (middle, "middle"),
                (final_node, final_role),
            ),
            relaxation > 0,
        )
