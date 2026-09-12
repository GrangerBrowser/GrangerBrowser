from __future__ import annotations

from .stage_trace import traced

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass
from typing import Protocol

from .errors import OverlayRoutingError
from .peer import NodeDescriptor, node_supports_route_role, validate_node_id


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


def _middle_follows_anchor(middle: NodeDescriptor, anchor: NodeDescriptor) -> bool:
    return node_supports_route_role(
        middle,
        "middle",
        previous_node_id=anchor.node_id,
    ) and (middle.reachability != "adjacent" or middle.endpoint == anchor.endpoint)


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
    # Identities and ordered pairs are invariant across greedy selection rounds.
    remaining = []
    for index, combination in enumerate(combinations):
        a, b, c = (node.node_id for node in combination[3:])
        remaining.append((index, combination, (a, b, c), ((a, b), (a, c), (b, c))))
    node_use: dict[str, int] = {}
    pair_use: dict[tuple[str, str], int] = {}
    ordered: list[RelayCombination] = []

    def score(item):
        a, b, c = item[2]
        ab, ac, bc = item[3]
        x, y, z = pair_use.get(ab, 0), pair_use.get(ac, 0), pair_use.get(bc, 0)
        na, nb, nc = node_use.get(a, 0), node_use.get(b, 0), node_use.get(c, 0)
        return max(x, y, z), x + y + z, max(na, nb, nc), na + nb + nc, item[0]

    while remaining and len(ordered) < limit:
        selected_index, selected, selected_ids, selected_pairs = min(remaining, key=score)
        ordered.append(selected)
        for node_id in selected_ids:
            node_use[node_id] = node_use.get(node_id, 0) + 1
        for pair in selected_pairs:
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

    @traced("client-route-selection")
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
            if node.node_id not in used and node_supports_route_role(node, "access")
        ]
        entries = self._guard_order([
            node
            for node in self._candidates(
                _selection_target(context, "entry"),
                "entry",
            )
            if node.node_id not in used and node_supports_route_role(node, "entry")
        ])
        middles = [
            node
            for node in self._candidates(
                _selection_target(context, "middle"),
                "middle",
            )
            if node.node_id not in used and node_supports_route_role(node, "middle")
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
                    if not _middle_follows_anchor(middle, entry):
                        continue
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

    @traced("host-route-selection")
    def service_route(
        self,
        service_id: str,
        final_node: NodeDescriptor,
        final_role: str,
        *,
        excluded_ids: set[str] | None = None,
        excluded_access_ids: set[str] | None = None,
        excluded_service_relay_ids: set[str] | None = None,
        excluded_middle_ids: set[str] | None = None,
    ) -> WanRouteSelection:
        if final_role not in {"introduction", "rendezvous"}:
            raise OverlayRoutingError("service route final role is invalid")
        final_node.verify()
        if final_role not in final_node.capabilities:
            raise OverlayRoutingError("service route final node lacks its role")
        if not node_supports_route_role(final_node, final_role):
            raise OverlayRoutingError("service route final node is not directly reachable")
        context = service_id.encode("ascii") + final_node.node_id.encode("ascii")
        used = {
            validate_node_id(node_id) for node_id in (excluded_ids or ())
        } | {final_node.node_id}
        blocked_accesses = used | {
            validate_node_id(node_id) for node_id in (excluded_access_ids or ())
        }
        blocked_service_relays = used | {
            validate_node_id(node_id)
            for node_id in (excluded_service_relay_ids or ())
        }
        blocked_middles = used | {
            validate_node_id(node_id) for node_id in (excluded_middle_ids or ())
        }
        accesses = [
            node
            for node in self._candidates(
                _selection_target(context, "access"), "access"
            )
            if node.node_id not in blocked_accesses
            and node_supports_route_role(node, "access")
        ]
        guards = self._guard_order([
            node
            for node in self._candidates(
                _selection_target(context, "service-relay"), "service-relay"
            )
            if node.node_id not in blocked_service_relays
            and node_supports_route_role(node, "service-relay")
        ])
        middles = [
            node
            for node in self._candidates(
                _selection_target(context, "middle"), "middle"
            )
            if node.node_id not in blocked_middles
            and node_supports_route_role(node, "middle")
        ]
        choices: list[
            tuple[int, int, int, int, NodeDescriptor, NodeDescriptor, NodeDescriptor]
        ] = []
        for guard_index, guard in enumerate(guards):
            for access_index, access in enumerate(accesses):
                for middle_index, middle in enumerate(middles):
                    if not _middle_follows_anchor(middle, guard):
                        continue
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


@traced("host-route-set")
def select_service_route_set(
    selector: WanRouteSelector,
    service_id: str,
    introduction_nodes: tuple[NodeDescriptor, ...] | list[NodeDescriptor],
    rendezvous_node: NodeDescriptor,
    *,
    failed_route_ids: set[str] | None = None,
    failed_access_ids: set[str] | None = None,
    failed_service_relay_ids: set[str] | None = None,
    failed_middle_ids: set[str] | None = None,
) -> tuple[tuple[WanRouteSelection, ...], WanRouteSelection, bool]:
    """Retry transient failure hints without relaxing the selector's route policy."""
    blocked_ids = set(failed_route_ids or ())
    blocked_accesses = set(failed_access_ids or ())
    blocked_service_relays = set(failed_service_relay_ids or ())
    blocked_middles = set(failed_middle_ids or ())
    if blocked_ids and (blocked_accesses or blocked_service_relays or blocked_middles):
        raise OverlayRoutingError("service route exclusions are ambiguous")

    def select(
        route_ids: set[str] | None,
        access_ids: set[str] | None,
        service_relay_ids: set[str] | None,
        middle_ids: set[str] | None,
    ) -> tuple[tuple[WanRouteSelection, ...], WanRouteSelection]:
        introductions = tuple(
            selector.service_route(
                service_id,
                node,
                "introduction",
                excluded_ids=route_ids,
                excluded_access_ids=access_ids,
                excluded_service_relay_ids=service_relay_ids,
                excluded_middle_ids=middle_ids,
            )
            for node in introduction_nodes
        )
        rendezvous = selector.service_route(
            service_id,
            rendezvous_node,
            "rendezvous",
            excluded_ids=route_ids,
            excluded_access_ids=access_ids,
            excluded_service_relay_ids=service_relay_ids,
            excluded_middle_ids=middle_ids,
        )
        return introductions, rendezvous

    try:
        introductions, rendezvous = select(
            blocked_ids,
            blocked_accesses,
            blocked_service_relays,
            blocked_middles,
        )
        return introductions, rendezvous, False
    except OverlayRoutingError:
        if not (
            blocked_ids
            or blocked_accesses
            or blocked_service_relays
            or blocked_middles
        ):
            raise
    introductions, rendezvous = select(None, None, None, None)
    return introductions, rendezvous, True
