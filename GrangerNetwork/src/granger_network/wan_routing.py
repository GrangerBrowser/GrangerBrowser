from __future__ import annotations

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass

from .errors import OverlayRoutingError
from .peer import NodeDescriptor, validate_node_id
from .wan_discovery import WanDiscoveryClient


ROUTE_SELECTION_DOMAIN = b"granger-network-v0.4/route-selection\x00"


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


@dataclass(frozen=True)
class WanRouteSelection:
    route: tuple[tuple[NodeDescriptor, str], ...]
    diversity_relaxed: bool


class WanRouteSelector:
    def __init__(self, discovery: WanDiscoveryClient) -> None:
        self.discovery = discovery

    def _choose(
        self,
        capability: str,
        context: bytes,
        excluded_ids: set[str],
        excluded_groups: set[tuple[int, int]],
    ) -> tuple[NodeDescriptor, bool]:
        candidates = [
            candidate
            for candidate in self.discovery.find_nodes(
                _selection_target(context, capability),
                capability,
            )
            if candidate.node_id not in excluded_ids
        ]
        if not candidates:
            raise OverlayRoutingError(f"no reachable {capability} relay is available")
        diverse = [
            candidate
            for candidate in candidates
            if _network_group(candidate) not in excluded_groups
        ]
        return (diverse[0], False) if diverse else (candidates[0], True)

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
        entries = [
            node
            for node in self.discovery.find_nodes(
                _selection_target(context, "entry"),
                "entry",
            )
            if node.node_id not in used
        ]
        middles = [
            node
            for node in self.discovery.find_nodes(
                _selection_target(context, "middle"),
                "middle",
            )
            if node.node_id not in used
        ]
        if not entries or not middles:
            raise OverlayRoutingError("no complete client relay route is available")
        result: list[WanRouteSelection] = []
        seen: set[tuple[str, str]] = set()
        rounds = max(len(entries), len(middles))
        for offset in range(rounds):
            for entry_index, entry in enumerate(entries):
                middle = middles[(entry_index + offset) % len(middles)]
                pair = (entry.node_id, middle.node_id)
                if entry.node_id == middle.node_id or pair in seen:
                    continue
                seen.add(pair)
                result.append(
                    WanRouteSelection(
                        ((entry, "entry"), (middle, "middle")),
                        _network_group(entry) == _network_group(middle),
                    )
                )
                if len(result) >= limit:
                    return tuple(result)
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
        groups = {_network_group(final_node)}
        entry, relaxed_entry = self._choose("service-relay", context, used, groups)
        used.add(entry.node_id)
        groups.add(_network_group(entry))
        middle, relaxed_middle = self._choose("middle", context, used, groups)
        return WanRouteSelection(
            (
                (entry, "service-relay"),
                (middle, "middle"),
                (final_node, final_role),
            ),
            relaxed_entry or relaxed_middle,
        )
