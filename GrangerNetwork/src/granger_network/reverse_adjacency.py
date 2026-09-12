from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from .errors import DescriptorError, ResourceLimitError
from .peer import ADJACENT_NODE_DESCRIPTOR_VERSION, NodeDescriptor
from .peer_rpc import AuthenticatedPeer, PeerRole


@dataclass(frozen=True)
class ReverseAdjacencySnapshot:
    active_peers: int
    active_slots: int
    registrations: int
    acquired_slots: int
    rejected_registrations: int
    expired_slots: int

    def to_document(self) -> dict[str, int]:
        return {
            "acquiredSlots": self.acquired_slots,
            "activePeers": self.active_peers,
            "activeSlots": self.active_slots,
            "expiredSlots": self.expired_slots,
            "registrations": self.registrations,
            "rejectedRegistrations": self.rejected_registrations,
        }


@dataclass(frozen=True)
class _ReverseSlot:
    descriptor: NodeDescriptor
    peer: AuthenticatedPeer


class ReverseAdjacencyPool:
    """Bounded one-shot sessions offered by outbound-only relay peers."""

    def __init__(
        self,
        anchor: NodeDescriptor,
        *,
        max_peers: int = 128,
        max_slots_per_peer: int = 4,
        max_total_slots: int = 256,
        minimum_remaining_lifetime: int = 5,
        clock: Callable[[], float] = time.time,
        on_discard: Callable[[AuthenticatedPeer], None] | None = None,
    ) -> None:
        anchor.verify()
        if anchor.reachability != "reachable":
            raise DescriptorError("reverse adjacency anchor must be directly reachable")
        for value, minimum, maximum, label in (
            (max_peers, 1, 4096, "reverse adjacency peer limit"),
            (max_slots_per_peer, 1, 32, "reverse adjacency per-peer slot limit"),
            (max_total_slots, 1, 16384, "reverse adjacency slot limit"),
            (minimum_remaining_lifetime, 1, 300, "reverse adjacency lifetime floor"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ResourceLimitError(f"{label} is invalid")
        if max_total_slots < max_slots_per_peer:
            raise ResourceLimitError("reverse adjacency total limit is smaller than its per-peer limit")
        if not callable(clock):
            raise ResourceLimitError("reverse adjacency clock is invalid")
        self.anchor = anchor
        self.max_peers = max_peers
        self.max_slots_per_peer = max_slots_per_peer
        self.max_total_slots = max_total_slots
        self.minimum_remaining_lifetime = minimum_remaining_lifetime
        self._clock = clock
        self._on_discard = on_discard or (lambda peer: peer.close())
        self._slots: dict[str, deque[_ReverseSlot]] = {}
        self._latest: dict[str, NodeDescriptor] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._registrations = 0
        self._acquired_slots = 0
        self._rejected_registrations = 0
        self._expired_slots = 0

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ResourceLimitError("reverse adjacency clock is invalid")
        return int(value)

    def _validate_descriptor(self, descriptor: NodeDescriptor, *, now: int) -> None:
        descriptor.verify(
            now=now,
            expected_network_id=self.anchor.network_id,
            expected_protocol_version=self.anchor.protocol_version,
        )
        if (
            descriptor.version != ADJACENT_NODE_DESCRIPTOR_VERSION
            or descriptor.reachability != "adjacent"
            or descriptor.via_node_id != self.anchor.node_id
            or descriptor.endpoint != self.anchor.endpoint
            or descriptor.capabilities != ("middle",)
        ):
            raise DescriptorError("reverse adjacency descriptor is not bound to this anchor")
        if descriptor.expires_at - now < self.minimum_remaining_lifetime:
            raise DescriptorError("reverse adjacency descriptor expires too soon")

    def _validate_peer(self, peer: AuthenticatedPeer, *, now: int) -> NodeDescriptor:
        if not isinstance(peer, AuthenticatedPeer):
            raise DescriptorError("reverse adjacency peer is invalid")
        descriptor = peer.remote.descriptor
        if peer.remote.role is not PeerRole.RELAY or descriptor is None:
            raise DescriptorError("reverse adjacency requires an authenticated relay descriptor")
        if descriptor.identity_public_key != peer.remote.public_key:
            raise DescriptorError("reverse adjacency identity does not match its authenticated peer")
        self._validate_descriptor(descriptor, now=now)
        return descriptor

    def _purge_locked(self, now: int) -> list[AuthenticatedPeer]:
        discarded: list[AuthenticatedPeer] = []
        for node_id, slots in tuple(self._slots.items()):
            retained = deque(slot for slot in slots if slot.descriptor.expires_at > now)
            self._expired_slots += len(slots) - len(retained)
            discarded.extend(slot.peer for slot in slots if slot.descriptor.expires_at <= now)
            if retained:
                self._slots[node_id] = retained
            else:
                self._slots.pop(node_id, None)
                self._latest.pop(node_id, None)
        return discarded

    def _discard_all(self, peers: list[AuthenticatedPeer]) -> None:
        for peer in peers:
            self._on_discard(peer)

    def register(self, peer: AuthenticatedPeer) -> NodeDescriptor:
        now = self._now()
        try:
            descriptor = self._validate_peer(peer, now=now)
        except Exception:
            with self._lock:
                self._rejected_registrations += 1
            raise
        discarded: list[AuthenticatedPeer]
        try:
            with self._lock:
                if self._closed:
                    raise ResourceLimitError("reverse adjacency pool is closed")
                discarded = self._purge_locked(now)
                previous = self._latest.get(descriptor.node_id)
                if previous is not None:
                    if descriptor.issued_at < previous.issued_at:
                        raise DescriptorError("reverse adjacency descriptor rolled back")
                    if descriptor.issued_at == previous.issued_at and descriptor != previous:
                        raise DescriptorError("reverse adjacency descriptor equivocated")
                    if descriptor.issued_at > previous.issued_at:
                        replaced = self._slots.pop(descriptor.node_id, deque())
                        discarded.extend(slot.peer for slot in replaced)
                slots = self._slots.setdefault(descriptor.node_id, deque())
                active_peers = sum(bool(value) for value in self._slots.values())
                total_slots = sum(len(value) for value in self._slots.values())
                if not slots and active_peers >= self.max_peers:
                    self._slots.pop(descriptor.node_id, None)
                    raise ResourceLimitError("reverse adjacency peer limit is exhausted")
                if len(slots) >= self.max_slots_per_peer:
                    raise ResourceLimitError("reverse adjacency per-peer slot limit is exhausted")
                if total_slots >= self.max_total_slots:
                    if not slots:
                        self._slots.pop(descriptor.node_id, None)
                    raise ResourceLimitError("reverse adjacency slot limit is exhausted")
                slots.append(_ReverseSlot(descriptor, peer))
                self._latest[descriptor.node_id] = descriptor
                self._registrations += 1
        except Exception:
            with self._lock:
                self._rejected_registrations += 1
            raise
        finally:
            if "discarded" in locals():
                self._discard_all(discarded)
        return descriptor

    def discard(self, peer: AuthenticatedPeer) -> None:
        removed = False
        with self._lock:
            for node_id, slots in tuple(self._slots.items()):
                retained = deque(slot for slot in slots if slot.peer is not peer)
                if len(retained) != len(slots):
                    removed = True
                if retained:
                    self._slots[node_id] = retained
                else:
                    self._slots.pop(node_id, None)
                    self._latest.pop(node_id, None)
        if removed:
            self._on_discard(peer)

    def acquire(self, expected: NodeDescriptor) -> AuthenticatedPeer:
        now = self._now()
        self._validate_descriptor(expected, now=now)
        discarded: list[AuthenticatedPeer] = []
        try:
            with self._lock:
                if self._closed:
                    raise ResourceLimitError("reverse adjacency pool is closed")
                discarded = self._purge_locked(now)
                latest = self._latest.get(expected.node_id)
                if latest is None or latest != expected:
                    raise DescriptorError("reverse adjacency route descriptor is stale or unavailable")
                slots = self._slots.get(expected.node_id)
                if not slots:
                    raise ResourceLimitError("reverse adjacency has no available session")
                slot = slots.popleft()
                if not slots:
                    self._slots.pop(expected.node_id, None)
                    self._latest.pop(expected.node_id, None)
                self._acquired_slots += 1
            return slot.peer
        finally:
            self._discard_all(discarded)

    def available(self, descriptor: NodeDescriptor) -> bool:
        discarded: list[AuthenticatedPeer] = []
        try:
            now = self._now()
            self._validate_descriptor(descriptor, now=now)
            with self._lock:
                if self._closed:
                    return False
                discarded = self._purge_locked(now)
                return (
                    self._latest.get(descriptor.node_id) == descriptor
                    and bool(self._slots.get(descriptor.node_id))
                )
        except DescriptorError:
            return False
        finally:
            self._discard_all(discarded)

    def descriptors(self) -> tuple[NodeDescriptor, ...]:
        discarded: list[AuthenticatedPeer]
        with self._lock:
            discarded = self._purge_locked(self._now())
            descriptors = tuple(
                self._latest[node_id]
                for node_id, slots in self._slots.items()
                if slots and node_id in self._latest
            )
        self._discard_all(discarded)
        return descriptors

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            peers = [slot.peer for slots in self._slots.values() for slot in slots]
            self._slots.clear()
            self._latest.clear()
        self._discard_all(peers)

    def snapshot(self) -> ReverseAdjacencySnapshot:
        discarded: list[AuthenticatedPeer]
        with self._lock:
            discarded = self._purge_locked(self._now())
            snapshot = ReverseAdjacencySnapshot(
                active_peers=sum(bool(slots) for slots in self._slots.values()),
                active_slots=sum(len(slots) for slots in self._slots.values()),
                registrations=self._registrations,
                acquired_slots=self._acquired_slots,
                rejected_registrations=self._rejected_registrations,
                expired_slots=self._expired_slots,
            )
        self._discard_all(discarded)
        return snapshot
