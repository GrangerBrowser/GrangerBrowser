from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from enum import Enum


class NetworkState(str, Enum):
    OFFLINE = "OFFLINE"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    JOINING = "JOINING"
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    RESEEDING = "RESEEDING"


@dataclass(frozen=True)
class NetworkHealthSnapshot:
    state: NetworkState = NetworkState.OFFLINE
    bootstrap_attempted: int = 0
    authenticated_peers: int = 0
    known_peers: int = 0
    reachable_relays: int = 0
    dht_ready: bool = False
    failure_reason: str = ""
    updated_at: int = 0

    def to_document(self) -> dict[str, object]:
        return {
            "authenticatedPeers": self.authenticated_peers,
            "bootstrapAttempted": self.bootstrap_attempted,
            "dhtReady": self.dht_ready,
            "failureReason": self.failure_reason,
            "knownPeers": self.known_peers,
            "reachableRelays": self.reachable_relays,
            "state": self.state.value,
            "updatedAt": self.updated_at,
            "version": 1,
        }


class NetworkHealth:
    """Thread-safe, metadata-minimal network readiness state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot = NetworkHealthSnapshot(updated_at=int(time.time()))

    def snapshot(self) -> NetworkHealthSnapshot:
        with self._lock:
            return self._snapshot

    def update(
        self,
        state: NetworkState,
        *,
        bootstrap_attempted: int | None = None,
        authenticated_peers: int | None = None,
        known_peers: int | None = None,
        reachable_relays: int | None = None,
        dht_ready: bool | None = None,
        failure_reason: str | None = None,
    ) -> NetworkHealthSnapshot:
        if not isinstance(state, NetworkState):
            raise ValueError("network health state is invalid")
        with self._lock:
            current = self._snapshot
            values: dict[str, object] = {
                "state": state,
                "updated_at": int(time.time()),
            }
            for name, value in (
                ("bootstrap_attempted", bootstrap_attempted),
                ("authenticated_peers", authenticated_peers),
                ("known_peers", known_peers),
                ("reachable_relays", reachable_relays),
                ("dht_ready", dht_ready),
                ("failure_reason", failure_reason),
            ):
                if value is not None:
                    values[name] = value
            candidate = replace(current, **values)
            for count in (
                candidate.bootstrap_attempted,
                candidate.authenticated_peers,
                candidate.known_peers,
                candidate.reachable_relays,
            ):
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise ValueError("network health counter is invalid")
            if not isinstance(candidate.dht_ready, bool):
                raise ValueError("network health DHT state is invalid")
            if not isinstance(candidate.failure_reason, str) or len(candidate.failure_reason) > 128:
                raise ValueError("network health failure reason is invalid")
            self._snapshot = candidate
            return candidate
