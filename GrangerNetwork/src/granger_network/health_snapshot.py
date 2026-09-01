from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterable, Mapping
from pathlib import Path


SNAPSHOT_VERSION = 1
NETWORK_HEALTH_MAX_AGE_SECONDS = 120
_SERVICE_ADDRESS = re.compile(r"^[a-z2-7]{52}\.granger$")
_SOURCE_VERSION = re.compile(r"^[A-Za-z0-9._+\-]{1,64}$")
_REASON_CODES = frozenset({
    "AUTH_HANDSHAKE_TIMEOUT",
    "AUTH_IDENTITY_REJECTED",
    "CIRCUIT_BUILD_FAILED",
    "DHT_HEALTH_STALE",
    "DHT_LOOKUP_TIMEOUT",
    "DHT_UNAVAILABLE",
    "FIRST_CONTACT_FAILED",
    "FIRST_CONTACT_MULTIPLE_FAILURES",
    "GENERATION_EXPIRED",
    "HOST_PROCESS_DEAD",
    "HOST_STATUS_STALE",
    "HOST_WORKER_UNAVAILABLE",
    "I2P_NOT_READY",
    "INSUFFICIENT_DHT_PEERS",
    "INTRO_DESCRIPTOR_EXPIRED",
    "INTRO_DESCRIPTOR_STALE",
    "INTRO_HEARTBEAT_STALE",
    "INTRO_REJECTED",
    "NETWORK_HEALTH_STALE",
    "NETWORK_UNAVAILABLE",
    "NO_RESEED_SOURCE",
    "NO_ROUTE_CANDIDATES",
    "PEER_SAMPLE_TIMEOUT",
    "PEER_DESCRIPTOR_EXPIRED",
    "RENDEZVOUS_TIMEOUT",
    "RESEED_EXPIRED",
    "ROUTE_RECOVERY",
    "SERVICE_DESCRIPTOR_EXPIRED",
    "SESSION_LIMIT_REACHED",
    "STOPPED",
    "TCP_CONNECT_TIMEOUT",
    "TOR_TLS_TIMEOUT",
    "UNCLASSIFIED_FAILURE",
})


def _integer(value: object, default: int = 0, *, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return min(maximum, max(0, value))


def _boolean(value: object) -> bool:
    return value is True


def _reason(value: object, default: str = "") -> str:
    if not isinstance(value, str):
        return default
    candidate = value.strip().upper().replace("-", "_")
    return candidate if candidate in _REASON_CODES else default


def _age(now: int, timestamp: object) -> int | None:
    value = _integer(timestamp)
    if value <= 0 or value > now:
        return None
    return now - value


def _remaining(now: int, timestamp: object) -> int:
    return max(0, _integer(timestamp) - now)


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _bounded_ages(value: object) -> tuple[int, int] | None:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return None
    ages = [_integer(item, maximum=7 * 24 * 60 * 60) for item in value]
    ages = [item for item in ages if item > 0]
    return (min(ages), max(ages)) if ages else None


def build_health_snapshot(
    *,
    generation: Mapping[str, object] | None = None,
    network: Mapping[str, object] | None = None,
    peers: Iterable[Mapping[str, object]] = (),
    routing: Mapping[str, object] | None = None,
    hosting: Mapping[str, object] | None = None,
    rendezvous: Mapping[str, object] | None = None,
    resources: Mapping[str, object] | None = None,
    tor: Mapping[str, object] | None = None,
    i2p: Mapping[str, object] | None = None,
    required_peers: int = 4,
    started_at: int = 0,
    source_version: str = "",
    now: int | None = None,
) -> dict[str, object]:
    """Build a bounded observer snapshot from existing runtime documents.

    Input mappings are treated as untrusted. Only explicitly selected metadata
    leaves this boundary; raw errors, paths, payloads, headers, and addresses do
    not. The result never participates in routing or health decisions.
    """

    current = int(time.time()) if now is None else _integer(now)
    if current <= 0:
        raise ValueError("snapshot time is invalid")
    required = _integer(required_peers, default=4, maximum=64)
    if required < 2:
        required = 4

    generation_document = _mapping(generation)
    network_document = _mapping(network)
    routing_document = _mapping(routing)
    hosting_document = _mapping(hosting)
    rendezvous_document = _mapping(rendezvous)
    resources_document = _mapping(resources)
    tor_document = _mapping(tor)
    i2p_document = _mapping(i2p)

    generation_number = _integer(generation_document.get("generation"))
    generation_expiry = _integer(generation_document.get("expiresAt"))
    protocol_version = _integer(
        generation_document.get("protocolVersion", network_document.get("protocolVersion")),
        maximum=255,
    )
    generation_missing = generation_number <= 0 or generation_expiry <= 0
    generation_expired = not generation_missing and generation_expiry <= current

    reported_authenticated = _integer(
        network_document.get("authenticatedPeers"), maximum=64
    )
    dht_ready = _boolean(network_document.get("dhtReady"))
    network_age = _age(current, network_document.get("updatedAt"))
    network_stale = network_age is None or network_age > NETWORK_HEALTH_MAX_AGE_SECONDS
    reported_state = str(network_document.get("state", "OFFLINE")).upper()
    network_reason = _reason(network_document.get("failureReason"))

    peer_documents = tuple(_mapping(peer) for peer in peers)
    authenticated_peers = tuple(peer for peer in peer_documents if _boolean(peer.get("authenticated")))
    authenticated = (
        min(reported_authenticated, len(authenticated_peers))
        if peer_documents else reported_authenticated
    )
    descriptor_expiries = tuple(
        _integer(peer.get("descriptorExpiresAt")) for peer in authenticated_peers
    )
    valid_descriptors = sum(expiry > current for expiry in descriptor_expiries)
    last_contacts = tuple(
        _integer(peer.get("lastAuthenticatedAt")) for peer in authenticated_peers
    )
    latest_contact = max(last_contacts, default=0)
    peer_reason = next(
        (
            reason for reason in (
                _reason(peer.get("failureReason")) for peer in peer_documents
            ) if reason
        ),
        "",
    )

    if generation_missing:
        network_state = "FAILED"
        network_reason = "NO_RESEED_SOURCE"
    elif generation_expired:
        network_state = "FAILED"
        network_reason = "GENERATION_EXPIRED"
    elif reported_state in {"BOOTSTRAPPING", "JOINING", "RESEEDING", "STARTING"}:
        network_state = "STARTING"
    elif reported_state == "OFFLINE":
        network_state = "OFFLINE"
        network_reason = network_reason or "NETWORK_UNAVAILABLE"
    elif network_stale:
        network_state = "DEGRADED"
        network_reason = "NETWORK_HEALTH_STALE"
    elif authenticated < required:
        network_state = "DEGRADED"
        network_reason = "INSUFFICIENT_DHT_PEERS"
    elif peer_documents and valid_descriptors < required:
        network_state = "DEGRADED"
        network_reason = "PEER_DESCRIPTOR_EXPIRED"
    elif not dht_ready or reported_state != "CONNECTED":
        network_state = "DEGRADED"
        network_reason = network_reason or "DHT_UNAVAILABLE"
    else:
        network_state = "CONNECTED"
        network_reason = ""

    circuit_ages = _bounded_ages(routing_document.get("circuitAgesSeconds"))
    routing_snapshot: dict[str, object] = {
        "buildingCircuits": _integer(routing_document.get("buildingCircuits"), maximum=4096),
        "lastFailureReason": _reason(routing_document.get("lastFailureReason")),
        "retiringCircuits": _integer(routing_document.get("retiringCircuits"), maximum=4096),
        "rotationCount": _integer(
            routing_document.get(
                "rotationCount", network_document.get("circuitRotations")
            )
        ),
        "usableCircuits": _integer(
            routing_document.get(
                "usableCircuits", network_document.get("activeServiceCircuits")
            ),
            maximum=4096,
        ),
    }
    if circuit_ages is not None:
        routing_snapshot["circuitAgeRangeSeconds"] = {
            "maximum": circuit_ages[1],
            "minimum": circuit_ages[0],
        }

    hosting_state = str(hosting_document.get("state", "OFFLINE")).upper()
    if hosting_state not in {
        "OFFLINE", "STARTING", "ONLINE", "DEGRADED", "STOPPING", "FAILED",
    }:
        hosting_state = "FAILED"
    hosting_reason = _reason(
        hosting_document.get("healthReason", hosting_document.get("failureReason"))
    )
    status_age = _age(current, hosting_document.get("updatedAt"))
    heartbeat_age = _age(current, hosting_document.get("lastHeartbeatAt"))
    health_lease = _integer(hosting_document.get("healthLeaseSeconds"), default=30, maximum=3600)
    pid_alive = _boolean(hosting_document.get("pidAlive"))
    if hosting_state == "ONLINE" and not pid_alive:
        hosting_state = "OFFLINE"
        hosting_reason = "HOST_PROCESS_DEAD"
    elif hosting_state == "ONLINE" and (
        status_age is None or status_age > max(1, health_lease)
    ):
        hosting_state = "DEGRADED"
        hosting_reason = "HOST_STATUS_STALE"
    elif hosting_state == "ONLINE" and (
        heartbeat_age is not None and heartbeat_age > max(1, health_lease)
    ):
        hosting_state = "DEGRADED"
        hosting_reason = "INTRO_HEARTBEAT_STALE"

    service_expiry = _integer(hosting_document.get("serviceDescriptorExpiresAt"))
    intro_expiry = _integer(hosting_document.get("introductionExpiresAt"))
    if service_expiry and service_expiry <= current:
        hosting_state = "FAILED"
        hosting_reason = "SERVICE_DESCRIPTOR_EXPIRED"
    elif intro_expiry and intro_expiry <= current:
        hosting_state = "DEGRADED"
        hosting_reason = "INTRO_DESCRIPTOR_EXPIRED"
    address = hosting_document.get("canonicalName")

    tor_progress = _integer(tor_document.get("bootstrapProgress"), maximum=100)
    tor_verified = _boolean(tor_document.get("routeVerified")) and tor_progress == 100
    tor_running = _boolean(tor_document.get("processRunning"))
    tor_reason = _reason(tor_document.get("failureReason"))
    tor_state = (
        "CONNECTED" if tor_verified else
        "FAILED" if tor_reason else
        "STARTING" if tor_running else
        "OFF"
    )

    i2p_running = _boolean(i2p_document.get("processRunning"))
    i2p_ready = _boolean(i2p_document.get("ready")) and _boolean(
        i2p_document.get("routeVerified")
    )
    i2p_reason = _reason(i2p_document.get("failureReason"))
    if i2p_running and not i2p_ready and not i2p_reason:
        i2p_reason = "I2P_NOT_READY"
    i2p_state = (
        "READY" if i2p_ready else
        "FAILED" if i2p_reason and not i2p_running else
        "STARTING" if i2p_running else
        "OFF"
    )

    source = source_version if _SOURCE_VERSION.fullmatch(source_version) else ""
    dht_state = (
        "READY" if network_state == "CONNECTED" and dht_ready else
        "FAILED" if network_state == "FAILED" else
        "OFFLINE" if network_state == "OFFLINE" else
        "STARTING" if network_state == "STARTING" else
        "DEGRADED"
    )
    snapshot: dict[str, object] = {
        "dht": {
            "currentQuorum": authenticated,
            "lastFailureReason": network_reason if not dht_ready else "",
            "lastSuccessfulLookupAgeSeconds": _age(
                current, network_document.get("lastSuccessfulLookupAt")
            ),
            "ready": network_state == "CONNECTED" and dht_ready,
            "requiredQuorum": required,
            "state": dht_state,
        },
        "generatedAt": current,
        "hosting": {
            "activeSessions": _integer(hosting_document.get("activeSessions"), maximum=4096),
            "heartbeatAgeSeconds": heartbeat_age,
            "hostPid": _integer(hosting_document.get("pid"), maximum=2**31 - 1),
            "introExpiry": intro_expiry,
            "introRemainingSeconds": _remaining(current, intro_expiry),
            "introSequence": _integer(hosting_document.get("introductionSequence")),
            "lastFailureReason": hosting_reason,
            "lastRendezvousAgeSeconds": _age(
                current, hosting_document.get("lastSuccessfulRendezvousAt")
            ),
            "pendingHandshakes": _integer(hosting_document.get("pendingSessions"), maximum=4096),
            "serviceDescriptorExpiry": service_expiry,
            "sessionLimit": _integer(hosting_document.get("sessionLimit"), maximum=4096),
            "state": hosting_state,
            "statusAgeSeconds": status_age,
        },
        "i2p": {
            "lastFailureReason": i2p_reason,
            "ready": i2p_ready,
            "state": i2p_state,
        },
        "network": {
            "failClosed": network_state != "CONNECTED",
            "failClosedReason": network_reason,
            "generationExpiry": generation_expiry,
            "generationRemainingSeconds": _remaining(current, generation_expiry),
            "generationSequence": generation_number,
            "protocolVersion": protocol_version,
            "state": network_state,
            "statusAgeSeconds": network_age,
        },
        "peers": {
            "authenticated": authenticated,
            "descriptorExpiry": min(descriptor_expiries, default=0),
            "descriptorRemainingSeconds": min(
                (_remaining(current, value) for value in descriptor_expiries),
                default=0,
            ),
            "lastFailureReason": peer_reason,
            "lastSuccessfulContactAgeSeconds": _age(current, latest_contact),
            "required": required,
            "validDescriptors": valid_descriptors,
        },
        "rendezvous": {
            "abandonedHandshakes": _integer(
                rendezvous_document.get("abandonedHandshakes"), maximum=2**31 - 1
            ),
            "activeSessions": _integer(rendezvous_document.get("activeSessions"), maximum=4096),
            "pendingGrants": _integer(rendezvous_document.get("pendingGrants"), maximum=4096),
            "rejectedAtLimit": _integer(
                rendezvous_document.get("rejectedAtLimit"), maximum=2**31 - 1
            ),
            "successfulSessions": _integer(
                rendezvous_document.get("successfulSessions"), maximum=2**31 - 1
            ),
        },
        "resources": {
            "processRssBytes": _integer(resources_document.get("processRssBytes")),
            "socketCount": _integer(resources_document.get("socketCount"), maximum=65536),
            "workerCount": _integer(resources_document.get("workerCount"), maximum=65536),
        },
        "routing": routing_snapshot,
        "sourceVersion": source,
        "tor": {
            "bootstrapProgress": tor_progress,
            "lastFailureReason": tor_reason,
            "routeVerified": tor_verified,
            "state": tor_state,
        },
        "uptimeSeconds": _age(current, started_at),
        "version": SNAPSHOT_VERSION,
    }
    if isinstance(address, str) and _SERVICE_ADDRESS.fullmatch(address):
        snapshot["hosting"]["serviceAddress"] = address
    return snapshot


def write_health_snapshot(path: Path, **sources: object) -> dict[str, object]:
    destination = Path(path).resolve()
    snapshot = build_health_snapshot(**sources)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    encoded = json.dumps(snapshot, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return snapshot


def try_write_health_snapshot(path: Path, **sources: object) -> bool:
    """Best-effort observer export; network/runtime callers never depend on it."""

    try:
        write_health_snapshot(path, **sources)
        return True
    except (OSError, TypeError, ValueError):
        return False
