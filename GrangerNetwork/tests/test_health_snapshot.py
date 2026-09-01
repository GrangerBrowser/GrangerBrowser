from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from granger_network.health_snapshot import (
    build_health_snapshot,
    try_write_health_snapshot,
    write_health_snapshot,
)


NOW = 2_000_000_000
ADDRESS = "a" * 52 + ".granger"


def healthy_sources() -> dict[str, object]:
    return {
        "generation": {
            "expiresAt": NOW + 3600,
            "generation": 8,
            "protocolVersion": 3,
        },
        "network": {
            "authenticatedPeers": 4,
            "dhtReady": True,
            "state": "CONNECTED",
            "updatedAt": NOW - 2,
        },
        "peers": tuple(
            {
                "authenticated": True,
                "descriptorExpiresAt": NOW + 7200,
                "lastAuthenticatedAt": NOW - index,
            }
            for index in range(1, 5)
        ),
        "required_peers": 4,
        "now": NOW,
    }


class HealthSnapshotTests(unittest.TestCase):
    def test_healthy_four_peer_network_is_connected(self) -> None:
        snapshot = build_health_snapshot(**healthy_sources())
        self.assertEqual(snapshot["network"]["state"], "CONNECTED")
        self.assertFalse(snapshot["network"]["failClosed"])
        self.assertEqual(snapshot["peers"]["authenticated"], 4)
        self.assertEqual(snapshot["peers"]["validDescriptors"], 4)
        self.assertTrue(snapshot["dht"]["ready"])

    def test_three_of_four_is_degraded_and_tcp_only_peer_is_not_authenticated(self) -> None:
        sources = healthy_sources()
        sources["network"] = dict(sources["network"], authenticatedPeers=3)
        sources["peers"] = (
            *sources["peers"][:3],
            {"tcpConnected": True, "authenticated": False},
        )
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["network"]["state"], "DEGRADED")
        self.assertEqual(snapshot["network"]["failClosedReason"], "INSUFFICIENT_DHT_PEERS")
        self.assertEqual(snapshot["peers"]["authenticated"], 3)

    def test_peer_evidence_conservatively_bounds_reported_authentication(self) -> None:
        sources = healthy_sources()
        sources["peers"] = (
            *sources["peers"][:3],
            {"tcpConnected": True, "authenticated": False},
        )
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["peers"]["authenticated"], 3)
        self.assertEqual(snapshot["network"]["state"], "DEGRADED")
        self.assertEqual(snapshot["network"]["failClosedReason"], "INSUFFICIENT_DHT_PEERS")

    def test_expired_generation_is_explicit(self) -> None:
        sources = healthy_sources()
        sources["generation"] = dict(sources["generation"], expiresAt=NOW)
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["network"]["state"], "FAILED")
        self.assertEqual(snapshot["network"]["failClosedReason"], "GENERATION_EXPIRED")
        self.assertEqual(snapshot["dht"]["state"], "FAILED")
        self.assertFalse(snapshot["dht"]["ready"])

    def test_missing_generation_is_not_misreported_as_expired(self) -> None:
        sources = healthy_sources()
        sources["generation"] = {}
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["network"]["state"], "FAILED")
        self.assertEqual(snapshot["network"]["failClosedReason"], "NO_RESEED_SOURCE")

    def test_stale_peer_descriptor_degrades_connected_report(self) -> None:
        sources = healthy_sources()
        sources["peers"] = (
            dict(sources["peers"][0], descriptorExpiresAt=NOW),
            *sources["peers"][1:],
        )
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["network"]["state"], "DEGRADED")
        self.assertEqual(snapshot["network"]["failClosedReason"], "PEER_DESCRIPTOR_EXPIRED")
        self.assertEqual(snapshot["peers"]["validDescriptors"], 3)

    def test_stale_or_dead_host_cannot_remain_online(self) -> None:
        sources = healthy_sources()
        sources["hosting"] = {
            "canonicalName": ADDRESS,
            "healthLeaseSeconds": 30,
            "pid": 42,
            "pidAlive": True,
            "state": "ONLINE",
            "updatedAt": NOW - 31,
        }
        stale = build_health_snapshot(**sources)
        self.assertEqual(stale["hosting"]["state"], "DEGRADED")
        self.assertEqual(stale["hosting"]["lastFailureReason"], "HOST_STATUS_STALE")
        sources["hosting"] = dict(sources["hosting"], pidAlive=False, updatedAt=NOW)
        dead = build_health_snapshot(**sources)
        self.assertEqual(dead["hosting"]["state"], "OFFLINE")
        self.assertEqual(dead["hosting"]["lastFailureReason"], "HOST_PROCESS_DEAD")

    def test_intro_expiry_and_session_counters_are_explicit(self) -> None:
        sources = healthy_sources()
        sources["hosting"] = {
            "activeSessions": 2,
            "canonicalName": ADDRESS,
            "introductionExpiresAt": NOW,
            "pendingSessions": 1,
            "pid": 42,
            "pidAlive": True,
            "sessionLimit": 4,
            "state": "ONLINE",
            "updatedAt": NOW,
        }
        sources["rendezvous"] = {
            "abandonedHandshakes": 3,
            "activeSessions": 2,
            "pendingGrants": 1,
            "rejectedAtLimit": 4,
            "successfulSessions": 5,
        }
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["hosting"]["state"], "DEGRADED")
        self.assertEqual(snapshot["hosting"]["lastFailureReason"], "INTRO_DESCRIPTOR_EXPIRED")
        self.assertEqual(snapshot["hosting"]["pendingHandshakes"], 1)
        self.assertEqual(snapshot["hosting"]["sessionLimit"], 4)
        self.assertEqual(snapshot["rendezvous"]["abandonedHandshakes"], 3)

    def test_stale_heartbeat_cannot_remain_online(self) -> None:
        sources = healthy_sources()
        sources["hosting"] = {
            "healthLeaseSeconds": 30,
            "lastHeartbeatAt": NOW - 31,
            "pid": 42,
            "pidAlive": True,
            "state": "ONLINE",
            "updatedAt": NOW,
        }
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["hosting"]["state"], "DEGRADED")
        self.assertEqual(snapshot["hosting"]["lastFailureReason"], "INTRO_HEARTBEAT_STALE")

    def test_tor_and_i2p_require_verified_readiness(self) -> None:
        sources = healthy_sources()
        sources["tor"] = {
            "bootstrapProgress": 10,
            "failureReason": "TOR_TLS_TIMEOUT",
            "processRunning": True,
            "routeVerified": False,
        }
        sources["i2p"] = {
            "processRunning": True,
            "ready": False,
            "routeVerified": False,
        }
        snapshot = build_health_snapshot(**sources)
        self.assertEqual(snapshot["tor"]["state"], "FAILED")
        self.assertFalse(snapshot["tor"]["routeVerified"])
        self.assertEqual(snapshot["i2p"]["state"], "STARTING")
        self.assertFalse(snapshot["i2p"]["ready"])
        self.assertEqual(snapshot["i2p"]["lastFailureReason"], "I2P_NOT_READY")

    def test_untrusted_sources_are_redacted_by_construction(self) -> None:
        sentinels = (
            "SUPER_SECRET_PRIVATE_KEY",
            "SECRET_COOKIE_VALUE",
            "SECRET_POST_BODY",
            "CLIENT_SOURCE_IP_SENTINEL",
        )
        sources = healthy_sources()
        sources["network"] = dict(
            sources["network"],
            privateKey=sentinels[0],
            cookie=sentinels[1],
            postBody=sentinels[2],
            clientIp=sentinels[3],
            failureReason="C:\\Users\\Secret\\raw-error",
        )
        sources["hosting"] = {
            "authorization": sentinels[0],
            "canonicalName": "not-a-service-address",
            "headers": {"Cookie": sentinels[1]},
            "httpBody": sentinels[2],
            "sourceIp": sentinels[3],
        }
        encoded = json.dumps(build_health_snapshot(**sources), sort_keys=True)
        for sentinel in sentinels:
            self.assertNotIn(sentinel, encoded)
        self.assertNotIn("Users", encoded)

    def test_export_is_atomic_redacted_and_nonfatal_when_unavailable(self) -> None:
        sources = healthy_sources()
        sources["network"] = dict(sources["network"], privateKey="SUPER_SECRET_PRIVATE_KEY")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "health.json"
            written = write_health_snapshot(destination, **sources)
            loaded = json.loads(destination.read_text(encoding="ascii"))
            self.assertEqual(loaded, written)
            self.assertNotIn("SUPER_SECRET_PRIVATE_KEY", destination.read_text(encoding="ascii"))
            with patch("granger_network.health_snapshot.os.replace", side_effect=OSError):
                self.assertFalse(try_write_health_snapshot(destination, **sources))
            self.assertTrue(destination.is_file())


if __name__ == "__main__":
    unittest.main()
