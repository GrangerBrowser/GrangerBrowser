from __future__ import annotations

import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from granger_network.browser_gateway import (
    CircuitRotationPolicy,
    _GatewaySessionSlot,
    _WanGateway,
)
from granger_network.cells import CoverTrafficProfile
from granger_network.errors import ProtocolError, RendezvousError
from granger_network.http_bridge import HttpResult


class _FakeSession:
    def __init__(
        self,
        *,
        block: threading.Event | None = None,
        fail_request: bool = False,
    ) -> None:
        self.application_mux = SimpleNamespace(failed=False)
        self.block = block
        self.fail_request = fail_request
        self.started = threading.Event()
        self.closed = False

    def fetch(self, *_args, **_kwargs) -> HttpResult:
        self.started.set()
        if self.fail_request:
            self.application_mux.failed = True
            raise ProtocolError("test session closed")
        if self.block is not None:
            self.block.wait(3.0)
        return HttpResult(200, "OK", {"content-type": "text/plain"}, b"ok")

    def close(self) -> None:
        self.closed = True


def _connection(session: _FakeSession):
    return SimpleNamespace(
        service=SimpleNamespace(canonical_name="test.granger"),
        session=session,
    )


def _gateway(policy: CircuitRotationPolicy) -> _WanGateway:
    gateway = _WanGateway.__new__(_WanGateway)
    gateway._runtime = object()
    gateway._resolver = object()
    gateway._route_attempts = 3
    gateway._timeout = 2.0
    gateway._sessions = {}
    gateway._session_locks = tuple(threading.Lock() for _ in range(4))
    gateway._rotation_policy = policy
    gateway._cover_profile = CoverTrafficProfile.STANDARD
    gateway._rotation_count = 0
    gateway._closed = False
    gateway._lock = threading.Lock()
    return gateway


class CircuitRotationTests(unittest.TestCase):
    def test_wan_gateway_starts_and_stops_browser_peer_automatically(self) -> None:
        config = SimpleNamespace(
            bootstrap_path=Path("bootstrap.json"),
            authority_pin_path=Path("authority.pin"),
            alias_pins={},
            route_attempts=3,
            timeout=2.0,
            replication_factor=3,
            minimum_replicas=2,
        )
        runtime = SimpleNamespace(
            identity=object(),
            discovery=object(),
            reseed=object(),
        )
        relay_identity = object()
        peer_policy = object()
        browser_peer = Mock()
        health_changed = Mock()
        with (
            patch("granger_network.browser_gateway.load_browser_wan_config", return_value=config),
            patch("granger_network.browser_gateway.load_discovery_runtime", return_value=runtime),
            patch(
                "granger_network.browser_gateway._load_browser_peer_identity",
                return_value=relay_identity,
            ),
            patch(
                "granger_network.browser_gateway._browser_peer_policy_from_environment",
                return_value=peer_policy,
            ),
            patch("granger_network.browser_gateway.BrowserPeerRuntime", return_value=browser_peer) as peer_type,
        ):
            gateway = _WanGateway(
                Path("browser-wan.json"), Path("state"),
                on_health_changed=health_changed,
            )
        peer_type.assert_called_once_with(
            relay_identity,
            runtime.discovery,
            Path("state") / "browser-peer",
            lifecycle_policy=peer_policy,
            reseed_store=runtime.reseed,
            wan_config_publisher=None,
            on_state_changed=health_changed,
        )
        peer_type.call_args.kwargs["on_state_changed"]()
        health_changed.assert_called_once_with()
        browser_peer.start.assert_called_once_with()
        gateway.close()
        browser_peer.stop.assert_called_once_with()

    def test_idempotent_request_retries_once_after_session_failure(self) -> None:
        first = _FakeSession(fail_request=True)
        second = _FakeSession()
        gateway = _gateway(CircuitRotationPolicy())
        with patch(
            "granger_network.browser_gateway.connect_service",
            side_effect=(_connection(first), _connection(second)),
        ) as connect:
            response = gateway.fetch_gateway("test.granger", "/", "GET", {}, b"")
        self.assertEqual(response.body, b"ok")
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(first.closed)
        gateway.close()

    def test_service_session_cache_evicts_oldest_inactive_circuit(self) -> None:
        sessions = tuple(_FakeSession() for _ in range(3))
        gateway = _gateway(CircuitRotationPolicy(max_cached_services=2))
        with patch(
            "granger_network.browser_gateway.connect_service",
            side_effect=tuple(_connection(session) for session in sessions),
        ):
            gateway.fetch_gateway("first.granger", "/", "GET", {}, b"")
            time.sleep(0.001)
            gateway.fetch_gateway("second.granger", "/", "GET", {}, b"")
            gateway.fetch_gateway("third.granger", "/", "GET", {}, b"")

        self.assertEqual(set(gateway._sessions), {"second.granger", "third.granger"})
        self.assertTrue(sessions[0].closed)
        self.assertFalse(sessions[1].closed)
        self.assertFalse(sessions[2].closed)
        gateway.close()

    def test_service_session_cache_fails_closed_when_every_slot_is_active(self) -> None:
        existing = _FakeSession()
        replacement = _FakeSession()
        gateway = _gateway(CircuitRotationPolicy(max_cached_services=1))
        gateway._sessions["active.granger"] = _GatewaySessionSlot(
            _connection(existing),
            time.monotonic(),
            active_requests=1,
        )
        with patch(
            "granger_network.browser_gateway.connect_service",
            return_value=_connection(replacement),
        ):
            with self.assertRaisesRegex(RendezvousError, "cache limit"):
                gateway.fetch_gateway("new.granger", "/", "GET", {}, b"")

        self.assertEqual(set(gateway._sessions), {"active.granger"})
        self.assertTrue(replacement.closed)
        self.assertFalse(existing.closed)
        gateway._sessions["active.granger"].active_requests = 0
        gateway.close()

    def test_post_is_not_retried_after_ambiguous_session_failure(self) -> None:
        first = _FakeSession(fail_request=True)
        gateway = _gateway(CircuitRotationPolicy())
        with patch(
            "granger_network.browser_gateway.connect_service",
            return_value=_connection(first),
        ) as connect:
            with self.assertRaises(ProtocolError):
                gateway.fetch_gateway("test.granger", "/message", "POST", {}, b"value")
        self.assertEqual(connect.call_count, 1)
        self.assertTrue(first.closed)
        gateway.close()

    def test_request_limit_builds_replacement_before_retiring_old_circuit(self) -> None:
        first = _FakeSession()
        second = _FakeSession()
        gateway = _gateway(
            CircuitRotationPolicy(
                max_age_seconds=3600,
                max_requests=1,
                max_transferred_bytes=1024 * 1024,
            )
        )
        with patch(
            "granger_network.browser_gateway.connect_service",
            side_effect=(_connection(first), _connection(second)),
        ) as connect:
            self.assertEqual(gateway.fetch_gateway("test.granger", "/", "GET", {}, b"").body, b"ok")
            self.assertFalse(first.closed)
            self.assertEqual(gateway.fetch_gateway("test.granger", "/", "GET", {}, b"").body, b"ok")
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(first.closed)
        self.assertFalse(second.closed)
        self.assertEqual(gateway._rotation_count, 1)
        gateway.close()
        self.assertTrue(second.closed)

    def test_active_old_request_drains_after_atomic_rotation(self) -> None:
        release_first = threading.Event()
        first = _FakeSession(block=release_first)
        second = _FakeSession()
        gateway = _gateway(
            CircuitRotationPolicy(
                max_age_seconds=1,
                max_requests=100,
                max_transferred_bytes=1024 * 1024,
            )
        )
        results: list[bytes] = []
        with patch(
            "granger_network.browser_gateway.connect_service",
            side_effect=(_connection(first), _connection(second)),
        ):
            worker = threading.Thread(
                target=lambda: results.append(
                    gateway.fetch_gateway("test.granger", "/slow", "GET", {}, b"").body
                )
            )
            worker.start()
            self.assertTrue(first.started.wait(1.0))
            with gateway._lock:
                gateway._sessions["test.granger"].created_at = time.monotonic() - 2.0
            self.assertEqual(
                gateway.fetch_gateway("test.granger", "/fast", "GET", {}, b"").body,
                b"ok",
            )
            self.assertFalse(first.closed)
            release_first.set()
            worker.join(timeout=2.0)
        self.assertEqual(results, [b"ok"])
        self.assertTrue(first.closed)
        gateway.close()


if __name__ == "__main__":
    unittest.main()
