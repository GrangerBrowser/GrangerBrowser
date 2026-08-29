from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from granger_network.browser_gateway import (
    CircuitRotationPolicy,
    _WanGateway,
)
from granger_network.cells import CoverTrafficProfile
from granger_network.errors import ProtocolError
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
