from __future__ import annotations

import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from granger_network.errors import UpstreamPolicyError
from granger_network.hosting import initialize_hosted_service
from granger_network.http_bridge import (
    MAX_HTTP_BODY, LoopbackHttpBridge, LoopbackHttpTarget, _run_socket_stage,
)
from granger_network.wan_application import (
    ApplicationRequest,
    decode_application_request,
    decode_application_response,
    encode_application_request,
    encode_application_response,
)


@dataclass
class ApplicationState:
    database: Path
    requests: list[dict[str, object]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


class ReusableHttpServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def application_handler(state: ApplicationState):
    class ApplicationHandler(BaseHTTPRequestHandler):
        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(length)

        def _record(self, body: bytes) -> None:
            with state.lock:
                state.requests.append(
                    {
                        "body": body,
                        "client": self.client_address[0],
                        "headers": {name.lower(): value for name, value in self.headers.items()},
                        "method": self.command,
                        "path": self.path,
                    }
                )

        def _respond(
            self,
            status: int,
            body: bytes = b"",
            *,
            content_type: str = "application/octet-stream",
            headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _dispatch(self) -> None:
            body = self._body()
            self._record(body)
            path = self.path.split("?", 1)[0]
            if path == "/cookie":
                cookie = self.headers.get("Cookie", "")
                self._respond(
                    200,
                    cookie.encode("utf-8") or b"cookie-created",
                    content_type="text/plain; charset=utf-8",
                    headers={"Set-Cookie": "session=granger; Path=/; HttpOnly; SameSite=Strict"},
                )
                return
            if path == "/multiple-cookies":
                self.send_response(200)
                self.send_header("Set-Cookie", "primary=one; Path=/; HttpOnly")
                self.send_header("Set-Cookie", "secondary=two; Path=/; SameSite=Strict")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/status":
                self._respond(422, b"validation failed", content_type="text/plain")
                return
            if path == "/binary":
                self._respond(200, b"\x00\x01\xffGRANGER\x00")
                return
            if path == "/redirect-local":
                port = int(self.server.server_address[1])
                self._respond(
                    302,
                    headers={"Location": f"http://127.0.0.1:{port}/next?source=backend"},
                )
                return
            if path == "/truncated-body":
                self.send_response(200)
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"short")
                self.close_connection = True
                return
            if path in {"/slow-body", "/slow-eof-body"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                if path == "/slow-body":
                    self.send_header("Content-Length", "8")
                self.end_headers()
                try:
                    for byte in b"deadline":
                        self.wfile.write(bytes((byte,)))
                        self.wfile.flush()
                        time.sleep(0.04)
                except OSError:
                    pass
                return
            if path == "/headers":
                self._respond(
                    200,
                    b"headers",
                    content_type="text/html; charset=utf-8",
                    headers={
                        "Access-Control-Allow-Origin": "granger-network://test.granger",
                        "Content-Security-Policy": "default-src 'none'",
                        "Server": "private-framework/9.9",
                        "X-Frame-Options": "DENY",
                        "X-Powered-By": "private-runtime",
                    },
                )
                return
            if path == "/oversized":
                self._respond(200, b"x" * (MAX_HTTP_BODY + 1))
                return
            if path == "/threads" and self.command == "POST":
                title = str(json.loads(body.decode("utf-8"))["title"])
                with closing(sqlite3.connect(state.database)) as database:
                    cursor = database.execute("INSERT INTO threads(title) VALUES (?)", (title,))
                    thread_id = int(cursor.lastrowid)
                    database.commit()
                self._respond(
                    201,
                    json.dumps({"id": thread_id}).encode("utf-8"),
                    content_type="application/json",
                )
                return
            if path == "/threads" and self.command == "GET":
                with closing(sqlite3.connect(state.database)) as database:
                    rows = database.execute("SELECT id, title FROM threads ORDER BY id").fetchall()
                self._respond(200, json.dumps(rows).encode("utf-8"), content_type="application/json")
                return
            if path.startswith("/threads/") and path.endswith("/replies") and self.command == "POST":
                thread_id = int(path.split("/")[2])
                message = str(json.loads(body.decode("utf-8"))["message"])
                with closing(sqlite3.connect(state.database)) as database:
                    database.execute(
                        "INSERT INTO replies(thread_id, message) VALUES (?, ?)",
                        (thread_id, message),
                    )
                    database.commit()
                self._respond(201, b"stored", content_type="text/plain")
                return
            if path.startswith("/threads/") and self.command == "GET":
                thread_id = int(path.split("/")[2])
                with closing(sqlite3.connect(state.database)) as database:
                    thread = database.execute(
                        "SELECT id, title FROM threads WHERE id = ?", (thread_id,)
                    ).fetchone()
                    replies = database.execute(
                        "SELECT message FROM replies WHERE thread_id = ? ORDER BY id", (thread_id,)
                    ).fetchall()
                self._respond(
                    200,
                    json.dumps({"thread": thread, "replies": replies}).encode("utf-8"),
                    content_type="application/json",
                )
                return
            response_headers = {}
            if self.command == "OPTIONS":
                response_headers["Access-Control-Allow-Methods"] = (
                    "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
                )
            self._respond(
                202 if self.command not in {"GET", "HEAD"} else 200,
                body if body else f"{self.command} {self.path}".encode("ascii"),
                content_type=self.headers.get("Content-Type", "text/plain"),
                headers=response_headers,
            )

        do_DELETE = _dispatch
        do_GET = _dispatch
        do_HEAD = _dispatch
        do_OPTIONS = _dispatch
        do_PATCH = _dispatch
        do_POST = _dispatch
        do_PUT = _dispatch

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return ApplicationHandler


def start_backend(state: ApplicationState, port: int = 0) -> tuple[ReusableHttpServer, threading.Thread]:
    server = ReusableHttpServer(("127.0.0.1", port), application_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_backend(server: ReusableHttpServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


class ApplicationHostingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-application-hosting-")
        self.root = Path(self.temporary.name)
        database = self.root / "forum.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(
                "CREATE TABLE threads(id INTEGER PRIMARY KEY, title TEXT NOT NULL);"
                "CREATE TABLE replies(id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL, "
                "message TEXT NOT NULL);"
            )
        self.state = ApplicationState(database)
        self.server, self.thread = start_backend(self.state)
        self.virtual_host = f"{'a' * 52}.granger"
        self.bridge = LoopbackHttpBridge(
            LoopbackHttpTarget("127.0.0.1", int(self.server.server_address[1])),
            virtual_host=self.virtual_host,
        )

    def tearDown(self) -> None:
        if self.server is not None:
            stop_backend(self.server, self.thread)
        self.temporary.cleanup()

    def test_application_http_semantics_and_privacy_boundary(self) -> None:
        bodies = {
            "application/json": b'{"message":"hello"}',
            "application/x-www-form-urlencoded": b"message=hello+world",
            "multipart/form-data; boundary=granger": (
                b"--granger\r\nContent-Disposition: form-data; name=upload; filename=x.bin\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n\x00\xffpayload\r\n--granger--\r\n"
            ),
            "application/octet-stream": b"\x00\x01\xffbinary\x00",
            "text/plain; charset=utf-8": "Привет Granger".encode("utf-8"),
        }
        for content_type, body in bodies.items():
            with self.subTest(content_type=content_type):
                response = self.bridge.fetch(
                    "POST",
                    "/echo?source=test",
                    {
                        "authorization": "Bearer application-token",
                        "content-type": content_type,
                        "cookie": "client=session",
                        "forwarded": "for=198.51.100.7",
                        "x-forwarded-for": "198.51.100.7",
                        "x-granger-node": "must-not-pass",
                        "x-real-ip": "198.51.100.7",
                    },
                    body,
                    session_identity="gs_internal_identity_must_not_pass",
                )
                self.assertEqual(response.status, 202)
                self.assertEqual(response.body, body)
                captured = self.state.requests[-1]
                self.assertEqual(captured["body"], body)
                self.assertEqual(captured["path"], "/echo?source=test")
                self.assertEqual(captured["client"], "127.0.0.1")
                headers = captured["headers"]
                self.assertEqual(headers["host"], self.virtual_host)
                self.assertEqual(headers["authorization"], "Bearer application-token")
                self.assertEqual(headers["cookie"], "client=session")
                for forbidden in (
                    "forwarded", "x-forwarded-for", "x-granger-node", "x-granger-session",
                    "x-real-ip",
                ):
                    self.assertNotIn(forbidden, headers)

        for method in ("GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                body = b"method-body" if method in {"PUT", "PATCH", "DELETE", "OPTIONS"} else b""
                response = self.bridge.fetch(method, "/echo", {"content-type": "text/plain"}, body)
                self.assertIn(response.status, {200, 202})
                self.assertEqual(response.body, b"" if method == "HEAD" else (body or f"{method} /echo".encode()))

        created = self.bridge.fetch("GET", "/cookie")
        self.assertIn("session=granger", created.headers["set-cookie"])
        multiple = self.bridge.fetch("GET", "/multiple-cookies")
        set_cookie_fields = [
            value for name, value in multiple.header_fields if name == "set-cookie"
        ]
        self.assertEqual(len(set_cookie_fields), 2)
        self.assertIn("primary=one", set_cookie_fields[0])
        self.assertIn("secondary=two", set_cookie_fields[1])
        decoded = decode_application_response(encode_application_response(multiple))
        self.assertEqual(
            [value for name, value in decoded.header_fields if name == "set-cookie"],
            set_cookie_fields,
        )
        returned = self.bridge.fetch("GET", "/cookie", {"cookie": "session=granger"})
        self.assertEqual(returned.body, b"session=granger")
        self.assertEqual(self.bridge.fetch("GET", "/status").status, 422)
        self.assertEqual(self.bridge.fetch("GET", "/binary").body, b"\x00\x01\xffGRANGER\x00")
        self.assertEqual(
            self.bridge.fetch("GET", "/redirect-local").headers["location"],
            f"granger-network://{self.virtual_host}/next?source=backend",
        )

        headers = self.bridge.fetch("GET", "/headers").headers
        self.assertEqual(headers["content-security-policy"], "default-src 'none'")
        self.assertIn("access-control-allow-origin", headers)
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertNotIn("server", headers)
        self.assertNotIn("x-powered-by", headers)

    def test_backend_failure_is_bounded_and_restart_recovers(self) -> None:
        port = int(self.server.server_address[1])
        self.assertEqual(self.bridge.fetch("GET", "/").status, 200)
        stop_backend(self.server, self.thread)
        self.server = None
        unavailable = self.bridge.fetch("GET", "/")
        self.assertIn(unavailable.status, {503, 504})
        self.assertFalse(self.bridge.health_snapshot()["backendAvailable"])

        self.server, self.thread = start_backend(self.state, port)
        recovered = self.bridge.fetch("GET", "/")
        self.assertEqual(recovered.status, 200)
        self.assertTrue(self.bridge.health_snapshot()["backendAvailable"])

    def test_body_stage_has_an_absolute_deadline(self) -> None:
        bridge = LoopbackHttpBridge(
            self.bridge.target,
            virtual_host=self.virtual_host,
            connect_timeout=0.5,
            header_timeout=0.5,
            body_timeout=0.1,
        )
        started = time.monotonic()
        response = bridge.fetch("GET", "/slow-body")
        self.assertEqual(response.status, 504)
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertEqual(bridge.health_snapshot()["backendError"], "timeout")

    def test_eof_response_cannot_succeed_after_stage_deadline(self) -> None:
        bridge = LoopbackHttpBridge(self.bridge.target, body_timeout=0.1)
        response = bridge.fetch("GET", "/slow-eof-body")
        self.assertEqual(response.status, 504)
        self.assertEqual(bridge.health_snapshot()["backendError"], "timeout")

    def test_eof_returned_by_deadline_abort_is_not_success(self) -> None:
        aborted = threading.Event()

        class Connection:
            def shutdown(self, _how: int) -> None:
                aborted.set()

            def close(self) -> None:
                pass

        def eof_after_shutdown() -> bytes:
            self.assertTrue(aborted.wait(2.0))
            return b"partial"

        with self.assertRaises(TimeoutError):
            _run_socket_stage(Connection(), 0.05, eof_after_shutdown)

    def test_truncated_content_length_is_rejected(self) -> None:
        self.assertEqual(self.bridge.fetch("GET", "/truncated-body").status, 502)

    def test_target_validation_never_resolves_or_accepts_non_loopback(self) -> None:
        with patch("socket.getaddrinfo") as resolver:
            for target in (
                "http://localhost:80",
                "http://example.com:80",
                "http://0.0.0.0:80",
                "http://8.8.8.8:80",
                "http://10.0.0.1:80",
                "http://192.168.1.1:80",
                "http://169.254.1.1:80",
                "http://203.0.113.7:80",
            ):
                with self.subTest(target=target), self.assertRaises(UpstreamPolicyError):
                    LoopbackHttpTarget.parse(target)
            resolver.assert_not_called()
        self.assertEqual(LoopbackHttpTarget.parse("http://127.0.0.1:43172").host, "127.0.0.1")
        self.assertEqual(LoopbackHttpTarget.parse("http://[::1]:43172").host, "::1")

    def test_protocol_methods_and_resource_limits(self) -> None:
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            body = b"payload" if method not in {"GET", "HEAD"} else b""
            encoded = encode_application_request(
                ApplicationRequest(method, "/resource?x=1", {"content-type": "text/plain"}, body)
            )
            decoded = decode_application_request(encoded)
            self.assertEqual(decoded, ApplicationRequest(method, "/resource?x=1", {"content-type": "text/plain"}, body))
        with self.assertRaises(UpstreamPolicyError):
            self.bridge.fetch("POST", "/echo", body=b"x" * (MAX_HTTP_BODY + 1))
        self.assertEqual(self.bridge.fetch("GET", "/oversized").status, 502)

    def test_sqlite_state_is_shared_and_survives_backend_restart(self) -> None:
        second_client = LoopbackHttpBridge(
            self.bridge.target,
            virtual_host=self.virtual_host,
        )
        created = self.bridge.fetch(
            "POST", "/threads", {"content-type": "application/json"}, b'{"title":"first"}'
        )
        self.assertEqual(created.status, 201)
        thread_id = int(json.loads(created.body)["id"])
        listing = json.loads(second_client.fetch("GET", "/threads").body)
        self.assertEqual(listing, [[thread_id, "first"]])
        self.assertEqual(
            second_client.fetch(
                "POST",
                f"/threads/{thread_id}/replies",
                {"content-type": "application/json"},
                b'{"message":"reply"}',
            ).status,
            201,
        )
        document = json.loads(self.bridge.fetch("GET", f"/threads/{thread_id}").body)
        self.assertEqual(document["replies"], [["reply"]])

        port = int(self.server.server_address[1])
        stop_backend(self.server, self.thread)
        self.server = None
        self.server, self.thread = start_backend(self.state, port)
        after_restart = json.loads(second_client.fetch("GET", f"/threads/{thread_id}").body)
        self.assertEqual(after_restart, document)

    def test_services_remain_isolated_under_concurrency(self) -> None:
        other_state = ApplicationState(self.root / "other.sqlite3")
        with closing(sqlite3.connect(other_state.database)) as database:
            database.executescript(
                "CREATE TABLE threads(id INTEGER PRIMARY KEY, title TEXT NOT NULL);"
                "CREATE TABLE replies(id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL, message TEXT NOT NULL);"
            )
        other_server, other_thread = start_backend(other_state)
        try:
            other = LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(other_server.server_address[1])),
                virtual_host=f"{'b' * 52}.granger",
            )

            def fetch(index: int) -> bytes:
                bridge = self.bridge if index % 2 == 0 else other
                return bridge.fetch("POST", "/echo", body=f"service-{index % 2}".encode()).body

            with ThreadPoolExecutor(max_workers=8) as executor:
                responses = list(executor.map(fetch, range(100)))
            self.assertEqual(responses.count(b"service-0"), 50)
            self.assertEqual(responses.count(b"service-1"), 50)
            self.assertTrue(all(request["headers"]["host"] == self.virtual_host for request in self.state.requests))
            self.assertTrue(
                all(request["headers"]["host"] == f"{'b' * 52}.granger" for request in other_state.requests)
            )
        finally:
            stop_backend(other_server, other_thread)

    def test_service_descriptor_never_contains_local_backend(self) -> None:
        port = int(self.server.server_address[1])
        _config, descriptor = initialize_hosted_service(
            self.root / "services",
            "1" * 32,
            "Application",
            "local-application",
            upstream=f"http://127.0.0.1:{port}",
        )
        encoded = descriptor.to_json()
        self.assertNotIn("127.0.0.1", encoded)
        self.assertNotIn(str(port), encoded)
        self.assertNotIn(str(self.root), encoded)


if __name__ == "__main__":
    unittest.main()
