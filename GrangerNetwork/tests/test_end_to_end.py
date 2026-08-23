from __future__ import annotations

import ipaddress
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from granger_network.client import GrangerClient
from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import ResolutionError, UpstreamPolicyError
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.identity import ServiceIdentity
from granger_network.resolver import LocalResolver
from granger_network.service import GrangerServiceHost
from granger_network.transport import ClientTransport, LoopbackEndpoint, LoopbackTcpTransport


PAGE = b"<!doctype html><title>Private</title><h1>Granger test page</h1>"


class PageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class RecordingSocket:
    def __init__(self, wrapped: socket.socket, connections: list[tuple]) -> None:
        self._wrapped = wrapped
        self._connections = connections

    def connect(self, address: tuple) -> None:
        self._connections.append(address)
        self._wrapped.connect(address)

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


class RecordingSocketFactory:
    def __init__(self) -> None:
        self.connections: list[tuple] = []

    def __call__(self, family: int, kind: int) -> RecordingSocket:
        return RecordingSocket(socket.socket(family, kind), self.connections)


class ForbiddenTransport(ClientTransport):
    def connect(self, endpoint: LoopbackEndpoint, timeout: float) -> socket.socket:
        raise AssertionError(f"transport was reached for unresolved name: {endpoint}")


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.http_server = ThreadingHTTPServer(("127.0.0.1", 0), PageHandler)
        self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        self.http_thread.start()

    def tearDown(self) -> None:
        self.http_server.shutdown()
        self.http_server.server_close()
        self.http_thread.join(timeout=2.0)

    def test_test_granger_fetch_is_encrypted_verified_and_loopback_only(self) -> None:
        http_port = int(self.http_server.server_address[1])
        identity = ServiceIdentity.generate()
        descriptor = ServiceDescriptor.create(
            identity,
            LoopbackEndpoint("127.0.0.1", available_port()),
        )
        service_sockets = RecordingSocketFactory()
        client_sockets = RecordingSocketFactory()

        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary) / "registry")
            resolver.import_descriptor(descriptor, "test.granger")
            bridge = LoopbackHttpBridge(
                LoopbackHttpTarget.parse(f"http://127.0.0.1:{http_port}"),
                socket_factory=service_sockets,
            )
            with GrangerServiceHost(identity, descriptor, bridge):
                client = GrangerClient(
                    resolver,
                    LoopbackTcpTransport(socket_factory=client_sockets),
                )
                with (
                    patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
                    patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
                    patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS used")) as gethostbyname_ex,
                ):
                    response = client.fetch("test.granger")
                self.assertEqual(getaddrinfo.call_count, 0)
                self.assertEqual(gethostbyname.call_count, 0)
                self.assertEqual(gethostbyname_ex.call_count, 0)

            self.assertEqual(response.status, 200)
            self.assertEqual(response.body, PAGE)
            self.assertEqual(response.canonical_service, descriptor.canonical_name)
            connections = client_sockets.connections + service_sockets.connections
            self.assertEqual(len(connections), 2)
            self.assertTrue(all(ipaddress.ip_address(address[0]).is_loopback for address in connections))
            self.assertEqual({address[1] for address in connections}, {descriptor.endpoint.port, http_port})

    def test_resolution_failure_opens_no_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = GrangerClient(LocalResolver(Path(temporary)), ForbiddenTransport())
            with self.assertRaises(ResolutionError):
                client.fetch("missing.granger")
            with self.assertRaises(ResolutionError):
                client.fetch("example.com")

    def test_http_bridge_rejects_non_loopback_and_hostnames(self) -> None:
        for upstream in ("http://example.com:8080", "http://203.0.113.1:8080"):
            with self.subTest(upstream=upstream), self.assertRaises(UpstreamPolicyError):
                LoopbackHttpTarget.parse(upstream)
        with self.assertRaises(UpstreamPolicyError):
            LoopbackHttpTarget("203.0.113.1", 8080)


if __name__ == "__main__":
    unittest.main()
