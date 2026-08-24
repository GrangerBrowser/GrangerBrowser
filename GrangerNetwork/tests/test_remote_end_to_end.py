from __future__ import annotations

import ipaddress
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from granger_network.address import service_id_from_public_key
from granger_network.client import GrangerClient
from granger_network.descriptor import ServiceDescriptor
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.identity import ServiceIdentity
from granger_network.rendezvous import RendezvousServer
from granger_network.rendezvous_control import (
    create_host_registration,
    receive_control,
    send_control,
)
from granger_network.resolver import LocalResolver
from granger_network.service import RendezvousServiceHost
from granger_network.transport import (
    RendezvousClientTransport,
    RendezvousEndpoint,
    RendezvousHostTransport,
)


PAGE = b"<!doctype html><title>Remote private page</title><h1>test.granger remote</h1>"


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


class RelayCaptureSocket:
    def __init__(self, wrapped: socket.socket, wire: bytearray) -> None:
        self._wrapped = wrapped
        self._wire = wire

    def accept(self) -> tuple["RelayCaptureSocket", tuple]:
        connection, peer = self._wrapped.accept()
        return RelayCaptureSocket(connection, self._wire), peer

    def recv(self, size: int) -> bytes:
        data = self._wrapped.recv(size)
        self._wire.extend(data)
        return data

    def sendall(self, data: bytes) -> None:
        self._wire.extend(data)
        self._wrapped.sendall(data)

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


class RelayCaptureSocketFactory:
    def __init__(self, wire: bytearray) -> None:
        self.wire = wire

    def __call__(self, family: int, kind: int) -> RelayCaptureSocket:
        return RelayCaptureSocket(socket.socket(family, kind), self.wire)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def connect_control(endpoint: RendezvousEndpoint, document: dict) -> tuple[socket.socket, dict]:
    connection = socket.socket(endpoint.family, socket.SOCK_STREAM)
    connection.settimeout(2.0)
    connection.connect(endpoint.socket_address)
    send_control(connection, document)
    return connection, receive_control(connection)


class RemoteEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.http_server = ThreadingHTTPServer(("127.0.0.1", 0), PageHandler)
        self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        self.http_thread.start()

    def tearDown(self) -> None:
        self.http_server.shutdown()
        self.http_server.server_close()
        self.http_thread.join(timeout=2.0)

    def test_remote_fetch_uses_only_rendezvous_and_hides_plaintext(self) -> None:
        endpoint = RendezvousEndpoint("127.0.0.1", available_port())
        identity = ServiceIdentity.generate()
        descriptor = ServiceDescriptor.create_remote(
            identity,
            "test-relay",
            metadata={"contentType": "text/html", "title": "Remote test"},
        )
        client_sockets = RecordingSocketFactory()
        relay_wire = bytearray()
        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary) / "registry")
            resolver.import_descriptor(descriptor, "test.granger")
            resolver.configure_rendezvous("test-relay", endpoint)
            bridge = LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(self.http_server.server_address[1]))
            )
            relay = RendezvousServer(
                endpoint,
                socket_factory=RelayCaptureSocketFactory(relay_wire),
            )
            host = RendezvousServiceHost(
                identity,
                descriptor,
                bridge,
                RendezvousHostTransport(endpoint),
            )
            relay.start_background()
            host.start_background()
            try:
                client = GrangerClient(
                    resolver,
                    remote_transport_factory=lambda relay_endpoint: RendezvousClientTransport(
                        relay_endpoint,
                        socket_factory=client_sockets,
                    ),
                )
                with (
                    patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
                    patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
                    patch(
                        "socket.gethostbyname_ex",
                        side_effect=AssertionError("DNS used"),
                    ) as gethostbyname_ex,
                ):
                    response = client.fetch("test.granger")
                self.assertEqual(getaddrinfo.call_count, 0)
                self.assertEqual(gethostbyname.call_count, 0)
                self.assertEqual(gethostbyname_ex.call_count, 0)
            finally:
                host.stop()
                relay.stop()

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, PAGE)
        self.assertEqual(response.canonical_service, descriptor.canonical_name)
        self.assertGreaterEqual(len(client_sockets.connections), 1)
        self.assertTrue(
            all(connection == endpoint.socket_address for connection in client_sockets.connections)
        )
        self.assertEqual(
            sum(
                1
                for connection in client_sockets.connections
                if connection != endpoint.socket_address
            ),
            0,
        )
        self.assertTrue(
            all(ipaddress.ip_address(connection[0]).is_loopback for connection in client_sockets.connections)
        )
        captured = bytes(relay_wire)
        for marker in (PAGE, b"GET /", b"Host:", b"Remote private page"):
            self.assertNotIn(marker, captured)
        self.assertGreater(len(captured), 0)

    def test_relay_rejects_host_identity_substitution(self) -> None:
        endpoint = RendezvousEndpoint("127.0.0.1", available_port())
        expected = ServiceIdentity.generate()
        attacker = ServiceIdentity.generate()
        claimed_id = service_id_from_public_key(expected.public_key_bytes)
        attacker_id = service_id_from_public_key(attacker.public_key_bytes)
        registration = create_host_registration(attacker, attacker_id)
        registration["serviceId"] = claimed_id
        with RendezvousServer(endpoint) as relay:
            connection, response = connect_control(endpoint, registration)
            connection.close()
        self.assertEqual(response["type"], "error")
        self.assertEqual(response["code"], "INVALID_REQUEST")
        self.assertIn("IdentityVerificationError", relay.errors)

    def test_relay_rejects_replayed_host_registration(self) -> None:
        endpoint = RendezvousEndpoint("127.0.0.1", available_port())
        identity = ServiceIdentity.generate()
        service_id = service_id_from_public_key(identity.public_key_bytes)
        registration = create_host_registration(identity, service_id)
        with RendezvousServer(endpoint) as relay:
            first, first_response = connect_control(endpoint, registration)
            second, second_response = connect_control(endpoint, registration)
            second.close()
            first.close()
            deadline = time.monotonic() + 1.0
            while relay.rejected_replays == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertEqual(first_response, {"type": "registered", "version": 1})
        self.assertEqual(second_response["type"], "error")
        self.assertEqual(second_response["code"], "REPLAY")
        self.assertEqual(relay.rejected_replays, 1)


if __name__ == "__main__":
    unittest.main()
