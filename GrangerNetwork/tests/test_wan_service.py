from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from granger_network.descriptor import ServiceDescriptor
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.hosting import StaticSiteBridge
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_service import WanServiceClient, WanServiceHost


HTML = b"<!doctype html><link rel=stylesheet href=/style.css><script src=/script.js></script><h1>Granger forum</h1>"
CSS = b"body{background:#101216;color:#eef}"
SCRIPT = b"document.documentElement.dataset.granger='ready';"
MESSAGE = b"GRANGER_TEST_MESSAGE_123"


class ForumHandler(BaseHTTPRequestHandler):
    messages: list[bytes] = []
    lock = threading.Lock()

    def do_GET(self) -> None:
        content_type = "text/plain"
        if self.path == "/":
            body = HTML
            content_type = "text/html"
        elif self.path == "/style.css":
            body = CSS
            content_type = "text/css"
        elif self.path == "/script.js":
            body = SCRIPT
            content_type = "application/javascript"
        elif self.path == "/messages":
            with self.lock:
                body = b"\n".join(self.messages)
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/message":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with self.lock:
            self.messages.append(body)
        response = b"stored"
        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        ForumHandler.messages = []
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), ForumHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-service-")
        self.root = Path(self.temporary.name)
        roles = (
            "entry",
            "middle",
            "service-relay",
            "middle",
            "introduction",
            "rendezvous",
        )
        self.identities = [ServiceIdentity.generate() for _ in roles]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                (role,),
                RelayPolicy(
                    enabled=True,
                    max_circuits=64,
                    max_streams=64,
                    max_connections=128,
                    max_bandwidth_kib_per_second=64 * 1024,
                    idle_timeout_seconds=30,
                ),
                lifetime=3600,
            )
            for identity, role in zip(self.identities, roles, strict=True)
        ]
        self.nodes = [
            WanNodeServer(identity, descriptor, self.root / f"node-{index}")
            for index, (identity, descriptor) in enumerate(
                zip(self.identities, self.descriptors, strict=True)
            )
        ]
        for node in self.nodes:
            node.start_background()

    def tearDown(self) -> None:
        for node in self.nodes:
            node.stop()
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=2.0)
        self.temporary.cleanup()

    def test_static_dynamic_and_concurrent_requests_stay_inside_overlay(self) -> None:
        (
            client_entry,
            client_middle,
            service_entry,
            host_middle,
            introduction_node,
            rendezvous_node,
        ) = self.descriptors
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-service",
            metadata={"contentType": "text/html", "title": "Granger forum"},
            lifetime=1800,
        )
        introduction = IntroductionDescriptor.create(
            service_identity,
            service,
            [introduction_node.node_id],
            sequence=1,
            lifetime=900,
        )
        bridge = LoopbackHttpBridge(
            LoopbackHttpTarget("127.0.0.1", int(self.backend.server_address[1]))
        )
        host = WanServiceHost(
            service_identity,
            service,
            introduction,
            (
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (rendezvous_node, "rendezvous"),
            ),
            bridge,
            timeout=5.0,
            rendezvous_lifetime=120,
        )
        connections: list[tuple[str, tuple]] = []
        connection_lock = threading.Lock()
        original_connect = socket.socket.connect

        def record_connect(sock: socket.socket, address: tuple) -> None:
            with connection_lock:
                connections.append((threading.current_thread().name, address))
            original_connect(sock, address)

        try:
            with (
                patch("socket.socket.connect", new=record_connect),
                patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
                patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
                patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS used")) as gethostbyname_ex,
            ):
                host.start_background()
                host.wait_ready(15.0)
                client = WanServiceClient(
                    ServiceIdentity.generate(),
                    service,
                    introduction,
                    (
                        (client_entry, "entry"),
                        (client_middle, "middle"),
                    ),
                    timeout=5.0,
                )
                session = client.connect(introduction_node)
                try:
                    self.assertEqual(session.fetch("/").body, HTML)
                    self.assertEqual(session.fetch("/style.css").body, CSS)
                    self.assertEqual(session.fetch("/script.js").body, SCRIPT)
                    posted = session.fetch(
                        "/message",
                        method="POST",
                        headers={"content-type": "text/plain"},
                        body=MESSAGE,
                    )
                    self.assertEqual(posted.status, 201)
                    self.assertEqual(session.fetch("/messages").body, MESSAGE)
                    results: list[bytes] = []
                    failures: list[BaseException] = []

                    def read_messages() -> None:
                        try:
                            results.append(session.fetch("/messages").body)
                        except BaseException as error:
                            failures.append(error)

                    readers = [threading.Thread(target=read_messages) for _ in range(6)]
                    for reader in readers:
                        reader.start()
                    for reader in readers:
                        reader.join(timeout=8.0)
                    self.assertEqual(failures, [])
                    self.assertEqual(results, [MESSAGE] * 6)
                finally:
                    session.close()
                self.assertEqual(getaddrinfo.call_count, 0)
                self.assertEqual(gethostbyname.call_count, 0)
                self.assertEqual(gethostbyname_ex.call_count, 0)
        finally:
            host.stop()

        main_destinations = [address for name, address in connections if name == "MainThread"]
        host_destinations = [
            address for name, address in connections if name == "granger-wan-service-host"
        ]
        application_destinations = [
            address for name, address in connections if name == "granger-wan-application"
        ]
        self.assertTrue(main_destinations)
        self.assertTrue(
            all(address[1] == client_entry.endpoint.port for address in main_destinations)
        )
        self.assertTrue(host_destinations)
        self.assertTrue(
            all(address[1] == service_entry.endpoint.port for address in host_destinations)
        )
        self.assertTrue(application_destinations)
        self.assertTrue(
            all(address[1] == int(self.backend.server_address[1]) for address in application_destinations)
        )
        for node in self.nodes:
            for observation in node.circuit_observations:
                self.assertFalse(observation.contains(MESSAGE))
                self.assertFalse(observation.contains(b"POST /message"))
        self.assertEqual(host.errors, [])

    def test_static_site_bridge_stays_inside_encrypted_overlay(self) -> None:
        (
            client_entry,
            client_middle,
            service_entry,
            host_middle,
            introduction_node,
            rendezvous_node,
        ) = self.descriptors
        site = self.root / "static-site"
        (site / "images").mkdir(parents=True)
        files = {
            "index.html": b"<!doctype html><h1>Hosted through Granger</h1>",
            "style.css": b"body{background:#101216}",
            "script.js": b"document.body.dataset.hosted='yes'",
            "data.json": b'{"hosted":true}',
            "images/mark.png": b"\x89PNG\r\n\x1a\nGRANGER_STATIC_IMAGE",
        }
        for relative, content in files.items():
            (site / relative).write_bytes(content)

        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "distributed-overlay",
            metadata={"contentType": "text/html", "title": "Static Granger site"},
            lifetime=1800,
        )
        introduction = IntroductionDescriptor.create(
            service_identity,
            service,
            [introduction_node.node_id],
            sequence=1,
            lifetime=900,
        )
        host = WanServiceHost(
            service_identity,
            service,
            introduction,
            (
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (rendezvous_node, "rendezvous"),
            ),
            StaticSiteBridge(site),
            timeout=5.0,
            rendezvous_lifetime=120,
        )
        connections: list[tuple] = []
        original_connect = socket.socket.connect

        def record_connect(sock: socket.socket, address: tuple) -> None:
            connections.append(address)
            original_connect(sock, address)

        try:
            with (
                patch("socket.socket.connect", new=record_connect),
                patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
                patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
                patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS used")) as gethostbyname_ex,
            ):
                host.start_background()
                host.wait_ready(15.0)
                client = WanServiceClient(
                    ServiceIdentity.generate(),
                    service,
                    introduction,
                    (
                        (client_entry, "entry"),
                        (client_middle, "middle"),
                    ),
                    timeout=5.0,
                )
                with client.connect(introduction_node) as session:
                    for relative, content in files.items():
                        response = session.fetch("/" + relative)
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.body, content)
                    self.assertEqual(session.fetch("/", method="HEAD").status, 200)
                    self.assertEqual(session.fetch("/", method="HEAD").body, b"")
                    self.assertEqual(session.fetch("/", method="POST", body=b"x").status, 405)
                self.assertEqual(getaddrinfo.call_count, 0)
                self.assertEqual(gethostbyname.call_count, 0)
                self.assertEqual(gethostbyname_ex.call_count, 0)
        finally:
            host.stop()

        allowed_ports = {descriptor.endpoint.port for descriptor in self.descriptors}
        self.assertTrue(connections)
        self.assertTrue(all(address[1] in allowed_ports for address in connections))
        for node in self.nodes:
            for observation in node.circuit_observations:
                for content in files.values():
                    self.assertFalse(observation.contains(content))
        self.assertEqual(host.errors, [])


if __name__ == "__main__":
    unittest.main()
