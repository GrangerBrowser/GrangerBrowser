from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import GrangerNetworkError, OverlayRoutingError, ProtocolError
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.hosting import StaticSiteBridge
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import RpcFrame, RpcType
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_control import IntroductionRequest, encode_intro_request
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


class WanOperationTimeoutTests(unittest.TestCase):
    def test_introduction_request_uses_the_configured_operation_timeout(self) -> None:
        identities = [ServiceIdentity.generate() for _ in range(4)]
        capabilities = (("access",), ("entry",), ("middle",), ("introduction",))
        descriptors = tuple(
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                capability,
                RelayPolicy(enabled=True, max_bandwidth_kib_per_second=64 * 1024),
                lifetime=3600,
            )
            for identity, capability in zip(identities, capabilities, strict=True)
        )
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-service",
            lifetime=1800,
        )
        introduction = IntroductionDescriptor.create(
            service_identity,
            service,
            [descriptors[3].node_id],
            sequence=1,
            lifetime=900,
        )

        class FakeConnection:
            timeout: float | None = None

            def settimeout(self, value: float | None) -> None:
                self.timeout = value

        connection = FakeConnection()

        class FakeRpc:
            def request(self, *_args, **_kwargs):
                self.assert_timeout()
                raise TimeoutError("simulated silent introduction point")

            @staticmethod
            def assert_timeout() -> None:
                if connection.timeout != 0.25:
                    raise AssertionError("WAN control request was left unbounded")

        class FakeCircuit:
            endpoint = SimpleNamespace(
                channel=SimpleNamespace(connection=connection),
                rpc=FakeRpc(),
            )

            def close(self) -> None:
                pass

        client = WanServiceClient(
            ServiceIdentity.generate(),
            service,
            introduction,
            tuple(zip(descriptors[:3], ("access", "entry", "middle"), strict=True)),
            timeout=0.25,
        )
        with patch("granger_network.wan_service.CircuitBuilder.open", return_value=FakeCircuit()):
            with self.assertRaisesRegex(OverlayRoutingError, "introduction stage failed during request"):
                client.connect(descriptors[3])

    def test_startup_failure_reports_every_identity_in_the_failed_route(self) -> None:
        identities = [ServiceIdentity.generate() for _ in range(5)]
        capabilities = (
            ("access",),
            ("service-relay",),
            ("middle",),
            ("introduction",),
            ("rendezvous",),
        )
        descriptors = tuple(
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                capability,
                RelayPolicy(enabled=True, max_bandwidth_kib_per_second=64 * 1024),
                lifetime=3600,
            )
            for identity, capability in zip(identities, capabilities, strict=True)
        )
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-service",
            lifetime=1800,
        )
        introduction = IntroductionDescriptor.create(
            service_identity,
            service,
            [descriptors[3].node_id],
            sequence=1,
            lifetime=900,
        )
        introduction_route = tuple(zip(
            descriptors[:4],
            ("access", "service-relay", "middle", "introduction"),
            strict=True,
        ))
        rendezvous_route = tuple(zip(
            (*descriptors[:3], descriptors[4]),
            ("access", "service-relay", "middle", "rendezvous"),
            strict=True,
        ))
        host = WanServiceHost(
            service_identity,
            service,
            introduction,
            introduction_route,
            rendezvous_route,
            SimpleNamespace(),
            timeout=0.25,
        )
        try:
            with patch(
                "granger_network.wan_service.CircuitBuilder.open",
                side_effect=TimeoutError("simulated protocol-silent relay"),
            ):
                host.start_background()
                with self.assertRaisesRegex(ProtocolError, "protocol-silent relay"):
                    host.wait_ready(1.0)
            self.assertEqual(
                host.startup_failed_route_ids,
                frozenset(descriptor.node_id for descriptor in descriptors[:4]),
            )
            self.assertEqual(
                host.startup_failed_middle_ids,
                frozenset({descriptors[2].node_id}),
            )
        finally:
            host.stop()


class WanServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        ForumHandler.messages = []
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), ForumHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-service-")
        self.root = Path(self.temporary.name)
        roles = (
            ("access",),
            ("entry",),
            ("middle",),
            ("access",),
            ("service-relay",),
            ("middle",),
            ("introduction",),
            ("middle", "rendezvous"),
        )
        self.identities = [ServiceIdentity.generate() for _ in roles]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                role,
                RelayPolicy(
                    enabled=True,
                    max_circuits=64,
                    max_streams=64,
                    max_connections=128,
                    max_bandwidth_kib_per_second=64 * 1024,
                    idle_timeout_seconds=5,
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

    def _rotation_pair(self, *, max_sessions: int = 4) -> tuple[WanServiceHost, WanServiceClient, NodeDescriptor]:
        client_access, client_entry, client_middle, access, guard, middle, intro, rendezvous = self.descriptors
        identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(identity, "rotation-regression", lifetime=1800)
        introduction = IntroductionDescriptor.create(
            identity, service, [intro.node_id], sequence=1, lifetime=900,
        )
        host = WanServiceHost(
            identity, service, introduction,
            ((access, "access"), (guard, "service-relay"), (middle, "middle"), (intro, "introduction")),
            ((access, "access"), (guard, "service-relay"), (middle, "middle"), (rendezvous, "rendezvous")),
            LoopbackHttpBridge(LoopbackHttpTarget("127.0.0.1", self.backend.server_address[1])),
            timeout=2.0, rendezvous_lifetime=120, max_sessions=max_sessions,
        )
        client = WanServiceClient(
            ServiceIdentity.generate(), service, introduction,
            ((client_access, "access"), (client_entry, "entry"), (client_middle, "middle")),
            timeout=3.0,
        )
        return host, client, intro

    def test_replacement_session_opens_before_previous_session_is_closed(self) -> None:
        host, client, intro = self._rotation_pair()
        keep_alive = threading.Event()
        failures: list[BaseException] = []
        worker = None
        previous = None
        replacement = None
        try:
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                host.start_background()
                host.wait_ready(15.0)
                previous = client.connect(intro)
                self.assertEqual(previous.fetch("/").body, HTML)

                def keep_previous_usable() -> None:
                    while not keep_alive.wait(0.1):
                        try:
                            self.assertEqual(previous.fetch("/").body, HTML)
                        except BaseException as error:
                            failures.append(error)
                            return

                worker = threading.Thread(target=keep_previous_usable)
                worker.start()
                replacement = client.connect(intro)
                self.assertEqual(replacement.fetch("/").body, HTML)
                keep_alive.set()
                worker.join(timeout=5.0)
                self.assertEqual(failures, [])
                self.assertEqual(previous.fetch("/").body, HTML)
                self.assertFalse(host.recovery_requested)
        finally:
            keep_alive.set()
            if replacement is not None:
                replacement.close()
            if previous is not None:
                previous.close()
            if worker is not None:
                worker.join(timeout=5.0)
            host.stop()

    def test_ten_replacements_release_sessions_and_preserve_service_identity(self) -> None:
        host, client, intro = self._rotation_pair(max_sessions=2)
        current = None
        replacement = None
        try:
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                host.start_background()
                host.wait_ready(15.0)
                current = client.connect(intro)
                for cycle in range(10):
                    with self.subTest(cycle=cycle):
                        replacement = client.connect(intro)
                        self.assertEqual(replacement.fetch("/").body, HTML)
                        self.assertEqual(current.fetch("/").body, HTML)
                        self.assertEqual(replacement.service, current.service)
                        self.assertNotEqual(replacement.grant.cookie, current.grant.cookie)
                        self.assertEqual(host.active_sessions, 2)
                        current.close()
                        current, replacement = replacement, None
                        deadline = time.monotonic() + 5.0
                        while host.active_sessions > 1 and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertEqual(host.active_sessions, 1)
                        self.assertFalse(host.recovery_requested)
        finally:
            if current is not None:
                current.close()
            if replacement is not None:
                replacement.close()
            host.stop()
        self.assertEqual(host.active_sessions, 0)
        self.assertTrue(host.wait(0))
        self.assertEqual(host.errors, [])

    def test_session_capacity_fails_closed_and_stop_releases_active_sessions(self) -> None:
        host, client, intro = self._rotation_pair(max_sessions=2)
        sessions = []
        try:
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")):
                host.start_background()
                host.wait_ready(15.0)
                sessions.extend((client.connect(intro), client.connect(intro)))
                self.assertEqual(host.active_sessions, 2)
                with self.assertRaises(OverlayRoutingError):
                    client.connect(intro)
                for session in sessions:
                    self.assertEqual(session.fetch("/").body, HTML)
                self.assertEqual(host.active_sessions, 2)
                self.assertIn("introduction:RENDEZVOUS_BUSY", host.session_failures)
                self.assertFalse(host.recovery_requested)
                with host._grant_condition:
                    owners = tuple(host._sessions)
                host.stop()
                self.assertEqual(host.active_sessions, 0)
                self.assertTrue(all(not owner.thread.is_alive() for owner in owners))
                self.assertTrue(all(not owner.server._workers for owner in owners))
                for session in sessions:
                    with self.assertRaises((GrangerNetworkError, OSError)):
                        session.fetch("/")
        finally:
            for session in sessions:
                session.close()
            host.stop()

    def test_static_dynamic_and_concurrent_requests_stay_inside_overlay(self) -> None:
        (
            client_access,
            client_entry,
            client_middle,
            service_access,
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
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_access, "access"),
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
                        (client_access, "access"),
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
            all(address[1] == client_access.endpoint.port for address in main_destinations)
        )
        self.assertTrue(host_destinations)
        self.assertTrue(
            all(address[1] == service_access.endpoint.port for address in host_destinations)
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
            client_access,
            client_entry,
            client_middle,
            service_access,
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
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_access, "access"),
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
                        (client_access, "access"),
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

    def test_active_cover_traffic_does_not_hit_an_absolute_bridge_lifetime(self) -> None:
        (
            client_access,
            client_entry,
            client_middle,
            service_access,
            service_entry,
            host_middle,
            introduction_node,
            rendezvous_node,
        ) = self.descriptors
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "long-lived-introduction",
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
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (rendezvous_node, "rendezvous"),
            ),
            LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(self.backend.server_address[1]))
            ),
            timeout=5.0,
            rendezvous_lifetime=30,
        )
        try:
            with patch.dict("os.environ", {"GRANGER_COVER_PROFILE": "standard"}):
                host.start_background()
                host.wait_ready(15.0)
                time.sleep(15.5)
                self.assertFalse(host.recovery_requested, host.recovery_reason)

                client = WanServiceClient(
                    ServiceIdentity.generate(),
                    service,
                    introduction,
                    (
                        (client_access, "access"),
                        (client_entry, "entry"),
                        (client_middle, "middle"),
                    ),
                    timeout=5.0,
                )
                with client.connect(introduction_node) as session:
                    response = session.fetch("/")
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.body, HTML)
            self.assertEqual(host.errors, [])
        finally:
            host.stop()

    def test_rendezvous_target_is_removed_from_the_client_route_prefix(self) -> None:
        (
            client_access,
            client_entry,
            client_middle,
            service_access,
            service_entry,
            host_middle,
            introduction_node,
            rendezvous_node,
        ) = self.descriptors
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "rendezvous-reselection",
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
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (rendezvous_node, "rendezvous"),
            ),
            LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(self.backend.server_address[1]))
            ),
            timeout=5.0,
            rendezvous_lifetime=30,
        )
        selected_targets: list[str] = []

        def select_alternate(
            target: NodeDescriptor,
        ) -> tuple[tuple[NodeDescriptor, str], ...]:
            selected_targets.append(target.node_id)
            return (
                (client_access, "access"),
                (client_entry, "entry"),
                (client_middle, "middle"),
            )

        try:
            host.start_background()
            host.wait_ready(15.0)
            client = WanServiceClient(
                ServiceIdentity.generate(),
                service,
                introduction,
                (
                    (client_access, "access"),
                    (client_entry, "entry"),
                    (rendezvous_node, "middle"),
                ),
                timeout=5.0,
                rendezvous_route_selector=select_alternate,
            )
            with client.connect(introduction_node) as session:
                response = session.fetch("/")
                self.assertEqual(response.status, 200)
                self.assertEqual(response.body, HTML)
                self.assertEqual(
                    [node.node_id for node, _role in session.circuit.route],
                    [
                        client_access.node_id,
                        client_entry.node_id,
                        client_middle.node_id,
                        rendezvous_node.node_id,
                    ],
                )
            self.assertEqual(selected_targets, [rendezvous_node.node_id])
            self.assertFalse(host.recovery_requested, host.recovery_reason)
        finally:
            host.stop()

    def test_host_requests_route_recovery_when_introduction_circuit_breaks(self) -> None:
        (
            _client_access,
            _client_entry,
            _client_middle,
            service_access,
            service_entry,
            host_middle,
            introduction_node,
            rendezvous_node,
        ) = self.descriptors
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "distributed-overlay",
            metadata={"contentType": "text/html", "title": "Recovery test"},
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
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (rendezvous_node, "rendezvous"),
            ),
            LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(self.backend.server_address[1]))
            ),
            timeout=2.0,
            rendezvous_lifetime=30,
        )
        try:
            host.start_background()
            host.wait_ready(10.0)
            self.assertTrue(host._intro_circuits)
            host._intro_circuits[0].close()

            deadline = time.monotonic() + 5.0
            while not host.recovery_requested and time.monotonic() < deadline:
                time.sleep(0.05)

            self.assertTrue(host.recovery_requested)
            self.assertTrue(host.recovery_reason.startswith("introduction:"))
            self.assertTrue(host.wait(5.0))
            self.assertEqual(host.errors, [])
        finally:
            host.stop()

    def test_busy_rendezvous_slot_rejects_request_without_route_recovery(self) -> None:
        (
            _client_access,
            _client_entry,
            _client_middle,
            service_access,
            service_entry,
            host_middle,
            introduction_node,
            rendezvous_node,
        ) = self.descriptors
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "distributed-overlay",
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
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (introduction_node, "introduction"),
            ),
            (
                (service_access, "access"),
                (service_entry, "service-relay"),
                (host_middle, "middle"),
                (rendezvous_node, "rendezvous"),
            ),
            LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(self.backend.server_address[1]))
            ),
            timeout=0.01,
            rendezvous_lifetime=30,
        )
        request = RpcFrame(
            RpcType.INTRO_DELIVER,
            0,
            b"r" * 16,
            0,
            encode_intro_request(
                IntroductionRequest(
                    service.service_id,
                    introduction.points[0].token,
                    b"n" * 16,
                )
            ),
        )
        sent: list[tuple[RpcType, bytes, dict[str, object]]] = []

        class FakeRpc:
            def receive(self) -> RpcFrame:
                return request

            def send(self, message_type: RpcType, payload: bytes, **options: object) -> bytes:
                sent.append((message_type, payload, options))
                host._stop.set()
                return request.request_id

        class FakeEndpoint:
            rpc = FakeRpc()

        class FakeCircuit:
            endpoint = FakeEndpoint()

        host._answer_introductions(FakeCircuit())

        self.assertFalse(host.recovery_requested)
        self.assertEqual(host.session_failures, ["introduction:RENDEZVOUS_BUSY"])
        self.assertEqual(sent[0][0], RpcType.ERROR)
        self.assertEqual(sent[0][2]["request_id"], request.request_id)
        self.assertTrue(sent[0][2]["response"])
        self.assertTrue(sent[0][2]["error"])


if __name__ == "__main__":
    unittest.main()
