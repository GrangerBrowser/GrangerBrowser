from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from granger_network.errors import UpstreamPolicyError
from granger_network.hosting import (
    CONFIG_FILE,
    IDENTITY_FILE,
    SERVICE_DESCRIPTOR_FILE,
    StaticSiteBridge,
    initialize_hosted_service,
    inspect_static_site,
    load_hosted_service,
    main as hosting_main,
    probe_loopback_application,
    update_hosted_service,
)
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget


class RecordingHandler(BaseHTTPRequestHandler):
    requests: list[dict[str, str]] = []
    bodies: list[bytes] = []
    lock = threading.Lock()

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        with self.lock:
            self.requests.append({name.lower(): value for name, value in self.headers.items()})
        self._respond(200, b"loopback")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with self.lock:
            self.requests.append({name.lower(): value for name, value in self.headers.items()})
            self.bodies.append(body)
        self._respond(201, b"stored")

    def log_message(self, _format: str, *_args: object) -> None:
        return


def create_site(root: Path) -> Path:
    site = root / "site"
    (site / "images").mkdir(parents=True)
    (site / "fonts").mkdir()
    (site / "index.html").write_text(
        "<!doctype html><link rel=stylesheet href=/style.css>"
        "<script src=/script.js></script><h1>Private site</h1>",
        encoding="utf-8",
    )
    (site / "style.css").write_text("body{color:#eef}", encoding="utf-8")
    (site / "script.js").write_text("document.body.dataset.ready='1'", encoding="utf-8")
    (site / "data.json").write_text('{"ok":true}', encoding="utf-8")
    (site / "images" / "pixel.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (site / "fonts" / "ui.woff2").write_bytes(b"wOF2")
    return site


class StaticHostingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-hosting-static-")
        self.root = Path(self.temporary.name)
        self.site = create_site(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_inspection_reports_site_assets(self) -> None:
        result = inspect_static_site(self.site)
        self.assertTrue(result.ok)
        self.assertTrue(result.indexFound)
        self.assertEqual(result.files, 6)
        self.assertEqual(result.cssFiles, 1)
        self.assertEqual(result.jsFiles, 1)
        self.assertEqual(result.assets, 2)
        self.assertEqual(result.errors, ())

    def test_static_bridge_serves_supported_content_and_head(self) -> None:
        bridge = StaticSiteBridge(self.site)
        self.assertIn(b"Private site", bridge.fetch("GET", "/").body)
        self.assertEqual(bridge.fetch("GET", "/style.css").headers["content-type"], "text/css; charset=utf-8")
        self.assertIn(b"dataset.ready", bridge.fetch("GET", "/script.js").body)
        self.assertEqual(json.loads(bridge.fetch("GET", "/data.json").body), {"ok": True})
        self.assertEqual(bridge.fetch("GET", "/images/pixel.png").body[:4], b"\x89PNG")
        self.assertEqual(bridge.fetch("HEAD", "/index.html").body, b"")

    def test_static_bridge_rechecks_file_limit_at_request_time(self) -> None:
        bridge = StaticSiteBridge(self.site, max_file_bytes=64 * 1024)
        (self.site / "data.json").write_bytes(b"x" * (64 * 1024 + 1))
        response = bridge.fetch("GET", "/data.json")
        self.assertEqual(response.status, 403)
        self.assertLess(len(response.body), 64 * 1024)

    def test_static_bridge_blocks_traversal_and_absolute_paths(self) -> None:
        outside = self.root / "outside.html"
        outside.write_text("secret", encoding="utf-8")
        bridge = StaticSiteBridge(self.site)
        for path in ("/../outside.html", "/%2e%2e/outside.html", "/C:/Windows/win.ini", "//server/share"):
            response = bridge.fetch("GET", path)
            self.assertIn(response.status, {403, 404}, path)
            self.assertNotIn(b"secret", response.body)

    def test_static_bridge_rejects_post_and_unknown_files(self) -> None:
        bridge = StaticSiteBridge(self.site)
        self.assertEqual(bridge.fetch("POST", "/", body=b"x").status, 405)
        self.assertEqual(bridge.fetch("GET", "/missing.html").status, 404)

    def test_inspection_rejects_executables_and_oversized_files(self) -> None:
        (self.site / "run.cmd").write_text("exit", encoding="ascii")
        result = inspect_static_site(self.site)
        self.assertFalse(result.ok)
        self.assertTrue(any("forbidden executable" in error for error in result.errors))
        (self.site / "run.cmd").unlink()
        (self.site / "large.json").write_bytes(b"x" * (64 * 1024 + 1))
        result = inspect_static_site(self.site, max_file_bytes=64 * 1024)
        self.assertFalse(result.ok)
        self.assertTrue(any("size limit" in error for error in result.errors))

    def test_inspection_counts_rejected_files_against_scan_limit(self) -> None:
        site = self.root / "bounded-site"
        site.mkdir()
        (site / "index.html").write_text("<!doctype html>", encoding="utf-8")
        (site / "first.tmp").write_text("blocked", encoding="utf-8")
        (site / "second.tmp").write_text("blocked", encoding="utf-8")
        with patch("granger_network.hosting.MAX_STATIC_FILES", 2):
            result = inspect_static_site(site)
        self.assertFalse(result.ok)
        self.assertTrue(any("file-count limit" in error for error in result.errors))

    def test_inspection_error_details_are_bounded(self) -> None:
        site = self.root / "many-invalid-files"
        site.mkdir()
        (site / "index.html").write_text("<!doctype html>", encoding="utf-8")
        for index in range(80):
            (site / f"blocked-{index}.tmp").write_text("blocked", encoding="utf-8")
        result = inspect_static_site(site)
        self.assertFalse(result.ok)
        self.assertEqual(len(result.errors), 64)

    def test_inspection_supports_spaces_unicode_and_deep_paths(self) -> None:
        site = self.root / "site with spaces" / "\u0442\u0435\u0441\u0442"
        for index in range(12):
            site /= f"segment-{index:02d}-abcdefgh"
        site.mkdir(parents=True)
        (site / "index.html").write_text("<!doctype html><h1>ok</h1>", encoding="utf-8")
        result = inspect_static_site(site)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(Path(result.root), site.resolve())

    def test_inspection_rejects_empty_and_missing_index_folders(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        self.assertIn("index.html is missing", inspect_static_site(empty).errors)
        missing_index = self.root / "missing-index"
        missing_index.mkdir()
        (missing_index / "style.css").write_text("body{}", encoding="utf-8")
        result = inspect_static_site(missing_index)
        self.assertFalse(result.ok)
        self.assertIn("index.html is missing", result.errors)

    def test_inspection_reports_permission_denied_file(self) -> None:
        blocked = (self.site / "data.json").resolve()
        original_open = Path.open

        def guarded_open(path: Path, *args: object, **kwargs: object):
            if path.resolve() == blocked:
                raise PermissionError("blocked by test")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            result = inspect_static_site(self.site)
        self.assertFalse(result.ok)
        self.assertTrue(any("file is not readable: data.json" in error for error in result.errors))

    @unittest.skipIf(os.name == "nt", "ordinary Windows symlinks require elevated privileges")
    def test_inspection_blocks_symlink_escape(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "hidden.html").write_text("secret", encoding="utf-8")
        (self.site / "escape").symlink_to(outside, target_is_directory=True)
        result = inspect_static_site(self.site)
        self.assertFalse(result.ok)
        self.assertTrue(any("symlink escapes" in error for error in result.errors))


class HostedServiceStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-hosting-store-")
        self.root = Path(self.temporary.name)
        self.site = create_site(self.root)
        RecordingHandler.requests = []
        RecordingHandler.bodies = []
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()

    def tearDown(self) -> None:
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=2.0)
        self.temporary.cleanup()

    def test_ten_services_have_unique_identity_storage_and_address(self) -> None:
        services = self.root / "services"
        addresses: set[str] = set()
        public_keys: set[bytes] = set()
        for index in range(10):
            identifier = f"{index + 1:032x}"
            config, descriptor = initialize_hosted_service(
                services,
                identifier,
                f"Site {index + 1}",
                "static",
                source=str(self.site.resolve()),
            )
            loaded, identity, loaded_descriptor = load_hosted_service(services / identifier)
            self.assertEqual(config, loaded)
            self.assertEqual(descriptor.canonical_name, loaded_descriptor.canonical_name)
            addresses.add(descriptor.canonical_name)
            public_keys.add(identity.public_key_bytes)
            self.assertTrue((services / identifier / CONFIG_FILE).is_file())
            self.assertTrue((services / identifier / IDENTITY_FILE).is_file())
            self.assertTrue((services / identifier / SERVICE_DESCRIPTOR_FILE).is_file())
        self.assertEqual(len(addresses), 10)
        self.assertEqual(len(public_keys), 10)

    def test_update_preserves_identity_and_changes_signed_metadata(self) -> None:
        services = self.root / "services"
        identifier = "1" * 32
        _config, descriptor = initialize_hosted_service(
            services, identifier, "Before", "static", source=str(self.site.resolve())
        )
        before_identity = load_hosted_service(services / identifier)[1].public_key_bytes
        updated, updated_descriptor = update_hosted_service(
            services / identifier, title="After", source=str(self.site.resolve())
        )
        after_identity = load_hosted_service(services / identifier)[1].public_key_bytes
        self.assertEqual(before_identity, after_identity)
        self.assertEqual(descriptor.canonical_name, updated_descriptor.canonical_name)
        self.assertEqual(updated.title, "After")
        self.assertEqual(updated_descriptor.metadata["title"], "After")

    def test_local_application_must_be_reachable_numeric_loopback(self) -> None:
        services = self.root / "services"
        port = int(self.backend.server_address[1])
        config, descriptor = initialize_hosted_service(
            services,
            "2" * 32,
            "Forum",
            "local-application",
            upstream=f"http://127.0.0.1:{port}",
        )
        self.assertEqual(config.upstream, f"http://127.0.0.1:{port}")
        self.assertTrue(descriptor.canonical_name.endswith(".granger"))
        with self.assertRaises(UpstreamPolicyError):
            initialize_hosted_service(
                services,
                "3" * 32,
                "Unsafe",
                "local-application",
                upstream="http://example.com:80",
            )
        self.assertEqual(LoopbackHttpTarget("::1", port).url, f"http://[::1]:{port}")

    def test_local_application_probe_rejects_offline_and_non_http_ports(self) -> None:
        offline = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        offline.bind(("127.0.0.1", 0))
        offline_port = int(offline.getsockname()[1])
        offline.close()
        with self.assertRaisesRegex(UpstreamPolicyError, "not reachable"):
            probe_loopback_application(f"http://127.0.0.1:{offline_port}", timeout=0.2)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])

        def send_invalid_response() -> None:
            connection, _address = listener.accept()
            with connection:
                connection.recv(4096)
                connection.sendall(b"not-http\r\n")
            listener.close()

        worker = threading.Thread(target=send_invalid_response, daemon=True)
        worker.start()
        with self.assertRaisesRegex(UpstreamPolicyError, "valid HTTP response"):
            probe_loopback_application(f"http://127.0.0.1:{port}")
        worker.join(timeout=2.0)

    def test_local_application_probe_accepts_ipv6_loopback_when_available(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 is unavailable")

        class Ipv6Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6

        try:
            backend = Ipv6Server(("::1", 0), RecordingHandler)
        except OSError as error:
            self.skipTest(f"IPv6 loopback is unavailable: {error}")
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            port = int(backend.server_address[1])
            target = probe_loopback_application(f"http://[::1]:{port}")
            self.assertEqual(target.host, "::1")
        finally:
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=2.0)

    def test_cli_failure_uses_structured_json_contract(self) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
        probe.close()
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = hosting_main([
                "probe-application",
                "--upstream",
                f"http://127.0.0.1:{port}",
            ])
        document = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertFalse(document["ok"])
        self.assertEqual(document["error"]["code"], "backend_unreachable")
        self.assertIn("not reachable", document["error"]["message"])
        self.assertIn("granger-hosting:", stderr.getvalue())

    def test_loopback_proxy_strips_client_and_relay_metadata(self) -> None:
        port = int(self.backend.server_address[1])
        bridge = LoopbackHttpBridge(LoopbackHttpTarget("127.0.0.1", port))
        response = bridge.fetch(
            "POST",
            "/message",
            {
                "content-type": "text/plain",
                "x-forwarded-for": "198.51.100.10",
                "forwarded": "for=198.51.100.10",
                "x-real-ip": "198.51.100.10",
                "x-granger-session": "gs_attacker_controlled_value",
            },
            b"hello",
            session_identity="gs_local_session_identity",
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(RecordingHandler.bodies, [b"hello"])
        received = RecordingHandler.requests[-1]
        self.assertEqual(received.get("x-granger-session"), "gs_local_session_identity")
        self.assertNotIn("x-forwarded-for", received)
        self.assertNotIn("forwarded", received)
        self.assertNotIn("x-real-ip", received)

    def test_failed_creation_does_not_leave_partial_service(self) -> None:
        services = self.root / "services"
        with self.assertRaises(UpstreamPolicyError):
            initialize_hosted_service(
                services,
                "4" * 32,
                "Missing",
                "static",
                source=str(self.root / "missing"),
            )
        self.assertFalse((services / ("4" * 32)).exists())
        self.assertEqual(list(services.glob(".*.creating")), [])


if __name__ == "__main__":
    unittest.main()
