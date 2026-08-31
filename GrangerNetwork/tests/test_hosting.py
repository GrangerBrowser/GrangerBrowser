from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
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
    PUBLICATION_CONTENT,
    PUBLICATION_MANIFEST,
    SERVICE_DESCRIPTOR_FILE,
    StaticSiteBridge,
    _ensure_publication_snapshot,
    _service_route_startup_timeout,
    _hosting_health_state,
    initialize_hosted_service,
    inspect_static_site,
    load_hosted_service,
    main as hosting_main,
    probe_loopback_application,
    update_hosted_service,
)
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.descriptor import ServiceDescriptor
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.peer import node_id_from_public_key


class HostingHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        identity = ServiceIdentity.generate()
        self.service = ServiceDescriptor.create_remote(identity, "health-test", lifetime=1800)
        self.introduction = IntroductionDescriptor.create(
            identity, self.service,
            [node_id_from_public_key(ServiceIdentity.generate().public_key_bytes)],
            sequence=1, lifetime=900,
        )
        self.now = int(time.time())
        self.host = {
            "ready": True, "running": True, "recoveryRequested": False,
            "healthyIntroductions": 1, "requiredIntroductions": 1,
        }
        self.network = {"updatedAt": self.now, "state": "CONNECTED", "dhtReady": True}

    def check(self) -> tuple[str, str]:
        return _hosting_health_state(
            self.host, self.network, self.service, self.introduction, now=self.now,
        )

    def test_online_requires_recent_authenticated_health(self) -> None:
        self.assertEqual(self.check(), ("online", ""))
        self.network["updatedAt"] = self.now - 121
        self.assertEqual(self.check(), ("degraded", "DHT_HEALTH_STALE"))
        self.network["updatedAt"] = self.now + 1
        self.assertEqual(self.check(), ("degraded", "DHT_HEALTH_STALE"))

    def test_lost_dht_and_introduction_have_distinct_states(self) -> None:
        self.network["dhtReady"] = False
        self.assertEqual(self.check(), ("network-unavailable", "DHT_UNAVAILABLE"))
        self.host["healthyIntroductions"] = 0
        self.assertEqual(self.check(), ("intro-unavailable", "INTRO_HEARTBEAT_STALE"))
        self.host["recoveryRequested"] = True
        self.assertEqual(self.check(), ("recovering", "ROUTE_RECOVERY"))

    def test_expiry_and_dead_worker_cannot_remain_online(self) -> None:
        self.host["running"] = False
        self.assertEqual(self.check(), ("recovering", "HOST_WORKER_UNAVAILABLE"))
        self.now = self.introduction.expires_at
        self.assertEqual(self.check(), ("intro-unavailable", "INTRO_DESCRIPTOR_EXPIRED"))
        self.now = self.service.expires_at
        self.assertEqual(self.check(), ("service-unpublished", "SERVICE_DESCRIPTOR_EXPIRED"))


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

    def test_service_route_startup_budget_is_bounded_and_network_aware(self) -> None:
        self.assertEqual(_service_route_startup_timeout(1.0, 3), 15.0)
        self.assertEqual(_service_route_startup_timeout(30.0, 3), 90.0)
        self.assertEqual(_service_route_startup_timeout(30.0, 30), 90.0)

    def test_inspection_reports_site_assets(self) -> None:
        result = inspect_static_site(self.site)
        self.assertTrue(result.ok)
        self.assertTrue(result.indexFound)
        self.assertEqual(result.files, 6)
        self.assertEqual(result.htmlFiles, 1)
        self.assertEqual(result.cssFiles, 1)
        self.assertEqual(result.jsFiles, 1)
        self.assertEqual(result.jsonFiles, 1)
        self.assertEqual(result.assets, 2)
        self.assertEqual(result.entryPage, "index.html")
        self.assertEqual(result.entryCandidates, ("index.html",))
        self.assertFalse(result.requiresEntrySelection)
        self.assertEqual(result.errors, ())

    def test_single_non_index_html_is_automatic_entry_page(self) -> None:
        (self.site / "index.html").rename(self.site / "nova_demo_site.html")
        inspection = inspect_static_site(self.site)
        self.assertTrue(inspection.ok, inspection.errors)
        self.assertFalse(inspection.indexFound)
        self.assertEqual(inspection.entryPage, "nova_demo_site.html")
        bridge = StaticSiteBridge(self.site)
        self.assertIn(b"Private site", bridge.fetch("GET", "/").body)
        self.assertEqual(
            bridge.fetch("GET", "/nova_demo_site.html").body,
            bridge.fetch("GET", "/").body,
        )

    def test_index_htm_is_used_when_index_html_is_absent(self) -> None:
        (self.site / "index.html").rename(self.site / "index.htm")
        inspection = inspect_static_site(self.site)
        self.assertTrue(inspection.ok, inspection.errors)
        self.assertEqual(inspection.entryPage, "index.htm")
        self.assertIn(b"Private site", StaticSiteBridge(self.site).fetch("GET", "/").body)

    def test_multiple_html_files_require_an_explicit_entry_page(self) -> None:
        (self.site / "index.html").unlink()
        (self.site / "home.html").write_text("<h1>Home</h1>", encoding="utf-8")
        (self.site / "forum.html").write_text("<h1>Forum</h1>", encoding="utf-8")
        inspection = inspect_static_site(self.site)
        self.assertTrue(inspection.ok, inspection.errors)
        self.assertTrue(inspection.requiresEntrySelection)
        self.assertEqual(inspection.entryPage, "")
        self.assertEqual(inspection.entryCandidates, ("forum.html", "home.html"))
        with self.assertRaisesRegex(UpstreamPolicyError, "must be selected"):
            StaticSiteBridge(self.site)
        selected = inspect_static_site(self.site, entry_page="forum.html")
        self.assertTrue(selected.ok, selected.errors)
        self.assertEqual(selected.entryPage, "forum.html")
        self.assertIn(
            b"Forum",
            StaticSiteBridge(self.site, entry_page="forum.html").fetch("GET", "/").body,
        )

    def test_arbitrary_nested_static_types_are_supported_without_filename_rules(self) -> None:
        nested = self.site / "assets"
        nested.mkdir()
        files = {
            "theme.css": b"body{}",
            "runtime.mjs": b"export const ok=true",
            "content.json": b'{"ok":true}',
            "notes.txt": b"notes",
            "document.xml": b"<root/>",
            "font.ttf": b"font",
            "font.otf": b"font",
            "site.webmanifest": b'{"name":"site"}',
            "module.wasm": b"\x00asm\x01\x00\x00\x00",
            "opaque.bundle-v7": b"\x00\x01custom-binary\xff",
        }
        for name, content in files.items():
            (nested / name).write_bytes(content)
        inspection = inspect_static_site(self.site)
        self.assertTrue(inspection.ok, inspection.errors)
        self.assertEqual(inspection.cssFiles, 2)
        self.assertEqual(inspection.jsFiles, 2)
        self.assertEqual(inspection.jsonFiles, 2)
        bridge = StaticSiteBridge(self.site)
        for name, content in files.items():
            self.assertEqual(bridge.fetch("GET", f"/assets/{name}").body, content)

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

    def test_inspection_has_no_extension_whitelist_and_rejects_oversized_files(self) -> None:
        (self.site / "run.cmd").write_text("exit", encoding="ascii")
        result = inspect_static_site(self.site)
        self.assertTrue(result.ok, result.errors)
        self.assertIn("run.cmd", result.includedFiles)
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
            (site / f"oversized-{index}.data").write_bytes(b"x" * (64 * 1024 + 1))
        result = inspect_static_site(site, max_file_bytes=64 * 1024)
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

    def test_inspection_rejects_folders_without_html(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        self.assertIn("no HTML entry page found", inspect_static_site(empty).errors)
        missing_html = self.root / "missing-html"
        missing_html.mkdir()
        (missing_html / "style.css").write_text("body{}", encoding="utf-8")
        result = inspect_static_site(missing_html)
        self.assertFalse(result.ok)
        self.assertIn("no HTML entry page found", result.errors)

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
        self.assertTrue(any(
            finding.path == "escape" and finding.reason == "link_or_reparse_point"
            for finding in result.blockedFindings
        ))

    def test_preflight_excludes_development_metadata_recursively(self) -> None:
        excluded_files = {
            ".git/config": b"repository",
            "assets/old-project/.git/config": b"nested repository",
            "worktree/.git": b"gitdir: ../.git/worktrees/site",
            ".github/workflows/build.yml": b"workflow",
            ".idea/workspace.xml": b"workspace",
            ".vscode/settings.json": b"settings",
            ".vs/state.bin": b"state",
            "nested/__pycache__/module.pyc": b"cache",
            "nested/.pytest_cache/state": b"cache",
            "nested/.mypy_cache/state": b"cache",
            "nested/.cache/state": b"cache",
            ".gitmodules": b"modules",
            ".gitattributes": b"attributes",
            ".gitignore": b"ignore",
            "README.md": b"readme",
            "CHANGELOG-2026.md": b"changes",
            "CONTRIBUTING.rst": b"contributing",
            "CODE_OF_CONDUCT.md": b"conduct",
            "SECURITY.md": b"security",
            "nested/debug.pdb": b"symbols",
            "nested/session.log": b"log",
            "nested/swap.swp": b"swap",
            "nested/backup~": b"backup",
        }
        for relative, content in excluded_files.items():
            target = self.site / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        for directory in ("build", "dist", "out", "node_modules"):
            target = self.site / directory / "asset.unknown"
            target.parent.mkdir(parents=True)
            target.write_bytes(directory.encode("ascii"))

        inspection = inspect_static_site(self.site)
        self.assertTrue(inspection.ok, inspection.errors)
        excluded_paths = {item.path for item in inspection.excludedFiles}
        self.assertTrue({
            ".git", ".github", ".idea", ".vscode", ".vs",
            "assets/old-project/.git", "worktree/.git",
        } <= excluded_paths)
        self.assertIn("README.md", excluded_paths)
        for directory in ("build", "dist", "out", "node_modules"):
            self.assertIn(f"{directory}/asset.unknown", inspection.includedFiles)

    def test_preflight_blocks_high_confidence_secrets_and_opsec_paths(self) -> None:
        candidates = {
            ".env.production": "TOKEN=value",
            "server.pem": "certificate",
            "id_ed25519": "secret",
            "credentials-backup.json": "{}",
            "inline.txt": "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret",
            "local-path.txt": "workspace " + "C:" + "\\Users\\Someone\\project",
        }
        for relative, content in candidates.items():
            (self.site / relative).write_text(content, encoding="utf-8")
        inspection = inspect_static_site(self.site)
        self.assertFalse(inspection.ok)
        findings = {item.path: item.reason for item in inspection.blockedFindings}
        self.assertEqual(findings[".env.production"], "environment_secrets")
        self.assertEqual(findings["server.pem"], "private_credential_container")
        self.assertEqual(findings["id_ed25519"], "ssh_credentials")
        self.assertEqual(findings["credentials-backup.json"], "credential_filename")
        self.assertEqual(findings["inline.txt"], "private_key_material")
        self.assertEqual(findings["local-path.txt"], "local_path_disclosure")

    def test_binary_preflight_probe_is_bounded_and_does_not_hang(self) -> None:
        binary = self.site / "assets" / "large.custom"
        binary.parent.mkdir()
        binary.write_bytes(b"\x00" * (2 * 1024 * 1024))
        started = time.monotonic()
        inspection = inspect_static_site(self.site)
        self.assertTrue(inspection.ok, inspection.errors)
        self.assertIn("assets/large.custom", inspection.includedFiles)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_preflight_rejects_unc_source_without_network_access(self) -> None:
        inspection = inspect_static_site(Path("//127.0.0.1/granger-unavailable"))
        self.assertFalse(inspection.ok)
        self.assertIn("UNC source paths are not publishable", inspection.errors)

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_preflight_blocks_windows_junction(self) -> None:
        outside = self.root / "junction outside"
        outside.mkdir()
        (outside / "hidden.html").write_text("hidden", encoding="utf-8")
        junction = self.site / "linked content"
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
            check=False,
            text=True,
        )
        if created.returncode != 0:
            self.skipTest("Windows junction creation is unavailable")
        try:
            inspection = inspect_static_site(self.site)
            self.assertFalse(inspection.ok)
            self.assertTrue(any(
                finding.path == "linked content"
                and finding.reason == "link_or_reparse_point"
                for finding in inspection.blockedFindings
            ))
        finally:
            os.rmdir(junction)


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

    def test_static_publication_uses_filtered_immutable_snapshot(self) -> None:
        (self.site / ".git" / "objects").mkdir(parents=True)
        (self.site / ".git" / "config").write_text("private repository", encoding="utf-8")
        (self.site / "README.md").write_text("internal notes", encoding="utf-8")
        (self.site / "assets").mkdir()
        (self.site / "assets" / "module.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
        before = {
            path.relative_to(self.site).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.site.rglob("*") if path.is_file()
        }
        services = self.root / "services"
        identifier = "7" * 32
        config, _descriptor = initialize_hosted_service(
            services, identifier, "Snapshot", "static", source=str(self.site.resolve())
        )
        service_root = services / identifier
        content_root = service_root / PUBLICATION_CONTENT
        manifest_path = service_root / PUBLICATION_MANIFEST
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)

        after = {
            path.relative_to(self.site).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.site.rglob("*") if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertNotIn(str(self.site.resolve()), manifest_text)
        self.assertEqual(set(manifest), {
            "blockedFindings", "entryPoint", "excludedFiles", "includedFiles",
            "snapshotHash", "totalBytes", "totalFiles",
        })
        self.assertEqual(manifest["entryPoint"], config.entry_page)
        self.assertEqual(manifest["blockedFindings"], [])
        self.assertNotIn(".git/config", manifest["includedFiles"])
        self.assertNotIn("README.md", manifest["includedFiles"])
        self.assertFalse((content_root / ".git").exists())
        self.assertFalse((content_root / "README.md").exists())
        self.assertTrue((content_root / "assets" / "module.wasm").is_file())
        snapshot_inspection = inspect_static_site(
            content_root, entry_page=config.entry_page
        )
        self.assertEqual(snapshot_inspection.snapshotHash, manifest["snapshotHash"])
        self.assertEqual(snapshot_inspection.totalBytes, manifest["totalBytes"])

        bridge = StaticSiteBridge(content_root, entry_page=config.entry_page)
        original = bridge.fetch("GET", "/").body
        (self.site / "index.html").write_text("<h1>changed source</h1>", encoding="utf-8")
        (self.site / ".env").write_text("TOKEN=source-only", encoding="utf-8")
        self.assertEqual(bridge.fetch("GET", "/").body, original)
        self.assertNotIn(b"changed source", original)
        for excluded_path in ("/.git/config", "/README.md", "/.env"):
            response = bridge.fetch("GET", excluded_path)
            self.assertEqual(response.status, 404, excluded_path)
            self.assertNotIn(b"source-only", response.body)
        self.assertEqual(bridge.fetch("HEAD", "/assets/module.wasm").status, 200)
        self.assertEqual(bridge.fetch("POST", "/", body=b"x").status, 405)

    def test_snapshot_rebuild_preserves_identity_and_updates_content(self) -> None:
        services = self.root / "services"
        identifier = "8" * 32
        initialize_hosted_service(
            services, identifier, "Before", "static", source=str(self.site.resolve())
        )
        service_root = services / identifier
        identity_before = load_hosted_service(service_root)[1].public_key_bytes
        manifest_before = json.loads(
            (service_root / PUBLICATION_MANIFEST).read_text(encoding="utf-8")
        )
        (self.site / "index.html").write_text("<h1>updated snapshot</h1>", encoding="utf-8")
        update_hosted_service(
            service_root, title="After", source=str(self.site.resolve())
        )
        identity_after = load_hosted_service(service_root)[1].public_key_bytes
        manifest_after = json.loads(
            (service_root / PUBLICATION_MANIFEST).read_text(encoding="utf-8")
        )
        self.assertEqual(identity_before, identity_after)
        self.assertNotEqual(manifest_before["snapshotHash"], manifest_after["snapshotHash"])
        self.assertIn(
            b"updated snapshot",
            StaticSiteBridge(
                service_root / PUBLICATION_CONTENT,
                entry_page="index.html",
            ).fetch("GET", "/").body,
        )

    def test_tampered_publication_snapshot_fails_closed(self) -> None:
        services = self.root / "services"
        identifier = "9" * 32
        config, _descriptor = initialize_hosted_service(
            services, identifier, "Tamper check", "static", source=str(self.site.resolve())
        )
        service_root = services / identifier
        (service_root / PUBLICATION_CONTENT / "index.html").write_text(
            "<h1>tampered</h1>", encoding="utf-8"
        )
        with self.assertRaisesRegex(UpstreamPolicyError, "integrity check failed"):
            _ensure_publication_snapshot(service_root, config)

    def test_entry_page_is_persisted_without_modifying_the_source_folder(self) -> None:
        (self.site / "index.html").unlink()
        (self.site / "home.html").write_text("<h1>Home</h1>", encoding="utf-8")
        (self.site / "forum.html").write_text("<h1>Forum</h1>", encoding="utf-8")
        services = self.root / "services"
        config, descriptor = initialize_hosted_service(
            services,
            "5" * 32,
            "Forum",
            "static",
            source=str(self.site.resolve()),
            entry_page="forum.html",
        )
        self.assertEqual(config.entry_page, "forum.html")
        self.assertEqual(load_hosted_service(services / ("5" * 32))[0].entry_page, "forum.html")
        self.assertEqual(
            StaticSiteBridge(self.site, entry_page=config.entry_page).fetch("GET", "/").body,
            b"<h1>Forum</h1>",
        )
        self.assertFalse((self.site / "index.html").exists())
        self.assertTrue(descriptor.canonical_name.endswith(".granger"))

    def test_version_one_service_configuration_remains_readable(self) -> None:
        services = self.root / "services"
        identifier = "6" * 32
        initialize_hosted_service(
            services, identifier, "Legacy", "static", source=str(self.site.resolve())
        )
        config_path = services / identifier / CONFIG_FILE
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document.pop("entryPage")
        document["version"] = 1
        config_path.write_text(json.dumps(document), encoding="utf-8")
        loaded, _identity, _descriptor = load_hosted_service(services / identifier)
        self.assertEqual(loaded.entry_page, "index.html")

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
