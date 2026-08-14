from __future__ import annotations

from contextlib import ExitStack
from io import StringIO
from os import terminal_size
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests

from rich.console import Console

from pamp import main as pamp_main
from pamp.core.domain_analyzer import analyze_domain
from pamp.core.http_surface import INTERESTING_PATHS, _check_interesting_paths
from pamp.core.models import ArtifactRecord
from pamp.core.sensitive_file_checker import check_sensitive_files
from pamp.report.html_exporter import (
    REPORT_LOGO_CANDIDATES,
    _asset_payload,
    _branding_assets,
    export_html_report,
)


class ReleasePolishTests(unittest.TestCase):
    def tearDown(self) -> None:
        pamp_main.set_language("en")

    def test_startup_banner_is_exact_and_cli_has_no_frames(self) -> None:
        expected_banner = """██████╗  █████╗ ███╗   ███╗██████╗
██╔══██╗██╔══██╗████╗ ████║██╔══██╗
██████╔╝███████║██╔████╔██║██████╔╝
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔═══╝
██║      ██║  ██║██║ ╚═╝ ██║██║
╚═╝      ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝"""
        for language in ("en", "ru"):
            stream = StringIO()
            original_console = pamp_main.console
            try:
                pamp_main.console = Console(file=stream, force_terminal=False, color_system=None, width=120)
                pamp_main.set_language(language)
                with patch("pamp.main.shutil.get_terminal_size", return_value=terminal_size((100, 24))):
                    pamp_main.show_startup_banner()
            finally:
                pamp_main.console = original_console
            output = stream.getvalue()
            self.assertEqual(output.rstrip("\n"), pamp_main.center_ascii_art(expected_banner, 100))
            for forbidden in (
                "Security Analyzer",
                "Attack Surface Intelligence Platform",
                "Платформа анализа поверхности атаки",
                "Version",
                "Версия",
                "GitHub",
                "Current language",
                "Текущий язык",
                "Ready",
                "Готово",
            ):
                self.assertNotIn(forbidden, output)

        self.assertEqual(pamp_main.center_ascii_art(expected_banner, 20), expected_banner)
        centered_lines = pamp_main.center_ascii_art(expected_banner, 100).splitlines()
        expected_padding = (100 - max(map(len, expected_banner.splitlines()))) // 2
        self.assertTrue(all(line.startswith(" " * expected_padding) for line in centered_lines))

        menu_stream = StringIO()
        original_console = pamp_main.console
        try:
            pamp_main.console = Console(file=menu_stream, force_terminal=False, color_system=None, width=120)
            pamp_main.set_language("ru")
            pamp_main.show_menu(
                {
                    "target": "88.119.176.157",
                    "target_type": "ip",
                    "case_file": "pamp/data/cases/current.json",
                    "report_path": "output/report.html",
                }
            )
        finally:
            pamp_main.console = original_console
        menu_output = menu_stream.getvalue()
        self.assertIn("последняя цель 88.119.176.157", menu_output)
        self.assertIn("[1] Анализ IP", menu_output)
        self.assertNotIn("╭", menu_output)
        self.assertNotIn("╰", menu_output)
        self.assertNotIn("│", menu_output)

    def test_report_uses_logo_system_cursor_and_chain_fallbacks(self) -> None:
        record = ArtifactRecord(type="domain", label="example.com", source="test", data={"domain": "example.com"})
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.html"
            assets = _branding_assets(report_path)
            export_html_report([record], {}, report_path, language="ru")
            html = report_path.read_text(encoding="utf-8")

            self.assertIn(assets["logo"]["kind"], {"image", "video"})
            self.assertTrue(assets["logo"]["name"].startswith("brand-logo."))
            if assets["logo"]["src"].startswith("data:"):
                self.assertIn(";base64,", assets["logo"]["src"])
            else:
                self.assertTrue((report_path.parent / assets["logo"]["src"]).is_file())
            self.assertNotIn("cursor", assets)
            self.assertNotIn("cursor_css", assets)
            self.assertIn('class="brand-block has-logo"', html)
            self.assertNotIn('class="brand-copy"', html)
            for custom_cursor_marker in (
                "has-custom-cursor-asset",
                "custom-cursor-enabled",
                "cursor-dot",
                "cursorDot",
                "cursor-image",
                "text-cursor",
                "initCustomCursor",
            ):
                self.assertNotIn(custom_cursor_marker, html)
            sidebar_css = html.split(".sidebar {", 1)[1].split("}", 1)[0]
            self.assertIn("background: #000000;", sidebar_css)
            self.assertNotIn("gradient", sidebar_css)
            self.assertNotIn("rgba(", sidebar_css)
            self.assertNotIn("backdrop-filter", sidebar_css)
            self.assertNotIn("box-shadow", sidebar_css)
            logo_css = html.split(".brand-media {", 1)[1].split("}", 1)[0]
            self.assertIn("object-fit: contain;", logo_css)
            self.assertIn("max-width: 100%;", logo_css)
            self.assertIn("max-height: 100%;", logo_css)
            self.assertIn("transition: transform .2s ease;", logo_css)
            self.assertIn("function chainFallbackIcon", html)
            self.assertIn('tr("Values")', html)

    def test_report_logo_image_priority(self) -> None:
        expected = ("brand-logo.png", "brand-logo.jpg", "brand-logo.jpeg", "brand-logo.webp")
        self.assertEqual(REPORT_LOGO_CANDIDATES[:4], expected)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_dir = root / "source"
            output_dir = root / "output" / "assets"
            report_dir = root / "output"
            source_dir.mkdir()
            report_dir.mkdir()
            for name in expected:
                (source_dir / name).write_bytes(name.encode("ascii"))

            for name in expected:
                payload = _asset_payload(source_dir, output_dir, report_dir, REPORT_LOGO_CANDIDATES, "test")
                self.assertEqual(payload["name"], name)
                self.assertEqual(payload["kind"], "image")
                self.assertTrue(payload["src"].startswith("data:image/"))
                (source_dir / name).unlink()

    def test_parallel_path_checks_keep_order_and_reuse_existing_results(self) -> None:
        session = requests.Session()
        try:
            with patch(
                "pamp.core.http_surface._check_interesting_path",
                side_effect=lambda _session, base, path, *_args: {
                    "path": path,
                    "url": f"{base}{path}",
                    "status": 200,
                },
            ):
                rows = _check_interesting_paths(session, "https://example.com", True, None, [])
        finally:
            session.close()
        self.assertEqual([row["path"] for row in rows], list(INTERESTING_PATHS))

        checked: list[str] = []
        known = [
            {"path": "/robots.txt", "url": "https://example.com/robots.txt", "status": 200},
            {"path": "/sitemap.xml", "url": "https://example.com/sitemap.xml", "status": 302},
        ]
        with patch(
            "pamp.core.sensitive_file_checker._check_path",
            side_effect=lambda _base, path, *_args: (checked.append(path) and None, ""),
        ):
            result = check_sensitive_files(
                "https://example.com",
                known_paths=known,
                skip_paths=INTERESTING_PATHS,
            )
        self.assertIn("robots.txt", [row["path"] for row in result["findings"]])
        self.assertNotIn("sitemap.xml", [row["path"] for row in result["findings"]])
        self.assertNotIn("robots.txt", checked)
        self.assertNotIn("sitemap.xml", checked)

    def test_domain_pipeline_completes_background_scan_and_progress(self) -> None:
        port_surface = {
            "status": "unavailable",
            "skip_reason": "test fixture",
            "open_ports": [],
            "summary": {"open_ports": 0, "services_identified": 0, "sensitive_services": 0},
            "errors": [],
        }
        http_surface = {
            "errors": [],
            "_html": "",
            "_body_text": "",
            "status_code": None,
            "primary_url": "",
            "final_url": "",
            "headers": {},
            "probes": [],
            "redirect_chain": [],
            "interesting_paths": [],
            "security_signals": [],
            "favicon": {},
        }
        updates: list[tuple[int, int, str, str]] = []
        with ExitStack() as stack:
            stack.enter_context(patch("pamp.core.domain_analyzer.analyze_port_surface", return_value=port_surface))
            stack.enter_context(patch("pamp.core.domain_analyzer.analyze_http_surface", return_value=http_surface))
            stack.enter_context(patch("pamp.core.domain_analyzer._reverse_dns_for_ips", return_value=[]))
            stack.enter_context(patch("pamp.core.domain_analyzer._tls_certificate", return_value={}))
            stack.enter_context(patch("pamp.core.domain_analyzer._asn_bgp_for_ips", return_value=[]))
            stack.enter_context(
                patch(
                    "pamp.core.domain_analyzer.analyze_cloud_buckets",
                    return_value={"candidates": [], "verified": [], "public_objects": [], "summary": {}, "errors": []},
                )
            )
            result = analyze_domain(
                "203.0.113.5",
                progress_callback=lambda completed, total, label, status: updates.append(
                    (completed, total, label, status)
                ),
            )

        self.assertIs(result["port_surface"], port_surface)
        self.assertEqual(updates[-1][:3], (10, 10, "progress.complete"))
        self.assertTrue(any(row["stage"] == "port_surface" for row in result["execution_log"]))


if __name__ == "__main__":
    unittest.main()
