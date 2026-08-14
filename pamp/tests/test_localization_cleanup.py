from __future__ import annotations

from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rich.console import Console

from pamp import main as pamp_main
from pamp.core.models import ArtifactRecord
from pamp.i18n import DEFAULT_LANGUAGE, load_locale, normalize_language
from pamp.report.html_exporter import export_html_report
from pamp.report.mention_search_exporter import export_mention_search_report


class LocalizationCleanupTests(unittest.TestCase):
    def tearDown(self) -> None:
        pamp_main.set_language(DEFAULT_LANGUAGE)

    def test_default_language_and_fallback_are_english(self) -> None:
        self.assertEqual(DEFAULT_LANGUAGE, "en")
        self.assertEqual(normalize_language(None), "en")
        self.assertEqual(normalize_language("unsupported"), "en")
        self.assertEqual(load_locale("en")["menu.analyze_ip"], "IP Analysis")

    def test_cli_menu_has_only_five_supported_actions(self) -> None:
        english = self._menu_text("en")
        russian = self._menu_text("ru")

        self.assertIn("[1] IP Analysis", english)
        self.assertIn("[2] Domain Analysis", english)
        self.assertIn("[3] Mentions Search", english)
        self.assertIn("[4] Switch Language (RU)", english)
        self.assertIn("[5] Exit", english)

        self.assertIn("[1] Анализ IP", russian)
        self.assertIn("[2] Анализ домена", russian)
        self.assertIn("[3] Поиск упоминаний", russian)
        self.assertIn("[4] Переключить язык (ENG)", russian)
        self.assertIn("[5] Выход", russian)

        for output in (english, russian):
            self.assertNotIn("[6]", output)
            self.assertNotIn("PCAP", output)
            self.assertNotIn("Browser Fingerprint", output)
            self.assertNotIn("Cookie/Storage", output)
            self.assertNotIn("Pamp Security Analyzer", output)
            self.assertNotIn("Attack Surface Intelligence Platform", output)
            self.assertNotIn("Платформа анализа поверхности атаки", output)

        self.assertEqual(load_locale("en")["prompt.menu"], "pamp::menu")
        self.assertEqual(load_locale("ru")["prompt.menu"], "pamp::menu")

    def test_legacy_cli_modules_and_locale_keys_are_removed(self) -> None:
        core = Path(pamp_main.__file__).resolve().parent / "core"
        for filename in ("pcap_analyzer.py", "fingerprint_analyzer.py", "cookie_analyzer.py"):
            self.assertFalse((core / filename).exists())

        forbidden_keys = {
            "menu.analyze_pcap",
            "menu.import_fingerprint",
            "menu.import_cookies",
            "prompt.pcap",
            "prompt.fingerprint",
            "prompt.cookies",
            "app.name",
            "app.tagline",
            "startup.version",
            "startup.github",
            "startup.language",
            "startup.ready",
            "menu.select_mode",
        }
        for language in ("en", "ru"):
            self.assertTrue(forbidden_keys.isdisjoint(load_locale(language)))

    def test_locale_catalogs_are_complete_and_clean(self) -> None:
        english = load_locale("en")
        russian = load_locale("ru")
        self.assertEqual(set(english), set(russian))
        self.assertTrue(all(value and "?" not in value for value in russian.values()))

        expected = {
            "Domain Intelligence": "Анализ домена",
            "Application Blueprint": "Архитектурная карта приложения",
            "Application Route Intelligence": "Анализ маршрутов приложения",
            "Search by IP": "Поиск по IP",
            "Search routes": "Поиск по маршрутам",
            "Search ports": "Поиск по портам",
            "Open Ports": "Открытые порты",
            "Risk Signals": "Сигналы риска",
            "No data available": "Нет данных",
        }
        for key, value in expected.items():
            self.assertEqual(russian[key], value)
            self.assertEqual(english[key], key)

    def test_reports_generate_in_both_languages_without_translating_raw_data(self) -> None:
        record = ArtifactRecord(
            type="domain",
            label="example.com",
            source="test",
            data={
                "domain": "example.com",
                "input": "example.com",
                "http_surface": {"primary_url": "https://example.com"},
                "technologies": [{"name": "React", "source": "test"}],
                "api_endpoints": [{"url": "https://example.com/api/admin/users", "path": "/api/admin/users"}],
                "cdn_detection": [{"name": "Cloudflare", "source": "test"}],
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            outputs = {}
            for language in ("en", "ru"):
                path = Path(tmpdir) / f"report-{language}.html"
                export_html_report([record], {}, path, language=language)
                outputs[language] = path.read_text(encoding="utf-8")

        self.assertIn('<html lang="en">', outputs["en"])
        self.assertIn('const CURRENT_LANGUAGE = "en";', outputs["en"])
        self.assertIn('<html lang="ru">', outputs["ru"])
        self.assertIn('const CURRENT_LANGUAGE = "ru";', outputs["ru"])
        self.assertIn("Отчёт Pamp", outputs["ru"])
        self.assertEqual(load_locale("ru")["Values"], "Значения")
        self.assertIn('tr("Values")', outputs["ru"])

        for html in outputs.values():
            self.assertIn("/api/admin/users", html)
            self.assertIn("Cloudflare", html)
            self.assertIn("React", html)
            self.assertNotIn(">undefined<", html)
            self.assertNotIn(">null<", html)

    def test_mention_report_uses_english_default_and_shared_locales(self) -> None:
        data = {
            "target": "example.com",
            "primary_url": "https://example.com",
            "keywords": ["/api/admin/users"],
            "summary": {"matches": 0},
            "matches": [],
            "pages": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            english_path = Path(tmpdir) / "mentions-en.html"
            russian_path = Path(tmpdir) / "mentions-ru.html"
            export_mention_search_report(data, english_path)
            export_mention_search_report(data, russian_path, language="ru")
            english = english_path.read_text(encoding="utf-8")
            russian = russian_path.read_text(encoding="utf-8")

        self.assertIn('<html lang="en">', english)
        self.assertIn("Mention Search", english)
        self.assertIn('<html lang="ru">', russian)
        self.assertIn("Поиск упоминаний", russian)
        self.assertIn("/api/admin/users", english)
        self.assertIn("/api/admin/users", russian)

    @staticmethod
    def _menu_text(language: str) -> str:
        stream = StringIO()
        console = Console(file=stream, force_terminal=False, color_system=None, width=120)
        pamp_main.set_language(language)
        with patch.object(pamp_main, "console", console):
            pamp_main.show_menu({})
        return stream.getvalue()


if __name__ == "__main__":
    unittest.main()
