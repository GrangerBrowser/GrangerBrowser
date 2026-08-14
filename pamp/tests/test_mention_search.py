from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pamp.core.mention_search import (
    SourceDocument,
    _find_matches,
    _page_results,
    _parse_html_sources,
    generate_variants,
    is_meaningful_query,
    normalize_modes,
    parse_keywords,
    search_mentions,
)
from pamp.core.models import ArtifactRecord
from pamp.report.html_exporter import build_report_model
from pamp.report.mention_search_exporter import export_mention_search_report


class MentionSearchTests(unittest.TestCase):
    def test_keywords_modes_and_variants(self) -> None:
        self.assertEqual(
            parse_keywords("steam, @steam\nlogin"),
            ["steam", "@steam", "login"],
        )
        self.assertEqual(
            normalize_modes("default"),
            ["case-insensitive", "variants"],
        )
        variants = generate_variants("steam")
        self.assertIn("@steam", variants)
        self.assertIn("steams", variants)
        self.assertIn("steamLogin", variants)
        self.assertIn("steam_auth", variants)
        self.assertIn("steam-callback", variants)
        self.assertTrue(is_meaningful_query("steam"))
        self.assertFalse(is_meaningful_query("1"))
        self.assertFalse(is_meaningful_query("_"))
        self.assertFalse(is_meaningful_query("a"))

    @patch("pamp.core.mention_search._collect_http_sources")
    def test_meaningless_query_is_rejected_before_network(self, collect_http) -> None:
        for query in ("1", "_", "a"):
            with self.subTest(query=query), self.assertRaises(ValueError):
                search_mentions("example.test", query)
        collect_http.assert_not_called()

    def test_overlap_dedupe_and_sensitive_proximity(self) -> None:
        documents = [
            SourceDocument(
                "api",
                "https://example.test/api/auth/steam",
                "api endpoint",
                "/api/auth/steam callback",
            )
        ]
        matches = _find_matches(
            documents,
            ["steam"],
            {"steam": generate_variants("steam")},
            normalize_modes("default"),
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["matched_text"].lower(), "steam")
        self.assertEqual(matches[0]["risk"], "sensitive")

    @patch("pamp.core.mention_search._collect_browser_sources")
    @patch("pamp.core.mention_search._collect_http_sources")
    @patch("pamp.core.mention_search._collect_assets", return_value=[])
    def test_hunt_summary_and_dedupe(
        self,
        _assets,
        http_sources,
        browser_sources,
    ) -> None:
        http_sources.return_value = {
            "documents": [
                SourceDocument(
                    "html",
                    "https://example.test/",
                    "title",
                    "Steam Login",
                ),
                SourceDocument(
                    "api",
                    "https://example.test/api/auth/steam",
                    "api endpoint",
                    "/api/auth/steam",
                ),
            ],
            "coverage": {"html": 1, "api": 1},
            "js_urls": [],
            "css_urls": [],
            "primary_url": "https://example.test/",
            "page_urls": ["https://example.test/"],
            "browser_urls": [],
            "stats": {"pages_scanned": 1, "buttons_scanned": 1},
        }
        browser_sources.return_value = {
            "documents": [],
            "coverage": {},
            "js_urls": [],
            "css_urls": [],
            "page_urls": [],
            "stats": {},
        }
        result = search_mentions("example.test", "steam")
        self.assertEqual(result["type"], "mention_search")
        self.assertEqual(result["summary"]["matches"], 2)
        self.assertGreater(result["summary"]["mention_score"], 0)
        self.assertEqual(result["summary"]["pages_scanned"], 1)
        self.assertEqual(result["limits"]["max_pages"], 100)
        self.assertEqual(result["limits"]["max_depth"], 3)
        self.assertEqual(
            result["summary"]["risk_counts"]["sensitive"],
            1,
        )

    def test_report_model_without_graph(self) -> None:
        data = {
            "type": "mention_search",
            "target": "example.test",
            "keywords": ["steam"],
            "variants": [{"keyword": "steam", "values": ["steam", "Steam"]}],
            "summary": {
                "matches": 1,
                "unique_urls": 1,
                "source_types": {"api": 1},
                "risk_counts": {"sensitive": 1, "interesting": 0, "info": 0},
                "mention_score": 70,
            },
            "matches": [
                {
                    "keyword": "steam",
                    "matched_text": "<Steam>",
                    "variant": "steam",
                    "source_type": "api",
                    "source_url": "https://example.test/api/auth/steam",
                    "location": "api endpoint",
                    "line": 1,
                    "context_before": "<script>",
                    "context_after": "</script>",
                    "confidence": "high",
                    "risk": "sensitive",
                    "notes": "auth proximity",
                    "count": 1,
                }
            ],
            "top_matches": [],
            "source_coverage": {"api": 1},
            "errors": [],
        }
        data["top_matches"] = data["matches"]
        record = ArtifactRecord(
            type="mention_search",
            label="example.test",
            data=data,
            source="mention_search",
        )
        report = build_report_model(
            [record.to_dict()],
            {},
            language="ru",
        )
        self.assertEqual(report["target_type"], "mention_search")
        self.assertEqual(report["artifact_counts"]["mention_search"], 1)
        legacy_key = "cor" + "relation"
        self.assertNotIn(legacy_key, report)
        context = report["mention_hunter"]["matches"][0]["context"]
        self.assertEqual(context["match"], "<Steam>")
        self.assertEqual(context["before"], "<script>")

    def test_semantic_html_elements_include_navigation_paths(self) -> None:
        parsed = _parse_html_sources(
            """
            <html><body>
              <nav><a href="/market">Steam Market</a></nav>
              <form action="/login" method="post">
                <label for="user">Steam username</label>
                <input id="user" placeholder="Steam account">
                <button>Login with Steam</button>
              </form>
            </body></html>
            """,
            "https://example.test/",
        )
        matches = _find_matches(
            parsed["documents"],
            ["steam"],
            {"steam": generate_variants("steam")},
            normalize_modes("default"),
        )
        types = {row["element_type"] for row in matches}
        self.assertIn("Navigation", types)
        self.assertIn("Button", types)
        self.assertIn("Form Field", types)
        self.assertTrue(all(row["css_selector"] or row["xpath"] for row in matches))
        self.assertTrue(
            any("#:~:text=" in row["navigation_url"] for row in matches)
        )

    def test_page_text_excludes_hidden_markup_and_groups_equivalent_urls(self) -> None:
        parsed = _parse_html_sources(
            """
            <html><head><style>.hidden-steam { color: red; }</style></head>
            <body><script>const hiddenSteam = true;</script><template>steam template</template>
            <p>Visible Steam profile</p></body></html>
            """,
            "https://example.test/",
        )
        page_text = next(row.text for row in parsed["documents"] if row.location == "Page text")
        self.assertEqual(page_text, "Visible Steam profile")
        self.assertTrue(any(row.source_type == "js" for row in parsed["documents"]))

        pages = _page_results(
            [
                {"page_url": "https://EXAMPLE.test/path/#one", "count": 1, "section": "Page"},
                {"page_url": "https://example.test/path", "count": 2, "section": "Page"},
            ],
            ["https://example.test/path/", "https://example.test/path"],
        )
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["matches"], 2)
        self.assertEqual(pages[0]["occurrences"], 3)

    @patch("pamp.core.mention_search._collect_assets", return_value=[])
    @patch("pamp.core.mention_search._collect_browser_sources", side_effect=RuntimeError("browser unavailable"))
    @patch("pamp.core.mention_search._collect_http_sources", side_effect=RuntimeError("network unavailable"))
    def test_collection_failures_still_return_a_result(self, _http, _browser, _assets) -> None:
        debug = []
        result = search_mentions("example.test", "steam", debug_log=debug.append)
        self.assertEqual(result["type"], "mention_search")
        self.assertEqual(result["summary"]["matches"], 0)
        self.assertGreaterEqual(len(result["errors"]), 2)
        self.assertTrue(any("[MENTION][HTTP]" in row for row in debug))

    def test_specialized_report_is_compact_and_escapes_context(self) -> None:
        data = {
            "type": "mention_search",
            "target": "example.test",
            "primary_url": "https://example.test/",
            "keywords": ["steam"],
            "search_modes": ["case-insensitive"],
            "timestamp": "2026-06-25T20:00:00+00:00",
            "summary": {
                "matches": 1,
                "total_occurrences": 1,
                "pages_scanned": 2,
                "pages_with_matches": 1,
                "sections": {"Navigation": 1},
                "scan_stats": {"links_scanned": 4},
            },
            "pages": [
                {
                    "url": "https://example.test/login",
                    "path": "/login",
                    "matches": 1,
                    "occurrences": 1,
                    "sections": {"Navigation": 1},
                }
            ],
            "matches": [
                {
                    "keyword": "steam",
                    "matched_text": "<Steam>",
                    "source_type": "dom",
                    "page_url": "https://example.test/login",
                    "page_path": "/login",
                    "navigation_url": "https://example.test/login#:~:text=Steam",
                    "element_type": "Button",
                    "section": "Form",
                    "context_before": "<script>",
                    "context_after": "</script>",
                    "css_selector": "#login",
                }
            ],
            "errors": [],
            "limits": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mentions_report.html"
            export_mention_search_report(data, path, language="ru")
            html = path.read_text(encoding="utf-8")
        self.assertIn("Поиск упоминаний", html)
        self.assertIn("mentions_report", str(path))
        self.assertNotIn("<script><Steam>", html)
        self.assertNotIn("Карта поверхности", html)


if __name__ == "__main__":
    unittest.main()
