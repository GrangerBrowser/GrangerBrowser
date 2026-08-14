from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pamp.core.application_blueprint import build_application_blueprint
from pamp.core.application_route_intelligence import (
    build_application_route_intelligence,
    build_endpoint_correlations,
    build_route_tree,
    build_route_risk_candidates,
    extract_dynamic_imports,
    extract_html_route_sources,
    extract_hidden_api_hosts,
    extract_javascript_routes,
    extract_parameter_intelligence,
    extract_permission_mappings,
)
from pamp.core.models import ArtifactRecord
from pamp.report.html_exporter import build_report_model, export_html_report


class ApplicationRouteIntelligenceTests(unittest.TestCase):
    def test_html_route_extraction(self) -> None:
        html = """
        <html><head>
          <link rel="canonical" href="/dashboard">
          <link rel="modulepreload" href="/assets/admin.chunk.js">
          <link rel="manifest" href="/manifest.json">
        </head><body>
          <a href="/login">Login</a>
          <form method="post" action="/api/auth/session"><input name="email"></form>
          <script src="/static/app.js"></script>
        </body></html>
        """
        endpoints = extract_html_route_sources(html, "https://example.test/")
        urls = {row["absolute_url"] for row in endpoints}

        self.assertIn("https://example.test/login", urls)
        self.assertIn("https://example.test/api/auth/session", urls)
        self.assertIn("https://example.test/assets/admin.chunk.js", urls)
        self.assertTrue(any(row["method"] == "POST" for row in endpoints))

    def test_javascript_route_recovery_patterns(self) -> None:
        script = """
          fetch('/api/users');
          axios.post('/api/auth/login');
          const xhr = new XMLHttpRequest();
          xhr.open('PUT', '/api/users/42');
          new WebSocket('/ws/events');
          router.push('/admin/users');
          history.replaceState({}, '', '/dashboard/settings');
          window.location.href = '/oauth/callback';
        """
        routes = extract_javascript_routes(script, "https://example.test/app.js")
        by_url = {row["absolute_url"]: row for row in routes}
        axios_login = next(row for row in routes if row["matched_pattern"] == "axios")
        xhr_user = next(row for row in routes if row["matched_pattern"] == "XMLHttpRequest.open")
        websocket = next(row for row in routes if row["matched_pattern"] == "WebSocket")

        self.assertIn("https://example.test/api/users", by_url)
        self.assertEqual(axios_login["method"], "POST")
        self.assertEqual(xhr_user["method"], "PUT")
        self.assertEqual(websocket["method"], "CONNECT")
        self.assertEqual(by_url["https://example.test/admin/users"]["category"], "admin")
        self.assertEqual(by_url["https://example.test/oauth/callback"]["category"], "auth")

    def test_dynamic_import_extraction(self) -> None:
        script = """
          const Admin = React.lazy(() => import(/* webpackChunkName: "admin-users" */ './admin/users.js'));
          const billing = dynamic(() => import('/modules/billing/reports.js'));
          import(`./debug/tools.js`);
        """
        imports = extract_dynamic_imports(script, "https://example.test/app.js")
        paths = {row["import_path"] for row in imports}

        self.assertIn("./admin/users.js", paths)
        self.assertIn("/modules/billing/reports.js", paths)
        self.assertTrue(any(row["category"] in {"admin", "debug"} for row in imports))
        self.assertTrue(any("manual verification" in row["risk_hint"] for row in imports))

    def test_noise_filtering_ignores_selectors_assets_and_hashes(self) -> None:
        script = """
          const root = '#app';
          const image = '/assets/logo.png';
          const hash = '2f52a6dc0fe22da31f61c20b0dbcd85f';
          const route = '/internal/debug';
        """
        routes = extract_javascript_routes(script, "https://example.test/app.js")
        urls = {row["absolute_url"] for row in routes}

        self.assertNotIn("https://example.test/app", urls)
        self.assertNotIn("https://example.test/assets/logo.png", urls)
        self.assertIn("https://example.test/internal/debug", urls)

    def test_route_tree_building(self) -> None:
        tree = build_route_tree(
            [
                {"host": "example.test", "path": "/dashboard/settings", "category": "public", "observed": True},
                {"host": "example.test", "path": "/dashboard/profile", "category": "public", "observed": False},
                {"host": "example.test", "path": "/api/v1/users", "category": "api", "observed": True},
            ]
        )

        self.assertEqual(tree[0]["label"], "example.test")
        labels = {child["label"] for child in tree[0]["children"]}
        self.assertIn("dashboard", labels)
        self.assertIn("api", labels)

    def test_katana_level_2_parameter_extraction(self) -> None:
        script = """
          fetch('/api/orders?order_id=42', {
            body: JSON.stringify({ account_id: accountId, redirect: next })
          });
        """
        js_routes = extract_javascript_routes(script, "https://example.test/app.js")
        route_payload = {"javascript_routes": js_routes, "endpoints": [], "routes": [], "dynamic_imports": []}
        data = self._fixture_data()
        data["html"]["forms"] = [
            {"method": "POST", "action": "/upload", "input_names": ["filename", "description"]}
        ]

        parameters = extract_parameter_intelligence(data, route_payload)
        by_name = {row["name"]: row for row in parameters}

        self.assertEqual(by_name["order_id"]["location"], "query")
        self.assertEqual(by_name["account_id"]["category"], "identifier")
        self.assertEqual(by_name["redirect"]["category"], "redirect")
        self.assertEqual(by_name["filename"]["location"], "form")

    def test_katana_level_2_hidden_api_and_permissions(self) -> None:
        script = """
          const API_BASE = 'https://api.internal.example.test/v2';
          const routes = [{ path: '/admin', allowedRoles: ['admin'], requiresAuth: true }];
        """
        js_routes = extract_javascript_routes(script, "https://example.test/app.js")
        route_payload = {"javascript_routes": js_routes, "endpoints": [], "routes": [], "dynamic_imports": []}
        data = self._fixture_data()

        hidden = extract_hidden_api_hosts(data, route_payload)
        permissions = extract_permission_mappings(data, route_payload)

        self.assertTrue(any(row["host"] == "api.internal.example.test" for row in hidden))
        self.assertTrue(any(row["route"] == "/admin" and row["permission_or_role"] == "admin" for row in permissions))
        self.assertTrue(any(row["route"] == "/admin" and row["type"] == "auth" for row in permissions))

    def test_katana_level_2_correlations_and_risk_rules(self) -> None:
        route_payload = {
            "routes": [
                {
                    "path": "/profile",
                    "absolute_url": "https://example.test/profile?id=7",
                    "category": "public",
                    "observed": True,
                    "static_asset": False,
                    "high_interest": False,
                }
            ],
            "endpoints": [
                {
                    "path": "/profile?id=7",
                    "absolute_url": "https://example.test/profile?id=7",
                    "source_file": "profile.js",
                }
            ],
            "javascript_routes": [
                {
                    "absolute_url": "https://example.test/profile?id=7",
                    "source_file": "profile.js",
                }
            ],
            "dynamic_imports": [],
        }
        parameters = [
            {
                "name": "id",
                "route": "https://example.test/profile?id=7",
                "category": "identifier",
            }
        ]

        chains = build_endpoint_correlations(route_payload, parameters, [])
        risks = build_route_risk_candidates(route_payload, parameters, [], chains)

        self.assertTrue(any(row["title"] == "Potential IDOR Candidate" for row in chains))
        self.assertTrue(any(row["title"] == "Potential IDOR Candidate" for row in risks))
        self.assertTrue(all("requires manual verification" in row["analyst_note"] for row in risks))

    def test_json_artifact_generation_and_blueprint_integration(self) -> None:
        data = self._fixture_data()
        route_intel = build_application_route_intelligence(data)
        data["application_route_intelligence"] = route_intel
        blueprint = build_application_blueprint(data)

        self.assertEqual(route_intel["status"], "completed")
        self.assertGreaterEqual(route_intel["summary"]["total_routes"], 5)
        self.assertGreaterEqual(route_intel["summary"]["dynamic_imports"], 1)
        self.assertTrue(route_intel["high_interest_routes"])
        self.assertEqual(route_intel["katana_level_2"]["status"], "completed")
        self.assertIn("route_risk_candidates", route_intel["katana_level_2"])
        node_types = {node["type"] for node in blueprint["nodes"]}
        self.assertTrue({"route", "recovered_route", "dynamic_import", "high_interest_route"} & node_types)
        self.assertIn("hidden_api_cluster", node_types)
        self.assertIn("parameter_cluster", node_types)
        self.assertIn("route_risk_cluster", node_types)
        self.assertIn("routes", blueprint["summary"])

    def test_html_report_model_and_rendering(self) -> None:
        data = self._fixture_data()
        data["application_route_intelligence"] = build_application_route_intelligence(data)
        data["application_blueprint"] = build_application_blueprint(data)
        record = ArtifactRecord(type="domain", label="example.test", data=data, source="test")

        report = build_report_model([record.to_dict()], {}, language="en")
        route_section = report["domains"][0]["application_route_intelligence"]
        self.assertGreater(route_section["summary"]["total_routes"], 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.html"
            export_html_report([record], {}, output, language="en")
            html = output.read_text(encoding="utf-8")

        self.assertIn("Application Route Intelligence", html)
        self.assertIn("table-route-endpoints", html)
        self.assertIn("Katana Level 2", html)
        self.assertIn("table-route-level2-parameters", html)
        self.assertIn("table-route-level2-risks", html)

    def _fixture_data(self) -> dict:
        return {
            "domain": "example.test",
            "http_surface": {"primary_url": "https://example.test/"},
            "http": {"final_url": "https://example.test/"},
            "html": {
                "canonical": "https://example.test/dashboard",
                "script_links": ["https://example.test/static/app.js"],
                "source_map_links": ["https://example.test/static/app.js.map"],
                "forms": [{"method": "POST", "action": "https://example.test/api/auth/session", "input_names": ["email"]}],
                "api_endpoints": [{"endpoint": "https://example.test/api/public", "method": "GET"}],
                "login_admin_paths": ["https://example.test/admin"],
            },
            "devtools": {
                "network_requests": [
                    {"url": "https://example.test/api/users", "method": "GET", "resource_type": "fetch", "status": 200},
                    {"url": "wss://example.test/socket", "method": "GET", "resource_type": "websocket", "status": 101},
                ],
                "loaded_js": ["https://example.test/static/app.js", "https://example.test/assets/admin.chunk.js"],
                "dom_links": ["https://example.test/dashboard/settings"],
            },
            "js_intelligence": {
                "api_endpoints": [
                    {
                        "endpoint": "https://example.test/api/auth/login",
                        "source_js": "https://example.test/static/app.js",
                        "method": "POST",
                        "evidence": "axios.post('/api/auth/login')",
                    }
                ],
                "websockets": [
                    {
                        "endpoint": "wss://example.test/socket",
                        "source_js": "https://example.test/static/app.js",
                        "method": "CONNECT",
                    }
                ],
            },
            "javascript_intelligence": {
                "markers": [
                    {
                        "source": "https://example.test/static/app.js",
                        "evidence": "React.lazy(() => import('./admin/users.js'))",
                    }
                ],
                "scripts": [{"url": "https://example.test/static/app.js"}],
            },
            "discovery": {
                "base_url": "https://example.test",
                "findings": [
                    {"path": "metrics", "url": "https://example.test/metrics", "status_code": 200, "source_wordlist": "docs_paths.txt"}
                ],
            },
            "security_findings": [
                {"type": "manual_review", "url": "https://example.test/admin", "detail": "Admin route requires manual verification"}
            ],
        }


if __name__ == "__main__":
    unittest.main()
