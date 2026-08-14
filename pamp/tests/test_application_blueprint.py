from __future__ import annotations

import unittest

from pamp.core.application_blueprint import build_application_blueprint
from pamp.core.models import ArtifactRecord
from pamp.report.html_exporter import build_report_model


class ApplicationBlueprintTests(unittest.TestCase):
    def test_blueprint_builds_nodes_edges_and_insights_from_existing_data(self) -> None:
        data = {
            "domain": "example.test",
            "linked_ip_addresses": ["203.0.113.10"],
            "dns": {
                "A": ["203.0.113.10"],
                "NS": ["alice.ns.cloudflare.com"],
            },
            "asn_bgp": [
                {
                    "ip": "203.0.113.10",
                    "asn": "64500",
                    "name": "EXAMPLE-NET",
                    "bgp_prefix": "203.0.113.0/24",
                }
            ],
            "tls_certificate": {
                "subject": "example.test",
                "issuer": "Example CA",
                "valid_to": "Sep 6 16:39:24 2026 GMT",
                "tls_version": "TLSv1.3",
                "days_remaining": 60,
                "verification_error": "",
            },
            "http_surface": {"primary_url": "https://example.test/", "server": "nginx"},
            "technologies": [
                {"name": "Cloudflare", "category": "Infra / CDN / WAF", "confidence": "high"},
                {"name": "React", "category": "Frontend", "confidence": "high"},
            ],
            "api_endpoints": [
                {
                    "endpoint": "https://example.test/api/users",
                    "method": "GET",
                    "risk": "Low",
                    "source_file": "app.js",
                }
            ],
            "js_intelligence": {
                "files": [{"url": "https://example.test/static/app.js", "status": 200}],
                "api_endpoints": [{"value": "https://example.test/api/session", "method": "GET"}],
            },
            "oauth_intelligence": {
                "providers": [{"name": "GitHub", "provider": "GitHub", "confidence": "medium"}],
            },
            "cloud_buckets": {
                "candidates": [{"value": "https://demo.s3.amazonaws.com/config.json", "provider": "AWS S3"}],
            },
            "port_surface": {
                "ip": "203.0.113.10",
                "open_ports": [{"port": 443, "protocol": "tcp", "service": "https", "risk": "info"}],
            },
            "social_intelligence": {
                "profiles": [{"platform": "GitHub", "url": "https://github.com/example", "handle": "example"}],
            },
            "traffic_chain": {
                "requests": [
                    {"url": "https://www.google-analytics.com/g/collect", "resource_type": "fetch"},
                ]
            },
            "security_findings": [
                {"type": "missing_header", "detail": "Content-Security-Policy", "evidence": "HTTP response"}
            ],
            "analyst_notes": ["HTTPS is available and selected as primary surface."],
        }

        blueprint = build_application_blueprint(data)
        self.assertEqual(blueprint["status"], "completed")
        self.assertGreaterEqual(blueprint["summary"]["nodes"], 10)
        self.assertGreaterEqual(blueprint["summary"]["edges"], 8)

        node_types = {node["type"] for node in blueprint["nodes"]}
        self.assertTrue(
            {
                "domain",
                "ip",
                "asn",
                "dns",
                "tls",
                "server",
                "frontend",
                "api",
                "oauth",
                "bucket",
                "port",
                "third_party",
                "social",
                "finding",
            }.issubset(node_types)
        )
        edge_types = {edge["type"] for edge in blueprint["edges"]}
        self.assertTrue(
            {
                "resolves_to",
                "hosted_on",
                "protected_by",
                "uses",
                "exposes",
                "calls",
                "authenticates_with",
                "loads",
                "linked_to",
                "has_finding",
            }.issubset(edge_types)
        )
        insight_titles = {row["title"] for row in blueprint["insights"]}
        self.assertIn("Application is protected by Cloudflare.", insight_titles)
        self.assertIn("Public API endpoints were discovered.", insight_titles)
        self.assertIn("Open network ports extend the attack surface.", insight_titles)

    def test_blueprint_does_not_create_fake_nodes_without_source_data(self) -> None:
        blueprint = build_application_blueprint({"domain": "empty.test"})
        self.assertEqual(blueprint["summary"]["nodes"], 1)
        self.assertEqual(blueprint["summary"]["edges"], 0)
        self.assertEqual(blueprint["summary"]["apis"], 0)
        self.assertEqual(blueprint["summary"]["external_services"], 0)
        self.assertEqual(blueprint["nodes"][0]["type"], "domain")

    def test_report_model_exposes_application_blueprint(self) -> None:
        data = {
            "domain": "example.test",
            "linked_ip_addresses": ["203.0.113.10"],
            "dns": {"A": ["203.0.113.10"]},
            "http_surface": {},
            "security_findings": [],
        }
        data["application_blueprint"] = build_application_blueprint(data)
        record = ArtifactRecord(type="domain", label="example.test", data=data, source="test")

        report = build_report_model([record.to_dict()], {}, language="en")
        blueprint = report["domains"][0]["application_blueprint"]

        self.assertEqual(blueprint["status"], "completed")
        self.assertEqual(blueprint["summary"]["domains"], 1)
        self.assertEqual(blueprint["summary"]["nodes"], 2)


if __name__ == "__main__":
    unittest.main()
