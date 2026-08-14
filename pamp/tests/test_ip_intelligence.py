from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pamp.core.ip_analyzer import analyze_ip
from pamp.core.models import ArtifactRecord
from pamp.report.html_exporter import build_report_model, export_html_report


class IpInfrastructureIntelligenceTests(unittest.TestCase):
    def test_ip_intelligence_contract_and_classification(self) -> None:
        with self._mock_analysis_sources():
            result = analyze_ip("8.8.8.8")

        intelligence = result["ip_intelligence"]
        self.assertEqual(intelligence["status"], "completed")
        self.assertTrue(
            {
                "summary",
                "geo",
                "asn",
                "provider",
                "registry",
                "services",
                "ports",
                "technologies",
                "relationships",
                "risk_signals",
                "evidence",
                "insights",
            }.issubset(intelligence)
        )
        self.assertEqual(intelligence["geo"]["country_code"], "US")
        self.assertEqual(intelligence["summary"]["open_ports"], 3)
        self.assertEqual([row["port"] for row in intelligence["ports"]], [22, 80, 443])
        self.assertEqual(intelligence["classification"]["primary_role"], "Likely CDN Edge")
        self.assertFalse(intelligence["classification"]["origin_asserted"])
        self.assertTrue(any(row["title"] == "Public SSH" for row in intelligence["risk_signals"]))
        self.assertTrue(all(row["confirmed"] is False for row in intelligence["risk_signals"]))
        self.assertTrue(intelligence["evidence"])
        self.assertTrue(intelligence["timeline"])
        self.assertTrue(intelligence["blueprint"]["nodes"])

    def test_report_model_and_offline_assets(self) -> None:
        with self._mock_analysis_sources():
            result = analyze_ip("8.8.8.8")
        record = ArtifactRecord(type="ip", label=result["ip"], data=result, source="test")
        report = build_report_model([record.to_dict()], {}, language="en")
        ip_report = report["ip_intelligence"]

        self.assertEqual(report["target_type"], "ip")
        self.assertIn("<svg", ip_report["assets"]["world_svg"])
        self.assertIn('id="us"', ip_report["assets"]["world_svg"])
        self.assertTrue(ip_report["assets"]["flag_data_uri"].startswith("data:image/svg+xml;base64,"))

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.html"
            export_html_report([record], {}, output, language="en")
            html = output.read_text(encoding="utf-8")

        for marker in (
            "IP / Infrastructure Intelligence",
            "ip-world-map",
            "ip-country",
            "ip-owner",
            "ip-classification",
            "table-ip-ports",
            "table-ip-technologies",
            "ip-relationship-flow",
            "ip-timeline",
            "ip-risk-grid",
            "ip-evidence-list",
            "ip-blueprint-flow",
        ):
            self.assertIn(marker, html)

    @staticmethod
    def _mock_analysis_sources():
        ip_api = {
            "country": "United States",
            "countryCode": "US",
            "region": "CA",
            "regionName": "California",
            "city": "Los Angeles",
            "lat": 34.05,
            "lon": -118.24,
            "timezone": "America/Los_Angeles",
            "as": "AS13335 CLOUDFLARENET",
            "asname": "CLOUDFLARENET",
            "org": "Cloudflare, Inc.",
            "isp": "Cloudflare, Inc.",
            "hosting": True,
        }
        rdap = {
            "handle": "NET-203-0-113-0-1",
            "name": "TEST-NET-3",
            "type": "DIRECT ALLOCATION",
            "country": "US",
            "start_address": "203.0.113.0",
            "end_address": "203.0.113.255",
            "port43": "whois.arin.net",
            "cidrs": [{"version": 4, "prefix": "203.0.113.0", "length": 24}],
            "abuse_contacts": ["abuse@example.test"],
        }
        port_surface = {
            "status": "completed",
            "profile": "service-light-top-1000",
            "duration_ms": 1200,
            "errors": [],
            "summary": {"open_ports": 3, "services_identified": 3},
            "open_ports": [
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.24", "risk": "info"},
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.2", "risk": "warning", "risk_reason": "Remote shell service is reachable from the Internet."},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.24", "risk": "info"},
            ],
        }
        http_rows = [
            {"url": "http://8.8.8.8/", "port": 80, "scheme": "http", "status": 301, "server": "cloudflare", "location": "https://example.test/", "content_type": "text/html"},
            {"url": "https://8.8.8.8/", "port": 443, "scheme": "https", "status": 200, "server": "cloudflare", "content_type": "text/html"},
        ]
        tls_rows = [
            {"port": 443, "tls_version": "TLSv1.3", "subject": "example.test", "issuer": "Test CA", "san_dns": ["example.test"], "san_ip": [], "days_remaining": 30}
        ]
        stack = ExitStack()
        stack.enter_context(patch("pamp.core.ip_analyzer._ip_api_lookup", return_value=ip_api))
        stack.enter_context(patch("pamp.core.ip_analyzer._rdap_lookup", return_value=rdap))
        stack.enter_context(patch("pamp.core.ip_analyzer._reverse_dns", return_value="edge.example.test"))
        stack.enter_context(patch("pamp.core.ip_analyzer._is_tor_exit", return_value=False))
        stack.enter_context(patch("pamp.core.ip_analyzer.analyze_port_surface", return_value=port_surface))
        stack.enter_context(patch("pamp.core.ip_analyzer._probe_http_services", return_value=http_rows))
        stack.enter_context(patch("pamp.core.ip_analyzer._probe_tls_services", return_value=tls_rows))
        stack.enter_context(patch("pamp.core.ip_analyzer._reverse_dns_resolves_to", return_value=True))
        return stack


if __name__ == "__main__":
    unittest.main()
