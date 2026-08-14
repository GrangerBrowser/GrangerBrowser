from __future__ import annotations

import unittest
from unittest.mock import patch

from pamp.core.cloud_bucket_intelligence import analyze_cloud_buckets
from pamp.core.domain_analyzer import _social_links_from_collected_data
from pamp.core.endpoint_utils import is_probable_endpoint
from pamp.core.js_intelligence import analyze_javascript
from pamp.core.oauth_intelligence import analyze_oauth
from pamp.core.social_intelligence import build_social_intelligence, normalize_social_url, social_platform
from pamp.core.traffic_chain import build_traffic_chain
from pamp.core.models import ArtifactRecord
from pamp.report.html_exporter import build_report_model


class DomainIntelligenceTests(unittest.TestCase):
    def test_endpoint_noise_filter(self) -> None:
        self.assertTrue(is_probable_endpoint("https://example.test/api/users"))
        self.assertTrue(is_probable_endpoint("https://example.test/v2/orders"))
        self.assertFalse(is_probable_endpoint("https://example.test/Callback;s.push(ew(()="))
        self.assertFalse(
            is_probable_endpoint(
                "https://nextjs.org/docs/messages/next-dynamic-api-wrong-context"
            )
        )
        self.assertFalse(
            is_probable_endpoint(
                "https://github.com/zloirock/core-js/blob/v3.38.1/LICENSE"
            )
        )

    def test_js_static_analysis_masks_secrets(self) -> None:
        html = """
        <script>
          const routes = ["/api/auth", "/v1/users"];
          const client_id = "public-client-123";
          const client_secret = "supersecretvalue123456";
          const socket = "wss://socket.example.test/events";
          const operation = `mutation UpdateUser { updateUser { id } }`;
        </script>
        """
        result = analyze_javascript("https://example.test", html, {}, {})
        endpoints = {row["value"] for row in result["api_endpoints"]}
        self.assertIn("https://example.test/api/auth", endpoints)
        self.assertIn("https://example.test/v1/users", endpoints)
        self.assertEqual(result["graphql"][0]["value"], "UpdateUser")
        self.assertTrue(result["websockets"])
        serialized = str(result["secret_like_values"])
        self.assertNotIn("supersecretvalue123456", serialized)
        self.assertIn("****", serialized)

    @patch("pamp.core.cloud_bucket_intelligence.requests.head")
    def test_cloud_bucket_checks_only_referenced_url(self, mock_head) -> None:
        response = mock_head.return_value
        response.status_code = 200
        response.url = "https://demo.s3.amazonaws.com/assets/config.json"
        response.headers = {
            "Content-Type": "application/json",
            "Content-Length": "42",
        }
        result = analyze_cloud_buckets(
            [
                {
                    "source": "fixture",
                    "value": "https://demo.s3.amazonaws.com/assets/config.json",
                }
            ]
        )
        self.assertEqual(mock_head.call_count, 1)
        self.assertEqual(
            mock_head.call_args.args[0],
            "https://demo.s3.amazonaws.com/assets/config.json",
        )
        self.assertEqual(result["verified"][0]["status"], "public")
        self.assertEqual(result["public_objects"][0]["risk"], "high")

    @patch("pamp.core.oauth_intelligence._fetch_metadata", return_value={})
    def test_oauth_filters_static_assets_and_detects_provider(self, _metadata) -> None:
        result = analyze_oauth(
            "https://example.test",
            [
                {
                    "source": "fixture",
                    "value": [
                        "https://example.test/_next/static/chunks/app.js",
                        "https://example.test/api/auth/steam",
                    ],
                }
            ],
        )
        routes = {row["value"] for row in result["auth_routes"]}
        providers = {row["name"] for row in result["providers"]}
        self.assertNotIn(
            "https://example.test/_next/static/chunks/app.js",
            routes,
        )
        self.assertIn("https://example.test/api/auth/steam", routes)
        self.assertIn("Steam", providers)

    def test_traffic_chain_classifies_browser_requests(self) -> None:
        devtools = {
            "final_url": "https://example.test/",
            "traffic_requests": [
                {
                    "sequence": 1,
                    "method": "GET",
                    "url": "https://example.test/",
                    "status": 200,
                    "resource_type": "document",
                    "duration_ms": 42,
                    "response_headers": {"content-type": "text/html"},
                },
                {
                    "sequence": 2,
                    "method": "GET",
                    "url": "https://example.test/api/auth/session",
                    "status": 401,
                    "resource_type": "fetch",
                    "duration_ms": 15,
                    "response_headers": {"content-type": "application/json"},
                },
                {
                    "sequence": 3,
                    "method": "GET",
                    "url": "https://www.google-analytics.com/g/collect",
                    "status": 204,
                    "resource_type": "image",
                    "duration_ms": 8,
                },
            ],
            "lifecycle": {"domcontentloaded_ms": 40, "load_ms": 80},
        }
        chain = build_traffic_chain(target="example.test", final_url="https://example.test/", devtools=devtools)
        self.assertEqual(chain["summary"]["total_requests"], 3)
        self.assertEqual(chain["summary"]["api_requests"], 1)
        self.assertEqual(chain["summary"]["failed_requests"], 1)
        self.assertEqual(chain["summary"]["third_party_requests"], 1)
        self.assertEqual(chain["requests"][1]["category"], "auth")
        self.assertEqual(chain["requests"][1]["importance"], "critical")

        record = ArtifactRecord(
            type="domain",
            label="example.test",
            data={
                "domain": "example.test",
                "linked_ip_addresses": [],
                "traffic_chain": chain,
                "http_surface": {},
                "security_findings": [],
            },
            source="test",
        )
        report = build_report_model([record.to_dict()], {}, language="en")
        domain = report["domains"][0]
        self.assertEqual(domain["summary"]["traffic_requests"], 3)
        self.assertEqual(domain["traffic_chain"]["summary"]["api_requests"], 1)

    def test_social_intelligence_builds_identity_and_signals(self) -> None:
        profiles = [
            {
                "platform": "X",
                "url": "https://x.com/acme",
                "handle": "@acme",
                "display_name": "Acme",
                "verified": True,
                "confidence": "high",
                "fetch_status": "ok",
                "external_links": ["https://acme.test/about"],
                "recent_posts": [{"title": "Launch", "date": "2026-01-01"}],
            },
            {
                "platform": "Instagram",
                "url": "https://instagram.com/acme",
                "handle": "@acme",
                "display_name": "Acme",
                "verified": None,
                "confidence": "medium",
                "fetch_status": "login_required",
                "external_links": [],
                "recent_posts": [],
            },
        ]
        result = build_social_intelligence(profiles, "acme.test")
        self.assertEqual(result["summary"]["platforms_found"], 2)
        self.assertEqual(result["summary"]["reused_handles"], 1)
        self.assertEqual(result["summary"]["verified_profiles"], 1)
        self.assertEqual(result["summary"]["fetch_warnings"], 1)
        self.assertTrue(result["profiles"][0]["links_back_to_target"])
        names = {row["name"] for row in result["signals"]}
        self.assertIn("Verified account detected", names)
        self.assertIn("Multiple platforms share the same handle", names)

        record = ArtifactRecord(
            type="domain",
            label="acme.test",
            data={
                "domain": "acme.test",
                "linked_ip_addresses": [],
                "social_links": [row["url"] for row in profiles],
                "social_profiles": profiles,
                "social_intelligence": result,
                "http_surface": {},
                "security_findings": [],
            },
            source="test",
        )
        report = build_report_model([record.to_dict()], {}, language="en")
        social = report["domains"][0]["social_intelligence"]
        self.assertEqual(social["summary"]["profiles_analyzed"], 2)
        self.assertEqual(len(social["profiles"]), 2)

    def test_social_platform_normalization_and_noise(self) -> None:
        self.assertEqual(social_platform("https://www.twitch.tv/rockstargames"), "Twitch")
        self.assertEqual(social_platform("https://discord.gg/rockstargames"), "Discord")
        self.assertEqual(
            normalize_social_url("https://twitter.com/rockstargames/?utm_source=site"),
            "https://x.com/rockstargames",
        )
        links, sources = _social_links_from_collected_data(
            {"social_links": []},
            {
                "dom_links": [
                    "https://instagram.com/rockstargames",
                    "https://discord.gg/rockstargames",
                    "https://example.test/privacy",
                ],
                "network_requests": [],
            },
        )
        self.assertEqual(len(links), 2)
        self.assertEqual(sources["https://instagram.com/rockstargames"], "rendered DOM")


if __name__ == "__main__":
    unittest.main()
