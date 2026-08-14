from __future__ import annotations

from contextlib import ExitStack
import unittest
from unittest.mock import patch

from pamp.core.agents.orchestrator import run_orchestrator
from pamp.core.domain_analyzer import analyze_domain
from pamp.report.html_exporter import _module_status_rows


class ReliabilityTests(unittest.TestCase):
    def test_orchestrator_continues_after_one_agent_fails(self) -> None:
        debug = []
        with ExitStack() as stack:
            stack.enter_context(patch("pamp.core.agents.orchestrator.run_crawler_agent", side_effect=RuntimeError("crawler failed")))
            stack.enter_context(patch("pamp.core.agents.orchestrator.run_devtools_agent", return_value={"summary": {"requests": 4}}))
            stack.enter_context(patch("pamp.core.agents.orchestrator.run_technology_agent", return_value={"summary": {"technologies": 2}}))
            stack.enter_context(patch("pamp.core.agents.orchestrator.run_discovery_agent", return_value={"summary": {}, "findings": []}))
            stack.enter_context(patch("pamp.core.agents.orchestrator.run_sqli_agent", return_value={"summary": {}, "findings": []}))
            stack.enter_context(patch("pamp.core.agents.orchestrator.run_report_agent", return_value={"summary": {"security_findings": 0}}))
            result = run_orchestrator("example.test", {}, debug_log=debug.append)

        statuses = {row["agent"]: row["status"] for row in result["steps"]}
        self.assertEqual(statuses["crawler_agent"], "failed")
        self.assertEqual(statuses["devtools_agent"], "done")
        self.assertEqual(statuses["report_agent"], "done")
        self.assertTrue(any("Traceback" in row for row in debug))

    def test_domain_future_failure_does_not_stop_report_model(self) -> None:
        port_surface = {
            "status": "completed",
            "open_ports": [],
            "summary": {"open_ports": 0, "services_identified": 0, "sensitive_services": 0},
            "errors": [],
        }
        http_surface = {
            "errors": [], "_html": "", "_body_text": "", "status_code": None,
            "primary_url": "", "final_url": "", "headers": {}, "probes": [],
            "redirect_chain": [], "interesting_paths": [], "security_signals": [], "favicon": {},
        }
        debug = []
        with ExitStack() as stack:
            stack.enter_context(patch("pamp.core.domain_analyzer.analyze_port_surface", return_value=port_surface))
            stack.enter_context(patch("pamp.core.domain_analyzer.analyze_http_surface", return_value=http_surface))
            stack.enter_context(patch("pamp.core.domain_analyzer._reverse_dns_for_ips", side_effect=RuntimeError("PTR resolver crashed")))
            stack.enter_context(patch("pamp.core.domain_analyzer._tls_certificate", return_value={}))
            stack.enter_context(patch("pamp.core.domain_analyzer._asn_bgp_for_ips", return_value=[]))
            stack.enter_context(patch("pamp.core.domain_analyzer.analyze_cloud_buckets", return_value={"candidates": [], "verified": [], "public_objects": [], "summary": {}, "errors": []}))
            result = analyze_domain("203.0.113.5", debug_log=debug.append)

        self.assertIs(result["port_surface"], port_surface)
        self.assertEqual(result["reverse_dns"], [])
        self.assertTrue(any(row["stage"] == "reverse_dns" and "failed" in row["status"] for row in result["execution_log"]))
        self.assertTrue(any("Traceback" in row for row in debug))

    def test_report_module_statuses_are_structured_and_merged(self) -> None:
        rows = _module_status_rows(
            [
                {"stage": "dns", "status": "12 records"},
                {"stage": "rdap", "status": "timeout"},
                {"stage": "javascript", "status": "28 resources"},
                {"stage": "javascript", "status": "partial: one source unavailable"},
                {"stage": "browser", "status": "skipped for IP input"},
            ],
            20,
        )
        by_stage = {row["stage"]: row for row in rows}
        self.assertEqual(by_stage["dns"]["status"], "Completed")
        self.assertEqual(by_stage["rdap"]["status"], "Failed")
        self.assertEqual(by_stage["javascript"]["status"], "Partial")
        self.assertIn("28 resources", by_stage["javascript"]["details"])
        self.assertEqual(by_stage["browser"]["status"], "Skipped")


if __name__ == "__main__":
    unittest.main()
