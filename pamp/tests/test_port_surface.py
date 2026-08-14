from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from pamp.core.models import ArtifactRecord
from pamp.core.port_surface import analyze_port_surface, parse_nmap_xml, port_surface_notes
from pamp.report.html_exporter import build_report_model


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <address addr="203.0.113.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0">
          <cpe>cpe:/a:openbsd:openssh:9.6</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" />
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed" />
        <service name="mysql" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


class PortSurfaceTests(unittest.TestCase):
    def test_parse_nmap_xml_and_sensitive_service_notes(self) -> None:
        parsed = parse_nmap_xml(NMAP_XML)
        self.assertEqual(parsed["summary"]["open_ports"], 2)
        self.assertEqual(parsed["summary"]["services_identified"], 2)
        self.assertEqual(parsed["summary"]["sensitive_services"], 1)
        self.assertEqual(parsed["open_ports"][0]["risk_label"], "SSH")
        self.assertEqual(parsed["open_ports"][1]["product"], "nginx")
        notes = port_surface_notes(parsed)
        self.assertIn("SSH service is publicly accessible.", notes)
        self.assertIn("Non-web services are reachable from the Internet.", notes)

    @patch("pamp.core.port_surface.subprocess.run")
    @patch("pamp.core.port_surface._resolve_nmap_path", return_value="C:/Tools/nmap.exe")
    def test_safe_nmap_profile_and_report_integration(self, _which, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, stdout=NMAP_XML, stderr="")
        result = analyze_port_surface("example.test", "203.0.113.10")
        command = run_mock.call_args.args[0]
        self.assertIn("-sV", command)
        self.assertIn("--version-light", command)
        self.assertIn("--top-ports", command)
        self.assertIn("--open", command)
        self.assertIn("--max-retries", command)
        self.assertNotIn("-A", command)
        self.assertNotIn("-O", command)
        self.assertNotIn("-sU", command)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["xml_parsed"])
        self.assertGreater(result["xml_bytes"], 0)
        self.assertEqual(result["exit_code"], 0)

        record = ArtifactRecord(
            type="domain",
            label="example.test",
            data={
                "domain": "example.test",
                "linked_ip_addresses": ["203.0.113.10"],
                "port_surface": result,
                "http_surface": {},
                "security_findings": [],
            },
            source="test",
        )
        report = build_report_model([record.to_dict()], {}, language="en")
        domain = report["domains"][0]
        self.assertEqual(domain["summary"]["open_ports"], 2)
        self.assertEqual(domain["summary"]["detected_services"], 2)
        self.assertEqual(domain["port_surface"]["open_ports"][0]["risk"], "warning")

    @patch("pamp.core.port_surface._resolve_nmap_path", return_value="")
    def test_missing_nmap_is_non_fatal_and_logged(self, _which) -> None:
        messages: list[str] = []
        result = analyze_port_surface("example.test", "203.0.113.10", messages.append)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["summary"]["open_ports"], 0)
        self.assertTrue(messages)
        self.assertIn("[DOMAIN][PORT]", messages[0])

    @patch("pamp.core.port_surface.subprocess.run")
    @patch("pamp.core.port_surface._resolve_nmap_path", return_value="C:/Tools/nmap.exe")
    def test_nmap_host_timeout_is_not_reported_as_zero_port_success(self, _which, run_mock) -> None:
        xml = """<nmaprun><host timedout="true"><status state="up"/></host>
        <runstats><finished elapsed="240.01" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""
        run_mock.return_value = subprocess.CompletedProcess([], 0, stdout=xml, stderr="")
        result = analyze_port_surface("example.test", "203.0.113.10")
        self.assertEqual(result["status"], "timeout")
        self.assertTrue(result["xml_parsed"])
        self.assertTrue(result["summary"]["scan_timed_out"])
        self.assertIn("results may be incomplete", result["reason"])

    @patch("pamp.core.port_surface.subprocess.run")
    @patch("pamp.core.port_surface._resolve_nmap_path", return_value="C:/Tools/nmap.exe")
    def test_nmap_process_error_keeps_diagnostics(self, _which, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 2, stdout="", stderr="fatal scan error")
        result = analyze_port_surface("example.test", "203.0.113.10")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["stderr"], "fatal scan error")
        self.assertEqual(result["reason"], "fatal scan error")
        self.assertTrue(result["command"])


if __name__ == "__main__":
    unittest.main()
