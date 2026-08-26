from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


NETWORK_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = NETWORK_ROOT / "src"
ACCEPTANCE_TOOL = NETWORK_ROOT / "tools" / "wan_process_acceptance.py"


class WanMultiProcessAcceptanceTests(unittest.TestCase):
    def test_separate_processes_preserve_endpoint_privacy_and_forum_round_trip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-wan-process-test-") as temporary:
            root = Path(temporary)
            report_path = root / "acceptance.json"
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPATH"] = str(SOURCE_ROOT) + (
                os.pathsep + environment["PYTHONPATH"]
                if environment.get("PYTHONPATH")
                else ""
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ACCEPTANCE_TOOL),
                    "--work-dir",
                    str(root / "work"),
                    "--report",
                    str(report_path),
                ],
                cwd=NETWORK_ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=360.0,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["physicalWan"], "UNVERIFIED")
            self.assertEqual(report["orphanProcesses"], [])
            self.assertGreaterEqual(report["processCount"], 26)
            self.assertTrue(all(report["checks"].values()))
            self.assertEqual(report["markerHits"], [])


if __name__ == "__main__":
    unittest.main()
