from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


NETWORK_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = NETWORK_ROOT / "src"
ACCEPTANCE_TOOL = NETWORK_ROOT / "tools" / "wan_process_acceptance.py"
TOOLS_ROOT = NETWORK_ROOT / "tools"
sys.path.insert(0, str(TOOLS_ROOT))
import wan_process_acceptance as acceptance


class WanMultiProcessAcceptanceTests(unittest.TestCase):
    def test_port_allocator_skips_a_reused_kernel_port(self) -> None:
        class FakeSocket:
            ports = iter((41000, 41000, 41001))

            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_exc: object) -> None:
                return None

            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def getsockname(self) -> tuple[str, int]:
                return ("127.0.0.1", next(self.ports))

        acceptance._ALLOCATED_PORTS.clear()
        try:
            with patch.object(acceptance.socket, "socket", FakeSocket):
                self.assertEqual(acceptance.available_port(), 41000)
                self.assertEqual(acceptance.available_port(), 41001)
        finally:
            acceptance._ALLOCATED_PORTS.clear()

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
                timeout=480.0,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["physicalWan"], "UNVERIFIED")
            self.assertEqual(report["orphanProcesses"], [])
            self.assertGreaterEqual(report["processCount"], 26)
            self.assertTrue(all(report["checks"].values()))
            self.assertEqual(report["markerHits"], [])
            startup = report["hostStartup"]
            for phase in ("initialSeconds", "restartSeconds"):
                self.assertGreater(startup[phase], 0)
                self.assertLess(startup[phase], startup["deadlineSeconds"])


if __name__ == "__main__":
    unittest.main()
