from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import wan_process_acceptance as acceptance


class AcceptanceWaitTests(unittest.TestCase):
    def test_exit_timeout_captures_before_caller_can_terminate(self):
        child = Mock(name="child")
        child.name = "client-d"
        child.process.pid = 123
        child.process.wait.side_effect = subprocess.TimeoutExpired("fixture", 150)
        with patch.dict(os.environ, {"GRANGER_ACCEPTANCE_TRACE_DIR": "trace-fixture"}), \
                patch.object(acceptance, "capture") as capture:
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.wait_exit(child, 150)
            capture.assert_called_once()
            self.assertEqual(capture.call_args.args[2:4], (123, "deadline"))
            child.process.terminate.assert_not_called()
            child.process.kill.assert_not_called()
            child.process.wait.assert_called_once_with(timeout=150)

    def test_readiness_timeout_captures_without_extending_budget(self):
        child = Mock()
        child.name = "host-restarted"
        with patch.object(acceptance.time, "monotonic", side_effect=(0, 0, 108)), \
                patch.object(acceptance, "capture_wait_timeout") as capture:
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.wait_json(Path("unused.json"), child, 107)
            capture.assert_called_once()
            child.process.kill.assert_not_called()

    def test_success_and_disabled_diagnostics_do_not_capture(self):
        child = Mock()
        child.process.wait.return_value = 0
        with patch.dict(os.environ, {"GRANGER_ACCEPTANCE_TRACE_DIR": ""}), \
                patch.object(acceptance, "capture") as capture:
            self.assertEqual(acceptance.wait_exit(child, 150), 0)
            acceptance.capture_wait_timeout(child, 0, "2026-01-01T00:00:00Z")
            capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
