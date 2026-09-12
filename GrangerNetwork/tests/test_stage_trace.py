import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from granger_network.stage_trace import StageTrace, traced


class StageTraceTests(unittest.TestCase):
    def test_circuit_failure_context_is_bounded_and_sanitized(self):
        trace = StageTrace(Path("unused"))
        for hop, phase in ((2, "extension"), (True, "SECRET"), (200, None)):
            error = TimeoutError("SECRET route details")
            error.circuit_failure_hop_index = hop
            error.circuit_failure_stage = phase
            trace.end(trace.begin("circuit-construction"), error)
        document = trace.snapshot()
        self.assertEqual(document["completed"][0]["failedHop"], 2)
        self.assertEqual(document["completed"][0]["failedCircuitStage"], "extension")
        for item in document["completed"][1:]:
            self.assertNotIn("failedHop", item)
            self.assertNotIn("failedCircuitStage", item)
        self.assertNotIn("SECRET", json.dumps(document))

    def test_remote_error_category_is_allowlisted_without_peer_content(self):
        from granger_network.errors import OverlayRoutingError, PeerRpcError

        trace = StageTrace(Path("unused"))
        for code in ("SERVICE_OFFLINE", "SECRET peer response"):
            error = OverlayRoutingError("SECRET wrapped error")
            error.__cause__ = PeerRpcError(code)
            trace.end(trace.begin("service-connect"), error)
        document = trace.snapshot()
        self.assertEqual([item["remoteErrorCategory"] for item in document["completed"]],
                         ["SERVICE_OFFLINE", "OTHER_REMOTE_ERROR"])
        self.assertNotIn("SECRET", json.dumps(document))

    def test_bounded_history_retains_stage_summary_without_error_content(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = StageTrace(Path(directory))
            trace.end(trace.begin("startup"))
            for _ in range(600):
                trace.end(trace.begin("peer-auth"), TimeoutError("SECRET error content"))
            document = trace.snapshot()
            self.assertEqual(len(document["completed"]), 512)
            self.assertEqual(document["summaries"]["startup"]["PASS"], 1)
            self.assertEqual(document["summaries"]["peer-auth"]["TIMEOUT"], 600)
            self.assertNotIn("SECRET", json.dumps(document))
            self.assertNotIn("locals", json.dumps(document))

    def test_pending_is_bounded_and_reports_responsible_thread(self):
        trace = StageTrace(Path("unused"))
        tokens = [trace.begin("peer-rpc") for _ in range(140)]
        document = trace.snapshot()
        self.assertEqual(len(document["active"]), 128)
        self.assertEqual(document["dropped"], 12)
        self.assertEqual(document["active"][0]["result"], "PENDING")
        self.assertGreater(document["active"][0]["thread"], 0)
        for token in tokens:
            trace.end(token)
        self.assertFalse(trace.snapshot()["active"])

    def test_disabled_instrumentation_does_not_start_observer(self):
        @traced("unit")
        def operation(value):
            return value + 1
        with patch.dict(os.environ, {}, clear=True), patch("granger_network.stage_trace._get") as get:
            self.assertEqual(operation(2), 3)
            get.assert_not_called()

    def test_resolver_stages_separate_failures_without_record_content(self):
        from granger_network.errors import GrangerNetworkError, ResolutionError
        from granger_network.wan_discovery import WanDistributedResolver

        discovery = Mock()
        discovery.lookup.side_effect = ResolutionError("SECRET record content")
        resolver = WanDistributedResolver(discovery)
        service = SimpleNamespace(service_id="SECRET", verify=lambda **kwargs: None)
        trace = StageTrace(Path("unused"))
        with patch.dict(os.environ, {"GRANGER_ACCEPTANCE_TRACE_DIR": "unused"}), \
                patch("granger_network.stage_trace._get", return_value=trace):
            for action in (
                lambda: resolver.resolve("unknown.granger"),
                lambda: resolver.resolve_introduction(service),
                lambda: resolver.resolve_node("invalid-node-id"),
            ):
                with self.assertRaises(GrangerNetworkError):
                    action()
        document = trace.snapshot()
        self.assertEqual(set(document["summaries"]), {
            "service-descriptor-lookup", "introduction-descriptor-lookup", "node-descriptor-lookup",
        })
        self.assertTrue(all(row["result"] == "FAIL" for row in document["completed"]))
        self.assertFalse(document["active"])
        self.assertNotIn("SECRET", json.dumps(document))

    def test_timeout_snapshot_precedes_process_termination(self):
        path = Path(__file__).resolve().parents[1] / "tools" / "acceptance_diagnostics.py"
        spec = importlib.util.spec_from_file_location("acceptance_diagnostics_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observed = []
            original = module.capture
            def capture(*args):
                # Verify the child is actually alive at both capture points.
                pid = args[2]
                if os.name == "posix":
                    os.kill(pid, 0)
                observed.append(args[3])
                return original(*args)
            with patch.object(module, "capture", side_effect=capture):
                with self.assertRaises(subprocess.TimeoutExpired):
                    module.run_traced([sys.executable, "-c", "import time; time.sleep(30)"],
                                      cwd=root, env=os.environ.copy(), directory=root,
                                      qt_path=root / "qt.json", timeout=0.5)
            self.assertEqual(observed, ["near-deadline", "deadline"])
            evidence = json.loads((root / "capture-deadline.json").read_text())
            self.assertTrue(evidence["capturedBeforeTermination"])
            self.assertEqual(evidence["result"], "TIMEOUT")
            self.assertLess(evidence["durationMs"], 3000)


if __name__ == "__main__":
    unittest.main()
