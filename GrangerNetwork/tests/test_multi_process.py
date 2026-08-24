from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PAGE = b"<!doctype html><title>Three process test</title><h1>remote transport passed</h1>"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=3.0)


class MultiProcessRemoteTest(unittest.TestCase):
    def test_host_relay_and_client_are_separate_processes(self) -> None:
        http_server = ThreadingHTTPServer(("127.0.0.1", 0), PageHandler)
        http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        http_thread.start()
        relay_process: subprocess.Popen[str] | None = None
        host_process: subprocess.Popen[str] | None = None
        client_process: subprocess.Popen[str] | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="granger-network-processes-") as temporary:
                root = Path(temporary)
                state = root / "service"
                registry = root / "registry"
                ready = root / "relay-ready.json"
                capture = root / "relay-wire.bin"
                fetched = root / "fetched.html"
                relay_port = available_port()
                environment = os.environ.copy()
                source_path = str(PROJECT_ROOT / "src")
                existing_pythonpath = environment.get("PYTHONPATH")
                environment["PYTHONPATH"] = (
                    source_path
                    if not existing_pythonpath
                    else source_path + os.pathsep + existing_pythonpath
                )

                relay_process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "granger_network.rendezvous",
                        "--listen-host",
                        "127.0.0.1",
                        "--listen-port",
                        str(relay_port),
                        "--capture",
                        str(capture),
                        "--ready-file",
                        str(ready),
                    ],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                deadline = time.monotonic() + 5.0
                while not ready.is_file() and time.monotonic() < deadline:
                    if relay_process.poll() is not None:
                        stdout, stderr = relay_process.communicate()
                        self.fail(f"rendezvous exited early: {stdout}\n{stderr}")
                    time.sleep(0.05)
                self.assertTrue(ready.is_file(), "rendezvous did not become ready")

                initialized = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "granger_network.host",
                        "init-remote",
                        "--state-dir",
                        str(state),
                        "--rendezvous-id",
                        "process-relay",
                        "--rendezvous-host",
                        "127.0.0.1",
                        "--rendezvous-port",
                        str(relay_port),
                        "--registry",
                        str(registry),
                        "--alias",
                        "test.granger",
                        "--title",
                        "Three process test",
                    ],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    check=False,
                )
                self.assertEqual(initialized.returncode, 0, initialized.stderr)

                host_process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "granger_network.host",
                        "serve",
                        "--state-dir",
                        str(state),
                        "--upstream",
                        f"http://127.0.0.1:{int(http_server.server_address[1])}",
                    ],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                client_process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "granger_network.client",
                        "fetch",
                        "test.granger",
                        "--registry",
                        str(registry),
                        "--output",
                        str(fetched),
                    ],
                    cwd=PROJECT_ROOT,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                client_stdout, client_stderr = client_process.communicate(timeout=20.0)
                self.assertEqual(
                    client_process.returncode,
                    0,
                    f"client stdout: {client_stdout}\nclient stderr: {client_stderr}",
                )
                self.assertEqual(fetched.read_bytes(), PAGE)
                self.assertEqual(
                    len({relay_process.pid, host_process.pid, client_process.pid}),
                    3,
                )
                deadline = time.monotonic() + 2.0
                while (not capture.exists() or capture.stat().st_size == 0) and time.monotonic() < deadline:
                    time.sleep(0.05)
                wire = capture.read_bytes()
                self.assertGreater(len(wire), 0)
                for marker in (PAGE, b"GET /", b"Host:", b"Three process test"):
                    self.assertNotIn(marker, wire)
        finally:
            stop_process(client_process)
            stop_process(host_process)
            stop_process(relay_process)
            http_server.shutdown()
            http_server.server_close()
            http_thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
