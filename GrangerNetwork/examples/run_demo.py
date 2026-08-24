from __future__ import annotations

import argparse
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from granger_network.client import GrangerClient  # noqa: E402
from granger_network.descriptor import ServiceDescriptor  # noqa: E402
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget  # noqa: E402
from granger_network.identity import ServiceIdentity  # noqa: E402
from granger_network.resolver import LocalResolver  # noqa: E402
from granger_network.service import GrangerServiceHost  # noqa: E402
from granger_network.transport import LoopbackEndpoint  # noqa: E402


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<!doctype html><title>Granger Network</title><h1>test.granger works</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Granger Network local compatibility demo")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--network-port", type=int, default=0)
    options = parser.parse_args()
    network_port = options.network_port or _available_port()

    http_server = ThreadingHTTPServer(("127.0.0.1", options.http_port), DemoHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="granger-network-demo-") as temporary:
            registry = LocalResolver(Path(temporary) / "registry")
            identity = ServiceIdentity.generate()
            descriptor = ServiceDescriptor.create(
                identity,
                LoopbackEndpoint("127.0.0.1", network_port),
            )
            registry.import_descriptor(descriptor, "test.granger")
            bridge = LoopbackHttpBridge(
                LoopbackHttpTarget.parse(f"http://127.0.0.1:{options.http_port}")
            )
            with GrangerServiceHost(identity, descriptor, bridge):
                response = GrangerClient(registry).fetch("test.granger")
                print(f"alias: test.granger")
                print(f"identity address: {response.canonical_service}")
                print(f"status: {response.status} {response.reason}")
                print(response.body.decode("utf-8"))
        return 0
    finally:
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=2.0)


if __name__ == "__main__":
    raise SystemExit(main())
