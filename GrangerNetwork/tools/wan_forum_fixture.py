from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from granger_network._codec import atomic_write_text
from granger_network.network_audit import install_from_environment


HTML = (
    b"<!doctype html><html><head><link rel=stylesheet href=/style.css>"
    b"<script defer src=/script.js></script></head><body>"
    b"<h1>Granger test forum</h1></body></html>"
)
CSS = b"body{background:#101216;color:#eef;font:16px sans-serif}"
SCRIPT = b"document.documentElement.dataset.granger='ready';"
MAX_MESSAGE_BYTES = 64 * 1024


class ForumHandler(BaseHTTPRequestHandler):
    messages: list[bytes] = []
    lock = threading.Lock()

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        if self.path == "/":
            self._respond(200, "text/html", HTML)
        elif self.path == "/style.css":
            self._respond(200, "text/css", CSS)
        elif self.path == "/script.js":
            self._respond(200, "application/javascript", SCRIPT)
        elif self.path == "/messages":
            with self.lock:
                body = b"\n".join(self.messages)
            self._respond(200, "text/plain", body)
        else:
            self._respond(404, "text/plain", b"not found")

    def do_POST(self) -> None:
        if self.path != "/message":
            self._respond(404, "text/plain", b"not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond(400, "text/plain", b"invalid content length")
            return
        if not 0 <= length <= MAX_MESSAGE_BYTES:
            self._respond(413, "text/plain", b"message too large")
            return
        message = self.rfile.read(length)
        if len(message) != length:
            self._respond(400, "text/plain", b"incomplete message")
            return
        with self.lock:
            self.messages.append(message)
        self._respond(201, "text/plain", b"stored")

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loopback-only Granger WAN forum fixture")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--ready-file", type=Path, required=True)
    options = parser.parse_args(argv)
    install_from_environment("backend")
    server = ThreadingHTTPServer(("127.0.0.1", options.listen_port), ForumHandler)
    try:
        atomic_write_text(
            options.ready_file,
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "pid": os.getpid(),
                    "port": int(server.server_address[1]),
                    "version": 1,
                },
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o644,
        )
        server.serve_forever(poll_interval=0.1)
        return 0
    finally:
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
