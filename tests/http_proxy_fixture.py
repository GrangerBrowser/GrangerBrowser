import argparse
import json
import socketserver
import threading
from pathlib import Path


HTML = b"""<!doctype html><meta charset=utf-8><title>HTTP Fixture</title>
<main id=http-fixture-ok>http-fixture-ok</main>"""


class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline(8192).decode("latin-1", "replace").strip()
        if not request_line:
            return
        while True:
            line = self.rfile.readline(8192)
            if not line or line in (b"\r\n", b"\n"):
                break
        parts = request_line.split(" ", 2)
        method = parts[0].upper() if parts else "UNKNOWN"
        target = parts[1] if len(parts) > 1 else ""
        self.server.record(method, target)
        if method == "CONNECT":
            self.wfile.write(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            return
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            + f"Content-Length: {len(HTML)}\r\n".encode("ascii")
            + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
            + HTML
        )


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, log_path):
        super().__init__(address, handler)
        self.log_path = Path(log_path)
        self.log_lock = threading.Lock()

    def record(self, method, target):
        entry = json.dumps({"method": method, "target": target}, ensure_ascii=True)
        with self.log_lock:
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(entry + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--log", required=True)
    parser.add_argument("--ready", required=True)
    args = parser.parse_args()
    log_path = Path(args.log)
    ready_path = Path(args.ready)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    ready_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")
    with FixtureServer(("127.0.0.1", args.port), ProxyHandler, log_path) as server:
        ready_path.write_text(
            json.dumps({"port": server.server_address[1]}), encoding="utf-8"
        )
        server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
