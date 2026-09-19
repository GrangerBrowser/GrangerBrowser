from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
from contextlib import closing
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
    database_path: Path

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
        elif self.path == "/cookie":
            cookie = self.headers.get("Cookie", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "session=granger; Path=/; HttpOnly; SameSite=Strict")
            body = cookie.encode("utf-8") or b"cookie-created"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        elif self.path == "/status":
            self._respond(409, "text/plain", b"conflict")
        elif self.path == "/binary":
            self._respond(200, "application/octet-stream", b"\x00\xffGRANGER-BINARY\x00")
        elif self.path == "/threads":
            with closing(sqlite3.connect(self.database_path)) as database:
                rows = database.execute("SELECT id, title FROM threads ORDER BY id").fetchall()
            self._respond(200, "application/json", json.dumps(rows).encode("utf-8"))
        elif self.path.startswith("/threads/"):
            try:
                thread_id = int(self.path.split("/", 3)[2])
            except (IndexError, ValueError):
                self._respond(404, "text/plain", b"not found")
                return
            with closing(sqlite3.connect(self.database_path)) as database:
                item = database.execute(
                    "SELECT id, title FROM threads WHERE id = ?", (thread_id,)
                ).fetchone()
                replies = database.execute(
                    "SELECT message FROM replies WHERE thread_id = ? ORDER BY id", (thread_id,)
                ).fetchall()
            self._respond(
                200 if item else 404,
                "application/json",
                json.dumps({"thread": item, "replies": replies}).encode("utf-8"),
            )
        else:
            self._respond(404, "text/plain", b"not found")

    def do_POST(self) -> None:
        if self.path == "/echo":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            self._respond(202, self.headers.get("Content-Type", "application/octet-stream"), body)
            return
        if self.path == "/threads":
            length = int(self.headers.get("Content-Length", "0"))
            try:
                title = str(json.loads(self.rfile.read(length).decode("utf-8"))["title"])
            except (KeyError, TypeError, ValueError, UnicodeDecodeError):
                self._respond(400, "text/plain", b"invalid thread")
                return
            with closing(sqlite3.connect(self.database_path)) as database:
                cursor = database.execute("INSERT INTO threads(title) VALUES (?)", (title,))
                thread_id = int(cursor.lastrowid)
                database.commit()
            self._respond(201, "application/json", json.dumps({"id": thread_id}).encode("utf-8"))
            return
        if self.path.startswith("/threads/") and self.path.endswith("/replies"):
            try:
                thread_id = int(self.path.split("/", 3)[2])
                length = int(self.headers.get("Content-Length", "0"))
                message = str(json.loads(self.rfile.read(length).decode("utf-8"))["message"])
            except (IndexError, KeyError, TypeError, ValueError, UnicodeDecodeError):
                self._respond(400, "text/plain", b"invalid reply")
                return
            with closing(sqlite3.connect(self.database_path)) as database:
                database.execute(
                    "INSERT INTO replies(thread_id, message) VALUES (?, ?)",
                    (thread_id, message),
                )
                database.commit()
            self._respond(201, "text/plain", b"stored")
            return
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

    def _application_method(self) -> None:
        if self.path != "/echo":
            self._respond(404, "text/plain", b"not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.send_response(202)
        self.send_header("Content-Type", self.headers.get("Content-Type", "application/octet-stream"))
        if self.command == "OPTIONS":
            self.send_header(
                "Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
            )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_DELETE = _application_method
    do_OPTIONS = _application_method
    do_PATCH = _application_method
    do_PUT = _application_method

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loopback-only Granger WAN forum fixture")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    options = parser.parse_args(argv)
    install_from_environment("backend")
    database_path = options.database or options.ready_file.with_suffix(".sqlite3")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path)) as database:
        database.executescript(
            "CREATE TABLE IF NOT EXISTS threads(id INTEGER PRIMARY KEY, title TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS replies(id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL, "
            "message TEXT NOT NULL);"
        )
    ForumHandler.database_path = database_path
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
