from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer

from granger_network.host import initialize_remote_service
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.identity import ServiceIdentity
from granger_network.rendezvous import RendezvousServer
from granger_network.service import RendezvousServiceHost
from granger_network.transport import RendezvousEndpoint, RendezvousHostTransport


PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def application_script(owner: str, other: str, escape_url: str) -> bytes:
    escape_websocket = escape_url.replace("http://", "ws://", 1)
    return f"""
window.grangerScriptLoaded = true;
(async () => {{
  const body = document.body;
  body.dataset.priorStorage = localStorage.getItem('origin-token') || '';
  body.dataset.priorCookie = document.cookie || '';
  localStorage.setItem('origin-token', {json.dumps(owner)});
  document.cookie = 'origin_cookie={owner}; SameSite=Strict; Path=/';
  try {{
    const response = await fetch('/api/data.json');
    const data = await response.json();
    body.dataset.fetch = data.owner === {json.dumps(owner)} ? 'ok' : 'wrong';
  }} catch (_error) {{ body.dataset.fetch = 'failed'; }}
  try {{
    await fetch('granger-network://{other}.granger/api/data.json');
    body.dataset.crossService = 'leaked';
  }} catch (_error) {{ body.dataset.crossService = 'blocked'; }}
  try {{
    await fetch({json.dumps(escape_url)});
    body.dataset.crossNetwork = 'leaked';
  }} catch (_error) {{ body.dataset.crossNetwork = 'blocked'; }}
  for (const [tag, attribute] of [['img', 'src'], ['script', 'src'], ['iframe', 'src']]) {{
    const element = document.createElement(tag);
    element[attribute] = {json.dumps(escape_url)};
    document.body.appendChild(element);
  }}
  const stylesheet = document.createElement('link');
  stylesheet.rel = 'stylesheet';
  stylesheet.href = {json.dumps(escape_url)};
  document.head.appendChild(stylesheet);
  try {{ new WebSocket({json.dumps(escape_websocket)}); }} catch (_error) {{}}
  try {{
    const workerCode = 'fetch(' + JSON.stringify({json.dumps(escape_url)})
      + ').catch(() => undefined);';
    const workerUrl = URL.createObjectURL(new Blob([workerCode], {{type: 'text/javascript'}}));
    const worker = new Worker(workerUrl);
    setTimeout(() => {{ worker.terminate(); URL.revokeObjectURL(workerUrl); }}, 1000);
  }} catch (_error) {{}}
  try {{
    const frameCode = '<script>fetch(' + JSON.stringify({json.dumps(escape_url)})
      + ').catch(() => undefined);<\\/script>';
    const blobFrame = document.createElement('iframe');
    blobFrame.src = URL.createObjectURL(new Blob([frameCode], {{type: 'text/html'}}));
    document.body.appendChild(blobFrame);
    const dataFrame = document.createElement('iframe');
    dataFrame.src = 'data:text/html;charset=utf-8,' + encodeURIComponent(frameCode);
    document.body.appendChild(dataFrame);
    const blankFrame = document.createElement('iframe');
    blankFrame.src = 'about:blank';
    blankFrame.addEventListener('load', () => {{
      blankFrame.contentWindow.fetch({json.dumps(escape_url)}).catch(() => undefined);
    }}, {{once: true}});
    document.body.appendChild(blankFrame);
  }} catch (_error) {{}}
  try {{ await fetch('/redirect'); }} catch (_error) {{}}
  body.dataset.crossVectors = 'scheduled';
  try {{
    await new Promise((resolve, reject) => {{
      const request = indexedDB.open('granger-origin-check', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('state');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {{
        const db = request.result;
        const transaction = db.transaction('state', 'readwrite');
        const store = transaction.objectStore('state');
        const previous = store.get('owner');
        previous.onsuccess = () => {{
          body.dataset.priorIndexedDb = previous.result || '';
          store.put({json.dumps(owner)}, 'owner');
        }};
        transaction.oncomplete = () => {{ db.close(); resolve(); }};
        transaction.onerror = () => reject(transaction.error);
      }};
    }});
    body.dataset.indexedDb = 'ok';
  }} catch (_error) {{ body.dataset.indexedDb = 'unsupported'; }}
  try {{
    const cache = await caches.open('granger-origin-cache');
    await cache.put('/cache-entry', new Response({json.dumps(owner)}));
    body.dataset.cache = (await (await cache.match('/cache-entry')).text()) === {json.dumps(owner)}
      ? 'ok' : 'wrong';
  }} catch (_error) {{ body.dataset.cache = 'unsupported'; }}
  try {{
    if (!('serviceWorker' in navigator)) throw new Error('unsupported');
    await navigator.serviceWorker.register('/sw.js', {{scope: '/'}});
    body.dataset.serviceWorker = 'ok';
  }} catch (_error) {{ body.dataset.serviceWorker = 'unsupported'; }}
  body.dataset.ready = 'true';
}})();
""".encode("utf-8")


def handler_for(owner: str, heading: str, other: str, escape_url: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/style.css":
                self._send(b"#style-probe { color: rgb(45, 212, 191); }", "text/css")
                return
            if path == "/app.js":
                self._send(
                    application_script(owner, other, escape_url),
                    "application/javascript; charset=utf-8",
                )
                return
            if path == "/pixel.png":
                self._send(PIXEL, "image/png")
                return
            if path == "/api/data.json":
                self._send(json.dumps({"owner": owner}).encode("ascii"), "application/json")
                return
            if path == "/sw.js":
                self._send(
                    (
                        "self.addEventListener('install', event => {"
                        "event.waitUntil(fetch("
                        + json.dumps(escape_url)
                        + ").catch(() => undefined));});"
                    ).encode("utf-8"),
                    "application/javascript; charset=utf-8",
                )
                return
            if path == "/redirect":
                self.send_response(302)
                self.send_header("Location", escape_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/next":
                self._send(
                    f"<!doctype html><title>Next</title><body data-page=\"next\"><h1>{heading}</h1>next</body>".encode(),
                    "text/html; charset=utf-8",
                )
                return
            if path == "/form":
                self._send(
                    f"<!doctype html><title>Form</title><body data-page=\"form\"><h1>{heading}</h1>form</body>".encode(),
                    "text/html; charset=utf-8",
                )
                return
            if path != "/":
                self.send_error(404)
                return
            page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{heading}</title>
<link rel="stylesheet" href="/style.css"></head>
<body data-page="root"><h1>{heading}</h1><p id="style-probe">styled</p>
<img id="relative-image" src="/pixel.png" alt="pixel">
<a id="relative-link" href="/next">next</a>
<form id="search-form" action="/form" method="get">
<input name="q" value="granger"><button type="submit">submit</button></form>
<script src="/app.js"></script></body></html>"""
            self._send(page.encode("utf-8"), "text/html; charset=utf-8")

        def _send(self, body: bytes, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


class EscapeProbeHandler(BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        with server.count_lock:
            server.connection_count += 1
        try:
            self.request.recv(4096)
            self.request.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        except OSError:
            pass


class EscapeProbe(ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), EscapeProbeHandler)
        self.connection_count = 0
        self.count_lock = threading.Lock()


class RelayCaptureSocket:
    def __init__(self, wrapped: socket.socket, wire: bytearray) -> None:
        self._wrapped = wrapped
        self._wire = wire

    def accept(self):
        connection, peer = self._wrapped.accept()
        return RelayCaptureSocket(connection, self._wire), peer

    def recv(self, size: int) -> bytes:
        data = self._wrapped.recv(size)
        self._wire.extend(data)
        return data

    def sendall(self, data: bytes) -> None:
        self._wire.extend(data)
        self._wrapped.sendall(data)

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


class RelayCaptureFactory:
    def __init__(self, wire: bytearray) -> None:
        self.wire = wire

    def __call__(self, family: int, kind: int):
        return RelayCaptureSocket(socket.socket(family, kind), self.wire)


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def run(browser: Path, output: Path, qt_bin: Path) -> int:
    repository = Path(__file__).resolve().parents[2]
    network_root = repository / "GrangerNetwork"
    wire = bytearray()
    probe = EscapeProbe()
    probe_thread = threading.Thread(target=probe.serve_forever, daemon=True)
    probe_thread.start()
    escape_url = f"http://127.0.0.1:{probe.server_address[1]}/escape"

    first_http = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_for("first", "Granger browser integration", "second", escape_url),
    )
    second_http = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_for("second", "Second Granger service", "test", escape_url),
    )
    first_http_thread = threading.Thread(target=first_http.serve_forever, daemon=True)
    second_http_thread = threading.Thread(target=second_http.serve_forever, daemon=True)
    first_http_thread.start()
    second_http_thread.start()

    with tempfile.TemporaryDirectory(prefix="granger-browser-network-") as temporary:
        root = Path(temporary)
        registry = root / "registry"
        relay_endpoint = RendezvousEndpoint("127.0.0.1", available_port())
        first_descriptor = initialize_remote_service(
            root / "first-service",
            "browser-smoke-relay",
            relay_endpoint,
            registry,
            "test.granger",
            metadata={"contentType": "text/html", "title": "Browser integration"},
        )
        second_descriptor = initialize_remote_service(
            root / "second-service",
            "browser-smoke-relay",
            relay_endpoint,
            registry,
            "second.granger",
            metadata={"contentType": "text/html", "title": "Origin isolation"},
        )
        relay = RendezvousServer(relay_endpoint, socket_factory=RelayCaptureFactory(wire))
        first_host = RendezvousServiceHost(
            ServiceIdentity.load(root / "first-service" / "service.key"),
            first_descriptor,
            LoopbackHttpBridge(LoopbackHttpTarget("127.0.0.1", first_http.server_address[1])),
            RendezvousHostTransport(relay_endpoint),
        )
        second_host = RendezvousServiceHost(
            ServiceIdentity.load(root / "second-service" / "service.key"),
            second_descriptor,
            LoopbackHttpBridge(LoopbackHttpTarget("127.0.0.1", second_http.server_address[1])),
            RendezvousHostTransport(relay_endpoint),
        )
        relay.start_background()
        first_host.start_background()
        second_host.start_background()
        time.sleep(0.2)
        environment = os.environ.copy()
        environment["PATH"] = str(qt_bin) + os.pathsep + environment.get("PATH", "")
        environment["GRANGER_DATA_ROOT"] = str(root / "browser-data")
        environment["GRANGER_CACHE_ROOT"] = str(root / "browser-cache")
        arguments = [
            str(browser),
            "--smoke-granger-network-browser",
            f"--smoke-output={output}",
            f"--granger-network-source={network_root}",
            f"--granger-network-registry={registry}",
            f"--granger-network-python={sys.executable}",
            "--granger-network-alias=test.granger",
            f"--granger-network-canonical={first_descriptor.canonical_name}",
            "--granger-network-second=second.granger",
        ]
        completed = subprocess.run(
            arguments,
            cwd=repository,
            env=environment,
            capture_output=True,
            text=True,
            timeout=150,
            check=False,
        )
        first_host.stop()
        second_host.stop()
        relay.stop()

        result = json.loads(output.read_text(encoding="utf-8")) if output.is_file() else {}
        worker_pid = int(result.get("runtime", {}).get("workerPid", 0))
        time.sleep(0.25)
        orphan_count = int(process_is_running(worker_pid))
        captured = bytes(wire)
        plaintext_observed = any(
            marker in captured
            for marker in (
                b"Granger browser integration",
                b"Second Granger service",
                b"GET /",
                b"Host:",
            )
        )
        harness = {
            "browserExitCode": completed.returncode,
            "escapeProbeConnections": probe.connection_count,
            "orphanProcesses": orphan_count,
            "relayBytes": len(captured),
            "relayPlaintextObserved": plaintext_observed,
            "firstHostErrors": first_host.connection_errors,
            "secondHostErrors": second_host.connection_errors,
            "stderr": completed.stderr[-4000:],
            "stdout": completed.stdout[-4000:],
        }
        result["harness"] = harness
        result["ok"] = bool(result.get("ok")) and completed.returncode == 0 \
            and probe.connection_count == 0 and orphan_count == 0 and not plaintext_observed
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    first_http.shutdown()
    second_http.shutdown()
    probe.shutdown()
    first_http.server_close()
    second_http.server_close()
    probe.server_close()
    first_http_thread.join(timeout=2)
    second_http_thread.join(timeout=2)
    probe_thread.join(timeout=2)
    return 0 if result.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Granger Network in the real Qt WebEngine browser")
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qt-bin", type=Path, required=True)
    options = parser.parse_args()
    return run(options.browser.resolve(), options.output.resolve(), options.qt_bin.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
