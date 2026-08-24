from __future__ import annotations

import argparse
import json
import select
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from ._codec import atomic_write_text
from .errors import GrangerNetworkError, ProtocolError, ReplayError
from .rendezvous_control import (
    CONTROL_VERSION,
    paired_document,
    receive_control,
    send_control,
    verify_connect_request,
    verify_host_registration,
)
from .transport import RendezvousEndpoint, SocketFactory


REPLAY_CACHE_SECONDS = 2 * 120 + 1


@dataclass
class _HostSlot:
    connection: socket.socket
    service_id: str
    paired: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)


class RendezvousServer:
    """Experimental relay that pairs two outbound connections and forwards bytes."""

    def __init__(
        self,
        endpoint: RendezvousEndpoint,
        *,
        socket_factory: SocketFactory = socket.socket,
        capture_path: Path | None = None,
        registration_timeout: float = 30.0,
    ) -> None:
        if not isinstance(endpoint, RendezvousEndpoint):
            raise TypeError("endpoint must be a RendezvousEndpoint")
        self.endpoint = endpoint
        self._socket_factory = socket_factory
        self.capture_path = Path(capture_path) if capture_path is not None else None
        self.registration_timeout = registration_timeout
        self._listener: socket.socket | None = None
        self._stop_event = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._threads: set[threading.Thread] = set()
        self._hosts: dict[str, deque[_HostSlot]] = defaultdict(deque)
        self._registration_nonces: dict[bytes, float] = {}
        self._session_ids: dict[bytes, float] = {}
        self._lock = threading.Lock()
        self._capture_lock = threading.Lock()
        self.captured_bytes = bytearray()
        self.completed_sessions = 0
        self.rejected_replays = 0
        self.errors: list[str] = []

    def start_background(self) -> None:
        if self._listener is not None:
            raise RuntimeError("rendezvous server is already running")
        self._open_listener()
        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="granger-rendezvous-accept",
            daemon=True,
        )
        self._accept_thread.start()

    def serve_forever(self) -> None:
        if self._listener is not None:
            raise RuntimeError("rendezvous server is already running")
        self._open_listener()
        self._stop_event.clear()
        self._accept_loop()

    def _open_listener(self) -> None:
        listener = self._socket_factory(self.endpoint.family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(self.endpoint.socket_address)
            listener.listen(64)
            listener.settimeout(0.25)
            self._listener = listener
        except Exception:
            listener.close()
            raise

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop_event.is_set():
            try:
                connection, _peer = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                raise
            connection.settimeout(self.registration_timeout)
            thread = threading.Thread(
                target=self._handle_connection,
                args=(connection,),
                name="granger-rendezvous-connection",
                daemon=True,
            )
            with self._lock:
                self._threads.add(thread)
            thread.start()

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            document = receive_control(connection)
            message_type = document.get("type")
            if message_type == "register":
                self._handle_host(connection, document)
            elif message_type == "connect":
                self._handle_client(connection, document)
            else:
                raise ProtocolError("unsupported rendezvous control message")
        except ReplayError as error:
            with self._lock:
                self.rejected_replays += 1
            self._send_error(connection, "REPLAY", str(error))
        except (GrangerNetworkError, OSError, TypeError, ValueError) as error:
            with self._lock:
                self.errors.append(type(error).__name__)
            self._send_error(connection, "INVALID_REQUEST", str(error))
        finally:
            connection.close()
            current = threading.current_thread()
            with self._lock:
                self._threads.discard(current)

    def _handle_host(self, connection: socket.socket, document: dict) -> None:
        service_id, nonce = verify_host_registration(document)
        self._claim_replay_token(self._registration_nonces, nonce)
        slot = _HostSlot(connection, service_id)
        with self._lock:
            self._hosts[service_id].append(slot)
        send_control(connection, {"type": "registered", "version": CONTROL_VERSION})
        if not slot.paired.wait(self.registration_timeout):
            with self._lock:
                queue = self._hosts.get(service_id)
                if queue is not None:
                    try:
                        queue.remove(slot)
                    except ValueError:
                        pass
                    if not queue:
                        self._hosts.pop(service_id, None)
            raise ProtocolError("host registration expired before a client arrived")
        slot.done.wait()

    def _handle_client(self, connection: socket.socket, document: dict) -> None:
        service_id, session_id = verify_connect_request(document)
        self._claim_replay_token(self._session_ids, session_id)
        slot = self._take_host(service_id)
        if slot is None:
            self._send_error(connection, "NO_HOST", "no host is waiting for this service")
            return
        try:
            send_control(slot.connection, paired_document(session_id))
            send_control(connection, paired_document(session_id))
            slot.paired.set()
            connection.settimeout(None)
            slot.connection.settimeout(None)
            self._forward_pair(connection, slot.connection)
            with self._lock:
                self.completed_sessions += 1
        finally:
            slot.paired.set()
            slot.done.set()

    def _take_host(self, service_id: str) -> _HostSlot | None:
        with self._lock:
            queue = self._hosts.get(service_id)
            if not queue:
                return None
            slot = queue.popleft()
            if not queue:
                self._hosts.pop(service_id, None)
            return slot

    def _claim_replay_token(self, cache: dict[bytes, float], token: bytes) -> None:
        now = time.monotonic()
        with self._lock:
            expired = [value for value, expiry in cache.items() if expiry <= now]
            for value in expired:
                cache.pop(value, None)
            if token in cache:
                raise ReplayError("rendezvous token was already used")
            cache[token] = now + REPLAY_CACHE_SECONDS

    def _forward_pair(self, client: socket.socket, host: socket.socket) -> None:
        peers = {client: host, host: client}
        readable = [client, host]
        while readable and not self._stop_event.is_set():
            ready, _, _ = select.select(readable, [], [], 0.25)
            for source in ready:
                destination = peers[source]
                data = source.recv(64 * 1024)
                if not data:
                    readable.remove(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                self._capture(data)
                destination.sendall(data)

    def _capture(self, data: bytes) -> None:
        with self._capture_lock:
            self.captured_bytes.extend(data)
            if self.capture_path is not None:
                self.capture_path.parent.mkdir(parents=True, exist_ok=True)
                with self.capture_path.open("ab") as output:
                    output.write(data)

    @staticmethod
    def _send_error(connection: socket.socket, code: str, message: str) -> None:
        try:
            send_control(
                connection,
                {
                    "code": code,
                    "message": message[:256],
                    "type": "error",
                    "version": CONTROL_VERSION,
                },
            )
        except (GrangerNetworkError, OSError):
            pass

    def stop(self) -> None:
        self._stop_event.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with self._lock:
            slots = [slot for queue in self._hosts.values() for slot in queue]
            self._hosts.clear()
        for slot in slots:
            slot.paired.set()
            slot.done.set()
            slot.connection.close()
        if self._accept_thread is not None and self._accept_thread is not threading.current_thread():
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=2.0)

    def __enter__(self) -> "RendezvousServer":
        self.start_background()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network v0.2 rendezvous relay")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=7788)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--ready-file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        endpoint = RendezvousEndpoint(options.listen_host, options.listen_port)
        server = RendezvousServer(endpoint, capture_path=options.capture)
        if options.capture is not None:
            options.capture.parent.mkdir(parents=True, exist_ok=True)
            options.capture.write_bytes(b"")
        server.start_background()
        if options.ready_file is not None:
            atomic_write_text(
                options.ready_file,
                json.dumps(
                    {"host": endpoint.host, "port": endpoint.port, "version": 1},
                    sort_keys=True,
                )
                + "\n",
                mode=0o600,
            )
        print(f"rendezvous: {endpoint.host}:{endpoint.port}")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            return 0
        finally:
            server.stop()
    except (GrangerNetworkError, OSError, TypeError, ValueError) as error:
        print(f"granger-rendezvous: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
