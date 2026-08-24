from __future__ import annotations

import base64
import socket
import threading

from .descriptor import ServiceDescriptor
from .errors import DescriptorError, GrangerNetworkError, ProtocolError
from .http_bridge import LoopbackHttpBridge
from .identity import ServiceIdentity
from .protocol import SecureChannel, server_handshake
from .transport import (
    GrangerHostTransport,
    LoopbackTcpServerTransport,
    ServerTransport,
)


def _serve_application_request(
    connection: socket.socket,
    identity: ServiceIdentity,
    bridge: LoopbackHttpBridge,
    *,
    protocol_version: int,
    session_id: bytes | None = None,
) -> str | None:
    channel: SecureChannel | None = None
    try:
        channel = server_handshake(
            connection,
            identity,
            expected_session_id=session_id,
            protocol_version=protocol_version,
        )
        request = channel.receive_json()
        if set(request) != {"headers", "method", "path", "type"} or request["type"] != "request":
            raise ProtocolError("unexpected application request")
        if not isinstance(request["method"], str) or not isinstance(request["path"], str):
            raise ProtocolError("request method and path must be text")
        if not isinstance(request["headers"], dict) or not all(
            isinstance(name, str) and isinstance(value, str)
            for name, value in request["headers"].items()
        ):
            raise ProtocolError("request headers must be a string map")
        result = bridge.fetch(request["method"], request["path"], request["headers"])
        channel.send_json(
            {
                "body": base64.b64encode(result.body).decode("ascii"),
                "headers": result.headers,
                "reason": result.reason,
                "status": result.status,
                "type": "response",
            }
        )
        return None
    except (GrangerNetworkError, OSError, TypeError, ValueError) as error:
        if channel is not None:
            try:
                channel.send_json({"code": "SERVICE_REQUEST_FAILED", "type": "error"})
            except (GrangerNetworkError, OSError):
                pass
        return type(error).__name__


class GrangerServiceHost:
    def __init__(
        self,
        identity: ServiceIdentity,
        descriptor: ServiceDescriptor,
        bridge: LoopbackHttpBridge,
        connection_timeout: float = 10.0,
        transport: ServerTransport | None = None,
    ) -> None:
        descriptor.verify()
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise DescriptorError("service identity does not match its signed descriptor")
        self.identity = identity
        self.descriptor = descriptor
        self.bridge = bridge
        self.connection_timeout = connection_timeout
        self._transport = transport or LoopbackTcpServerTransport()
        self._listener: socket.socket | None = None
        self._stop_event = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._connection_threads: set[threading.Thread] = set()
        self._thread_lock = threading.Lock()
        self.connection_errors: list[str] = []

    def start_background(self) -> None:
        if self._listener is not None:
            raise RuntimeError("service host is already running")
        self._listener = self._transport.listen(self.descriptor.endpoint)
        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="granger-service-accept",
            daemon=True,
        )
        self._accept_thread.start()

    def serve_forever(self) -> None:
        if self._listener is not None:
            raise RuntimeError("service host is already running")
        self._listener = self._transport.listen(self.descriptor.endpoint)
        self._stop_event.clear()
        self._accept_loop()

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
            thread = threading.Thread(
                target=self._handle_connection,
                args=(connection,),
                name="granger-service-connection",
                daemon=True,
            )
            with self._thread_lock:
                self._connection_threads.add(thread)
            thread.start()

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(self.connection_timeout)
            error_name = _serve_application_request(
                connection,
                self.identity,
                self.bridge,
                protocol_version=1,
            )
            if error_name is not None:
                with self._thread_lock:
                    self.connection_errors.append(error_name)
        except OSError as error:
            with self._thread_lock:
                self.connection_errors.append(type(error).__name__)
        finally:
            connection.close()
            current = threading.current_thread()
            with self._thread_lock:
                self._connection_threads.discard(current)

    def stop(self) -> None:
        self._stop_event.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._accept_thread is not None and self._accept_thread is not threading.current_thread():
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        with self._thread_lock:
            threads = list(self._connection_threads)
        for thread in threads:
            thread.join(timeout=2.0)

    def __enter__(self) -> "GrangerServiceHost":
        self.start_background()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


class RendezvousServiceHost:
    """Publishes a v0.2 service through outbound rendezvous sessions only."""

    def __init__(
        self,
        identity: ServiceIdentity,
        descriptor: ServiceDescriptor,
        bridge: LoopbackHttpBridge,
        transport: GrangerHostTransport,
        *,
        connection_timeout: float = 10.0,
        registration_timeout: float = 30.0,
    ) -> None:
        descriptor.verify()
        if not descriptor.is_remote or descriptor.endpoint is not None:
            raise DescriptorError("rendezvous host requires a remote v0.2 descriptor")
        if descriptor.identity_public_key != identity.public_key_bytes:
            raise DescriptorError("service identity does not match its signed descriptor")
        if not isinstance(transport, GrangerHostTransport):
            raise DescriptorError("rendezvous host requires a rendezvous transport")
        self.identity = identity
        self.descriptor = descriptor
        self.bridge = bridge
        self.transport = transport
        self.connection_timeout = connection_timeout
        self.registration_timeout = registration_timeout
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.connection_errors: list[str] = []

    def start_background(self) -> None:
        if self._thread is not None:
            raise RuntimeError("rendezvous service host is already running")
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve_loop,
            name="granger-rendezvous-service",
            daemon=True,
        )
        self._thread.start()

    def serve_forever(self) -> None:
        if self._thread is not None:
            raise RuntimeError("rendezvous service host is already running")
        self._stop_event.clear()
        self._serve_loop()

    def _serve_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                session = self.transport.wait_for_session(
                    self.descriptor.service_id,
                    self.identity,
                    self.registration_timeout,
                )
            except (GrangerNetworkError, OSError) as error:
                if self._stop_event.is_set():
                    break
                self.connection_errors.append(type(error).__name__)
                continue
            try:
                session.connection.settimeout(self.connection_timeout)
                error_name = _serve_application_request(
                    session.connection,
                    self.identity,
                    self.bridge,
                    protocol_version=2,
                    session_id=session.session_id,
                )
                if error_name is not None:
                    self.connection_errors.append(error_name)
            finally:
                session.close()

    def stop(self) -> None:
        self._stop_event.set()
        self.transport.close_pending()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "RendezvousServiceHost":
        self.start_background()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
