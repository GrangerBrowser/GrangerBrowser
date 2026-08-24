from __future__ import annotations

import ipaddress
import secrets
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from .errors import ProtocolError, RendezvousError, TransportPolicyError
from .identity import ServiceIdentity
from .rendezvous_control import (
    CONTROL_VERSION,
    create_connect_request,
    create_host_registration,
    parse_paired,
    receive_control,
    send_control,
    validate_service_id,
)


SocketFactory = Callable[[int, int], socket.socket]


@dataclass(frozen=True)
class LoopbackEndpoint:
    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.host, str):
            raise TransportPolicyError("transport endpoint host must be text")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TransportPolicyError("transport endpoint port must be an integer")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as error:
            raise TransportPolicyError("transport endpoints must use a numeric IP address") from error
        if not address.is_loopback:
            raise TransportPolicyError("v0.1 transport endpoints must remain on loopback")
        if not 1 <= self.port <= 65535:
            raise TransportPolicyError("transport port is outside the valid range")
        object.__setattr__(self, "host", address.compressed)

    @property
    def family(self) -> int:
        return socket.AF_INET6 if ipaddress.ip_address(self.host).version == 6 else socket.AF_INET

    @property
    def socket_address(self) -> tuple:
        if self.family == socket.AF_INET6:
            return (self.host, self.port, 0, 0)
        return (self.host, self.port)


class ClientTransport(ABC):
    @abstractmethod
    def connect(self, endpoint: LoopbackEndpoint, timeout: float) -> socket.socket:
        raise NotImplementedError


class ServerTransport(ABC):
    @abstractmethod
    def listen(self, endpoint: LoopbackEndpoint, backlog: int = 32) -> socket.socket:
        raise NotImplementedError


class LoopbackTcpTransport(ClientTransport):
    """Numeric loopback TCP with no hostname resolution or fallback path."""

    def __init__(self, socket_factory: SocketFactory = socket.socket) -> None:
        self._socket_factory = socket_factory

    def connect(self, endpoint: LoopbackEndpoint, timeout: float = 10.0) -> socket.socket:
        if not isinstance(endpoint, LoopbackEndpoint):
            raise TransportPolicyError("unsupported transport endpoint")
        connection = self._socket_factory(endpoint.family, socket.SOCK_STREAM)
        try:
            connection.settimeout(timeout)
            connection.connect(endpoint.socket_address)
            return connection
        except Exception:
            connection.close()
            raise


class LoopbackTcpServerTransport(ServerTransport):
    """Numeric loopback listener paired with LoopbackTcpTransport."""

    def __init__(self, socket_factory: SocketFactory = socket.socket) -> None:
        self._socket_factory = socket_factory

    def listen(self, endpoint: LoopbackEndpoint, backlog: int = 32) -> socket.socket:
        if not isinstance(endpoint, LoopbackEndpoint):
            raise TransportPolicyError("unsupported transport endpoint")
        listener = self._socket_factory(endpoint.family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(endpoint.socket_address)
            listener.listen(backlog)
            listener.settimeout(0.25)
            return listener
        except Exception:
            listener.close()
            raise


@dataclass(frozen=True)
class RendezvousEndpoint:
    """A numeric bootstrap endpoint for a relay, never a service address."""

    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.host, str):
            raise TransportPolicyError("rendezvous endpoint host must be text")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TransportPolicyError("rendezvous endpoint port must be an integer")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as error:
            raise TransportPolicyError("rendezvous endpoints must use numeric IP addresses") from error
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise TransportPolicyError("rendezvous endpoint address is not connectable")
        if not 1 <= self.port <= 65535:
            raise TransportPolicyError("rendezvous port is outside the valid range")
        object.__setattr__(self, "host", address.compressed)

    @property
    def family(self) -> int:
        return socket.AF_INET6 if ipaddress.ip_address(self.host).version == 6 else socket.AF_INET

    @property
    def socket_address(self) -> tuple:
        if self.family == socket.AF_INET6:
            return (self.host, self.port, 0, 0)
        return (self.host, self.port)


@dataclass
class TransportSession:
    connection: socket.socket
    destination_id: str
    session_id: bytes

    def send(self, frame: bytes) -> None:
        if not isinstance(frame, bytes):
            raise TransportPolicyError("transport frames must be bytes")
        self.connection.sendall(frame)

    def receive(self, maximum: int = 64 * 1024) -> bytes:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
            raise TransportPolicyError("transport receive limit must be positive")
        return self.connection.recv(maximum)

    def close(self) -> None:
        self.connection.close()


class GrangerTransport(ABC):
    """Destination-identity transport used by clients."""

    @abstractmethod
    def connect(self, destination_id: str, timeout: float = 10.0) -> TransportSession:
        raise NotImplementedError


class GrangerHostTransport(ABC):
    """Outbound transport used by a service waiting at a rendezvous."""

    @abstractmethod
    def wait_for_session(
        self,
        destination_id: str,
        identity: ServiceIdentity,
        timeout: float = 30.0,
    ) -> TransportSession:
        raise NotImplementedError

    @abstractmethod
    def close_pending(self) -> None:
        raise NotImplementedError


def _open_numeric_connection(
    endpoint: RendezvousEndpoint,
    timeout: float,
    socket_factory: SocketFactory,
) -> socket.socket:
    connection = socket_factory(endpoint.family, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(endpoint.socket_address)
        return connection
    except Exception:
        connection.close()
        raise


def _control_error(document: dict) -> tuple[str, str] | None:
    if document.get("type") != "error":
        return None
    if set(document) != {"code", "message", "type", "version"}:
        raise ProtocolError("invalid rendezvous error response")
    if document.get("version") != CONTROL_VERSION or isinstance(document.get("version"), bool):
        raise ProtocolError("unsupported rendezvous error response")
    code = document.get("code")
    message = document.get("message")
    if not isinstance(code, str) or not isinstance(message, str):
        raise ProtocolError("invalid rendezvous error response values")
    return code, message


class RendezvousClientTransport(GrangerTransport):
    def __init__(
        self,
        endpoint: RendezvousEndpoint,
        socket_factory: SocketFactory = socket.socket,
        retry_interval: float = 0.05,
    ) -> None:
        if not isinstance(endpoint, RendezvousEndpoint):
            raise TransportPolicyError("unsupported rendezvous endpoint")
        if retry_interval < 0:
            raise TransportPolicyError("rendezvous retry interval cannot be negative")
        self.endpoint = endpoint
        self._socket_factory = socket_factory
        self.retry_interval = retry_interval

    def connect(self, destination_id: str, timeout: float = 10.0) -> TransportSession:
        service_id = validate_service_id(destination_id)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise TransportPolicyError("transport timeout must be positive")
        deadline = time.monotonic() + timeout
        last_error: BaseException | None = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if last_error is not None:
                    raise RendezvousError(f"rendezvous connection timed out: {last_error}") from last_error
                raise RendezvousError("rendezvous connection timed out")
            connection: socket.socket | None = None
            session_id = secrets.token_bytes(16)
            try:
                connection = _open_numeric_connection(
                    self.endpoint,
                    remaining,
                    self._socket_factory,
                )
                send_control(connection, create_connect_request(service_id, session_id))
                response = receive_control(connection)
                error = _control_error(response)
                if error is not None:
                    code, message = error
                    if code == "NO_HOST":
                        last_error = RendezvousError(message)
                    else:
                        raise RendezvousError(f"rendezvous rejected client: {code}: {message}")
                else:
                    paired_id = parse_paired(response, session_id)
                    established = connection
                    connection = None
                    return TransportSession(established, service_id, paired_id)
            except OSError as error:
                last_error = error
            except (ProtocolError, RendezvousError):
                raise
            finally:
                if connection is not None:
                    connection.close()
            sleep_for = min(self.retry_interval, max(0.0, deadline - time.monotonic()))
            if sleep_for:
                time.sleep(sleep_for)


class RendezvousHostTransport(GrangerHostTransport):
    def __init__(
        self,
        endpoint: RendezvousEndpoint,
        socket_factory: SocketFactory = socket.socket,
    ) -> None:
        if not isinstance(endpoint, RendezvousEndpoint):
            raise TransportPolicyError("unsupported rendezvous endpoint")
        self.endpoint = endpoint
        self._socket_factory = socket_factory
        self._lock = threading.Lock()
        self._pending: socket.socket | None = None

    def wait_for_session(
        self,
        destination_id: str,
        identity: ServiceIdentity,
        timeout: float = 30.0,
    ) -> TransportSession:
        service_id = validate_service_id(destination_id)
        connection = _open_numeric_connection(self.endpoint, timeout, self._socket_factory)
        with self._lock:
            self._pending = connection
        try:
            send_control(connection, create_host_registration(identity, service_id))
            registered = receive_control(connection)
            error = _control_error(registered)
            if error is not None:
                raise RendezvousError(
                    f"rendezvous rejected host: {error[0]}: {error[1]}"
                )
            if registered != {"type": "registered", "version": CONTROL_VERSION}:
                raise ProtocolError("invalid host registration response")
            paired_id = parse_paired(receive_control(connection))
            return TransportSession(connection, service_id, paired_id)
        except Exception:
            connection.close()
            raise
        finally:
            with self._lock:
                if self._pending is connection:
                    self._pending = None

    def close_pending(self) -> None:
        with self._lock:
            connection = self._pending
            self._pending = None
        if connection is not None:
            connection.close()
