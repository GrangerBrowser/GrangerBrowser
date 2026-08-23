from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from .errors import TransportPolicyError


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
