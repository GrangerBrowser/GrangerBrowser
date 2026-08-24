from __future__ import annotations

import http.client
import ipaddress
import socket
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

from .errors import UpstreamPolicyError
from .transport import SocketFactory


MAX_HTTP_BODY = 2 * 1024 * 1024
MAX_PATH_LENGTH = 4096
_REQUEST_HEADERS = {"accept", "accept-language", "user-agent"}
_RESPONSE_HEADERS = {"cache-control", "content-language", "content-type", "etag", "last-modified"}


@dataclass(frozen=True)
class HttpResult:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class LoopbackHttpTarget:
    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.host, str):
            raise UpstreamPolicyError("service upstream host must be text")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise UpstreamPolicyError("service upstream port must be an integer")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as error:
            raise UpstreamPolicyError("service upstream must use a numeric IP address") from error
        if not address.is_loopback:
            raise UpstreamPolicyError("service upstream must remain on numeric loopback")
        if not 1 <= self.port <= 65535:
            raise UpstreamPolicyError("upstream port is outside the valid range")
        object.__setattr__(self, "host", address.compressed)

    @classmethod
    def parse(cls, url: str) -> "LoopbackHttpTarget":
        if not isinstance(url, str):
            raise UpstreamPolicyError("upstream URL must be text")
        try:
            parsed = urlsplit(url)
            if parsed.scheme != "http" or parsed.username or parsed.password:
                raise UpstreamPolicyError("service upstream must use plain HTTP on loopback")
            if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                raise UpstreamPolicyError("upstream URL must not contain a path, query, or fragment")
            if parsed.hostname is None:
                raise UpstreamPolicyError("upstream URL has no host")
            port = parsed.port if parsed.port is not None else 80
            return cls(parsed.hostname, port)
        except ValueError as error:
            raise UpstreamPolicyError(f"invalid loopback upstream URL: {error}") from error

    @property
    def family(self) -> int:
        return socket.AF_INET6 if ipaddress.ip_address(self.host).version == 6 else socket.AF_INET

    @property
    def socket_address(self) -> tuple:
        if self.family == socket.AF_INET6:
            return (self.host, self.port, 0, 0)
        return (self.host, self.port)


class LoopbackHttpBridge:
    def __init__(
        self,
        target: LoopbackHttpTarget,
        timeout: float = 10.0,
        socket_factory: SocketFactory = socket.socket,
    ) -> None:
        if not isinstance(target, LoopbackHttpTarget):
            raise UpstreamPolicyError("unsupported service upstream")
        self.target = target
        self.timeout = timeout
        self._socket_factory = socket_factory

    def fetch(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str] | None = None,
    ) -> HttpResult:
        if not isinstance(method, str):
            raise UpstreamPolicyError("request method must be text")
        normalized_method = method.upper()
        if normalized_method not in {"GET", "HEAD"}:
            raise UpstreamPolicyError("service bridge permits only GET and HEAD")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or len(path) > MAX_PATH_LENGTH
            or "\r" in path
            or "\n" in path
        ):
            raise UpstreamPolicyError("request path is not a safe HTTP origin-form path")
        try:
            encoded_path = path.encode("ascii")
        except UnicodeEncodeError as error:
            raise UpstreamPolicyError("request path must be ASCII with non-ASCII bytes escaped") from error
        if b"#" in encoded_path or any(byte <= 0x20 or byte == 0x7F for byte in encoded_path):
            raise UpstreamPolicyError("request path contains an unsafe character")

        forwarded_headers: dict[str, str] = {}
        for name, value in (headers or {}).items():
            if not isinstance(name, str):
                raise UpstreamPolicyError("request header name must be text")
            lower_name = name.lower()
            if lower_name not in _REQUEST_HEADERS:
                continue
            if not isinstance(value, str) or "\r" in value or "\n" in value or len(value) > 1024:
                raise UpstreamPolicyError("request header contains an invalid value")
            forwarded_headers[lower_name] = value

        authority = self.target.host
        if self.target.family == socket.AF_INET6:
            authority = f"[{authority}]"
        if self.target.port != 80:
            authority = f"{authority}:{self.target.port}"
        lines = [
            f"{normalized_method} {path} HTTP/1.1",
            f"Host: {authority}",
            "Connection: close",
        ]
        lines.extend(f"{name}: {value}" for name, value in sorted(forwarded_headers.items()))
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

        connection = self._socket_factory(self.target.family, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect(self.target.socket_address)
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            body = response.read(MAX_HTTP_BODY + 1)
            if len(body) > MAX_HTTP_BODY:
                raise UpstreamPolicyError("upstream response exceeds the protocol body limit")
            response_headers = {
                name.lower(): value
                for name, value in response.getheaders()
                if name.lower() in _RESPONSE_HEADERS and "\r" not in value and "\n" not in value
            }
            return HttpResult(response.status, response.reason or "", response_headers, body)
        except (OSError, http.client.HTTPException) as error:
            raise UpstreamPolicyError(f"loopback upstream request failed: {error}") from error
        finally:
            connection.close()
