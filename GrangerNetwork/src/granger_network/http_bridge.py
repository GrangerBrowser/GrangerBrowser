from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Mapping, TypeVar
from urllib.parse import urlsplit

from .errors import UpstreamPolicyError
from .transport import SocketFactory


MAX_HTTP_BODY = 2 * 1024 * 1024
MAX_PATH_LENGTH = 4096
DEFAULT_CONNECT_TIMEOUT = 1.5
DEFAULT_HEADER_TIMEOUT = 5.0
DEFAULT_BODY_TIMEOUT = 10.0
_APPLICATION_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_REQUEST_HEADERS = {
    "accept",
    "accept-language",
    "authorization",
    "cache-control",
    "content-encoding",
    "content-language",
    "content-type",
    "cookie",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "origin",
    "range",
    "referer",
    "user-agent",
    "x-csrf-token",
    "x-requested-with",
}
_RESPONSE_HEADERS = {
    "accept-ranges",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-range",
    "content-security-policy",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "location",
    "permissions-policy",
    "pragma",
    "referrer-policy",
    "retry-after",
    "set-cookie",
    "vary",
    "x-content-type-options",
    "x-frame-options",
}
_SERVICE_HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.granger$",
    re.IGNORECASE,
)
_StageResult = TypeVar("_StageResult")


def _run_socket_stage(
    connection: socket.socket,
    timeout: float,
    operation: Callable[[], _StageResult],
) -> _StageResult:
    expired = threading.Event()

    def abort() -> None:
        expired.set()
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except (AttributeError, OSError):
            pass
        try:
            connection.close()
        except OSError:
            pass

    deadline = threading.Timer(timeout, abort)
    deadline.daemon = True
    deadline.start()
    try:
        result = operation()
    except (OSError, http.client.HTTPException) as error:
        if expired.is_set():
            raise socket.timeout("loopback HTTP stage deadline expired") from error
        raise
    finally:
        deadline.cancel()
        # A fired deadline must finish before the same socket enters its next stage.
        deadline.join()
    if expired.is_set():
        raise socket.timeout("loopback HTTP stage deadline expired")
    return result


@dataclass(frozen=True)
class HttpResult:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    header_fields: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.header_fields:
            object.__setattr__(self, "header_fields", tuple(self.headers.items()))


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

    @property
    def url(self) -> str:
        authority = f"[{self.host}]" if self.family == socket.AF_INET6 else self.host
        return f"http://{authority}:{self.port}"


class LoopbackHttpBridge:
    def __init__(
        self,
        target: LoopbackHttpTarget,
        timeout: float | None = None,
        socket_factory: SocketFactory = socket.socket,
        *,
        virtual_host: str = "",
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        header_timeout: float = DEFAULT_HEADER_TIMEOUT,
        body_timeout: float = DEFAULT_BODY_TIMEOUT,
    ) -> None:
        if not isinstance(target, LoopbackHttpTarget):
            raise UpstreamPolicyError("unsupported service upstream")
        if timeout is not None:
            connect_timeout = header_timeout = body_timeout = timeout
        for value in (connect_timeout, header_timeout, body_timeout):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 60:
                raise UpstreamPolicyError("service upstream timeout is invalid")
        normalized_host = virtual_host.strip().lower() if isinstance(virtual_host, str) else ""
        if normalized_host and not _SERVICE_HOST.fullmatch(normalized_host):
            raise UpstreamPolicyError("service virtual host is invalid")
        self.target = target
        self.virtual_host = normalized_host
        self.connect_timeout = float(connect_timeout)
        self.header_timeout = float(header_timeout)
        self.body_timeout = float(body_timeout)
        self._socket_factory = socket_factory
        self._health_lock = threading.Lock()
        self._backend_available = True
        self._backend_error = ""

    @staticmethod
    def _error(status: int, reason: str) -> HttpResult:
        body = reason.lower().encode("ascii")
        return HttpResult(
            status,
            reason,
            {"cache-control": "no-store", "content-type": "text/plain; charset=utf-8"},
            body,
        )

    def _set_health(self, available: bool, category: str = "") -> None:
        with self._health_lock:
            self._backend_available = available
            self._backend_error = category

    def health_snapshot(self) -> dict[str, object]:
        with self._health_lock:
            return {
                "backendAvailable": self._backend_available,
                "backendError": self._backend_error,
            }

    def _response_header(self, name: str, value: str) -> tuple[str, str] | None:
        normalized = name.lower()
        if (
            normalized not in _RESPONSE_HEADERS
            or len(value.encode("utf-8")) > 4096
            or "\r" in value
            or "\n" in value
        ):
            return None
        if normalized != "location":
            return normalized, value

        try:
            location = urlsplit(value)
            if not location.scheme and not location.netloc:
                return None if value.startswith("//") else (normalized, value)
            if location.username or location.password or location.hostname is None:
                return None
            location_port = location.port if location.port is not None else 80
        except (ValueError, UnicodeError):
            return None
        try:
            address = ipaddress.ip_address(location.hostname)
        except ValueError:
            return None if location.hostname.lower() == "localhost" else (normalized, value)
        if not address.is_loopback:
            return normalized, value
        if (
            not self.virtual_host
            or address.compressed != self.target.host
            or location_port != self.target.port
        ):
            return None
        rewritten = f"granger-network://{self.virtual_host}{location.path or '/'}"
        if location.query:
            rewritten += "?" + location.query
        if location.fragment:
            rewritten += "#" + location.fragment
        return normalized, rewritten

    def fetch(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        *,
        session_identity: str = "",
    ) -> HttpResult:
        if not isinstance(method, str):
            raise UpstreamPolicyError("request method must be text")
        normalized_method = method.upper()
        if normalized_method not in _APPLICATION_METHODS:
            raise UpstreamPolicyError("service bridge request method is unsupported")
        if not isinstance(body, bytes) or len(body) > MAX_HTTP_BODY:
            raise UpstreamPolicyError("upstream request body exceeds the protocol limit")
        if normalized_method in {"GET", "HEAD"} and body:
            raise UpstreamPolicyError("GET and HEAD requests cannot carry a body")
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
            if (
                not isinstance(value, str)
                or "\r" in value
                or "\n" in value
                or len(value.encode("utf-8")) > 4096
            ):
                raise UpstreamPolicyError("request header contains an invalid value")
            forwarded_headers[lower_name] = value
        del session_identity

        authority = self.virtual_host
        if not authority:
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
        if normalized_method not in {"GET", "HEAD"} or body:
            lines.append(f"Content-Length: {len(body)}")
        lines.extend(f"{name}: {value}" for name, value in sorted(forwarded_headers.items()))
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

        connection = self._socket_factory(self.target.family, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.connect_timeout)
            connection.connect(self.target.socket_address)
            connection.settimeout(self.header_timeout)

            def receive_headers() -> http.client.HTTPResponse:
                connection.sendall(request)
                result = http.client.HTTPResponse(connection, method=normalized_method)
                result.begin()
                return result

            response = _run_socket_stage(connection, self.header_timeout, receive_headers)
            expected_length = response.length
            connection.settimeout(self.body_timeout)
            body = _run_socket_stage(
                connection, self.body_timeout, lambda: response.read(MAX_HTTP_BODY + 1)
            )
            if len(body) > MAX_HTTP_BODY:
                self._set_health(False, "response-too-large")
                return self._error(502, "Bad Gateway")
            if expected_length is not None and len(body) != expected_length:
                self._set_health(False, "malformed-response")
                return self._error(502, "Bad Gateway")
            response_headers: dict[str, str] = {}
            response_header_fields: list[tuple[str, str]] = []
            for name, value in response.getheaders():
                accepted = self._response_header(name, value)
                if accepted is not None:
                    response_header_fields.append(accepted)
                    response_headers[accepted[0]] = accepted[1]
            reason = response.reason or ""
            if len(reason.encode("utf-8")) > 256 or "\r" in reason or "\n" in reason:
                reason = ""
            self._set_health(True)
            return HttpResult(
                response.status,
                reason,
                response_headers,
                body,
                tuple(response_header_fields),
            )
        except socket.timeout:
            self._set_health(False, "timeout")
            return self._error(504, "Gateway Timeout")
        except http.client.HTTPException:
            self._set_health(False, "malformed-response")
            return self._error(502, "Bad Gateway")
        except OSError:
            self._set_health(False, "unavailable")
            return self._error(503, "Service Unavailable")
        finally:
            connection.close()
