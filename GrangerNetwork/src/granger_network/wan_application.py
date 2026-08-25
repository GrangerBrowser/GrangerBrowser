from __future__ import annotations

import struct
import threading
import secrets
from dataclasses import dataclass
from typing import Mapping

from .binary import BinaryReader, BinaryWriter
from .cells import CellMultiplexer, MuxStream
from .errors import GrangerNetworkError, ProtocolError, ResourceLimitError
from .http_bridge import HttpResult, MAX_HTTP_BODY, MAX_PATH_LENGTH


APPLICATION_VERSION = 1
MAX_APPLICATION_MESSAGE = 2 * MAX_HTTP_BODY + 16 * 1024
MAX_APPLICATION_HEADERS = 32
MAX_HEADER_NAME = 64
MAX_HEADER_VALUE = 4096
_METHOD_TO_ID = {"GET": 1, "HEAD": 2, "POST": 3}
_ID_TO_METHOD = {value: key for key, value in _METHOD_TO_ID.items()}


@dataclass(frozen=True)
class ApplicationRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


def _validate_headers(headers: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(headers, Mapping) or len(headers) > MAX_APPLICATION_HEADERS:
        raise ProtocolError("application header count is invalid")
    result: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ProtocolError("application headers must contain text")
        normalized = name.lower()
        if (
            not normalized
            or len(normalized.encode("ascii", errors="ignore")) != len(normalized)
            or len(normalized) > MAX_HEADER_NAME
            or not all(character.isalnum() or character == "-" for character in normalized)
            or "\r" in value
            or "\n" in value
            or len(value.encode("utf-8")) > MAX_HEADER_VALUE
        ):
            raise ProtocolError("application header is invalid")
        if normalized in result:
            raise ProtocolError("application header is duplicated")
        result[normalized] = value
    return result


def encode_application_request(request: ApplicationRequest) -> bytes:
    if not isinstance(request, ApplicationRequest):
        raise ProtocolError("application request is invalid")
    method = request.method.upper() if isinstance(request.method, str) else ""
    if method not in _METHOD_TO_ID:
        raise ProtocolError("application request method is unsupported")
    if (
        not isinstance(request.path, str)
        or not request.path.startswith("/")
        or request.path.startswith("//")
        or len(request.path) > MAX_PATH_LENGTH
        or "\r" in request.path
        or "\n" in request.path
        or "#" in request.path
    ):
        raise ProtocolError("application request path is invalid")
    try:
        request.path.encode("ascii")
    except UnicodeEncodeError as error:
        raise ProtocolError("application request path must be percent-encoded ASCII") from error
    if not isinstance(request.body, bytes) or len(request.body) > MAX_HTTP_BODY:
        raise ProtocolError("application request body exceeds its limit")
    if method in {"GET", "HEAD"} and request.body:
        raise ProtocolError("GET and HEAD application requests cannot carry a body")
    headers = _validate_headers(request.headers)
    writer = (
        BinaryWriter(MAX_APPLICATION_MESSAGE)
        .u8(APPLICATION_VERSION)
        .u8(_METHOD_TO_ID[method])
        .text_u16(request.path, MAX_PATH_LENGTH)
        .u8(len(headers))
    )
    for name, value in sorted(headers.items()):
        writer.text_u16(name, MAX_HEADER_NAME).text_u16(value, MAX_HEADER_VALUE)
    writer.bytes_u32(request.body, MAX_HTTP_BODY)
    return writer.build()


def decode_application_request(content: bytes) -> ApplicationRequest:
    reader = BinaryReader(content, MAX_APPLICATION_MESSAGE)
    if reader.u8() != APPLICATION_VERSION:
        raise ProtocolError("application request version is unsupported")
    method_id = reader.u8()
    if method_id not in _ID_TO_METHOD:
        raise ProtocolError("application request method is unknown")
    path = reader.text_u16(MAX_PATH_LENGTH)
    count = reader.u8()
    if count > MAX_APPLICATION_HEADERS:
        raise ProtocolError("application header count is invalid")
    headers: dict[str, str] = {}
    for _ in range(count):
        name = reader.text_u16(MAX_HEADER_NAME)
        value = reader.text_u16(MAX_HEADER_VALUE)
        if name in headers:
            raise ProtocolError("application header is duplicated")
        headers[name] = value
    body = reader.bytes_u32(MAX_HTTP_BODY)
    reader.finish()
    result = ApplicationRequest(_ID_TO_METHOD[method_id], path, _validate_headers(headers), body)
    encode_application_request(result)
    return result


def encode_application_response(response: HttpResult) -> bytes:
    if not isinstance(response, HttpResult):
        raise ProtocolError("application response is invalid")
    if (
        isinstance(response.status, bool)
        or not isinstance(response.status, int)
        or not 100 <= response.status <= 599
        or not isinstance(response.reason, str)
        or len(response.reason.encode("utf-8")) > 256
        or "\r" in response.reason
        or "\n" in response.reason
        or not isinstance(response.body, bytes)
        or len(response.body) > MAX_HTTP_BODY
    ):
        raise ProtocolError("application response fields are invalid")
    headers = _validate_headers(response.headers)
    writer = (
        BinaryWriter(MAX_APPLICATION_MESSAGE)
        .u8(APPLICATION_VERSION)
        .u16(response.status)
        .text_u16(response.reason, 256)
        .u8(len(headers))
    )
    for name, value in sorted(headers.items()):
        writer.text_u16(name, MAX_HEADER_NAME).text_u16(value, MAX_HEADER_VALUE)
    writer.bytes_u32(response.body, MAX_HTTP_BODY)
    return writer.build()


def decode_application_response(content: bytes) -> HttpResult:
    reader = BinaryReader(content, MAX_APPLICATION_MESSAGE)
    if reader.u8() != APPLICATION_VERSION:
        raise ProtocolError("application response version is unsupported")
    status = reader.u16()
    reason = reader.text_u16(256)
    count = reader.u8()
    if count > MAX_APPLICATION_HEADERS:
        raise ProtocolError("application response header count is invalid")
    headers: dict[str, str] = {}
    for _ in range(count):
        name = reader.text_u16(MAX_HEADER_NAME)
        value = reader.text_u16(MAX_HEADER_VALUE)
        if name in headers:
            raise ProtocolError("application response header is duplicated")
        headers[name] = value
    body = reader.bytes_u32(MAX_HTTP_BODY)
    reader.finish()
    result = HttpResult(status, reason, _validate_headers(headers), body)
    encode_application_response(result)
    return result


def _send_message(stream: MuxStream, content: bytes) -> None:
    if not isinstance(content, bytes) or len(content) > MAX_APPLICATION_MESSAGE:
        raise ProtocolError("application message exceeds its size limit")
    stream.sendall(struct.pack("!I", len(content)) + content)


def _receive_exact(stream: MuxStream, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise ProtocolError("application stream closed before its message completed")
        result.extend(chunk)
    return bytes(result)


def _receive_message(stream: MuxStream) -> bytes:
    size = struct.unpack("!I", _receive_exact(stream, 4))[0]
    if size > MAX_APPLICATION_MESSAGE:
        raise ProtocolError("application message length exceeds its limit")
    return _receive_exact(stream, size)


class WanApplicationClient:
    def __init__(self, multiplexer: CellMultiplexer, *, timeout: float = 10.0) -> None:
        self.multiplexer = multiplexer
        self.timeout = timeout

    def fetch(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResult:
        stream = self.multiplexer.open_stream(self.timeout)
        try:
            _send_message(
                stream,
                encode_application_request(
                    ApplicationRequest(method, path, dict(headers or {}), body)
                ),
            )
            return decode_application_response(_receive_message(stream))
        finally:
            stream.close()


class WanApplicationServer:
    def __init__(
        self,
        multiplexer: CellMultiplexer,
        bridge: object,
        *,
        max_concurrent_streams: int = 32,
        timeout: float = 10.0,
    ) -> None:
        if not 1 <= max_concurrent_streams <= 1024:
            raise ResourceLimitError("application stream limit is invalid")
        self.multiplexer = multiplexer
        self.bridge = bridge
        self.timeout = timeout
        self._session_identity = "gs_" + secrets.token_urlsafe(18)
        self._slots = threading.BoundedSemaphore(max_concurrent_streams)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._lock = threading.Lock()
        self.errors: list[str] = []

    def start_background(self) -> None:
        if self._thread is not None:
            raise RuntimeError("WAN application server is already running")
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                stream = self.multiplexer.accept_stream(0.25)
            except TimeoutError:
                continue
            except ProtocolError:
                if self._stop.is_set() or self.multiplexer.failed:
                    break
                raise
            if not self._slots.acquire(blocking=False):
                stream.reset()
                continue
            worker = threading.Thread(
                target=self._serve_stream,
                args=(stream,),
                name="granger-wan-application",
                daemon=True,
            )
            with self._lock:
                self._workers.add(worker)
            worker.start()

    def _serve_stream(self, stream: MuxStream) -> None:
        try:
            stream.settimeout(self.timeout)
            request = decode_application_request(_receive_message(stream))
            response = self.bridge.fetch(
                request.method,
                request.path,
                request.headers,
                request.body,
                session_identity=self._session_identity,
            )
            _send_message(stream, encode_application_response(response))
        except (GrangerNetworkError, OSError, TimeoutError) as error:
            with self._lock:
                if len(self.errors) < 1024:
                    self.errors.append(type(error).__name__)
            stream.reset()
        finally:
            stream.close()
            self._slots.release()
            with self._lock:
                self._workers.discard(threading.current_thread())

    def stop(self) -> None:
        self._stop.set()
        self.multiplexer.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
            self._thread = None
        with self._lock:
            workers = tuple(self._workers)
        for worker in workers:
            worker.join(timeout=2.0)
