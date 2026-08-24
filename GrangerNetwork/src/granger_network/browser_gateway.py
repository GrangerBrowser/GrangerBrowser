from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import socket
import sys
from pathlib import Path

from ._codec import parse_json_object
from .address import normalize_name
from .client import GrangerClient
from .descriptor import ServiceDescriptor
from .errors import (
    DescriptorError,
    GrangerNetworkError,
    IdentityVerificationError,
    ProtocolError,
    RendezvousError,
    ReplayError,
    ResolutionError,
)
from .http_bridge import HttpResult
from .identity import ServiceIdentity
from .resolver import LocalResolver
from .service import GrangerServiceHost
from .transport import LoopbackEndpoint


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 32 * 1024
MAX_PATH_LENGTH = 4096
MAX_HEADER_VALUE = 1024
MAX_RESPONSE_BODY = 2 * 1024 * 1024
_REQUEST_ID = re.compile(r"^[a-f0-9]{32}$")
_ALLOWED_REQUEST_HEADERS = {"accept", "accept-language", "user-agent"}
_dns_request_count = 0


class _LocalDemoBridge:
    def __init__(self, canonical_name: str) -> None:
        self.canonical_name = canonical_name

    def fetch(
        self,
        method: str,
        path: str,
        _headers: dict[str, str] | None = None,
    ) -> HttpResult:
        body = (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>Granger Network</title></head><body>"
            "<main><h1>test.granger works</h1>"
            "<p>Authenticated encrypted local Granger Network service.</p>"
            f"<code id=\"canonical\">{self.canonical_name}</code>"
            f"<p id=\"path\">{html.escape(path)}</p></main></body></html>"
        ).encode("utf-8")
        if method.upper() == "HEAD":
            body = b""
        return HttpResult(
            200,
            "OK",
            {
                "cache-control": "no-store",
                "content-type": "text/html; charset=utf-8",
            },
            body,
        )


class _LocalDemoResolver:
    def __init__(self, registry: Path, descriptor: ServiceDescriptor) -> None:
        self._persistent = LocalResolver(registry)
        self._descriptor = descriptor

    def resolve(self, name: str) -> ServiceDescriptor:
        normalized = normalize_name(name)
        if normalized in {"test.granger", self._descriptor.canonical_name}:
            return self._descriptor
        return self._persistent.resolve(normalized)

    def resolve_rendezvous(self, rendezvous_id: str):
        return self._persistent.resolve_rendezvous(rendezvous_id)


class _ReservedLoopbackTransport:
    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(32)
            self._listener.settimeout(0.25)
        except Exception:
            self._listener.close()
            raise
        self.endpoint = LoopbackEndpoint(
            "127.0.0.1", int(self._listener.getsockname()[1])
        )
        self._claimed = False

    def listen(self, endpoint: LoopbackEndpoint, _backlog: int = 32) -> socket.socket:
        if self._claimed or endpoint != self.endpoint:
            raise OSError("reserved local demo listener is unavailable")
        self._claimed = True
        return self._listener


class _LocalDemo:
    def __init__(self, registry: Path) -> None:
        transport = _ReservedLoopbackTransport()
        identity = ServiceIdentity.generate()
        self.descriptor = ServiceDescriptor.create(identity, transport.endpoint)
        self.resolver = _LocalDemoResolver(registry, self.descriptor)
        self.host = GrangerServiceHost(
            identity,
            self.descriptor,
            _LocalDemoBridge(self.descriptor.canonical_name),
            transport=transport,
        )

    def start(self) -> None:
        self.host.start_background()

    def stop(self) -> None:
        self.host.stop()


def _deny_dns(*_args: object, **_kwargs: object) -> object:
    global _dns_request_count
    _dns_request_count += 1
    raise OSError("DNS is disabled for the Granger Network browser gateway")


def install_dns_guard() -> None:
    socket.getaddrinfo = _deny_dns
    socket.gethostbyname = _deny_dns
    socket.gethostbyname_ex = _deny_dns


def _safe_request_id(document: object) -> str:
    if isinstance(document, dict):
        value = document.get("requestId")
        if isinstance(value, str) and _REQUEST_ID.fullmatch(value):
            return value
    return ""


def _validate_path(path: object) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or len(path) > MAX_PATH_LENGTH
        or "#" in path
        or "\r" in path
        or "\n" in path
    ):
        raise ValueError("request path is invalid")
    try:
        encoded = path.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("request path must be percent-encoded ASCII") from error
    if any(byte <= 0x20 or byte == 0x7F for byte in encoded):
        raise ValueError("request path contains an unsafe character")
    return path


def _validate_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict) or len(headers) > 16:
        raise ValueError("request headers are invalid")
    result: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("request headers must contain text")
        normalized = name.lower()
        if normalized not in _ALLOWED_REQUEST_HEADERS:
            continue
        if "\r" in value or "\n" in value or len(value) > MAX_HEADER_VALUE:
            raise ValueError("request header value is invalid")
        result[normalized] = value
    return result


def parse_request(content: bytes) -> dict[str, object]:
    if not content or len(content) > MAX_MESSAGE_BYTES:
        raise ValueError("gateway request exceeds the message limit")
    try:
        document = parse_json_object(content.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ValueError("gateway request is not UTF-8") from error
    expected = {"headers", "method", "name", "path", "requestId", "type", "version"}
    if set(document) != expected:
        raise ValueError("gateway request fields are invalid")
    if document["type"] != "fetch" or document["version"] != PROTOCOL_VERSION:
        raise ValueError("gateway request version is unsupported")
    request_id = document["requestId"]
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("gateway request identifier is invalid")
    method = document["method"]
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
        raise ValueError("gateway permits only GET and HEAD")
    try:
        name = normalize_name(document["name"])
    except GrangerNetworkError as error:
        raise ValueError("gateway destination is not a valid .granger name") from error
    return {
        "headers": _validate_headers(document["headers"]),
        "method": method.upper(),
        "name": name,
        "path": _validate_path(document["path"]),
        "requestId": request_id,
    }


def _error_code(error: BaseException) -> str:
    if isinstance(error, ResolutionError):
        return "SERVICE_NOT_FOUND"
    if isinstance(error, (DescriptorError, IdentityVerificationError)):
        return "IDENTITY_VERIFICATION_FAILED"
    if isinstance(error, ReplayError):
        return "REPLAY_REJECTED"
    if isinstance(error, RendezvousError):
        return "NETWORK_UNAVAILABLE"
    if isinstance(error, ProtocolError):
        return "CONNECTION_FAILED"
    if isinstance(error, OSError):
        return "NETWORK_UNAVAILABLE"
    return "REQUEST_REJECTED"


def handle_request(resolver: LocalResolver, timeout: float, content: bytes) -> dict[str, object]:
    request_id = ""
    try:
        document = parse_json_object(content.decode("utf-8"))
        request_id = _safe_request_id(document)
        request = parse_request(content)
        request_id = str(request["requestId"])
        response = GrangerClient(resolver, timeout=timeout).fetch(
            str(request["name"]),
            str(request["path"]),
            method=str(request["method"]),
            headers=request["headers"],
        )
        if len(response.body) > MAX_RESPONSE_BODY:
            raise ProtocolError("service response exceeds the browser gateway limit")
        return {
            "body": base64.b64encode(response.body).decode("ascii"),
            "canonicalService": response.canonical_service,
            "dnsRequests": _dns_request_count,
            "headers": response.headers,
            "ok": True,
            "reason": response.reason,
            "requestId": request_id,
            "status": response.status,
            "type": "response",
            "version": PROTOCOL_VERSION,
        }
    except (GrangerNetworkError, OSError, TypeError, ValueError) as error:
        return {
            "code": _error_code(error),
            "dnsRequests": _dns_request_count,
            "ok": False,
            "requestId": request_id,
            "type": "response",
            "version": PROTOCOL_VERSION,
        }


def _write(document: dict[str, object]) -> None:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def serve(registry: Path, timeout: float, local_demo: bool = False) -> int:
    demo = _LocalDemo(registry) if local_demo else None
    resolver = demo.resolver if demo is not None else LocalResolver(registry)
    if demo is not None:
        demo.start()
    try:
        install_dns_guard()
        ready: dict[str, object] = {
            "localDemo": demo is not None,
            "pid": os.getpid(),
            "type": "ready",
            "version": PROTOCOL_VERSION,
        }
        if demo is not None:
            ready["localDemoCanonical"] = demo.descriptor.canonical_name
        _write(ready)
        while True:
            content = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 2)
            if not content:
                return 0
            if len(content) > MAX_MESSAGE_BYTES + 1 or not content.endswith(b"\n"):
                _write(
                    {
                        "code": "REQUEST_REJECTED",
                        "ok": False,
                        "requestId": "",
                        "type": "response",
                        "version": PROTOCOL_VERSION,
                    }
                )
                return 2
            _write(handle_request(resolver, timeout, content[:-1]))
    finally:
        if demo is not None:
            demo.stop()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Browser private stdio gateway")
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--local-demo", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    if not 0.5 <= options.timeout <= 30.0:
        print("granger-browser-gateway: timeout is outside the allowed range", file=sys.stderr)
        return 2
    try:
        return serve(options.registry, options.timeout, options.local_demo)
    except (OSError, ValueError) as error:
        print(f"granger-browser-gateway: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
