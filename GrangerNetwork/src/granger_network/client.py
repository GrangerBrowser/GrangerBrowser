from __future__ import annotations

import argparse
import base64
import binascii
import sys
from dataclasses import dataclass
from pathlib import Path

from .descriptor import ServiceDescriptor
from .errors import GrangerNetworkError, ProtocolError
from .protocol import client_handshake
from .resolver import LocalResolver
from .transport import ClientTransport, LoopbackTcpTransport


@dataclass(frozen=True)
class GrangerResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    canonical_service: str


class GrangerClient:
    def __init__(
        self,
        resolver: LocalResolver,
        transport: ClientTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.resolver = resolver
        self.transport = transport or LoopbackTcpTransport()
        self.timeout = timeout

    def fetch(self, name: str, path: str = "/") -> GrangerResponse:
        descriptor = self.resolver.resolve(name)
        return self.fetch_descriptor(descriptor, path)

    def fetch_descriptor(self, descriptor: ServiceDescriptor, path: str = "/") -> GrangerResponse:
        descriptor.verify()
        connection = self.transport.connect(descriptor.endpoint, self.timeout)
        try:
            connection.settimeout(self.timeout)
            channel = client_handshake(connection, descriptor.identity_public_key)
            channel.send_json(
                {
                    "headers": {"accept": "text/html,application/xhtml+xml"},
                    "method": "GET",
                    "path": path,
                    "type": "request",
                }
            )
            response = channel.receive_json()
            if response.get("type") == "error":
                raise ProtocolError(f"service rejected the request: {response.get('code', 'UNKNOWN')}")
            if set(response) != {"body", "headers", "reason", "status", "type"}:
                raise ProtocolError("service returned an unexpected response object")
            if response["type"] != "response" or not isinstance(response["headers"], dict):
                raise ProtocolError("service returned an invalid response")
            if (
                isinstance(response["status"], bool)
                or not isinstance(response["status"], int)
                or not 100 <= response["status"] <= 599
            ):
                raise ProtocolError("service returned an invalid HTTP status")
            if not isinstance(response["reason"], str) or not isinstance(response["body"], str):
                raise ProtocolError("service returned invalid response text")
            if not all(
                isinstance(name, str) and isinstance(value, str)
                for name, value in response["headers"].items()
            ):
                raise ProtocolError("service returned invalid response headers")
            try:
                body = base64.b64decode(response["body"], validate=True)
            except (binascii.Error, TypeError, ValueError) as error:
                raise ProtocolError("service returned an invalid response body") from error
            return GrangerResponse(
                status=response["status"],
                reason=response["reason"],
                headers=response["headers"],
                body=body,
                canonical_service=descriptor.canonical_name,
            )
        finally:
            connection.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network v0.1 client")
    subcommands = parser.add_subparsers(dest="command", required=True)

    register = subcommands.add_parser("register", help="import a signed service descriptor")
    register.add_argument("--registry", type=Path, required=True)
    register.add_argument("--descriptor", type=Path, required=True)
    register.add_argument("--alias")

    fetch = subcommands.add_parser("fetch", help="fetch a page from the local .granger namespace")
    fetch.add_argument("name")
    fetch.add_argument("--registry", type=Path, required=True)
    fetch.add_argument("--path", default="/")
    fetch.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    options = parser.parse_args(argv)
    try:
        resolver = LocalResolver(options.registry)
        if options.command == "register":
            descriptor = ServiceDescriptor.from_json(options.descriptor.read_text(encoding="utf-8"))
            resolver.import_descriptor(descriptor, options.alias)
            print(descriptor.canonical_name)
            return 0
        client = GrangerClient(resolver)
        result = client.fetch(options.name, options.path)
        if options.output:
            options.output.write_bytes(result.body)
        else:
            sys.stdout.buffer.write(result.body)
        print(
            f"\n[{result.status} {result.reason}] {result.canonical_service}",
            file=sys.stderr,
        )
        return 0
    except (GrangerNetworkError, OSError) as error:
        print(f"granger-client: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
