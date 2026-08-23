from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ._codec import atomic_write_text
from .address import normalize_name
from .descriptor import ServiceDescriptor
from .errors import GrangerNetworkError
from .http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from .identity import ServiceIdentity
from .resolver import LocalResolver
from .service import GrangerServiceHost
from .transport import LoopbackEndpoint


IDENTITY_FILENAME = "service.key"
DESCRIPTOR_FILENAME = "service.json"


def initialize_service(
    state_dir: Path,
    endpoint: LoopbackEndpoint,
    registry: Path | None = None,
    alias: str | None = None,
) -> ServiceDescriptor:
    state_dir = Path(state_dir)
    identity_path = state_dir / IDENTITY_FILENAME
    descriptor_path = state_dir / DESCRIPTOR_FILENAME
    if identity_path.exists() or descriptor_path.exists():
        raise FileExistsError(f"service state already exists: {state_dir}")
    if alias is not None and registry is None:
        raise ValueError("--alias requires --registry")
    if alias is not None:
        normalize_name(alias)

    identity = ServiceIdentity.generate()
    descriptor = ServiceDescriptor.create(identity, endpoint)
    identity.save(identity_path)
    atomic_write_text(descriptor_path, descriptor.to_json(), mode=0o644)
    if registry is not None:
        LocalResolver(registry).import_descriptor(descriptor, alias)
    return descriptor


def load_service(state_dir: Path) -> tuple[ServiceIdentity, ServiceDescriptor]:
    state_dir = Path(state_dir)
    identity = ServiceIdentity.load(state_dir / IDENTITY_FILENAME)
    descriptor = ServiceDescriptor.from_json(
        (state_dir / DESCRIPTOR_FILENAME).read_text(encoding="utf-8")
    )
    if descriptor.identity_public_key != identity.public_key_bytes:
        raise ValueError("service identity does not match service.json")
    return identity, descriptor


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network v0.1 service host")
    subcommands = parser.add_subparsers(dest="command", required=True)

    initialize = subcommands.add_parser("init", help="create a service identity and descriptor")
    initialize.add_argument("--state-dir", type=Path, required=True)
    initialize.add_argument("--listen-host", default="127.0.0.1")
    initialize.add_argument("--listen-port", type=int, default=7777)
    initialize.add_argument("--registry", type=Path)
    initialize.add_argument("--alias")

    serve = subcommands.add_parser("serve", help="serve a loopback HTTP application")
    serve.add_argument("--state-dir", type=Path, required=True)
    serve.add_argument("--upstream", default="http://127.0.0.1:8080")
    serve.add_argument("--timeout", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "init":
            descriptor = initialize_service(
                options.state_dir,
                LoopbackEndpoint(options.listen_host, options.listen_port),
                options.registry,
                options.alias,
            )
            print(descriptor.canonical_name)
            print(f"descriptor: {options.state_dir / DESCRIPTOR_FILENAME}")
            return 0

        identity, descriptor = load_service(options.state_dir)
        bridge = LoopbackHttpBridge(
            LoopbackHttpTarget.parse(options.upstream),
            timeout=options.timeout,
        )
        service = GrangerServiceHost(
            identity,
            descriptor,
            bridge,
            connection_timeout=options.timeout,
        )
        print(f"serving {descriptor.canonical_name}")
        print(f"transport: {descriptor.endpoint.host}:{descriptor.endpoint.port}")
        print(f"upstream: {options.upstream}")
        try:
            service.serve_forever()
        except KeyboardInterrupt:
            return 0
        finally:
            service.stop()
    except (GrangerNetworkError, OSError, ValueError) as error:
        print(f"granger-host: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
