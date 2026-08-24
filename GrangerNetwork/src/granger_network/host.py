from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .address import normalize_name
from .descriptor import ServiceDescriptor
from .errors import GrangerNetworkError
from .http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from .identity import ServiceIdentity
from .resolver import LocalResolver
from .service import GrangerServiceHost, RendezvousServiceHost
from .transport import LoopbackEndpoint, RendezvousEndpoint, RendezvousHostTransport


IDENTITY_FILENAME = "service.key"
DESCRIPTOR_FILENAME = "service.json"
RENDEZVOUS_FILENAME = "rendezvous.json"


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


def initialize_remote_service(
    state_dir: Path,
    rendezvous_id: str,
    rendezvous_endpoint: RendezvousEndpoint,
    registry: Path | None = None,
    alias: str | None = None,
    *,
    metadata: dict[str, str] | None = None,
    lifetime: int = 24 * 60 * 60,
) -> ServiceDescriptor:
    state_dir = Path(state_dir)
    identity_path = state_dir / IDENTITY_FILENAME
    descriptor_path = state_dir / DESCRIPTOR_FILENAME
    rendezvous_path = state_dir / RENDEZVOUS_FILENAME
    if identity_path.exists() or descriptor_path.exists() or rendezvous_path.exists():
        raise FileExistsError(f"service state already exists: {state_dir}")
    if alias is not None and registry is None:
        raise ValueError("--alias requires --registry")
    if alias is not None:
        normalize_name(alias)

    identity = ServiceIdentity.generate()
    descriptor = ServiceDescriptor.create_remote(
        identity,
        rendezvous_id,
        metadata=metadata,
        lifetime=lifetime,
    )
    identity.save(identity_path)
    atomic_write_text(descriptor_path, descriptor.to_json(), mode=0o644)
    atomic_write_text(
        rendezvous_path,
        json.dumps(
            {
                "host": rendezvous_endpoint.host,
                "id": rendezvous_id,
                "port": rendezvous_endpoint.port,
                "version": 1,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        mode=0o600,
    )
    if registry is not None:
        resolver = LocalResolver(registry)
        resolver.import_descriptor(descriptor, alias)
        resolver.configure_rendezvous(rendezvous_id, rendezvous_endpoint)
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


def load_rendezvous(state_dir: Path, descriptor: ServiceDescriptor) -> RendezvousEndpoint:
    if descriptor.rendezvous_id is None:
        raise ValueError("remote descriptor has no rendezvous identifier")
    try:
        document = parse_json_object(
            (Path(state_dir) / RENDEZVOUS_FILENAME).read_text(encoding="utf-8")
        )
        if set(document) != {"host", "id", "port", "version"}:
            raise ValueError("unexpected rendezvous configuration fields")
        if document["version"] != 1 or isinstance(document["version"], bool):
            raise ValueError("unsupported rendezvous configuration version")
        if document["id"] != descriptor.rendezvous_id:
            raise ValueError("rendezvous configuration does not match service descriptor")
        return RendezvousEndpoint(document["host"], document["port"])
    except (OSError, TypeError, ValueError) as error:
        raise ValueError(f"invalid service rendezvous configuration: {error}") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network v0.2 service host")
    subcommands = parser.add_subparsers(dest="command", required=True)

    initialize = subcommands.add_parser("init", help="create a service identity and descriptor")
    initialize.add_argument("--state-dir", type=Path, required=True)
    initialize.add_argument("--listen-host", default="127.0.0.1")
    initialize.add_argument("--listen-port", type=int, default=7777)
    initialize.add_argument("--registry", type=Path)
    initialize.add_argument("--alias")

    initialize_remote = subcommands.add_parser(
        "init-remote",
        help="create an identity and a rendezvous-only descriptor",
    )
    initialize_remote.add_argument("--state-dir", type=Path, required=True)
    initialize_remote.add_argument("--rendezvous-id", required=True)
    initialize_remote.add_argument("--rendezvous-host", required=True)
    initialize_remote.add_argument("--rendezvous-port", type=int, required=True)
    initialize_remote.add_argument("--registry", type=Path)
    initialize_remote.add_argument("--alias")
    initialize_remote.add_argument("--title")
    initialize_remote.add_argument("--lifetime", type=int, default=24 * 60 * 60)

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
        if options.command == "init-remote":
            metadata = {"contentType": "text/html"}
            if options.title:
                metadata["title"] = options.title
            descriptor = initialize_remote_service(
                options.state_dir,
                options.rendezvous_id,
                RendezvousEndpoint(options.rendezvous_host, options.rendezvous_port),
                options.registry,
                options.alias,
                metadata=metadata,
                lifetime=options.lifetime,
            )
            print(descriptor.canonical_name)
            print(f"descriptor: {options.state_dir / DESCRIPTOR_FILENAME}")
            return 0

        identity, descriptor = load_service(options.state_dir)
        bridge = LoopbackHttpBridge(
            LoopbackHttpTarget.parse(options.upstream),
            timeout=options.timeout,
        )
        if descriptor.is_remote:
            rendezvous = load_rendezvous(options.state_dir, descriptor)
            service = RendezvousServiceHost(
                identity,
                descriptor,
                bridge,
                RendezvousHostTransport(rendezvous),
                connection_timeout=options.timeout,
            )
        else:
            service = GrangerServiceHost(
                identity,
                descriptor,
                bridge,
                connection_timeout=options.timeout,
            )
        print(f"serving {descriptor.canonical_name}")
        if descriptor.is_remote:
            print(f"transport: rendezvous {descriptor.rendezvous_id}")
        else:
            assert descriptor.endpoint is not None
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
