from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from ._codec import atomic_write_text
from .descriptor import ServiceDescriptor
from .errors import GrangerNetworkError, NetworkUnavailableError, OverlayRoutingError
from .http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from .identity import ServiceIdentity
from .introduction import IntroductionDescriptor
from .wan_config import load_discovery_runtime
from .wan_routing import WanRouteSelector, select_service_route_set
from .wan_service import WanServiceHost


SERVICE_IDENTITY_FILE = "service-identity.json"
SERVICE_DESCRIPTOR_FILE = "service-descriptor.json"
INTRODUCTION_DESCRIPTOR_FILE = "introduction-descriptor.json"
INTRODUCTION_SEQUENCE_FILE = "introduction-sequence.txt"


def initialize_service(state_dir: Path, *, title: str = "Granger service") -> ServiceDescriptor:
    root = Path(state_dir)
    root.mkdir(parents=True, exist_ok=True)
    identity_path = root / SERVICE_IDENTITY_FILE
    if identity_path.exists():
        raise FileExistsError(f"service state already exists: {root}")
    identity = ServiceIdentity.generate()
    identity.save(identity_path)
    descriptor = ServiceDescriptor.create_remote(
        identity,
        "distributed-overlay",
        metadata={"contentType": "text/html", "title": title},
        lifetime=24 * 60 * 60,
    )
    atomic_write_text(root / SERVICE_DESCRIPTOR_FILE, descriptor.to_json(), mode=0o644)
    atomic_write_text(root / INTRODUCTION_SEQUENCE_FILE, "0\n", mode=0o600)
    return descriptor


def _next_sequence(path: Path) -> int:
    try:
        previous = int(path.read_text(encoding="ascii").strip()) if path.exists() else 0
    except (OSError, ValueError) as error:
        raise ValueError(f"introduction sequence state is invalid: {error}") from error
    if not 0 <= previous < 2**64 - 1:
        raise ValueError("introduction sequence is exhausted")
    current = previous + 1
    atomic_write_text(path, f"{current}\n", mode=0o600)
    return current


def _target(service_id: str, purpose: bytes) -> bytes:
    return hashlib.sha256(
        b"granger-network-v0.4/host-selection\x00"
        + purpose
        + b"\x00"
        + service_id.encode("ascii")
    ).digest()


def run_host(options: argparse.Namespace) -> int:
    root = options.state_dir
    if options.minimum_introduction_points > options.introduction_points:
        raise ValueError("minimum introduction points exceed the requested count")
    if not 60 <= options.refresh_margin < options.introduction_lifetime:
        raise ValueError("introduction refresh margin is invalid")
    if not 3600 <= options.service_lifetime <= 7 * 24 * 60 * 60:
        raise ValueError("service descriptor lifetime is invalid")
    if not 300 <= options.service_refresh_margin < options.service_lifetime:
        raise ValueError("service descriptor refresh margin is invalid")
    identity = ServiceIdentity.load(root / SERVICE_IDENTITY_FILE)
    service = ServiceDescriptor.from_json_for_owner_refresh(
        (root / SERVICE_DESCRIPTOR_FILE).read_text(encoding="utf-8"),
        identity,
    )
    runtime = load_discovery_runtime(
        options.bootstrap,
        options.authority_pin,
        root / "peer-cache.json",
        root / "network-identity.json",
        timeout=options.timeout,
        replication_factor=options.replication_factor,
        minimum_replicas=options.minimum_replicas,
    )
    selector = WanRouteSelector(
        runtime.discovery,
        guard_seed=runtime.identity.public_key_bytes,
    )
    bridge = LoopbackHttpBridge(LoopbackHttpTarget.parse(options.upstream))
    generation = 0
    recovery_cycles = 0
    while True:
        if options.ready_file is not None:
            options.ready_file.unlink(missing_ok=True)
        now = int(time.time())
        assert service.expires_at is not None
        if service.expires_at - now <= options.service_refresh_margin:
            service = ServiceDescriptor.create_remote(
                identity,
                "distributed-overlay",
                metadata=service.metadata,
                lifetime=options.service_lifetime,
            )
            atomic_write_text(
                root / SERVICE_DESCRIPTOR_FILE,
                service.to_json(),
                mode=0o644,
            )
        host: WanServiceHost | None = None
        intro_routes = None
        rendezvous_route = None
        startup_failures: list[str] = []
        middle_exclusions: set[str] = set()
        try:
            introductions = runtime.discovery.route_candidates(
                _target(service.service_id, b"introduction"), "introduction",
            )
            rendezvous_nodes = runtime.discovery.route_candidates(
                _target(service.service_id, b"rendezvous"), "rendezvous",
            )
            selected_introductions = introductions[: options.introduction_points]
            if (
                len(selected_introductions) < options.minimum_introduction_points
                or not rendezvous_nodes
            ):
                raise NetworkUnavailableError(
                    "introduction or rendezvous infrastructure is unavailable"
                )
            introduction_node_ids = {node.node_id for node in selected_introductions}
            rendezvous_node = next(
                (node for node in rendezvous_nodes if node.node_id not in introduction_node_ids),
                None,
            )
            if rendezvous_node is None:
                raise NetworkUnavailableError("no independent rendezvous node is available")
            introduction = IntroductionDescriptor.create(
                identity, service, [node.node_id for node in selected_introductions],
                sequence=_next_sequence(root / INTRODUCTION_SEQUENCE_FILE),
                lifetime=options.introduction_lifetime,
            )
            atomic_write_text(
                root / INTRODUCTION_DESCRIPTOR_FILE, introduction.to_json(), mode=0o644,
            )
            runtime.discovery.publish(service)
            for attempt in range(options.startup_attempts):
                candidate: WanServiceHost | None = None
                try:
                    intro_routes, rendezvous_route, reused_required_route = (
                        select_service_route_set(
                            selector,
                            service.service_id,
                            selected_introductions,
                            rendezvous_node,
                            failed_middle_ids=middle_exclusions,
                        )
                    )
                    if reused_required_route:
                        middle_exclusions.clear()
                    candidate = WanServiceHost(
                        identity,
                        service,
                        introduction,
                        tuple(route.route for route in intro_routes),
                        rendezvous_route.route,
                        bridge,
                        timeout=options.timeout,
                        rendezvous_lifetime=options.rendezvous_lifetime,
                    )
                    candidate.start_background()
                    candidate.wait_ready(options.startup_timeout)
                    host = candidate
                    break
                except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                    startup_failures.append(f"{type(error).__name__}:{error}")
                    if candidate is not None:
                        middle_exclusions.update(candidate.startup_failed_middle_ids)
                        candidate.stop()
                    if attempt + 1 < options.startup_attempts:
                        time.sleep(min(1.0, 0.2 * (attempt + 1)))
            if host is None or intro_routes is None or rendezvous_route is None:
                if generation == 0:
                    raise OverlayRoutingError(
                        "service private-route startup attempts were exhausted: "
                        + ";".join(startup_failures)
                    )
                recovery_cycles += 1
                time.sleep(min(2.0, 0.25 * recovery_cycles))
                continue
            runtime.discovery.publish(introduction)
            recovery_cycles = 0
            generation += 1
            if options.ready_file is not None:
                atomic_write_text(
                    options.ready_file,
                    json.dumps(
                        {
                            "canonicalName": service.canonical_name,
                            "generation": generation,
                            "introductionExpiresAt": introduction.expires_at,
                            "introductionNodeId": selected_introductions[0].node_id,
                            "introductionNodeIds": [
                                node.node_id for node in selected_introductions
                            ],
                            "introductionRoute": [
                                node.node_id for node, _role in intro_routes[0].route
                            ],
                            "introductionRoutes": [
                                [node.node_id for node, _role in route.route]
                                for route in intro_routes
                            ],
                            "pid": os.getpid(),
                            "rendezvousNodeId": rendezvous_node.node_id,
                            "rendezvousRoute": [
                                node.node_id for node, _role in rendezvous_route.route
                            ],
                            "version": 1,
                        },
                        ensure_ascii=True,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    mode=0o644,
                )
            refresh_at = introduction.expires_at - options.refresh_margin
            while not host.wait(0.25):
                if int(time.time()) >= refresh_at:
                    break
            if host.recovery_requested:
                recovery_cycles += 1
                print(
                    f"granger-wan-host: route recovery requested: {host.recovery_reason}",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(min(2.0, 0.25 * recovery_cycles))
            elif host.wait(0):
                if host.errors:
                    raise RuntimeError(host.errors[0])
                raise RuntimeError("service host stopped before descriptor refresh")
        except NetworkUnavailableError:
            if generation == 0:
                raise
            if host is not None:
                host.stop()
                host = None
            # Discovery loss must not terminate an already published service.
            # Rebuilding remains gated by the unchanged authenticated quorum.
            recovery_cycles += 1
            time.sleep(min(30.0, 2.0 * recovery_cycles))
        finally:
            if host is not None:
                host.stop()
            if options.ready_file is not None:
                options.ready_file.unlink(missing_ok=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network WAN service host")
    subcommands = parser.add_subparsers(dest="command", required=True)
    initialize = subcommands.add_parser("init")
    initialize.add_argument("--state-dir", type=Path, required=True)
    initialize.add_argument("--title", default="Granger service")

    serve = subcommands.add_parser("serve")
    serve.add_argument("--state-dir", type=Path, required=True)
    serve.add_argument("--bootstrap", type=Path, required=True)
    serve.add_argument("--authority-pin", type=Path, required=True)
    serve.add_argument("--upstream", required=True)
    serve.add_argument("--ready-file", type=Path)
    serve.add_argument("--timeout", type=float, default=8.0)
    serve.add_argument("--rendezvous-lifetime", type=int, default=600)
    serve.add_argument("--introduction-lifetime", type=int, default=15 * 60)
    serve.add_argument("--refresh-margin", type=int, default=2 * 60)
    serve.add_argument("--service-lifetime", type=int, default=24 * 60 * 60)
    serve.add_argument("--service-refresh-margin", type=int, default=60 * 60)
    serve.add_argument("--introduction-points", type=int, choices=range(1, 9), default=2)
    serve.add_argument(
        "--minimum-introduction-points",
        type=int,
        choices=range(1, 9),
        default=2,
    )
    serve.add_argument("--replication-factor", type=int, choices=range(2, 9), default=3)
    serve.add_argument("--minimum-replicas", type=int, choices=range(2, 9), default=2)
    serve.add_argument("--startup-attempts", type=int, choices=range(1, 9), default=4)
    serve.add_argument("--startup-timeout", type=float, default=15.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    from .network_audit import install_from_environment

    install_from_environment("service")
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "init":
            descriptor = initialize_service(options.state_dir, title=options.title)
            print(descriptor.canonical_name)
            return 0
        return run_host(options)
    except KeyboardInterrupt:
        return 130
    except (GrangerNetworkError, OSError, RuntimeError, ValueError) as error:
        print(f"granger-wan-host: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
