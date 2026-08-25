from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .descriptor import ServiceDescriptor
from ._codec import atomic_write_text
from .errors import GrangerNetworkError, OverlayRoutingError
from .peer import NodeDescriptor
from .wan_config import WanDiscoveryRuntime
from .wan_config import load_discovery_runtime
from .wan_discovery import WanDistributedResolver
from .wan_routing import WanRouteSelection, WanRouteSelector
from .wan_service import WanServiceClient, WanServiceSession


@dataclass(frozen=True)
class WanClientConnection:
    service: ServiceDescriptor
    session: WanServiceSession
    route: WanRouteSelection
    introduction_node: NodeDescriptor
    attempts: int


def connect_service(
    runtime: WanDiscoveryRuntime,
    resolver: WanDistributedResolver,
    name: str,
    *,
    excluded_ids: set[str] | None = None,
    route_attempts: int = 3,
    timeout: float = 8.0,
) -> WanClientConnection:
    if not 1 <= route_attempts <= 8:
        raise ValueError("WAN route attempt count is invalid")
    service = resolver.resolve(name)
    introduction = resolver.resolve_introduction(service)
    selector = WanRouteSelector(runtime.discovery)
    failures: list[str] = []
    attempts = 0
    introduction_nodes = []
    for point in introduction.points:
        try:
            introduction_nodes.append(resolver.resolve_node(point.node_id))
        except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
            failures.append(type(error).__name__)
    for introduction_node in introduction_nodes:
        try:
            candidates = selector.client_candidates(
                service.service_id,
                excluded_ids=set(excluded_ids or ()) | {introduction_node.node_id},
                limit=route_attempts,
            )
        except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
            failures.append(type(error).__name__)
            continue
        for prefix in candidates:
            if attempts >= route_attempts:
                break
            attempts += 1
            client = WanServiceClient(
                runtime.identity,
                service,
                introduction,
                prefix.route,
                timeout=timeout,
            )
            try:
                return WanClientConnection(
                    service,
                    client.connect(introduction_node),
                    prefix,
                    introduction_node,
                    attempts,
                )
            except (GrangerNetworkError, OSError, TimeoutError, ValueError) as error:
                failures.append(type(error).__name__)
        if attempts >= route_attempts:
            break
    raise OverlayRoutingError(
        "private route attempts were exhausted without a direct fallback: "
        + ",".join(failures)
    )


def _alias_pins(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("alias pins use alias=service-id format")
        alias, service_id = value.split("=", 1)
        result[alias] = service_id
    return result


def _connect(options: argparse.Namespace):
    state = options.state_dir
    runtime = load_discovery_runtime(
        options.bootstrap,
        options.authority_pin,
        state / "peer-cache.json",
        state / "client-identity.json",
        timeout=options.timeout,
        replication_factor=options.replication_factor,
        minimum_replicas=options.minimum_replicas,
    )
    resolver = WanDistributedResolver(runtime.discovery, _alias_pins(options.alias_pin))
    connected = connect_service(
        runtime,
        resolver,
        options.name,
        excluded_ids=set(options.exclude_node),
        route_attempts=options.route_attempts,
        timeout=options.timeout,
    )
    return connected.service, connected.session, connected.route, connected.attempts


def run_fetch(options: argparse.Namespace) -> int:
    service, session, prefix, route_attempts = _connect(options)
    try:
        body = options.body_file.read_bytes() if options.body_file is not None else b""
        response = session.fetch(
            options.path,
            method=options.method,
            headers={"content-type": options.content_type} if options.content_type else None,
            body=body,
        )
        if options.output is not None:
            options.output.write_bytes(response.body)
        else:
            sys.stdout.buffer.write(response.body)
        print(
            f"\n[{response.status} {response.reason}] {service.canonical_name}",
            file=sys.stderr,
        )
        if options.report is not None:
            atomic_write_text(
                options.report,
                json.dumps(
                    {
                        "canonicalName": service.canonical_name,
                        "clientEntryNodeId": prefix.route[0][0].node_id,
                        "clientMiddleNodeId": prefix.route[1][0].node_id,
                        "diversityRelaxed": prefix.diversity_relaxed,
                        "pid": os.getpid(),
                        "responseBytes": len(response.body),
                        "routeAttempts": route_attempts,
                        "status": response.status,
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o644,
            )
        return 0
    finally:
        session.close()


def run_demo(options: argparse.Namespace) -> int:
    service, session, prefix, route_attempts = _connect(options)
    try:
        page = session.fetch("/")
        style = session.fetch("/style.css")
        script = session.fetch("/script.js")
        posted = session.fetch(
            "/message",
            method="POST",
            headers={"content-type": "text/plain"},
            body=options.message.encode("utf-8"),
        )
        messages = session.fetch("/messages")
        report = {
            "canonicalName": service.canonical_name,
            "clientEntryNodeId": prefix.route[0][0].node_id,
            "clientMiddleNodeId": prefix.route[1][0].node_id,
            "diversityRelaxed": prefix.diversity_relaxed,
            "messagePresent": options.message.encode("utf-8") in messages.body,
            "pageStatus": page.status,
            "pid": os.getpid(),
            "postStatus": posted.status,
            "routeAttempts": route_attempts,
            "scriptStatus": script.status,
            "styleStatus": style.status,
            "version": 1,
        }
        if options.report is not None:
            atomic_write_text(
                options.report,
                json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                mode=0o644,
            )
        else:
            print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
        return 0 if all(
            (
                page.status == 200,
                style.status == 200,
                script.status == 200,
                posted.status in {200, 201, 204},
                report["messagePresent"],
            )
        ) else 2
    finally:
        session.close()


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--authority-pin", type=Path, required=True)
    parser.add_argument("--alias-pin", action="append", default=[])
    parser.add_argument("--exclude-node", action="append", default=[])
    parser.add_argument("--route-attempts", type=int, choices=range(1, 9), default=3)
    parser.add_argument("--replication-factor", type=int, choices=range(2, 9), default=3)
    parser.add_argument("--minimum-replicas", type=int, choices=range(2, 9), default=2)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--report", type=Path)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network WAN client")
    subcommands = parser.add_subparsers(dest="command", required=True)
    fetch = subcommands.add_parser("fetch")
    _common(fetch)
    fetch.add_argument("--path", default="/")
    fetch.add_argument("--method", choices=("GET", "HEAD", "POST"), default="GET")
    fetch.add_argument("--body-file", type=Path)
    fetch.add_argument("--content-type")
    fetch.add_argument("--output", type=Path)

    demo = subcommands.add_parser("demo")
    _common(demo)
    demo.add_argument("--message", default="GRANGER_TEST_MESSAGE_123")
    return parser


def main(argv: list[str] | None = None) -> int:
    from .network_audit import install_from_environment

    install_from_environment("client")
    options = _build_parser().parse_args(argv)
    try:
        return run_demo(options) if options.command == "demo" else run_fetch(options)
    except (GrangerNetworkError, OSError, RuntimeError, ValueError) as error:
        print(f"granger-wan-client: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
