from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .bootstrap import BootstrapPool, BootstrapSet
from .errors import DescriptorError, DiscoveryError, GrangerNetworkError
from .identity import ServiceIdentity
from .node import (
    NODE_DESCRIPTOR_FILE,
    NODE_IDENTITY_FILE,
    NodeListenerEndpoint,
    WanNodeServer,
    load_node,
)
from .peer import (
    MAX_NODE_DESCRIPTOR_LIFETIME,
    NODE_CAPABILITIES,
    NODE_NETWORK_ID,
    NODE_PROTOCOL_VERSION,
    RELAY_CAPABILITIES,
    NodeDescriptor,
    RelayPolicy,
)
from .reseed import ReseedStore
from .transport import RendezvousEndpoint
from .wan_config import load_authority_pin
from .wan_discovery import WanDiscoveryClient


OPERATOR_CONFIG_VERSION = 1
MAX_OPERATOR_PATHS = 64
DEFAULT_STATUS_INTERVAL = 30


@dataclass(frozen=True)
class OperatorConfig:
    listen: NodeListenerEndpoint
    advertise: RendezvousEndpoint
    capabilities: tuple[str, ...]
    relay_policy: RelayPolicy
    descriptor_lifetime: int
    renew_before: int
    discovery_interval: int
    peer_descriptors: tuple[Path, ...]
    authority_pins: tuple[Path, ...]
    bootstrap_bundles: tuple[Path, ...]


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the supported range")
    return value


def _endpoint(document: object, label: str, *, listener: bool):
    if not isinstance(document, dict) or set(document) != {"host", "port"}:
        raise ValueError(f"{label} endpoint schema is invalid")
    if listener:
        return NodeListenerEndpoint(document["host"], document["port"])
    return RendezvousEndpoint(document["host"], document["port"])


def _paths(base: Path, values: object, label: str, maximum: int) -> tuple[Path, ...]:
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{label} list is invalid")
    result: list[Path] = []
    for value in values:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(f"{label} path is invalid")
        candidate = Path(value).expanduser()
        result.append((base / candidate).resolve() if not candidate.is_absolute() else candidate.resolve())
    return tuple(result)


def load_operator_config(path: Path) -> OperatorConfig:
    source = Path(path).resolve()
    try:
        document = parse_json_object(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"operator config is unavailable: {error}") from error
    expected = {
        "advertise",
        "bootstrap",
        "capabilities",
        "descriptorLifetimeSeconds",
        "discoveryIntervalSeconds",
        "listen",
        "peerDescriptors",
        "relayPolicy",
        "renewBeforeSeconds",
        "version",
    }
    if set(document) != expected or document["version"] != OPERATOR_CONFIG_VERSION:
        raise ValueError("operator config schema is unsupported")
    capabilities = document["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or any(not isinstance(item, str) for item in capabilities)
    ):
        raise ValueError("operator capabilities are invalid")
    normalized_capabilities = tuple(sorted(set(capabilities)))
    if len(normalized_capabilities) != len(capabilities) or not set(normalized_capabilities) <= NODE_CAPABILITIES:
        raise ValueError("operator capabilities contain duplicates or unknown roles")
    policy = RelayPolicy.from_document(document["relayPolicy"])
    relay_enabled = bool(set(normalized_capabilities) & RELAY_CAPABILITIES)
    if policy.enabled != relay_enabled:
        raise ValueError("operator relay policy does not match its capabilities")
    bootstrap = document["bootstrap"]
    if not isinstance(bootstrap, dict) or set(bootstrap) != {"authorityPins", "bundles"}:
        raise ValueError("operator bootstrap config schema is invalid")
    base = source.parent
    pins = _paths(base, bootstrap["authorityPins"], "bootstrap authority", 8)
    bundles = _paths(base, bootstrap["bundles"], "bootstrap bundle", 64)
    if bool(pins) != bool(bundles):
        raise ValueError("bootstrap bundles and authority pins must be configured together")
    lifetime = _integer(
        document["descriptorLifetimeSeconds"],
        60,
        MAX_NODE_DESCRIPTOR_LIFETIME,
        "descriptor lifetime",
    )
    renew_before = _integer(
        document["renewBeforeSeconds"],
        60,
        lifetime - 1,
        "descriptor renewal window",
    )
    return OperatorConfig(
        listen=_endpoint(document["listen"], "listener", listener=True),
        advertise=_endpoint(document["advertise"], "advertised", listener=False),
        capabilities=normalized_capabilities,
        relay_policy=policy,
        descriptor_lifetime=lifetime,
        renew_before=renew_before,
        discovery_interval=_integer(
            document["discoveryIntervalSeconds"],
            30,
            3600,
            "discovery interval",
        ),
        peer_descriptors=_paths(base, document["peerDescriptors"], "peer descriptor", MAX_OPERATOR_PATHS),
        authority_pins=pins,
        bootstrap_bundles=bundles,
    )


def _parse_endpoint(value: str, *, listener: bool):
    if not isinstance(value, str) or not value:
        raise ValueError("endpoint is empty")
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("endpoint must use numeric HOST:PORT syntax")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port = int(port_text)
    return NodeListenerEndpoint(host, port) if listener else RendezvousEndpoint(host, port)


def _apply_overrides(
    config: OperatorConfig,
    *,
    bootstrap: bool,
    relay: bool,
    listen: str,
    advertise: str,
) -> OperatorConfig:
    capabilities = set(config.capabilities)
    if bootstrap:
        capabilities.update({"bootstrap", "discovery"})
    if relay:
        capabilities.update(RELAY_CAPABILITIES)
        capabilities.add("discovery")
    policy = config.relay_policy
    if relay and not policy.enabled:
        policy = replace(policy, enabled=True)
    if not (set(capabilities) & RELAY_CAPABILITIES) and policy.enabled:
        policy = replace(policy, enabled=False)
    return replace(
        config,
        listen=_parse_endpoint(listen, listener=True) if listen else config.listen,
        advertise=_parse_endpoint(advertise, listener=False) if advertise else config.advertise,
        capabilities=tuple(sorted(capabilities)),
        relay_policy=policy,
    )


def _chmod(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def _descriptor_matches(descriptor: NodeDescriptor, config: OperatorConfig) -> bool:
    return (
        descriptor.endpoint == config.advertise
        and descriptor.capabilities == config.capabilities
        and descriptor.relay_policy == config.relay_policy
        and descriptor.network_id == NODE_NETWORK_ID
        and descriptor.protocol_version == NODE_PROTOCOL_VERSION
    )


def prepare_node(
    config: OperatorConfig,
    state_dir: Path,
    public_dir: Path,
    *,
    now: int | None = None,
) -> tuple[NodeDescriptor, bool]:
    current = int(time.time()) if now is None else now
    state = Path(state_dir).resolve()
    public = Path(public_dir).resolve()
    state.mkdir(parents=True, exist_ok=True)
    public.mkdir(parents=True, exist_ok=True)
    _chmod(state, 0o700)
    _chmod(public, 0o755)
    identity_path = state / NODE_IDENTITY_FILE
    descriptor_path = state / NODE_DESCRIPTOR_FILE
    if descriptor_path.exists() and not identity_path.exists():
        raise DescriptorError("node descriptor exists without its private identity")
    created = False
    if identity_path.exists():
        identity = ServiceIdentity.load(identity_path)
    else:
        identity = ServiceIdentity.generate()
        identity.save(identity_path)
        _chmod(identity_path, 0o600)
        created = True
    descriptor: NodeDescriptor | None = None
    if descriptor_path.exists():
        content = descriptor_path.read_text(encoding="utf-8")
        try:
            candidate = NodeDescriptor.from_json(
                content,
                now=current,
                expected_network_id=NODE_NETWORK_ID,
                expected_protocol_version=NODE_PROTOCOL_VERSION,
            )
        except DescriptorError:
            raw = parse_json_object(content)
            if not isinstance(raw.get("expiresAt"), int) or raw["expiresAt"] > current:
                raise
        else:
            if candidate.identity_public_key != identity.public_key_bytes:
                raise DescriptorError("node descriptor does not match its private identity")
            if _descriptor_matches(candidate, config) and candidate.expires_at - current > config.renew_before:
                descriptor = candidate
    if descriptor is None:
        descriptor = NodeDescriptor.create(
            identity,
            config.advertise,
            config.capabilities,
            config.relay_policy,
            issued_at=current,
            lifetime=config.descriptor_lifetime,
            network_id=NODE_NETWORK_ID,
            protocol_version=NODE_PROTOCOL_VERSION,
        )
        atomic_write_text(descriptor_path, descriptor.to_json(), mode=0o644)
        created = True
    public_descriptor = public / NODE_DESCRIPTOR_FILE
    atomic_write_text(public_descriptor, descriptor.to_json(), mode=0o644)
    _chmod(identity_path, 0o600)
    _chmod(descriptor_path, 0o644)
    _chmod(public_descriptor, 0o644)
    return descriptor, created


def _load_peer_descriptors(config: OperatorConfig) -> tuple[NodeDescriptor, ...]:
    peers: dict[str, NodeDescriptor] = {}
    for path in config.peer_descriptors:
        descriptor = NodeDescriptor.from_json(
            path.read_text(encoding="utf-8"),
            expected_network_id=NODE_NETWORK_ID,
            expected_protocol_version=NODE_PROTOCOL_VERSION,
        )
        previous = peers.get(descriptor.node_id)
        if previous is None or descriptor.issued_at > previous.issued_at:
            peers[descriptor.node_id] = descriptor
    return tuple(peers.values())


def _load_bootstrap_sets(
    config: OperatorConfig,
    state_dir: Path,
) -> tuple[BootstrapSet, ...]:
    if not config.bootstrap_bundles:
        return ()
    pins = tuple(load_authority_pin(path) for path in config.authority_pins)
    reseed = ReseedStore(
        Path(state_dir).resolve() / "reseed",
        pins,
        network_id=NODE_NETWORK_ID,
        protocol_version=NODE_PROTOCOL_VERSION,
    )
    for path in config.bootstrap_bundles:
        reseed.import_path(path, source="operator-config")
    return reseed.load_active()


class _DiscoverySupervisor:
    def __init__(
        self,
        node: WanNodeServer,
        identity: ServiceIdentity,
        bootstrap_sets: tuple[BootstrapSet, ...],
        interval: int,
    ) -> None:
        self.node = node
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.snapshot: dict[str, object] = {
            "dhtReady": False,
            "failureReason": "NO_RESEED_SOURCE" if not bootstrap_sets else "",
            "state": "BOOTSTRAP_LISTENING" if not bootstrap_sets else "BOOTSTRAPPING",
        }
        self.discovery = (
            WanDiscoveryClient(
                identity,
                BootstrapPool(bootstrap_sets, node.peer_cache),
                cache=node.peer_cache,
                replication_factor=3,
                minimum_replicas=2,
                timeout=min(10.0, float(node.policy.connection_timeout_seconds)),
            )
            if bootstrap_sets
            else None
        )

    def start(self) -> None:
        if self.discovery is None:
            return
        self.thread = threading.Thread(
            target=self._run,
            name="granger-operator-discovery",
            daemon=True,
        )
        self.thread.start()

    def _run(self) -> None:
        assert self.discovery is not None
        target_seed = hashlib.sha256(self.node.descriptor.node_id.encode("ascii")).digest()
        while not self.stop_event.is_set():
            try:
                health = self.discovery.join_network()
                learned: dict[str, NodeDescriptor] = {}
                if health.state.value != "OFFLINE":
                    for capability in ("discovery", *sorted(RELAY_CAPABILITIES)):
                        target = hashlib.sha256(target_seed + capability.encode("ascii")).digest()
                        try:
                            for peer in self.discovery.find_nodes(target, capability):
                                if peer.node_id != self.node.descriptor.node_id:
                                    learned[peer.node_id] = peer
                        except (GrangerNetworkError, OSError):
                            continue
                for peer in learned.values():
                    self.node.add_known_peer(peer, source="operator-dht")
                with self.lock:
                    self.snapshot = self.discovery.health().to_document()
            except (GrangerNetworkError, OSError, ValueError) as error:
                with self.lock:
                    self.snapshot = {
                        "dhtReady": False,
                        "failureReason": type(error).__name__,
                        "state": "DEGRADED",
                    }
            self.stop_event.wait(self.interval)

    def status(self) -> dict[str, object]:
        with self.lock:
            return dict(self.snapshot)

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5.0)
            self.thread = None


class _PidLease:
    def __init__(self, path: Path) -> None:
        self.path = Path(path).resolve()
        self.acquired = False

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except (OSError, ValueError):
            return False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                existing = int(self.path.read_text(encoding="ascii").strip())
            except (OSError, UnicodeDecodeError, ValueError):
                existing = 0
            if existing > 0 and self._alive(existing):
                raise RuntimeError(f"Granger node already appears to be running as PID {existing}")
            self.path.unlink(missing_ok=True)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.acquired = True

    def release(self) -> None:
        if self.acquired:
            self.path.unlink(missing_ok=True)
            self.acquired = False


def _status_document(
    node: WanNodeServer,
    supervisor: _DiscoverySupervisor,
    *,
    state: str,
    started_at: int,
) -> dict[str, object]:
    return {
        "acceptedConnections": node.accepted_connections,
        "activeCircuits": node.runtime.active_circuits,
        "advertise": {
            "host": node.descriptor.endpoint.host,
            "port": node.descriptor.endpoint.port,
        },
        "capabilities": list(node.descriptor.capabilities),
        "descriptorExpiresAt": node.descriptor.expires_at,
        "identityPersistent": True,
        "listen": {
            "host": node.listener_endpoint.host,
            "port": node.listener_endpoint.port,
        },
        "network": supervisor.status(),
        "nodeId": node.descriptor.node_id,
        "peerCache": node.peer_cache.stats(),
        "pid": os.getpid(),
        "rejectedConnections": node.rejected_connections,
        "rpcRequests": node.rpc_requests,
        "startedAt": started_at,
        "state": state,
        "version": 1,
    }


def run_operator(
    config: OperatorConfig,
    state_dir: Path,
    public_dir: Path,
    pid_file: Path,
    ready_file: Path,
    status_file: Path,
    diagnostics_file: Path,
) -> int:
    descriptor, _created = prepare_node(config, state_dir, public_dir)
    identity = ServiceIdentity.load(Path(state_dir).resolve() / NODE_IDENTITY_FILE)
    bootstrap_sets = _load_bootstrap_sets(config, state_dir)
    known: dict[str, NodeDescriptor] = {
        peer.node_id: peer for peer in _load_peer_descriptors(config)
    }
    for bootstrap in bootstrap_sets:
        for peer in bootstrap.peers:
            if peer.node_id != descriptor.node_id:
                known[peer.node_id] = peer
    node = load_node(
        state_dir,
        tuple(known.values()),
        listener_endpoint=config.listen,
        diagnostics_path=diagnostics_file,
    )
    supervisor = _DiscoverySupervisor(node, identity, bootstrap_sets, config.discovery_interval)
    lease = _PidLease(pid_file)
    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    previous_handlers: dict[int, object] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)
    started_at = int(time.time())
    try:
        lease.acquire()
        node.start_background()
        supervisor.start()
        atomic_write_text(
            ready_file,
            json.dumps(
                {
                    "advertise": {
                        "host": descriptor.endpoint.host,
                        "port": descriptor.endpoint.port,
                    },
                    "listen": {"host": config.listen.host, "port": config.listen.port},
                    "nodeId": descriptor.node_id,
                    "pid": os.getpid(),
                    "version": 1,
                },
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )
        atomic_write_text(
            status_file,
            json.dumps(
                _status_document(node, supervisor, state="RUNNING", started_at=started_at),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )
        while not stop_event.wait(DEFAULT_STATUS_INTERVAL):
            if int(time.time()) >= descriptor.expires_at:
                raise DescriptorError("node descriptor expired while the operator was running")
            atomic_write_text(
                status_file,
                json.dumps(
                    _status_document(node, supervisor, state="RUNNING", started_at=started_at),
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o600,
            )
        return 0
    finally:
        supervisor.stop()
        node.stop()
        atomic_write_text(
            status_file,
            json.dumps(
                _status_document(node, supervisor, state="STOPPED", started_at=started_at),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )
        Path(ready_file).unlink(missing_ok=True)
        lease.release()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--relay", action="store_true")
    parser.add_argument("--listen", default="")
    parser.add_argument("--advertise", default="")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Granger Network bootstrap/relay operator")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    _common(prepare)
    run = commands.add_parser("run")
    _common(run)
    run.add_argument("--pid-file", type=Path, required=True)
    run.add_argument("--ready-file", type=Path, required=True)
    run.add_argument("--status-file", type=Path, required=True)
    run.add_argument("--diagnostics", type=Path, required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--state-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "inspect":
            state = options.state_dir.resolve()
            descriptor = NodeDescriptor.from_json(
                (state / NODE_DESCRIPTOR_FILE).read_text(encoding="utf-8"),
                expected_network_id=NODE_NETWORK_ID,
                expected_protocol_version=NODE_PROTOCOL_VERSION,
            )
            print(
                json.dumps(
                    {
                        "advertise": {
                            "host": descriptor.endpoint.host,
                            "port": descriptor.endpoint.port,
                        },
                        "capabilities": list(descriptor.capabilities),
                        "descriptorExpiresAt": descriptor.expires_at,
                        "nodeId": descriptor.node_id,
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        config = _apply_overrides(
            load_operator_config(options.config),
            bootstrap=options.bootstrap,
            relay=options.relay,
            listen=options.listen,
            advertise=options.advertise,
        )
        if options.command == "prepare":
            descriptor, created = prepare_node(config, options.state_dir, options.public_dir)
            print(
                json.dumps(
                    {
                        "createdOrRenewed": created,
                        "descriptor": str((options.public_dir / NODE_DESCRIPTOR_FILE).resolve()),
                        "expiresAt": descriptor.expires_at,
                        "nodeId": descriptor.node_id,
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        return run_operator(
            config,
            options.state_dir,
            options.public_dir,
            options.pid_file,
            options.ready_file,
            options.status_file,
            options.diagnostics,
        )
    except (GrangerNetworkError, OSError, RuntimeError, ValueError) as error:
        print(f"granger-operator: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
