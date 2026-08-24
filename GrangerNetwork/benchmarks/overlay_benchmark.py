from __future__ import annotations

import argparse
import json
import platform
import statistics
import threading
import time

import cryptography

from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import (
    DiscoveryPeer,
    DistributedDiscoveryNetwork,
    DistributedResolver,
)
from granger_network.identity import ServiceIdentity
from granger_network.introduction import AliasRecord, IntroductionDescriptor, IntroductionRegistry
from granger_network.multihop import MultiHopCircuit, OverlayRoutePlan, OverlayRoutePlanner
from granger_network.peer import RELAY_CAPABILITIES, GrangerNode, NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint


def _choose_first(sequence):
    def key(value):
        if isinstance(value, tuple):
            return value[1].node_id
        return value.node_id

    return sorted(sequence, key=key)[0]


def build_fixture() -> tuple[
    OverlayRoutePlan,
    dict[str, GrangerNode],
    ServiceIdentity,
]:
    now = int(time.time())
    service_identity = ServiceIdentity.generate()
    service = ServiceDescriptor.create_remote(
        service_identity,
        "overlay-benchmark",
        issued_at=now,
        lifetime=3600,
    )
    definitions = (
        ("entry",),
        ("middle",),
        ("introduction",),
        ("middle",),
        ("service-relay",),
        ("discovery",),
        ("discovery",),
    )
    peers: list[DiscoveryPeer] = []
    runtimes: dict[str, GrangerNode] = {}
    descriptors: list[NodeDescriptor] = []
    for index, relay_capabilities in enumerate(definitions, start=10):
        identity = ServiceIdentity.generate()
        capabilities = tuple(sorted({"discovery", *relay_capabilities}))
        policy = RelayPolicy(
            enabled=bool(set(capabilities) & RELAY_CAPABILITIES),
            max_circuits=16,
            max_bytes_per_circuit=64 * 1024 * 1024,
            max_bandwidth_kib_per_second=64 * 1024,
        )
        descriptor = NodeDescriptor.create(
            identity,
            RendezvousEndpoint(f"203.0.113.{index}", 24000 + index),
            capabilities,
            policy,
            issued_at=now,
            lifetime=3600,
        )
        descriptors.append(descriptor)
        peers.append(DiscoveryPeer(descriptor))
        if policy.enabled:
            runtimes[descriptor.node_id] = GrangerNode(identity, descriptor, policy)

    network = DistributedDiscoveryNetwork(peers, replication_factor=3, minimum_replicas=2)
    for descriptor in descriptors:
        network.publish(descriptor, now=now)
    network.publish(service, now=now)
    introduction_node = next(
        descriptor for descriptor in descriptors if "introduction" in descriptor.capabilities
    )
    introduction = IntroductionDescriptor.create(
        service_identity,
        service,
        [introduction_node.node_id],
        sequence=1,
        issued_at=now,
        lifetime=900,
    )
    alias = AliasRecord.create(
        service_identity,
        "benchmark.granger",
        sequence=1,
        issued_at=now,
        lifetime=1800,
    )
    network.publish(introduction, now=now)
    network.publish(alias, now=now)
    resolver = DistributedResolver(network, {alias.alias: service.service_id})
    route = OverlayRoutePlanner(resolver, chooser=_choose_first).plan(alias.alias, now=now)
    return route, runtimes, service_identity


def benchmark_setup(
    route: OverlayRoutePlan,
    runtimes: dict[str, GrangerNode],
    identity: ServiceIdentity,
    iterations: int,
) -> dict[str, float | int]:
    latencies: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        circuit = MultiHopCircuit.open(route, runtimes, identity, IntroductionRegistry())
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        circuit.close()
    ordered = sorted(latencies)
    return {
        "iterations": iterations,
        "meanMs": statistics.fmean(latencies),
        "p50Ms": statistics.median(latencies),
        "p95Ms": ordered[max(0, int(iterations * 0.95) - 1)],
    }


def benchmark_payload(
    route: OverlayRoutePlan,
    runtimes: dict[str, GrangerNode],
    identity: ServiceIdentity,
    frames: int,
    payload_size: int,
) -> dict[str, float | int | bool]:
    circuit = MultiHopCircuit.open(route, runtimes, identity, IntroductionRegistry())
    payload = b"overlay-benchmark-payload:" + b"x" * (payload_size - 26)
    received: list[bytes] = []
    failures: list[BaseException] = []

    def receive() -> None:
        try:
            for _ in range(frames):
                received.append(circuit.service_channel.receive_bytes())
        except BaseException as error:
            failures.append(error)

    receiver = threading.Thread(target=receive, name="overlay-benchmark-receiver")
    receiver.start()
    started = time.perf_counter()
    for _ in range(frames):
        circuit.client_channel.send_bytes(payload)
    receiver.join()
    elapsed = time.perf_counter() - started
    try:
        circuit.assert_healthy()
        if failures:
            raise failures[0]
        if len(received) != frames or any(frame != payload for frame in received):
            raise RuntimeError("multi-hop benchmark received corrupted frames")
        total = frames * payload_size
        return {
            "frames": frames,
            "payloadBytes": total,
            "seconds": elapsed,
            "miBPerSecond": total / (1024 * 1024) / elapsed,
            "relayPlaintextMarkerObserved": circuit.plaintext_observed(payload[:26]),
            "wireV3Sessions": circuit.session_count,
            "uniqueSessionBindings": len(circuit.unique_session_bindings),
        }
    finally:
        circuit.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the local Granger multi-hop prototype")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--frames", type=int, default=64)
    parser.add_argument("--payload-size", type=int, default=16 * 1024)
    options = parser.parse_args()
    if not 3 <= options.iterations <= 100:
        parser.error("iterations must be between 3 and 100")
    if not 1 <= options.frames <= 1024:
        parser.error("frames must be between 1 and 1024")
    if not 26 <= options.payload_size <= 1024 * 1024:
        parser.error("payload size must be between 26 bytes and 1 MiB")

    route, runtimes, identity = build_fixture()
    report = {
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "metadataDefenses": {
            "batchingEnabled": False,
            "coverTrafficEnabled": False,
            "paddingEnabled": False,
            "uniformFramesEnabled": False,
        },
        "setup": benchmark_setup(route, runtimes, identity, options.iterations),
        "payload": benchmark_payload(
            route,
            runtimes,
            identity,
            options.frames,
            options.payload_size,
        ),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
