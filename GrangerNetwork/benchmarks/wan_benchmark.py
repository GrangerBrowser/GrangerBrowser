from __future__ import annotations

import argparse
import gc
import json
import os
import platform
import socket
import statistics
import tempfile
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import cryptography

from granger_network._codec import atomic_write_text
from granger_network.bootstrap import BootstrapPool, BootstrapSet, PeerCache
from granger_network.cells import (
    CELL_SIZE,
    MAX_CELLS_PER_BATCH,
    CoverTrafficProfile,
)
from granger_network.circuit import CircuitBuilder
from granger_network.descriptor import ServiceDescriptor
from granger_network.http_bridge import LoopbackHttpBridge, LoopbackHttpTarget
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType, connect_authenticated_peer
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_service import WanServiceClient, WanServiceHost
from granger_network.wan_discovery import WanDiscoveryClient


ONE_MIB = 1024 * 1024
SMALL_BODY = b"Granger WAN benchmark"
BYTE_BODY = b"x" * ONE_MIB


class BenchmarkHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/small":
            body = SMALL_BODY
        elif self.path == "/bytes/1048576":
            body = BYTE_BODY
        elif self.path == "/bytes/65536":
            body = BYTE_BODY[: 64 * 1024]
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/echo":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= size <= 64 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(size)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def latency_summary(values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    return {
        "iterations": len(values),
        "meanMs": statistics.fmean(values),
        "p50Ms": statistics.median(values),
        "p95Ms": ordered[max(0, int(len(ordered) * 0.95 + 0.999999) - 1)],
    }


class WanBenchmarkFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-benchmark-")
        self.root = Path(self.temporary.name)
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        roles = (
            "access",
            "entry",
            "middle",
            "access",
            "service-relay",
            "middle",
            "introduction",
            "rendezvous",
        )
        self.identities = [ServiceIdentity.generate() for _ in roles]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                (role,),
                RelayPolicy(
                    enabled=True,
                    max_circuits=256,
                    max_streams=512,
                    max_connections=512,
                    max_bytes_per_circuit=256 * 1024 * 1024,
                    max_bandwidth_kib_per_second=256 * 1024,
                    burst_kib=256 * 1024,
                    memory_budget_kib=256 * 1024,
                    idle_timeout_seconds=300,
                ),
                lifetime=3600,
            )
            for identity, role in zip(self.identities, roles, strict=True)
        ]
        self.nodes = [
            WanNodeServer(identity, descriptor, self.root / f"node-{index}")
            for index, (identity, descriptor) in enumerate(
                zip(self.identities, self.descriptors, strict=True)
            )
        ]
        for node in self.nodes:
            node.start_background()
        (
            self.client_access,
            self.client_entry,
            self.client_middle,
            self.service_access,
            self.service_entry,
            self.service_middle,
            self.introduction_node,
            self.rendezvous_node,
        ) = self.descriptors
        self.service_identity = ServiceIdentity.generate()
        self.service = ServiceDescriptor.create_remote(
            self.service_identity,
            "wan-benchmark",
            lifetime=1800,
        )
        self.introduction = IntroductionDescriptor.create(
            self.service_identity,
            self.service,
            [self.introduction_node.node_id],
            sequence=1,
            lifetime=900,
        )
        self.host = WanServiceHost(
            self.service_identity,
            self.service,
            self.introduction,
            (
                (self.service_access, "access"),
                (self.service_entry, "service-relay"),
                (self.service_middle, "middle"),
                (self.introduction_node, "introduction"),
            ),
            (
                (self.service_access, "access"),
                (self.service_entry, "service-relay"),
                (self.service_middle, "middle"),
                (self.rendezvous_node, "rendezvous"),
            ),
            LoopbackHttpBridge(
                LoopbackHttpTarget("127.0.0.1", int(self.backend.server_address[1])),
                timeout=30.0,
            ),
            timeout=30.0,
            rendezvous_lifetime=300,
        )
        self.host.start_background()
        self.host.wait_ready(30.0)

    @property
    def client_route(self) -> tuple[tuple[NodeDescriptor, str], ...]:
        return (
            (self.client_access, "access"),
            (self.client_entry, "entry"),
            (self.client_middle, "middle"),
        )

    def connect_service(self):
        return WanServiceClient(
            ServiceIdentity.generate(),
            self.service,
            self.introduction,
            self.client_route,
            timeout=30.0,
        ).connect(self.introduction_node)

    def close(self) -> None:
        self.host.stop()
        for node in self.nodes:
            node.stop()
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=2.0)
        self.temporary.cleanup()


def benchmark_peer_handshake(fixture: WanBenchmarkFixture, iterations: int) -> dict:
    latencies: list[float] = []
    identity = ServiceIdentity.generate()
    for _ in range(iterations):
        started = time.perf_counter_ns()
        peer = connect_authenticated_peer(
            fixture.client_access,
            identity,
            PeerRole.CLIENT,
            timeout=10.0,
        )
        try:
            peer.rpc.request(RpcType.PING, b"benchmark", expected=RpcType.PONG)
        finally:
            peer.close()
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    return latency_summary(latencies)


def benchmark_circuit(fixture: WanBenchmarkFixture, iterations: int) -> dict:
    latencies: list[float] = []
    builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=20.0)
    route = (*fixture.client_route, (fixture.introduction_node, "introduction"))
    for _ in range(iterations):
        started = time.perf_counter_ns()
        circuit = builder.open(route)
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        circuit.close()
    return latency_summary(latencies)


def benchmark_sessions(fixture: WanBenchmarkFixture, iterations: int) -> tuple[dict, object]:
    introductions: list[float] = []
    rendezvous: list[float] = []
    sessions: list[float] = []
    first_response: list[float] = []
    for _ in range(iterations):
        session = fixture.connect_service()
        introductions.append(session.timings["introductionMs"])
        rendezvous.append(session.timings["rendezvousMs"])
        sessions.append(session.timings["sessionMs"])
        started = time.perf_counter_ns()
        response = session.fetch("/small")
        first_response.append((time.perf_counter_ns() - started) / 1_000_000)
        if response.status != 200 or response.body != SMALL_BODY:
            raise RuntimeError("WAN latency benchmark response was corrupted")
        session.close()
    active = fixture.connect_service()
    return (
        {
            "introduction": latency_summary(introductions),
            "rendezvous": latency_summary(rendezvous),
            "serviceSession": latency_summary(sessions),
            "smallBufferedResponse": latency_summary(first_response),
        },
        active,
    )


def benchmark_post(session, iterations: int) -> dict:
    payload = b"granger-post-benchmark" * 64
    latencies: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        response = session.fetch(
            "/echo",
            method="POST",
            headers={"content-type": "application/octet-stream"},
            body=payload,
        )
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        if response.status != 200 or response.body != payload:
            raise RuntimeError("WAN POST benchmark response was corrupted")
    return latency_summary(latencies)


def benchmark_cover_idle(session, seconds: float = 9.0) -> dict[str, float | int | str]:
    multiplexers = session.circuit.multiplexers
    before = sum(int(mux.traffic_counters["coverCellsSent"]) for mux in multiplexers)
    started = time.perf_counter()
    time.sleep(seconds)
    elapsed = time.perf_counter() - started
    after = sum(int(mux.traffic_counters["coverCellsSent"]) for mux in multiplexers)
    cells = after - before
    return {
        "elapsedSeconds": elapsed,
        "endpointDirectionCells": cells,
        "fixedCellBytes": cells * CELL_SIZE,
        "profile": multiplexers[0].cover_policy.profile.value,
    }


def benchmark_join(iterations: int) -> dict[str, object]:
    temporary = tempfile.TemporaryDirectory(prefix="granger-join-benchmark-")
    root = Path(temporary.name)
    authority = ServiceIdentity.generate()
    identities = [ServiceIdentity.generate() for _ in range(6)]
    capabilities = ("access", "bootstrap", "discovery", "entry", "middle")
    descriptors = [
        NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", available_port()),
            capabilities,
            RelayPolicy(
                enabled=True,
                max_circuits=256,
                max_streams=256,
                max_connections=512,
                max_bandwidth_kib_per_second=256 * 1024,
            ),
            lifetime=3600,
        )
        for identity in identities
    ]
    nodes = [
        WanNodeServer(
            identity,
            descriptor,
            root / f"node-{index}",
            known_peers=descriptors,
        )
        for index, (identity, descriptor) in enumerate(
            zip(identities, descriptors, strict=True)
        )
    ]
    for node in nodes:
        node.start_background()
    bootstrap = BootstrapSet.create(authority, descriptors, lifetime=1800)
    cold: list[float] = []
    warm: list[float] = []
    direct_first_contact = 0
    private_discovery = 0
    try:
        for index in range(iterations):
            cache = PeerCache(root / f"cache-{index}.json")
            cold_client = WanDiscoveryClient(
                ServiceIdentity.generate(),
                BootstrapPool(bootstrap, cache),
                cache=cache,
                timeout=5.0,
            )
            started = time.perf_counter_ns()
            cold_health = cold_client.join_network()
            cold.append((time.perf_counter_ns() - started) / 1_000_000)
            if cold_health.failure_reason:
                raise RuntimeError("cold WAN join failed")
            direct_first_contact += cold_client.direct_first_contact_requests
            private_discovery += cold_client.private_discovery_requests

            warm_client = WanDiscoveryClient(
                ServiceIdentity.generate(),
                BootstrapPool(bootstrap, cache),
                cache=cache,
                timeout=5.0,
            )
            started = time.perf_counter_ns()
            warm_health = warm_client.join_network()
            warm.append((time.perf_counter_ns() - started) / 1_000_000)
            if warm_health.failure_reason:
                raise RuntimeError("warm WAN join failed")
            direct_first_contact += warm_client.direct_first_contact_requests
            private_discovery += warm_client.private_discovery_requests
    finally:
        for node in nodes:
            node.stop()
        temporary.cleanup()
    return {
        "cold": latency_summary(cold),
        "directFirstContactRequests": direct_first_contact,
        "privateDiscoveryRequests": private_discovery,
        "warm": latency_summary(warm),
    }


def transfer(session, requests: int, size: int) -> dict[str, float | int]:
    path = f"/bytes/{size}"
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    for _ in range(requests):
        response = session.fetch(path)
        if response.status != 200 or len(response.body) != size:
            raise RuntimeError("WAN throughput response was corrupted")
    cpu_seconds = time.process_time() - cpu_started
    wall_seconds = time.perf_counter() - wall_started
    total = requests * size
    return {
        "bytes": total,
        "cpuPercentOneCoreEquivalent": cpu_seconds / wall_seconds * 100.0,
        "cpuSeconds": cpu_seconds,
        "miBPerSecond": total / ONE_MIB / wall_seconds,
        "requests": requests,
        "wallSeconds": wall_seconds,
    }


def benchmark_concurrent_streams(session, count: int = 16) -> dict:
    failures: list[str] = []
    results: list[int] = []
    lock = threading.Lock()

    def fetch() -> None:
        try:
            response = session.fetch("/bytes/65536")
            if response.status != 200:
                raise RuntimeError(f"unexpected status {response.status}")
            with lock:
                results.append(len(response.body))
        except BaseException as error:
            with lock:
                failures.append(type(error).__name__)

    started = time.perf_counter()
    threads = [threading.Thread(target=fetch) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60.0)
    elapsed = time.perf_counter() - started
    return {
        "completed": len(results),
        "failures": failures,
        "requested": count,
        "seconds": elapsed,
        "stuckThreads": sum(thread.is_alive() for thread in threads),
    }


def benchmark_idle_allocations(fixture: WanBenchmarkFixture, count: int = 3) -> dict:
    gc.collect()
    tracemalloc.start()
    baseline, _peak = tracemalloc.get_traced_memory()
    peers = [
        connect_authenticated_peer(
            fixture.client_entry,
            ServiceIdentity.generate(),
            PeerRole.CLIENT,
            timeout=10.0,
        )
        for _ in range(count)
    ]
    peer_current, _peer_peak = tracemalloc.get_traced_memory()
    for peer in peers:
        peer.close()
    gc.collect()
    circuit_baseline, _peak = tracemalloc.get_traced_memory()
    builder = CircuitBuilder(ServiceIdentity.generate(), PeerRole.CLIENT, timeout=20.0)
    route = (*fixture.client_route, (fixture.introduction_node, "introduction"))
    circuits = [builder.open(route) for _ in range(count)]
    circuit_current, peak = tracemalloc.get_traced_memory()
    for circuit in circuits:
        circuit.close()
    tracemalloc.stop()
    return {
        "method": "python-tracemalloc; excludes native Qt/crypto/socket allocations",
        "peerBytesApprox": max(0, peer_current - baseline) // count,
        "circuitBytesApprox": max(0, circuit_current - circuit_baseline) // count,
        "sampleCount": count,
        "tracemallocPeakBytes": peak,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the real Granger WAN socket path")
    parser.add_argument("--iterations", type=int, default=7)
    parser.add_argument(
        "--cover-profile",
        choices=[profile.value for profile in CoverTrafficProfile],
        default=CoverTrafficProfile.STANDARD.value,
    )
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(argv)
    if not 3 <= options.iterations <= 30:
        parser.error("iterations must be between 3 and 30")
    os.environ["GRANGER_COVER_PROFILE"] = options.cover_profile
    fixture = WanBenchmarkFixture()
    try:
        session_results, session = benchmark_sessions(fixture, options.iterations)
        try:
            report = {
                "cryptography": cryptography.__version__,
                "coverProfile": options.cover_profile,
                "fixedCellBytes": CELL_SIZE,
                "maximumCellsPerProtectedBatch": MAX_CELLS_PER_BATCH,
                "limitations": [
                    "smallBufferedResponse measures a complete small response because v0.4 buffers responses",
                    "memory figures exclude native allocations",
                    "loopback results are not physical WAN latency",
                ],
                "memory": benchmark_idle_allocations(fixture),
                "networkJoin": benchmark_join(options.iterations),
                "peerHandshakeAndPing": benchmark_peer_handshake(
                    fixture, options.iterations
                ),
                "platform": platform.platform(),
                "python": platform.python_version(),
                "service": session_results,
                "telescopedFourHopCircuit": benchmark_circuit(
                    fixture, options.iterations
                ),
                "postLatency": benchmark_post(session, options.iterations),
                "throughput1MiB": transfer(session, 1, ONE_MIB),
                "throughput10MiB": transfer(session, 10, ONE_MIB),
                "concurrentStreams": benchmark_concurrent_streams(session),
                "coverIdleWindow": benchmark_cover_idle(session),
                "version": 1,
            }
        finally:
            session.close()
        encoded = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        if options.output is not None:
            atomic_write_text(options.output, encoded, mode=0o644)
        print(encoded, end="")
        return 0
    finally:
        fixture.close()


if __name__ == "__main__":
    raise SystemExit(main())
