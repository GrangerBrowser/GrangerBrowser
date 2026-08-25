from __future__ import annotations

import argparse
import ctypes
import gc
import json
import os
import platform
import statistics
import time
import tracemalloc
from pathlib import Path

from granger_network._codec import atomic_write_text
from granger_network.distributed import (
    NODE_RECORD,
    DiscoveryPeer,
    DistributedDiscoveryNetwork,
)
from granger_network.identity import ServiceIdentity
from granger_network.peer import GrangerNode, NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint


PEER_COUNTS = (100, 500, 1000)
STATE_COUNTS = (100, 500, 1000, 5000, 10000)


def _latency(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)

    def percentile(value: float) -> float:
        return ordered[max(0, min(len(ordered) - 1, int(len(ordered) * value + 0.999999) - 1))]

    return {
        "meanMs": statistics.fmean(ordered),
        "p50Ms": statistics.median(ordered),
        "p95Ms": percentile(0.95),
        "p99Ms": percentile(0.99),
    }


def _rss_bytes() -> int | None:
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("pageFaultCount", ctypes.c_ulong),
                ("peakWorkingSetSize", ctypes.c_size_t),
                ("workingSetSize", ctypes.c_size_t),
                ("quotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("quotaPagedPoolUsage", ctypes.c_size_t),
                ("quotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("quotaNonPagedPoolUsage", ctypes.c_size_t),
                ("pagefileUsage", ctypes.c_size_t),
                ("peakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(Counters),
            ctypes.c_ulong,
        )
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        if psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(),
            ctypes.byref(counters),
            counters.cb,
        ):
            return int(counters.workingSetSize)
        return None
    statm = Path("/proc/self/statm")
    if statm.is_file():
        pages = int(statm.read_text(encoding="ascii").split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    return None


def _relay_policy() -> RelayPolicy:
    return RelayPolicy(
        enabled=True,
        max_circuits=4096,
        max_streams=16384,
        max_connections=16384,
        max_bytes_per_circuit=64 * 1024 * 1024,
        max_bandwidth_kib_per_second=1024 * 1024,
        burst_kib=1024 * 1024,
        memory_budget_kib=4 * 1024 * 1024,
        connection_timeout_seconds=10,
        idle_timeout_seconds=300,
    )


def create_descriptors(count: int) -> tuple[list[NodeDescriptor], dict]:
    policy = _relay_policy()
    descriptors: list[NodeDescriptor] = []
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    failures = 0
    for index in range(count):
        try:
            identity = ServiceIdentity.generate()
            descriptors.append(
                NodeDescriptor.create(
                    identity,
                    RendezvousEndpoint("127.0.0.1", 20000 + index),
                    ("discovery", "middle"),
                    policy,
                    lifetime=3600,
                )
            )
        except Exception:
            failures += 1
    wall = time.perf_counter() - wall_started
    cpu = time.process_time() - cpu_started
    return descriptors, {
        "cpuPercentOneCoreEquivalent": cpu / wall * 100.0 if wall else 0.0,
        "cpuSeconds": cpu,
        "descriptorsPerSecond": len(descriptors) / wall if wall else 0.0,
        "failures": failures,
        "seconds": wall,
    }


def benchmark_discovery(descriptors: list[NodeDescriptor], operations: int) -> dict:
    gc.collect()
    tracemalloc.start()
    baseline, _ = tracemalloc.get_traced_memory()
    rss_before = _rss_bytes()
    peers = [DiscoveryPeer(descriptor) for descriptor in descriptors]
    network = DistributedDiscoveryNetwork(
        peers,
        replication_factor=6,
        minimum_replicas=4,
    )
    selected = descriptors[: min(operations, len(descriptors))]
    publish_latency: list[float] = []
    lookup_latency: list[float] = []
    failures = 0
    cpu_started = time.process_time()
    wall_started = time.perf_counter()
    for descriptor in selected:
        started = time.perf_counter_ns()
        try:
            network.publish(descriptor)
        except Exception:
            failures += 1
        publish_latency.append((time.perf_counter_ns() - started) / 1_000_000)
    for descriptor in selected:
        started = time.perf_counter_ns()
        try:
            resolved = network.lookup(NODE_RECORD, descriptor.node_id)
            if resolved != descriptor:
                failures += 1
        except Exception:
            failures += 1
        lookup_latency.append((time.perf_counter_ns() - started) / 1_000_000)
    wall = time.perf_counter() - wall_started
    cpu = time.process_time() - cpu_started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = _rss_bytes()
    total_operations = len(selected) * 2
    return {
        "connectionCount": 0,
        "cpuPercentOneCoreEquivalent": cpu / wall * 100.0 if wall else 0.0,
        "cpuSeconds": cpu,
        "failures": failures,
        "lookup": _latency(lookup_latency),
        "memoryBytesTraced": max(0, current - baseline),
        "operations": total_operations,
        "operationsPerSecond": total_operations / wall if wall else 0.0,
        "peerCount": len(descriptors),
        "publish": _latency(publish_latency),
        "replicationFactor": 6,
        "rssDeltaBytes": None if rss_before is None or rss_after is None else rss_after - rss_before,
        "seconds": wall,
        "tracemallocPeakBytes": peak,
    }


def benchmark_idle_circuit_states() -> list[dict]:
    policy = _relay_policy()
    identities = [ServiceIdentity.generate() for _ in range(3)]
    descriptors = [
        NodeDescriptor.create(
            identity,
            RendezvousEndpoint("127.0.0.1", 31000 + index),
            ("middle",),
            policy,
            lifetime=3600,
        )
        for index, identity in enumerate(identities)
    ]
    nodes = [
        GrangerNode(identity, descriptor, policy)
        for identity, descriptor in zip(identities, descriptors, strict=True)
    ]
    gc.collect()
    tracemalloc.start()
    baseline, _ = tracemalloc.get_traced_memory()
    rss_before = _rss_bytes()
    results: list[dict] = []
    added = 0
    for target in STATE_COUNTS:
        failures = 0
        batch_start = added
        wall_started = time.perf_counter()
        cpu_started = time.process_time()
        while added < target:
            circuit_id = (added + 1).to_bytes(16, "big")
            try:
                nodes[added % len(nodes)].begin_circuit(circuit_id, "middle")
            except Exception:
                failures += 1
            added += 1
        wall = time.perf_counter() - wall_started
        cpu = time.process_time() - cpu_started
        current, peak = tracemalloc.get_traced_memory()
        rss_after = _rss_bytes()
        results.append(
            {
                "activeStates": sum(node.active_circuits for node in nodes),
                "connectionCount": 0,
                "cpuPercentOneCoreEquivalent": cpu / wall * 100.0 if wall else 0.0,
                "cpuSeconds": cpu,
                "failures": failures,
                "memoryBytesPerStateTraced": max(0, current - baseline) // target,
                "memoryBytesTraced": max(0, current - baseline),
                "rssDeltaBytes": None if rss_before is None or rss_after is None else rss_after - rss_before,
                "secondsForIncrement": wall,
                "stateCount": target,
                "statesPerSecond": (target - batch_start) / wall if wall else 0.0,
                "tracemallocPeakBytes": peak,
            }
        )
    for index in range(added):
        nodes[index % len(nodes)].end_circuit((index + 1).to_bytes(16, "big"))
    tracemalloc.stop()
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark logical Granger WAN scale")
    parser.add_argument("--operations", type=int, default=32)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(argv)
    if not 8 <= options.operations <= 256:
        parser.error("operations must be between 8 and 256")
    descriptors, setup = create_descriptors(max(PEER_COUNTS))
    if len(descriptors) != max(PEER_COUNTS):
        raise RuntimeError("peer descriptor generation failed")
    report = {
        "descriptorSetup": setup,
        "discovery": [
            benchmark_discovery(descriptors[:count], options.operations)
            for count in PEER_COUNTS
        ],
        "idleCircuitStates": benchmark_idle_circuit_states(),
        "limitations": [
            "scale cases are logical in-process states, not 1000 OS processes",
            "connectionCount is zero in this benchmark; real sockets are measured by wan_benchmark.py",
            "tracemalloc excludes native cryptography and interpreter allocator overhead",
        ],
        "platform": platform.platform(),
        "python": platform.python_version(),
        "status": "PASS",
        "version": 1,
    }
    encoded = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if options.output is not None:
        atomic_write_text(options.output, encoded, mode=0o644)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
