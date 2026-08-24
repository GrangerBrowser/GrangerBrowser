from __future__ import annotations

import argparse
import gc
import json
import platform
import secrets
import socket
import statistics
import threading
import time
import tracemalloc

import cryptography

from granger_network.identity import ServiceIdentity
from granger_network.protocol import VERSION_2, VERSION_3, SecureChannel, client_handshake, server_handshake


def open_channel_pair(
    identity: ServiceIdentity,
    protocol_version: int,
) -> tuple[SecureChannel, SecureChannel, int]:
    server_socket, client_socket = socket.socketpair()
    session_id = secrets.token_bytes(16)
    result: list[SecureChannel] = []
    failures: list[BaseException] = []

    def accept() -> None:
        try:
            result.append(
                server_handshake(
                    server_socket,
                    identity,
                    expected_session_id=session_id,
                    protocol_version=protocol_version,
                )
            )
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=accept)
    started = time.perf_counter_ns()
    thread.start()
    client = client_handshake(
        client_socket,
        identity.public_key_bytes,
        session_id=session_id,
        protocol_version=protocol_version,
    )
    thread.join()
    elapsed = time.perf_counter_ns() - started
    if failures:
        client.destroy()
        client_socket.close()
        server_socket.close()
        raise failures[0]
    return client, result[0], elapsed


def close_pair(client: SecureChannel, server: SecureChannel) -> None:
    client.destroy()
    server.destroy()
    client.connection.close()
    server.connection.close()


def benchmark_protocol(
    protocol_version: int,
    iterations: int,
    frames: int,
    payload_size: int,
) -> dict[str, float | int]:
    identity = ServiceIdentity.generate()
    for _ in range(20):
        client, server, _elapsed = open_channel_pair(identity, protocol_version)
        close_pair(client, server)

    gc.collect()
    latencies: list[float] = []
    tracemalloc.start()
    for _ in range(iterations):
        client, server, elapsed = open_channel_pair(identity, protocol_version)
        latencies.append(elapsed / 1_000_000)
        close_pair(client, server)
    _current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    client, server, _elapsed = open_channel_pair(identity, protocol_version)
    payload = b"x" * payload_size
    received: list[bytes] = []
    failures: list[BaseException] = []

    def receive_frames() -> None:
        try:
            for _ in range(frames):
                received.append(server.receive_bytes())
        except BaseException as error:
            failures.append(error)

    receiver = threading.Thread(target=receive_frames)
    receiver.start()
    started = time.perf_counter()
    for _ in range(frames):
        client.send_bytes(payload)
    receiver.join()
    throughput_seconds = time.perf_counter() - started
    close_pair(client, server)
    if failures:
        raise failures[0]
    if len(received) != frames or any(frame != payload for frame in received):
        raise RuntimeError("throughput benchmark received corrupted frames")

    ordered = sorted(latencies)
    total_payload = frames * payload_size
    return {
        "handshakeIterations": iterations,
        "handshakeMsMean": statistics.fmean(latencies),
        "handshakeMsP50": statistics.median(latencies),
        "handshakeMsP95": ordered[max(0, int(iterations * 0.95) - 1)],
        "pythonTracemallocPeakBytes": peak_memory,
        "throughputFrames": frames,
        "throughputPayloadBytes": total_payload,
        "throughputSeconds": throughput_seconds,
        "throughputMiBPerSecond": total_payload / (1024 * 1024) / throughput_seconds,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Granger Network crypto protocols")
    parser.add_argument("--iterations", type=int, default=250)
    parser.add_argument("--frames", type=int, default=256)
    parser.add_argument("--payload-size", type=int, default=64 * 1024)
    options = parser.parse_args()
    if options.iterations < 10 or options.frames < 1 or not 1 <= options.payload_size <= 4 * 1024 * 1024:
        parser.error("benchmark parameters are outside safe bounds")

    report = {
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "results": {
            "wireV2Classical": benchmark_protocol(
                VERSION_2,
                options.iterations,
                options.frames,
                options.payload_size,
            ),
            "wireV3Hybrid": benchmark_protocol(
                VERSION_3,
                options.iterations,
                options.frames,
                options.payload_size,
            ),
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
