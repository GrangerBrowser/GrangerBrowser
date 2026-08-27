# Distributed Overlay Benchmark

## Purpose

This benchmark records a local engineering baseline for the v0.3 multi-hop
prototype before considering padding, uniform frames, batching, or cover
traffic. It is not a WAN, anonymity, packet-capture, or cross-platform result.

## Environment

- Date: 2026-08-24
- Operating system: Windows 11 10.0.26200
- Python: 3.14.5
- `cryptography`: 49.0.0
- Transport: in-process socket pairs
- Route: entry, client middle, introduction, host middle, service relay
- Cryptography: unchanged wire 3

## Command

```powershell
$env:PYTHONPATH=(Resolve-Path src)
python benchmarks/overlay_benchmark.py
```

Default parameters use 20 route constructions and transfer 64 frames of
16 KiB, or 1 MiB total, through one route.

## Result

| Measurement | Result |
| --- | ---: |
| Wire 3 session bindings per route | 11 |
| Unique channel bindings | 11 |
| Setup mean | 25.70 ms |
| Setup median | 24.70 ms |
| Setup p95 | 31.58 ms |
| Payload throughput | 25.55 MiB/s |
| Relay plaintext marker observed | No |

Padding, uniform frames, batching, and cover traffic were disabled in this
historical v0.3 baseline.

## Interpretation

Eleven hybrid handshakes already impose measurable setup work before network
latency, loss, congestion, and process isolation are added. The throughput
number is an in-process best case and must not be used as an Internet estimate.

Padding and cover traffic can add bandwidth, CPU, memory, latency,
distinguishability, and denial-of-service costs. Current v0.5 local-socket
benchmarks measure the four-hop endpoint route with cover explicitly set to
`off` or `standard`; those results are not directly comparable with this old
three-hop, in-process baseline. Physical-WAN packet distributions remain
unverified.
