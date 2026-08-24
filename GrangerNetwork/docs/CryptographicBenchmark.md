# Cryptographic Benchmark

## Purpose

This benchmark compares the previous classical wire 2 implementation with the
hybrid wire 3 implementation in the same source tree and process. It is intended
to catch impractical latency, memory, or throughput regressions. It is not a
network benchmark, production capacity estimate, or cross-platform guarantee.

## Method

Command:

```powershell
$env:PYTHONPATH=(Resolve-Path GrangerNetwork/src)
python GrangerNetwork/benchmarks/crypto_benchmark.py
```

Recorded environment:

- Windows 11 build 26200, x64;
- Python 3.14.5;
- `cryptography` 49.0.0;
- 250 measured handshakes after 20 warmups per protocol;
- one local `socketpair` and a fresh session for each handshake;
- 256 encrypted frames of 64 KiB, 16 MiB total, for throughput;
- Python `tracemalloc` peak during the handshake loop.

The two protocols are measured sequentially in one invocation:

- before: wire 2, ephemeral X25519 and the classical key schedule;
- after: wire 3, ephemeral X25519 + ML-KEM-768, transcript-bound key
  separation, Finished confirmation, and ratcheted frame keys.

The memory figure covers Python-managed allocations visible to `tracemalloc`.
It does not include all native cryptographic backend allocations or process RSS.

## Results

| Metric | Wire 2 before | Wire 3 after | Difference |
| --- | ---: | ---: | ---: |
| Handshake mean | 0.862 ms | 1.716 ms | +0.854 ms |
| Handshake p50 | 0.849 ms | 1.693 ms | +0.843 ms |
| Handshake p95 | 1.016 ms | 1.940 ms | +0.924 ms |
| Python allocation peak | 18,377 B | 38,492 B | +20,115 B |
| Frame throughput | 533.5 MiB/s | 534.5 MiB/s | +0.2% |

The local hybrid handshake approximately doubles CPU-visible handshake latency,
but remains below 2 ms at the mean and p95 in this environment. The measured
Python allocation peak grows by about 20 KiB. Frame throughput is effectively
unchanged within normal run-to-run noise because both versions retain
ChaCha20-Poly1305 for data frames.

The added cost is acceptable for the current short-lived prototype fetch model
on this machine. Other processors, operating systems, Python versions,
cryptographic backends, real network latency, and concurrent session counts
still require measurement before setting production limits.

## Reproduction

Optional parameters:

```powershell
python GrangerNetwork/benchmarks/crypto_benchmark.py `
  --iterations 250 `
  --frames 256 `
  --payload-size 65536
```

The program validates received plaintext and exits nonzero on corruption or a
benchmark error. Raw JSON is printed to standard output so future runs can be
captured and compared without changing the benchmark source.
