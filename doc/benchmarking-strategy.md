# Merkle-Tox Benchmarking Strategy

## Overview

Merkle-Tox operates over a limited-bandwidth, high-latency network (Tox).
Benchmarks measure wire bytes and CPU time for serialization and cryptography.

The strategy is **Tiered**: micro-level primitives, protocol-level logic units,
and high-level user scenarios.

## 1. Chosen Benchmarks & Rationale

### Tier 1: Low-Level Serialization (`tox-proto`)

**Target:** `proto_bench`

*   **Why:** Serialization is the most frequent operation.
*   **Metrics:** Benchmarks `u64` (discriminator optimization), `SmallVec`
    (stack vs heap), and `Vec<u8>` (MessagePack `bin` specialization).
*   **Goal:** Ensure MessagePack implementation provides maximum byte-density
    and nanosecond-level performance.

### Tier 2: Algorithmic Scaling (`tox-reconcile`)

**Target:** `reconcile_bench`

*   **Why:** Invertible Bloom Lookup Tables (IBLT) are used for set
    reconciliation. If peeling (decoding differences) is slow, group
    synchronization stalls.
*   **Metrics:** Decoding time at maximum capacity for **Small**, **Medium**,
    and **Large** tiers.
*   **Goal:** Identify a gap of 500+ messages in <1ms.

### Tier 3: User Scenarios (`merkle-tox-core`)

**Target:** `core_bench`

Targets the "Hot Paths" of two primary scenarios:

#### A. The "New Joiner" Path

*   **Metric:** `unpack_wire` (Decryption + Decompression + Deserialization).
*   **Rationale:** Ingesting 10,000+ nodes requires `unpack_wire` < 10µs per
    node to prevent main thread blocking.

#### B. The "Blob Transfer" Path

*   **Metric:** `blob_chunk_verify_64kb`.
*   **Rationale:** Files transfer in 64KB chunks. Each chunk is verified against
    a Merkle tree.
*   **Goal:** Ensure integrity checks saturate high-speed connections without
    CPU bottlenecks.

## 2. Exclusions

**Excluded** from the Criterion suite:

*   **Disk I/O (SQLite/FS):** Disk performance is environment-dependent. Handled
    by integration benchmarks.
*   **End-to-End Networking:** Network jitter invalidates Criterion results.
    Measured separately via `merkle-tox-workbench` Swarm Simulator.
*   **UI/Rendering:** Decoupled from protocol performance.

## 3. Future Benchmarks

1.  **Engine Lock Contention:** Benchmark `MerkleToxEngine` under heavy
    multi-threaded contention (`parking_lot` vs. standard Mutexes).
2.  **State Promotion Latency:** Benchmark trial decryption and DAG validation
    cost during Opaque Store promotion flows.
3.  **Bao Full-Outboard Generation:** Benchmark full Bao outboard generation
    time for a 100MB file.

## How to Run

Run in **Release Mode** with the `--bench` flag:

```bash
# Protocol Benchmarks
bazel run -c opt //rs-toxcore-c/merkle-tox-core:core_bench -- --bench

# Serialization Benchmarks
bazel run -c opt //rs-toxcore-c/tox-proto:proto_bench -- --bench

# Algorithmic Scaling Benchmarks
bazel run -c opt //rs-toxcore-c/tox-reconcile:reconcile_bench -- --bench
```
