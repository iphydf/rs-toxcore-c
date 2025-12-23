# Merkle-Tox Benchmarking Strategy

## Overview

Merkle-Tox is a performance-critical decentralized synchronization system.
Because it operates over a limited-bandwidth, high-latency network (Tox), every
byte on the wire and every millisecond of CPU time spent on serialization or
cryptography directly impacts the user experience.

Our benchmarking strategy is **Tiered**, focusing on micro-level primitives,
protocol-level logic units, and high-level user scenarios.

## 1. Chosen Benchmarks & Rationale

### Tier 1: Low-Level Serialization (`tox-proto`)

**Target:** `proto_bench`

*   **Why:** Serialization is the most frequent operation in the system.
*   **Key Metrics:** We benchmark naked `u64` (for discriminator optimization),
    `SmallVec` (stack vs heap), and `Vec<u8>` (MessagePack `bin`
    specialization).
*   **Goal:** Ensure that our custom MessagePack implementation provides the
    theoretical maximum byte-density and nanosecond-level performance.

### Tier 2: Algorithmic Scaling (`tox-reconcile`)

**Target:** `reconcile_bench`

*   **Why:** Invertible Bloom Lookup Tables (IBLT) are used for set
    reconciliation. If the "peeling" process (decoding differences) is slow,
    group synchronization will stall.
*   **Key Metrics:** Decoding time at maximum capacity for **Small**,
    **Medium**, and **Large** tiers.
*   **Goal:** Verify that we can identify a gap of 500+ messages in under 1ms.

### Tier 3: Critical User Scenarios (`merkle-tox-core`)

**Target:** `core_bench` Instead of benchmarking every function, we target the
"Hot Paths" of the two most important user experiences:

#### A. The "New Joiner" Path

*   **Metric:** `unpack_wire` (Decryption + Decompression + Deserialization).
*   **Rationale:** A user joining a long-lived chat may need to ingest 10,000+
    nodes. If `unpack_wire` takes 1ms, the app freezes for 10 seconds. Our
    target is < 10µs per node to ensure smooth background loading.

#### B. The "Blob Transfer" Path

*   **Metric:** `blob_chunk_verify_64kb`.
*   **Rationale:** Files are transferred in 64KB chunks. Every chunk is verified
    against a Merkle tree.
*   **Goal:** Ensure integrity checks are fast enough to saturate high-speed
    fiber connections without bottlenecking the CPU.

## 2. Intentional Exclusions

We have intentionally **excluded** the following from our Criterion suite:

*   **Disk I/O (SQLite/FS):** Disk performance is highly variable and depends on
    the environment (NVMe vs. SD Card). These are better handled by "Stress
    Tests" and "Integration Benchmarks" rather than statistical
    micro-benchmarks.
*   **End-to-End Networking:** Real network jitter makes Criterion results
    meaningless. We use the `merkle-tox-workbench` Swarm Simulator to measure
    network convergence times separately.
*   **UI/Rendering:** The cost of drawing the TUI or GUI is decoupled from the
    protocol performance and is not measured here.

## 3. High-Priority Future Benchmarks

The following are the next critical areas for instrumentation:

1.  **Engine Lock Contention:** As we move to more highly parallel processing of
    incoming packets, we need to benchmark the `MerkleToxEngine` under heavy
    multi-threaded contention (using `parking_lot` vs. standard Mutexes).
2.  **Ratchet Chain Scaling:** In a DAG with many concurrent branches, the
    ratchet needs to "merge" many keys. We need to benchmark the cost of
    `ratchet_merge` when joining 10+ parent chains.
3.  **Bao Full-Outboard Generation:** Currently, we benchmark single-chunk
    verification. We need to benchmark the time it takes to generate the full
    Bao outboard for a 100MB file, as this happens on the "Sender" hot path.

## How to Run

Benchmarks should always be run in **Release Mode** with the `--bench` flag:

```bash
# Core Protocol Benchmarks
bazel run -c opt //rs-toxcore-c/merkle-tox-core:core_bench -- --bench

# Serialization Benchmarks
bazel run -c opt //rs-toxcore-c/tox-proto:proto_bench -- --bench

# Algorithmic Scaling Benchmarks
bazel run -c opt //rs-toxcore-c/tox-reconcile:reconcile_bench -- --bench
```
