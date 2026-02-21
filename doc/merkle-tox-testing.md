# Merkle-Tox Sub-Design: End-to-End Testing & Simulation Swarms

## Overview

Merkle-Tox is a decentralized, eventually consistent system. Verifying its
correctness requires testing not just individual components, but the emergent
behavior of a distributed swarm under adverse conditions.

This document defines the architecture for the **Merkle-Tox Benchmark & Chaos
Laboratory**, a suite designed to simulate large-scale network topologies,
inject impairments (loss, latency, partitions), and bridge virtual simulations
with real-world Tox nodes.

## 1. Abstractions

To support a unified testing environment, we decouple the protocol logic from
the physical networking and time.

### A. `Transport` Trait

The system logic (Sync Engine + Reliability Layer) interacts with the network
via a generic `Transport` trait.

```rust
pub trait Transport: Send + Sync {
    /// Returns the Public Key of this transport instance.
    fn local_pk(&self) -> PublicKey;

    /// Sends a raw, lossy packet to a destination.
    fn send_raw(&self, to: PublicKey, data: Vec<u8>) -> Result<(), TransportError>;
}
```

Implementations provided:

-   **`ToxTransport`**: Wraps a real `toxcore` instance for internet
    communication.
-   **`SimulatedTransport`**: Connects to an in-memory `VirtualHub`.

### B. `TimeProvider` Trait

To support high-speed simulations and reproducible "Time Travel" debugging, all
timers (RTT, retransmissions, slewing) must use a `TimeProvider` trait.

```rust
pub trait TimeProvider: Send + Sync {
    fn now_instant(&self) -> Instant;
    fn now_system_ms(&self) -> i64;
}
```

### C. `MerkleToxNode<T, S>` Container

The Tox instance is encapsulated in a generic container that orchestrates the
internal components:

1.  **`MerkleToxEngine`**: Pure DAG/Sync logic.
2.  **`SequenceSession`**: Reliability and Congestion Control.
3.  **`S: NodeStore`**: Persistence (SQLite, FS, or In-Memory).
4.  **`T: Transport`**: Delivery mechanism.

## 2. Virtual Hub (Chaos Engine)

The `VirtualHub` is a central coordinator for simulated swarms. It acts as a
virtual router and impairment injector.

### Impairment Model

The Hub applies a pipeline of impairments to every packet before delivery:

1.  **Drop Filter**: Random packet loss based on a probability curve (supports
    burst loss/Gilbert-Elliot model).
2.  **Delay Pipe**: A `DelayQueue` that holds packets for a duration ($Latency +
    Jitter$).
3.  **Partition Table**: A dynamic whitelist/blacklist that can isolate groups
    of nodes (simulating network partitions).
4.  **Blackout Engine**: Silences a node or a link for a fixed duration to test
    re-synchronization.

## 3. Hybrid Connectivity (Real + Virtual)

An essential feature of the benchmark suite is the ability to bridge simulated
environments with the real Tox network via a **Gateway Node**.

### Gateway Logic

1.  The Gateway node is an instance of `MerkleToxNode` that implements **two**
    transports: `SimulatedTransport` (facing the swarm) and `ToxTransport`
    (facing the internet).
2.  **Promotion**: When a simulated node sends a packet to a `PublicKey` not
    present in the `VirtualHub`, the Hub routes it to the Gateway. The Gateway
    re-emits the packet onto the real Tox network.
3.  **Demotion**: When the real Tox instance receives a packet, the Gateway
    injects it into the `VirtualHub` directed at the appropriate virtual peer.

## 4. Benchmark TUI Design

The benchmark application is a `ratatui`-based dashboard for observing swarm
convergence and performance. It is implemented in `merkle-tox-workbench/` and
follows a modular **MVU (Model-View-Update)** pattern for state management,
enabling testing and predictable UI state transitions.

### Tab 1: Fleet Overview (Network State)

-   **Global Indicators**: Total Nodes, Avg. RTT, Global DAG Convergence %,
    Heads Count.
-   **Node Grid**: A matrix of all instances. Color indicates status:
    -   `Green`: Synced (Heads match the global majority).
    -   `Yellow`: Speculative (Nodes received but not yet verified).
    -   `Cyan`: Downloading Blob (Multi-source fetch in progress).
-   **Live Metrics**: Real-time charts for RTT, CWND, and In-flight bytes for
    the selected node.

### Tab 2: DAG Viewer (Visual Tree)

-   **Graph View**: Visual tree showing the latest 50 nodes of the Merkle-DAG,
    highlighting branches and merge nodes.
-   **Node Status**: Detailed verification and speculative counts for the
    selected node.

### Tab 3: Topology & Chaos (Interference)

-   **Graph View**: Visual representation of peering relationships and active
    synchronization sessions.
-   **Legend**: Color-coded nodes (Virtual, Real, Gateway) and session links.

### Tab 4: Settings (Configuration)

-   **Structural Controls**: Adjust node counts, random seed, and topology
    template (requires restart).
-   **Runtime Controls**: Global impairment sliders (0-50% loss, 0-2000ms
    latency), message authoring rate, and manual message authoring (`m`) for the
    selected node.

## 5. Automated Scenarios

The suite includes pre-defined scripts to verify protocol robustness:

-   **Late Joiner**: 10 nodes author history for 5 minutes. An 11th node joins.
    Time how long until the 11th node's `VerifiedHeads == GlobalHeads`.
-   **Partition Heal**: Split a 20-node swarm into two groups of 10. Let each
    group author 100 messages. Heal the partition. Verify that both groups
    successfully merge branches and converge on identical heads.
-   **Key Rotation Storm**: Force a group re-key every 10 seconds in a high-loss
    environment. Verify that new members can still join and obtain the `K_conv`.
-   **Large Blob Swarm**: One node seeds a 50MB file. 50 nodes attempt to
    download it simultaneously via the Multi-Source Swarm Protocol. Measure
    bandwidth efficiency and Bao-verification CPU overhead.

## 6. Observability & Metrics API

Each `MerkleToxNode` exports a `NodeStatus` snapshot. The TUI polls this to
build its visualizations.

-   **Transport Metrics**: `cwnd`, `inflight_bytes`, `rtt_stats`,
    `retransmit_count`.
-   **DAG Metrics**: `heads` (List of hashes), `max_rank`, `verified_count`,
    `speculative_count`.
-   **Identity Metrics**: `authorized_devices` count, `current_generation`.
-   **Storage Metrics**: `db_size`, `write_latency_ms`.

## 7. Network Topology Templates

The benchmark supports defining swarms via topology recipes:

-   **`Mesh(N)`**: Every node is connected to every other node.
-   **`Star(N)`**: $N-1$ nodes connect to a single central Hub (or Gateway).
-   **`Dynamic(N, PeeringProbability)`**: Randomly generated graph.
-   **`Partitioned(Groups[])`**: Strictly separated clusters with optional
    Bridge nodes.

## 8. Implementation Refinements

-   **In-Memory Storage**: A `NodeStore` implementation that uses a simple
    `HashMap` for high-speed, non-persistent "transient" simulations.
-   **Virtual Clock**: The `TimeProvider` from `merkle-tox-core` will be used to
    allow the TUI to "Pause" the swarm or "Step" it forward frame-by-frame.
-   **Deterministic Simulation**: By seeding the RNG and using a manual
    `TimeProvider`, specific race conditions can be reproduced identically
    across runs.

## 9. Implementation Status

The benchmarking suite is **fully implemented** and available in
`merkle-tox-workbench/src/main.rs`.

### Completed Milestones

-   [x] **Refactor Bridge**: Extracted coordination logic into `MerkleToxNode`.
-   [x] **Transport/TimeProvider Traits**: Abstracted networking and time for
    deterministic simulation.
-   [x] **Virtual Hub**: Implemented in-memory router with Gilbert-Elliot loss.
-   [x] **TUI Workbench**: 4-tab dashboard with live metrics and DAG
    visualization.
-   [x] **Chaos Scenarios**: Automated Joiner, Partition, SenderKey Rotation,
    and Blob swarms.

### Future Enhancements

1.  **Metric Export**: Support for headless benchmark runs with CSV/JSON output.
2.  **Persistence Stress**: Integration with `merkle-tox-sqlite` for disk I/O
    bottleneck testing.
3.  **WASM Support**: Compiling the simulation hub to WASM for browser-based
    swarm visualizations.
