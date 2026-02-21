# Merkle-Tox Sub-Design: Network Time Protocol (`tox-clock`)

## Overview

Merkle-Tox requires a tamper-resistant, monotonic, and globally consistent clock
to linearize concurrent events in a decentralized Directed Acyclic Graph (DAG).
Since system clocks are unreliable and easily manipulated, we implement a
**Median-based Consensus Clock** with Round-Trip Time (RTT) compensation.

## 1. Algorithm: Byzantine-Resilient Median

Each node maintains a single, global view of "Network Time" ($T_{net}$) derived
from the offsets of all trusted peers.

### Calculation

1.  **Offset Discovery**: Node A measures the time difference (offset) between
    itself and Peer B using a time synchronization exchange to compensate for
    network latency (RTT).
2.  **Sample Collection**: Node A maintains a global table of offsets for all
    active, authenticated peers.
3.  **Median Selection**: The consensus offset is the **weighted median** of all
    collected samples.
    -   *Weighting*: Peers with longer-standing connections or higher trust
        (e.g., manually verified friends) may be given higher weight.
4.  **$T_{net}$ Derivation**: $T_{net} = T_{local} + Median(Offsets)$.

## 2. Measurement (Transport Integration)

Time synchronization measurements are integrated into the `tox-sequenced`
transport layer. This eliminates "ARQ Jitter" (retransmission delay) and uses
existing RTT heartbeats.

1.  **Transport PING/PONG**: The transport layer exchanges timestamps (Origin,
    Receive, Transmit) as part of its routine RTT measurement.
2.  **Sample Calculation**: When a PONG is received at $T_4$:
    -   $RTT = (T_4 - T_1) - (T_3 - T_2)$
    -   $Sample\_Offset = ((T_2 - T_1) + (T_3 - T_4)) / 2$
3.  **Interface**: The `SequenceSession` exposes the most recent `Sample_Offset`
    to the `NetworkClock` logic.

## 3. Tamper-Resistance Mechanisms

### Byzantine Fault Tolerance (BFT)

By using the **Median** instead of the Mean, an attacker must control $> 50\%$
of your authenticated peer connections to significantly shift your clock.
Outliers (e.g., a peer claiming the year 1970 or 2038) are naturally ignored by
the median calculation.

### Clock Slewing (Monotonicity)

To prevent the clock from "jumping" (which breaks UI ordering and timers),
$T_{net}$ is updated via **slewing**:

-   **Limit**: The slewing rate is capped at **±1%**. One second of "network
    time" will take between 0.99s and 1.01s of local real time.
-   **Monotonicity**: Network time NEVER moves backward. If the local clock is
    ahead of consensus, network time slows down but continues to advance.
-   **Hard-Sync Threshold**: If the observed drift between $T_{local}$ and
    consensus is **> 10 minutes**, slewing is disabled and the client SHOULD
    prompt the user to perform a "Hard Sync" to jump the clock to the target
    consensus.

### Sybil Resistance

Only offsets from peers with a valid Tox `PublicKey` who are present in the
user's friend list or a shared conversation are included in the consensus. This
prevents an anonymous attacker from flooding the network with fake time samples.

### Temporal Fingerprinting Protection

To prevent a peer from using precise clock offsets to track a user across
different sessions or rooms, Merkle-Tox introduces **Anti-Fingerprinting
Jitter**:

-   **Mechanism**: The `tox-sequenced` layer SHOULD inject a random offset
    (between `-TIME_JITTER_MS` and `+TIME_JITTER_MS`, where `TIME_JITTER_MS =
    5`) into the $T_2$ (Receive) and $T_3$ (Transmit) timestamps before sending
    a PONG.
-   **Impact**: This prevents a peer from calculating the sub-millisecond
    hardware clock drift that is unique to specific hardware oscillators.
-   **Resolution**: While this reduces the precision of the raw offset sample,
    the jitter is negligible for DAG linearization and is naturally smoothed out
    by the **Median Consensus** algorithm.

### Hard Monotonicity & Quarantine Rules

To prevent attackers from manipulating history by camping in the future or
rewriting the past with bogus timestamps, Merkle-Tox enforces **Hard
Monotonicity**:

1.  **Lower Bound**: A node's `network_timestamp` MUST be $\ge$ the maximum
    `network_timestamp` of all its parent nodes.
2.  **Upper Bound**: A node's `network_timestamp` MUST NOT be more than **10
    minutes** in the future relative to the observer's current $T_{net}$.
3.  **Quarantine**: Nodes that violate these rules are **Quarantined**:
    -   They are stored in the `Speculative` area of the database.
    -   They are **not** displayed in the UI.
    -   They **cannot** be used as parents for new nodes authored by the local
        client.
    -   **Vouching Exception**: A quarantined Admin node **STILL provides a
        structural vouch** for its parents (up to the cap defined in
        `merkle-tox-sync.md`). This ensures that an attacker cannot "hide"
        legitimate history by referencing it from a future-dated node.
    -   Once the network time catches up (for future-dated nodes), they are
        automatically moved out of quarantine and into the active DAG.

## 4. Usage in Merkle-Tox

Every `MerkleNode` includes the `network_timestamp` as seen by the author at the
moment of creation.

### Linearization Rule

When a client renders a conversation, it sorts nodes by:

1.  **Topological Rank**: A node always appears after its parents.
2.  **Network Time**: If nodes are concurrent (neither is a parent of the
    other), sort by `network_timestamp`.
3.  **Hash Tie-break**: If timestamps are identical, sort lexicographically by
    the Blake3 `hash`.

## 5. Persistence

The current `GlobalOffset` is stored in the SQLite `global_state` table. Upon
restart, the clock initializes with the last known offset to maintain continuity
until new samples are collected.
