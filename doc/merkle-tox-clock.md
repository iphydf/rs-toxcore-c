# Merkle-Tox Sub-Design: Network Time Protocol (`tox-clock`)

## Overview

Merkle-Tox requires a globally consistent clock to linearize concurrent events.
Implements a **Median-based Consensus Clock** with Round-Trip Time (RTT)
compensation. Monotonicity is enforced via slewing (§3); causal display ordering
uses `effective_timestamp` (§3).

## 1. Algorithm: Byzantine-Resilient Median

Each node maintains a single "Network Time" ($T_{net}$) derived from the offsets
of a bounded set of trusted peers.

### Calculation (The "Trusted Core" Approach)

1.  **Offset Discovery**: Node A measures time offset with Peer B, compensating
    for network latency (RTT).
2.  **Sample Collection (Primary Consensus)**: Node A maintains a global table
    of offsets, *exclusively* including peers in the user's explicit Tox
    **Friend List** (bidirectional consent established).
    -   **Fallback Consensus**: If the user has 0 online friends, the client
        pools authorized identities across all shared rooms.
3.  **Per-Identity Grouping**: Offsets MUST be grouped by **Logical Identity**
    (`author_pk` / Master Seed). Multiple devices per identity are averaged into
    a single offset, ensuring one vote per user.
4.  **Median Selection**: The consensus offset is the **median** of the
    per-identity offsets from the selected consensus pool.
5.  **Strict Sanity Bound**: The final median offset MUST be **hard-capped** at
    $\pm 5$ minutes from the local OS system clock. If consensus attempts to
    drag the clock further, the engine clamps the offset and SHOULD flag a UI
    warning.
6.  **$T_{net}$ Derivation**: $T_{net} = T_{local} +
    \text{Clamped\_Median}(Offsets)$.

## 2. Measurement (Transport Integration)

Time synchronization measurements are integrated into `tox-sequenced`,
eliminating "ARQ Jitter" (retransmission delay) and using existing RTT
heartbeats.

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
of authenticated peer connections to significantly shift the clock. Outliers are
naturally ignored.

### Clock Slewing (Monotonicity)

To prevent clock jumps, $T_{net}$ is updated via **slewing**:

-   **Limit**: The slewing rate is capped at **±1%**. One second of "network
    time" will take between 0.99s and 1.01s of local real time.
-   **Monotonicity**: Network time NEVER moves backward. If the local clock is
    ahead of consensus, network time slows down but continues to advance.
-   **Hard-Sync Threshold**: If the observed drift between $T_{local}$ and
    consensus is **> 10 minutes**, slewing is disabled and the client SHOULD
    prompt the user to perform a "Hard Sync" to jump the clock to the target
    consensus.

### Sybil Resistance

**External Sybil Resistance**: **Friend List** prioritization resists external
Sybil attacks. Attackers cannot force users to add Sybils as explicit friends,
isolating timelines from public rooms.

**Internal Sybil Resistance**: Per-identity grouping (§1, Step 3) prevents
authorized users from amplifying votes via multiple devices. In the fallback
consensus scenario, an attacker must control $>50\%$ of the distinct **logical
identities** across all shared rooms to shift the clock, and their maximum
impact is contained by the 5-minute hard bound.

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
-   **Resolution**: While this reduces raw offset precision, the jitter is
    negligible for DAG linearization and is smoothed out by the Median
    Consensus.

### Observer-Relative Validity & Quarantine Rules

**Observer-Relative Validity Window** prevents timestamp manipulation
(backdating/future-dating). Timestamp validity is checked against the observer's
$T_{net}$, **not** against parent timestamps, preventing a fast clock from
ratcheting downstream timestamps into the future.

1.  **Causal Lower Bound**: A strict wall-clock lower bound would quarantine
    legitimate offline messages. Instead, a node's timestamp MUST be $\ge$ the
    timestamp of its oldest parent minus 10 minutes (allowing for clock skew
    between parent author and replier), preventing backdating before the
    conversation started while allowing offline sync.
2.  **Upper Bound**: A node's `network_timestamp` MUST NOT be more than **10
    minutes** in the future relative to the observer's current $T_{net}$.
3.  **No Parent-Relative Constraint**: There is deliberately **no** requirement
    that a node's timestamp be $\ge$ the maximum timestamp of its parents. A
    reply authored at 12:00 to a message timestamped at 12:05 (due to clock
    skew) is valid as long as both timestamps fall within the $\pm 10$ minute
    window at the time of observation. Causal ordering is enforced by the DAG
    structure (topological rank), not by timestamps.
4.  **Quarantine**: Nodes that violate these rules are **Quarantined**:
    -   They are stored in the `Speculative` area of the database.
    -   They are **not** displayed in the UI.
    -   They **cannot** be used as parents for new nodes authored by the local
        client.
    -   **Vouching Exception**: A quarantined Admin node **STILL provides a
        structural vouch** for its parents (up to the cap defined in
        `merkle-tox-sync.md`), ensuring an attacker cannot "hide" legitimate
        history by referencing it from a future-dated node.
    -   Once the network time catches up (for future-dated nodes), they are
        automatically moved out of quarantine and into the active DAG.

### Effective Timestamp (Display Ordering)

The raw `network_timestamp` may violate causal intuition due to clock skew.
Clients compute an **effective timestamp** for monotonic UI rendering without
contaminating protocol logic:

$$T_{eff}(N) = \max\bigl(N.\text{network\_timestamp},\; \max_{P \in \text{parents}(N)} T_{eff}(P)\bigr)$$

-   **Applicability**: This formula applies only to decrypted nodes. Opaque
    nodes (undecrypted WireNodes in the Opaque Store) lack a `network_timestamp`
    and MUST NOT participate in `effective_timestamp` calculations. Their
    display ordering is deferred until promotion.
-   **Presentation-Layer Only**: `effective_timestamp` is used exclusively for
    display ordering and MUST NOT be used for any protocol-level decision
    (quarantine evaluation, key expiration, rotation triggers, `expires_at`
    checks, or Median Consensus input). All protocol logic uses the raw
    `network_timestamp` or $T_{net}$.
-   **Bounded Ratchet**: The effective timestamp can drift at most 10 minutes
    ahead of reality (due to the upper bound). It converges back to reality
    reality because real-world time continues to advance; once true network time
    surpasses the spoofed timestamp, new nodes naturally begin using their own
    current, accurate timestamps.
-   **Not Persisted**: `effective_timestamp` is computed on-the-fly from the DAG
    structure. It does not need to be stored, transmitted, or agreed upon by
    peers.

## 4. Usage in Merkle-Tox

Every `MerkleNode` includes the `network_timestamp` as seen by the author at the
moment of creation.

### Linearization Rule

When a client renders a conversation, it sorts nodes by:

1.  **Topological Rank**: A node always appears after its parents.
2.  **Effective Timestamp**: If nodes are concurrent (neither is a parent of the
    other), sort by `effective_timestamp` (Section 3).
3.  **Hash Tie-break**: If effective timestamps are identical, sort
    lexicographically by the Blake3 `hash`.

## 5. Persistence

The current `GlobalOffset` is stored in the SQLite `global_state` table. Upon
restart, the clock initializes with the last known offset to maintain continuity
until new samples are collected.
