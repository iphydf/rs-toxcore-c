# Merkle-Tox Sub-Design: Set Reconciliation (`tox-reconcile`)

## Overview

Merkle-Tox primarily uses a heads-based reconciliation strategy
(`merkle-tox-sync.md`). While effective for small groups, this approach scales
linearly with the number of concurrent branches (heads). To support large group
chats and background synchronization of large histories, we introduce
**Invertible Bloom Lookup Tables (IBLT)** via the `tox-reconcile` library.

`tox-reconcile` provides a way for two peers to identify the differences between
their sets of message hashes in $O(1)$ or $O(D)$ communication (where $D$ is the
number of differences), regardless of the total number of messages in the
history.

## 1. Algorithm: Invertible Bloom Lookup Tables

An IBLT is a probabilistic data structure that allows recovery of elements in a
set difference.

### A. Structure

An IBLT "Sketch" consists of an array of **Cells**. To align with Merkle-Tox
compact serialization, `IbltCell` is serialized as a **MessagePack Array
(Positional)**.

```rust
struct IbltCell {
    /// ID 0: Signed count
    pub count: i32,
    /// ID 1: XOR sum of 32-byte Blake3 hashes
    pub id_sum: [u8; 32],
    /// ID 2: XOR sum of truncated 64-bit check-hashes
    pub hash_sum: u64,
}
```

#### HashSum Details

-   **Algorithm**: The `hash_sum` is derived from the first 8 bytes of a **Keyed
    Blake3** hash.
-   **Context**: `"merkle-tox v1 iblt checksum"`.
-   **Execution**: While the mapping functions ($k_n$) and the `hash_sum` use
    different contexts, they are computed in a single pass over the element ID
    to minimize CPU overhead.

### B. Hashing Strategy

To map an ID to $K$ cells ($K=3$ or $K=4$): - We use **Keyed Blake3** for
performance and security. - **Contexts**: Each of the $K$ mapping functions uses
a unique context string (e.g., `"merkle-tox v1 iblt k0"`, `"merkle-tox v1 iblt
k1"`, etc.). - This ensures independent distribution across cells without
requiring multiple hash implementations.

### C. Operations

-   **Insert(ID)**: Map the ID to $K$ cells (using independent hash functions)
    and increment their counts, XOR the ID into `IdSum`, and XOR the secondary
    hash into `HashSum`.
-   **Difference(SketchA, SketchB)**: Subtracting two sketches is done by
    performing a cell-wise subtraction of `Count` and XORing `IdSum` and
    `HashSum`. The resulting "Difference Sketch" represents the set $(A
    \setminus B) \cup (B \setminus A)$.
-   **Peeling (Decoding)**: Iteratively find cells with a `Count` of 1 or -1.
    -   If `Count == 1`: The `IdSum` is an element present in A but missing in
        B.
    -   If `Count == -1`: The `IdSum` is an element present in B but missing in
        A.
    -   After extracting an element, its effect is removed from all $K$ cells it
        was mapped to.

## 2. Integration with Merkle-Tox

IBLTs are used to augment or replace the `SYNC_HEADS` exchange in large-scale
swarms.

### A. The `SYNC_SKETCH` Message

Peers exchange a compact sketch of their history.

```rust
struct SyncSketch {
    /// The Conversation ID (Genesis Hash).
    pub conversation_id: [u8; 32],
    /// The actual IBLT cells.
    pub cells: Vec<IbltCell>,
    /// The range of the DAG this sketch covers.
    pub range: SyncRange,
}

struct SyncRange {
    /// Minimum topological rank (inclusive).
    pub min_rank: u64,
    /// Maximum topological rank (inclusive).
    pub max_rank: u64,
}
```

### B. Standard Sizing Tiers

To ensure wire compatibility and transport, Merkle-Tox uses fixed sizing tiers.
A tier is selected based on the estimated difference size $D$.

Tier   | Cells ($m$) | Max Diff ($D$) | Wire Size | Transport Method
:----- | :---------- | :------------- | :-------- | :-------------------------
Tiny   | 16          | ~10            | ~700B     | Lossy Multicast (1 packet)
Small  | 64          | ~40            | ~2.8KB    | Reliable Unicast (3 pkts)
Medium | 256         | ~170           | ~11KB     | Reliable Unicast
Large  | 1024        | ~680           | ~45KB     | Reliable Unicast

-   **Heuristic**: $m \approx 1.5 \times D$ ensures a decoding success
    probability $> 99\%$.
-   **MTU Constraint**: Only the **Tiny** tier is guaranteed to fit within a
    single Tox custom packet (MTU ~1300B). Larger tiers require `tox-sequenced`
    reassembly.

### C. Multi-Level Reconciliation

To handle cases where the number of differences exceeds the capacity of a single
sketch:

1.  **Level 0 (Heads)**: Exchange current tips (standard sync).
2.  **Level 1 (Recent History Sketch)**: A small IBLT covering the last ~500
    messages.
3.  **Level 2 (Sharded Archive)**: Large history is split into logical "shards".
    -   **Deterministic Sharding**: Shards are defined by **Topological Rank
        ranges** (e.g., Shard 0: Rank 0-9999, Shard 1: 10000-19999).
    -   Peers compare shard-level Blake3 checksums. If a checksum differs, they
        exchange a **Medium** sketch for that specific shard.

## 3. Difference Estimation & Error Protocol

### A. Tier Selection (Initiator)

-   **Multicast Gossip**: Always uses the **Tiny** tier.
-   **Background Unicast (`RECONCILE_UNICAST_INTERVAL_MS = 300000`)**: Defaults
    to **Small** tier (covers most day-to-day syncs).
-   **Deep Sync**: Defaults to **Medium** tier.
-   **Adaptive Scaling**: If a sync session recently failed with a smaller tier,
    the initiator promotes the request to the next larger tier.

### B. Decoding Failure (Responder)

If a responder receives a `SYNC_SKETCH` and the peeling process fails to recover
the set difference:

1.  The responder MUST reply with a `SYNC_RECON_FAIL` message containing the
    `SyncRange` and the `Tier` that failed.
2.  Upon receiving `SYNC_RECON_FAIL`, the initiator MUST **Promote** the request
    for that range to the next larger tier (e.g., Small -> Medium).
3.  If the `Large` tier fails, the initiator SHOULD fallback to **Level 0
    (Heads-based)** sync for that specific range or shard.

### C. Adaptive Proof-of-Work (PoW) Binding

To prevent Denial of Service (DoS) attacks where an attacker floods a peer with
large, complex sketches to exhaust their CPU, Merkle-Tox uses **Adaptive
Reconciliation PoW**:

1.  **Tiered Access**:
    -   **Tiny/Small Tiers**: Always free to process.
    -   **Medium/Large Tiers**: Requires a PoW solution bound to the specific
        sync request.
2.  **Dynamic Difficulty Consensus**:
    -   Difficulty is not a fixed constant. Instead, peers include a
        **Difficulty Recommendation** ($D_{rec}$) in their `Announcement` or
        `SYNC_HEADS`.
    -   A node calculates the **Effective Difficulty** ($D_{eff}$) as the
        **weighted median** of all recommendations from authorized members of
        the conversation.
3.  **Hysteresis & Slewing**:
    -   $D_{eff}$ can only change by **±1 bit** per 24-hour period to prevent
        instability or "Difficulty Flapping".
4.  **Mechanism**:
    -   Responder sends a `RECON_POW_CHALLENGE` containing a unique nonce and
        the current $D_{eff}$.
    -   Initiator must solve the puzzle and reply with the solution.
    -   This ensures that "Sketch Spamming" is computationally expensive for an
        attacker (scaling with the group's collective experience of spam) but
        negligible for a legitimate peer performing a deep sync.

## 4. Sophistication & Evolution

The `tox-reconcile` crate supports the following stages of synchronization
sophistication:

1.  **Unicast Reconciliation**: Peer A sends a sketch to Peer B. Peer B decodes
    the difference and immediately sends the missing nodes to A.
2.  **Multicast Gossip**: A node multicasts a small sketch to a Tox Group. All
    group members compare it against their local state. This allows a single
    packet to identify missing data across a 1,000-node swarm.
3.  **IBLT-Fountain Hybrid**: For large sets, IBLT identifies *which* hashes are
    missing, and Fountain Coding (Erasure Coding) is used to broadcast the
    *content* of those nodes to ensure all peers converge simultaneously without
    redundant data transmissions.

## 4. Maintenance & Persistence

### A. Computational Cost

Hashing every message into an IBLT can be CPU-intensive for mobile devices.

-   **Incremental Updates**: Merkle-Tox maintains "Hot Sketches" in-memory. When
    a new node is verified, it is added to the running sketch via the additive
    property (XOR/Increment).
-   **Redaction & Pruning**:
    -   When a node is removed (e.g., during pruning), it is **subtracted** from
        the in-memory sketch (XOR/Decrement).
    -   **Persistence**: Since in-memory sketches can be lost on restart,
        Merkle-Tox MUST checkpoint "Shard Sketches" when a shard is filled or
        every 1,000 modified nodes (`SKETCH_CHECKPOINT_INTERVAL = 1000`) via the
        **`ReconciliationStore`** trait.
    -   **Reconstruction**: If a checkpoint is missing or corrupted, the sketch
        is rebuilt on-demand by scanning the `NodeStore` for the target range.

### B. Storage Interfaces

To avoid hard dependencies on specific database engines, `merkle-tox-core`
provides a storage-agnostic interface for sketches.

#### `ReconciliationStore` (Sketch Index)

Handles the storage and retrieval of serialized IBLT sketches.

-   `put_sketch(conv_id, range, sketch)`: Persists a serialized sketch.
-   `get_sketch(conv_id, range)`: Retrieves a sketch for a specific range.

Both `merkle-tox-sqlite` and `merkle-tox-fs` implement this trait to provide
durable reconciliation state.

## 5. Transport & Multicast Strategy

Set reconciliation is deployed differently depending on the network context:

### A. Multicast Gossip (Lossy)

-   Nodes MUST broadcast a **Tiny** sketch to the Tox Group at a fixed interval
    (`RECONCILE_GOSSIP_INTERVAL_MS = 60000`).
-   This identifies if any peers have "drifted" from the global consensus.
-   If a peer receives a multicast sketch and cannot decode a difference of 0,
    it initiates a **Reliable Unicast** sync with the broadcaster.

### B. Deep Reconciliation (Reliable)

-   For synchronization of long-term history, peers use **Medium** or **Large**
    sketches.
-   These are sent via `tox-sequenced` to ensure all fragments arrive and the
    sketch is whole before decoding.

## 6. Security & Privacy

### A. Poisoning Resistance

An attacker could send a "garbage" sketch designed to make the peeling process
consume excessive CPU.

-   **Protection**: The decoder enforces a strict limit on the number of peeling
    iterations and validates the `HashSum` of every extracted ID to ensure it
    hasn't been tampered with.
