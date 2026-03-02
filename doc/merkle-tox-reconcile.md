# Merkle-Tox Sub-Design: Set Reconciliation (`tox-reconcile`)

## Overview

Merkle-Tox primarily uses heads-based reconciliation (`merkle-tox-sync.md`),
which scales linearly with concurrent branches. For large groups, Merkle-Tox
uses **Invertible Bloom Lookup Tables (IBLT)** via `tox-reconcile`.

`tox-reconcile` identifies differences between sets of message hashes in $O(1)$
or $O(D)$ communication (where $D$ is the number of differences), regardless of
total history size.

## 1. Algorithm: Invertible Bloom Lookup Tables

An IBLT is a probabilistic data structure that allows recovery of elements in a
set difference.

### A. Structure

An IBLT "Sketch" consists of an array of **Cells**. `IbltCell` is serialized as
a **MessagePack Array**.

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

-   **Algorithm**: The `hash_sum` is derived from the first 8 bytes of
    `blake3::keyed_hash(K_iblt, element_id)`: `K_iblt = Blake3-KDF("merkle-tox
    v1 iblt-conv-key", K_conv || conversation_id)`
-   **Security**: Keying `hash_sum` with $K_{iblt}$ (derived from $K_{conv}$)
    ensures unauthorized parties cannot precompute valid `hash_sum` values,
    preventing external sketch poisoning.
-   **Residual Risk**: All authorized members of a conversation share the same
    $K_{iblt}$. An authorized-but-adversarial member can compute valid
    `hash_sum` values for their own crafted sketches. The residual risk is
    bounded by the per-peer CPU budget on sketch decoding (§3.C) and the
    exponential blacklist escalation defined in `merkle-tox-sync.md`.
-   **Execution**: The mapping functions ($k_n$) use separate public context
    strings (e.g., `"merkle-tox v1 iblt k0"`). The `hash_sum` uses the keyed
    hash above. Both are computed in a single pass over the element ID to
    minimize CPU overhead.

### B. Hashing Strategy

To map an ID to $K$ cells ($K=3$ or $K=4$), implementations MUST use **Keyed
Blake3**. Each of the $K$ mapping functions uses a unique context string (e.g.,
`"merkle-tox v1 iblt k0"`). This ensures independent distribution across cells
using a single hash primitive.

### C. Operations

-   **Insert(ID)**: Map the ID to $K$ cells (using independent hash functions)
    and increment their counts, XOR the ID into `IdSum`, and XOR the secondary
    hash into `HashSum`.
-   **Difference(SketchA, SketchB)**: Subtracting two sketches performs
    cell-wise subtraction of `Count` and XORing of `IdSum` and `HashSum`. The
    result represents the set $(A \setminus B) \cup (B \setminus A)$.
-   **Peeling (Decoding)**: Implementations MUST use a **Queue-Based (Linear)
    Peeling Algorithm** to guarantee O(m) worst-case CPU:
    1.  **Seed**: Scan all $m$ cells once. Enqueue cells where `Count == ±1`.
    2.  **Peel**: Dequeue a cell. `Count == 1` indicates an element in A but not
        B; `Count == -1` indicates B but not A. Validate the `HashSum`. Remove
        the element's effect from its $K$ mapped cells; enqueue any that become
        `Count == ±1`.
    3.  **Terminate**: The queue empties naturally. No outer retry loop exists.
    4.  **Extracted Capacity Cap ($D_{max}$)**: If extracted elements exceed the
        tier's $D_{max}$ (§2.B), the decoder MUST abort and return
        `SYNC_RECON_FAIL`, bounding output size and memory.
    5.  **Complexity**: Initial scan is O(m). Each extraction touches $K$ cells.
        Total work is O(m + K × D), which is O(m) since D ≤ D_max ≈ m / 1.5.

## 2. Integration with Merkle-Tox

IBLTs augment or replace the `SYNC_HEADS` exchange in large-scale swarms.

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

Merkle-Tox uses fixed sizing tiers. A tier is selected based on the estimated
difference size $D$.

Tier   | Cells ($m$) | $D_{max}$ | Wire Size | Transport Method
:----- | :---------- | :-------- | :-------- | :-------------------------
Tiny   | 16          | 10        | ~700B     | Lossy Multicast (1 packet)
Small  | 64          | 40        | ~2.8KB    | Reliable Unicast (3 pkts)
Medium | 256         | 170       | ~11KB     | Reliable Unicast
Large  | 1024        | 680       | ~45KB     | Reliable Unicast

-   **Heuristic**: $m \approx 1.5 \times D_{max}$ ensures a decoding success
    probability $> 99\%$ for legitimate sketches.
-   **$D_{max}$ (Extracted Capacity Cap)**: The decoder MUST abort if the number
    of extracted elements exceeds $D_{max}$ for the tier (the hard upper bound
    enforced by the queue-based peeling algorithm, §1.C).
-   **MTU Constraint**: Only the **Tiny** tier is guaranteed to fit within a
    single Tox custom packet (MTU ~1300B). Larger tiers require `tox-sequenced`
    reassembly.

### C. Multi-Level Reconciliation

When differences exceed single sketch capacity:

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

If peeling fails to recover the set difference for a received `SYNC_SKETCH`:

1.  The responder MUST reply with a `SYNC_RECON_FAIL` message containing the
    `SyncRange` and the `Tier` that failed.
2.  Upon receiving `SYNC_RECON_FAIL`, the initiator MUST **Promote** the request
    for that range to the next larger tier (e.g., Small -> Medium).
3.  If the `Large` tier fails, the initiator SHOULD fallback to **Level 0
    (Heads-based)** sync for that specific range or shard.

### C. Per-Peer CPU Budget (Token Bucket)

To prevent DoS via CPU exhaustion, each responder enforces a **per-peer CPU
budget** using a token bucket, directly capping the defender's resource
consumption regardless of attacker behavior. No PoW challenge/response protocol
is needed.

1.  **Budget**:
    -   Each authorized peer is assigned a token bucket of
        `SKETCH_CPU_BUDGET_MS` (500) milliseconds of IBLT decoding time per
        `SKETCH_CPU_WINDOW_MS` (60,000 = 1 minute).
    -   The bucket refills at a steady rate (≈8.3ms per second). Tokens are
        consumed by the wall-clock time spent decoding that peer's sketches.
2.  **Tiered Cost**:
    -   **Tiny/Small Tiers**: Negligible decoding cost (~0.01ms). Effectively
        free under the budget.
    -   **Medium/Large Tiers**: Non-trivial decoding cost (~0.1–1ms). A peer
        sending legitimate Medium sketches at normal sync intervals
        (`RECONCILE_UNICAST_INTERVAL_MS = 300000`) consumes a negligible
        fraction of their budget.
3.  **Enforcement**:
    -   Before decoding a sketch, the responder checks the sender's remaining
        budget. If insufficient tokens remain, the responder replies with
        `SYNC_RATE_LIMITED` (including the number of milliseconds until the
        bucket has enough tokens) and discards the sketch without decoding.
    -   **Rationale**: A token bucket provides a hard cap on receiver CPU
        consumption, whereas PoW only provides a probabilistic deterrent.
4.  **Blacklisting Integration**:
    -   If a peer's sketches consistently fail decoding (peeling failure or
        $D_{max}$ cap exceeded), the existing blacklist escalation
        (`merkle-tox-sync.md` §2) applies. Blacklisted peers have their budget
        set to zero for the blacklist duration.
    -   This separates rate-limiting (honest peers under normal load) from
        punishment (peers sending garbage).

## 4. Synchronization Stages

`tox-reconcile` supports the following synchronization stages:

1.  **Unicast Reconciliation**: Peer A sends a sketch to Peer B. Peer B decodes
    the difference and immediately sends the missing nodes to A.
2.  **Multicast Gossip**: A node multicasts a small sketch to a Tox Group. All
    group members compare it against their local state, allowing a single packet
    to identify missing data across a 1,000-node swarm.
3.  **IBLT-Fountain Hybrid**: For large sets, IBLT identifies *which* hashes are
    missing, and Fountain Coding (Erasure Coding) broadcasts the *content* of
    those nodes to ensure all peers converge simultaneously without redundant
    data transmissions.

## 5. Maintenance & Persistence

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

`merkle-tox-core` provides a storage-agnostic interface for sketches.

#### `ReconciliationStore` (Sketch Index)

Handles the storage and retrieval of serialized IBLT sketches.

-   `put_sketch(conv_id, range, sketch)`: Persists a serialized sketch.
-   `get_sketch(conv_id, range)`: Retrieves a sketch for a specific range.

Both `merkle-tox-sqlite` and `merkle-tox-fs` implement this trait to provide
durable reconciliation state.

## 6. Transport & Multicast Strategy

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

## 7. Security & Privacy

### A. Poisoning Resistance

Mitigations against algorithmic CPU/memory poisoning:

-   **Against external/unauthorized parties**: The `hash_sum` is computed via
    `blake3::keyed_hash(K_iblt, element_id)` where $K_{iblt}$ is derived from
    $K_{conv}$. An external party without $K_{conv}$ cannot compute valid
    `hash_sum` values, so any sketch they craft will fail the `HashSum`
    validation on the first extracted element and be rejected immediately.
-   **Against authorized members**: The mandatory **Queue-Based Peeling
    Algorithm** (§1.C) eliminates algorithmic poisoning as an attack vector. The
    decoder performs O(m) work regardless of sketch contents. There is no
    iterative loop an attacker can force into worst-case behavior. The
    **Extracted Capacity Cap** ($D_{max}$, §2.B) bounds output size per tier.
    Together, an authorized member with full knowledge of $K_{iblt}$ cannot make
    the decoder perform more work or allocate more memory than an honest sketch
    of the same tier. Aggregate CPU consumption from any single peer is
    hard-capped by the per-peer token bucket (§3.C), and persistent offenders
    are subject to exponential blacklist escalation (see `merkle-tox-sync.md`).
