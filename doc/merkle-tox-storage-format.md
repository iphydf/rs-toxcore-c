# Merkle-Tox File-Based Storage Specification (v1)

This document defines a production-quality, filesystem-based storage format for
Merkle-Tox.

## Design Principles

1.  **Simplicity First**: The format must be implementable in minimal C code
    (~500-1000 LOC) using only standard POSIX syscalls and a minimal MessagePack
    library.
2.  **Zero-Dependency**: Rely on the OS (filesystem atomicity, page cache,
    `mmap`) instead of embedding a complex database engine.
3.  **Durability by Design**: Every state transition must be crash-safe. Partial
    writes must be detectable and never lead to DAG corruption.
4.  **Transparency**: The storage structure should be human-readable/navigable
    via standard CLI tools (`ls`, `cd`, `hexedit`).
5.  **C Compatibility**: Performance-critical paths (lookups) must use simple
    structures like sorted arrays to enable `bsearch()` on memory-mapped data.

## 1. Directory Structure

The storage root is a directory (e.g., `~/.merkle-tox/storage/`).

```text
/storage/
├── .lock               # Global process-level lock
├── blacklist.bin       # Global Blacklist (Bad Actors)
├── objects/            # Global Content-Addressable Storage (Blobs)
│   ├── 00/             # Sharded by first byte of Hash
│   │   ├── [hash].data # Raw serialized Blob data
│   │   ├── [hash].info # Download status and bitmask (MsgPack)
│   │   └── [hash].bao  # Bao outboard verification tree
│   ├── ...
│   └── ff/
├── conversations/      # Conversation-specific metadata
│   └── [conv_id]/      # Hex-encoded Conversation ID
│       ├── .lock           # Conversation-level advisory lock
│       ├── state.bin       # Latest Heads and Generation metadata
│       ├── ratchet.bin     # Double-buffered active ChainKey table
│       ├── journal.bin     # Append-only log of recent Nodes (Hot)
│       ├── packs/          # Segmented historical Nodes (Cold Tier)
│       │   ├── [id].pack   # Bundled nodes
│       │   └── [id].idx    # Sorted index for this pack
│       ├── keys/           # Historical Conversation Keys (K_conv)
│       │   └── [generation].key # Raw 32-byte key for specific generation
│       ├── sketches/       # Cached Reconciliation Sketches
│       │   └── [range].bin # Serialized IBLT or other sketch
│       ├── permissions.bin # Persisted Effective Permissions cache
│       └── opaque/         # Undecryptable WireNodes (Opaque Tier)
│           ├── 0001.bin    # Segmented logs for cheap eviction
│           └── index.bin   # Volatile or persistent index for opaque nodes
└── global.bin          # Network clock offset and global settings
```

--------------------------------------------------------------------------------

## 2. Binary Encoding

Merkle-Tox uses two encoding styles depending on the performance requirements of
the file:

1.  **Positional MessagePack**: Metadata files with variable-length fields
    (`state.bin`, `permissions.bin`, `global.bin`) use the **Positional Array**
    format from `tox-proto`.
2.  **Fixed-Width Binary**: Files requiring $O(1)$ in-place updates
    (`ratchet.bin`) or Binary Search (`index.idx`) use flat, 8-byte aligned
    binary structures.

### 2.1. Atomicity & Durability

1.  **Metadata Updates**: Updates to `.bin` (excluding `journal.bin`) or `.idx`
    files **MUST** use the "Write-to-Temp + Fsync + Rename" pattern to ensure
    crash-safe atomicity on modern flash storage.
2.  **Journal Updates**: Updates to `journal.bin` **MUST** use `lseek(EOF)` +
    `write()`.
3.  **Durability Barrier**: `fsync()` calls MAY be deferred and coalesced (see
    Section 9). However, a full durability barrier **MUST** be completed before
    `state.bin` is updated.

--------------------------------------------------------------------------------

## 3. Concurrency & Locking

To prevent "lost updates" and data corruption when multiple threads or processes
access the same storage root, the following locking strategy is mandated:

### 3.1. Thread-Level Concurrency (Same Process)

Implementations **MUST** use internal synchronization (e.g., `Mutex` or
`RwLock`) to coordinate access to shared in-memory state and file handles.

### 3.2. Process-Level Concurrency (Different Processes)

Implementations **MUST** use **advisory file locking** (`flock` on Linux/POSIX,
`LockFileEx` on Windows):

1.  **Global Lock (`/storage/.lock`):** Acquired in **Shared Mode** (`LOCK_SH`)
    for general operations and **Exclusive Mode** (`LOCK_EX`) for global
    maintenance (like pruning orphans).
2.  **Conversation Lock (`/conversations/[conv_id]/.lock`):**
    *   **Shared Mode (`LOCK_SH`):** Required for reading `state.bin`,
        `ratchet.bin`, or the `index.idx`.
    *   **Exclusive Mode (`LOCK_EX`):** Required for any write operation
        (including `rename`) and the **Compaction** process.

### 3.3. Write-Safety (Read-Modify-Write)

When updating metadata (like adding a new head to `state.bin`):

1.  Acquire `LOCK_EX` on the conversation lock.
2.  Read the current `state.bin`.
3.  Modify the state in memory.
4.  Perform the Atomic Write sequence (Section 2.1).
5.  Release the lock.

--------------------------------------------------------------------------------

## 4. Storage Tiers

### 4.1. The Journal (Hot Tier)

To avoid the overhead of small files and multiple locking bottlenecks, all "Hot"
conversation events are multiplexed into the single `journal.bin`.

*   **Format:** `[JournalHeader] [Array<FramedRecord>] [OptionalFooter]`
*   **JournalHeader (16 bytes):** `[u64 generation_id] [u64 reserved]`
*   **FramedRecord:** `[u32 length] [u8[32] hash] [u8 type] [Payload]`
    *   **Type 0x01 (Node):** Hash is `blake3(Payload)`. Payload is `MsgPack([u8
        status, MerkleNode])`.
    *   **Type 0x02 (Vouch):** Hash is `blake3(Payload)`. Payload is
        `MsgPack([PhysicalDevicePk])`.
    *   **Type 0x03 (Blacklist):** Hash is `blake3(Payload)`. Payload is
        `MsgPack([Pk target, String reason])`.
    *   **Type 0x04 (Promotion):** Hash is `blake3(Payload)`. Payload is
        `MsgPack([NodeHash target])`.
    *   **Type 0x05 (Ratchet Advance):** Hash is `blake3(Payload)`. Payload is
        `MsgPack([NodeHash trigger, u64 sequence_number])`.
        *   Note: To preserve Forward Secrecy, `journal.bin` MUST NEVER store
            raw `chain_key`s. The `trigger` node hash is used to look up the
            `sender_pk`. Upon startup, the engine rebuilds the key cache in RAM
            by stepping the ratchet forward from the last compacted checkpoint
            up to this `sequence_number`.
*   **Tail-Commit Footer (Optional Optimization):** `[u32 magic_end] [u32
    record_count] [u8[32] journal_checksum] [IndexTable]`
    *   **Write Path**: The footer **SHOULD NOT** be written for every append.
        It is appended only during a **Clean Shutdown** or a **Coalesced
        Durability Barrier** (Section 9.1).
    *   **IndexTable:** An array of `[u8 type] [u8[32] hash] [u32 offset] [u8
        final_status]` for each record.
*   **Startup (The Fast Path):**
    1.  Read `state.bin` to get the `active_journal_id`.
    2.  Open `journal.bin` and read the `generation_id`. If they mismatch,
        truncate the journal immediately (Idempotency).
    3.  Seek to the end and check for a valid `Tail-Commit Footer` (`0x454E4421`
        -   "END!").
    4.  Verify the `journal_checksum` (Blake3 hash of all records).
    5.  If valid, **immediately populate** the in-memory Node Index (using
        `final_status`), Vouch Registry, and Local Blacklist using the
        `IndexTable`.
    6.  **Cleanup**: Before appending new records to the journal, the
        implementation **MUST** `ftruncate()` the file to remove the footer and
        restore the append-only record stream.
*   **Recovery (Deterministic Walking):**
    1.  If the footer is missing or invalid (e.g., after a crash), fall back to
        **Deterministic Walking** (starting at offset 16).
    2.  **Walk** the file: Read `length` and `hash`. Read `length` bytes.
    3.  Verify `blake3(Payload) == hash`.
    4.  If valid:
        *   For Type 0x01: Add node to index with its initial status.
        *   For Type 0x04: Update existing node status to Verified.
        *   For Type 0x05: Update volatile ratchet state.
        *   Move to the next record.
    5.  If invalid (hash mismatch or EOF), **stop and truncate** the journal at
        this boundary. No searching or scavenging is performed.* **Note on Data
        Loss**: In the rare event of a mid-file disk corruption, nodes following
        the corruption are discarded locally. The Merkle-Tox protocol will
        automatically re-sync these missing nodes from peers.
*   **Compaction**: When the journal is merged into the Cold Tier, only **Node**
    records are packed. Valid vouches and blacklists are carried forward into
    the new journal generation.

--------------------------------------------------------------------------------

## 5. Compaction (Incremental)

### 4.2. The Packed Tier (Cold Tier)

Historical nodes are bundled into `data.pack`.

#### 4.2.1. Index Format (`index.idx`)

| Offset         | Type        | Description                                  |
| :------------- | :---------- | :------------------------------------------- |
| `0`            | `u32`       | Magic Number (`0x4D544F58`)                  |
| `4`            | `u32`       | Fanout Bits ($B$): MUST be between 8 and 24. |
| `8`            | `u32`       | Bloom Filter K-Functions (MUST be between 1  |
:                :             : and 4).                                      :
| `12`           | `u32`       | Bloom Filter Size ($M$ in bytes).            |
| `16`           | `u8[M]`     | **Bloom Filter**: For fast "Not Found"       |
:                :             : rejection.                                   :
| `16+M`         | `u32[2^B]`  | **Fanout Table**: Cumulative counts (prefix  |
:                :             : sum) for hashes with prefix $\le i$.         :
| `16+M+4*2^B`   | `u32`       | Header Length ($L$)                          |
| `20+M+4*2^B`   | `MsgPack`   | Header: `{ "version": 1, "count": N }`       |
| `20+M+4*2^B+L` | `Record[N]` | Sorted Array of 56-byte records              |

#### 4.2.2. Index Record (56 bytes)

Offset | Type       | Description
:----- | :--------- | :----------------------------------------------------
`0`    | `[u8; 32]` | **NodeHash** (The primary key)
`32`   | `u64`      | **File Offset** (Location in `data.pack`)
`40`   | `u64`      | **Topological Rank**
`48`   | `u32`      | **Payload Length**: Size of serialized node in bytes.
`52`   | `u8`       | **Node Type** (0x01: Admin, 0x02: Content)
`53`   | `u8`       | **Status** (0x01: Verified, 0x02: Speculative)
`54`   | `u8`       | **Flags** (0x01: Banned Author)
`55`   | `u8`       | **Reserved** (Must be zero)

**Alignment Note**: The 56-byte record size is chosen to ensure 8-byte alignment
of all `u64` fields, optimizing performance for memory-mapped access across
64-bit architectures.

#### 4.2.3. Lookup Algorithm

To find an object by `hash`:

1.  **Journal Check:** Search the volatile index built from `journal.bin`.
2.  **Bloom Check:** Check the **Bloom Filter** in `index.idx`. If no match,
    skip this pack.
3.  **Fanout Lookup:** Use the first $B$ bits of the hash to look up the range
    $[low, high)$ in the **Fanout Table**.
4.  **Binary Search:** Perform **Binary Search** only within the Record Array
    from index $low$ to $high$.
5.  If found, use the `u64` offset to read from `data.pack`.

### 4.3. The Opaque Tier (Undecryptable)

Nodes that cannot yet be decrypted are stored in the `opaque/` directory as raw
`WireNode` MessagePack objects.

*   **Segments:** Nodes are appended to the current segment file (e.g.,
    `0001.bin`). When a segment reaches 10MB, a new one is created.
*   **Opaque Index (`index.bin`)**: To prevent duplicate processing, the
    implementation maintains a sorted binary index of all nodes in the opaque
    tier.
    *   **Format**: Sorted Array of `[u8[32] hash, u32 segment_id, u32 offset]`
        records.
    *   **Lookup**: Binary search ($O(\log N)$).
*   **Eviction (Root Carry-Forward):** If the total size of the `opaque/`
    directory exceeds 100MB, the implementation prepares to delete the oldest
    segment.
    1.  **Check Locks**: Skip any segment that has an active **Promotion Lock**
        (e.g., `0001.bin.lock`).
    2.  **Scan**: Perform a single linear scan of the segment about to be
        deleted.
    3.  **Promote**: Any **Admin** or **KeyWrap** nodes (the "Anchors") found in
        the segment **MUST** be re-appended to the newest segment.
    4.  **Delete**: Once the anchors are preserved, delete the old segment.
*   **Promotion Lock**: Before the engine begins a "Promotion Flow" (decrypting
    an opaque segment), it **MUST** create an advisory lock file
    (segment_id.lock) in the `opaque/` directory. This file SHOULD contain the
    current PID.
*   **Stale Lock Recovery**: On startup, any lock files referencing dead PIDs
    MUST be deleted.
*   **Deadlock Prevention:** This ensures that both the root of trust (keys) and
    nodes currently being processed are never evicted, while still effectively
    purging large volumes of unreadable history.
*   **Promotion (to Hot Tier):** Upon successful decryption, a node is read from
    its opaque segment, promoted to a `MerkleNode`, and written to the **Journal
    (Hot Tier)**.

### 4.4. The Blob Tier (Global CAS)

Large binary objects are stored in the global `objects/` directory to support
cross-conversation deduplication.

*   **[hash].data**: The raw binary payload.
*   **[hash].info**: MessagePack metadata containing:
    1.  `total_size`: `u64`
    2.  `status`: `Available`, `Downloading`, or `Pending`.
    3.  `received_mask`: `Binary` (Bitmask of 64KB chunks).
    4.  `bao_root`: `u8[32]` (The Blake3-Merkle root).
*   **[hash].bao**: The Bao outboard file, used for $O(\log N)$ incremental
    chunk verification during swarm sync.
*   **Durability**: The `.info` file **MUST** be updated via the
    "Write-to-Temp + Rename" pattern during active downloads.

--------------------------------------------------------------------------------

## 5. Compaction & Maintenance

Compaction moves data from the Journal to the Cold Tier. Unlike a full re-pack,
this process is **incremental** and does not require reading historical data.
See Section 7 for details.

--------------------------------------------------------------------------------

## 6. Storage Files

### 6.1. Conversation State (`state.bin`)

Serialized as a single **MessagePack Positional Array**:

1.  `heads`: `Array<NodeHash>`
2.  `admin_heads`: `Array<NodeHash>`
3.  `message_count`: `u32`
4.  `last_rotation_time`: `i64` (ms)
5.  `active_packs`: `Array<u64>` (List of pack IDs)
6.  `active_journal_id`: `u64` (Must match journal.bin header)

### 6.2. Ratchet Checkpoints (`ratchet.bin`)

To provide a stable surface for long-term forensic security and fast startup,
the **final** ratchet state of each sender is checkpointed to a fixed-size table
during compaction.

*   **Format:** A fixed-width header followed by $N$ slots. Each slot stores the
    `PhysicalDevicePk`, `ChainKey`, and `last_sequence_number`.
*   **Update Frequency**: Updated during every **Coalesced Durability Barrier**
    (defined by `DURABILITY_SYNC_MS = 2000` or `DURABILITY_SYNC_MESSAGES = 20`,
    see Section 9.1) using the standard "Write-to-Temp + Fsync + Rename"
    pattern. Waiting until Compaction would defeat Forward Secrecy by leaving
    old keys on disk.
*   **Source of Truth**: On startup, the implementation loads the checkpoint
    from `ratchet.bin` and then **rebuilds** the hot state by stepping the
    ratchet forward for each sender based on the `Ratchet Advance` (Type 0x05)
    sequence numbers recorded in `journal.bin`. This preserves Forward Secrecy
    on disk while providing $O(1)$ lookups in memory.

### 6.3. Permissions Cache (`permissions.bin`)

Serialized as a **MessagePack Positional Array** of entries:

*   **Format**: `Array<[PhysicalDevicePk, [u32 perms, i64 expiry, u64 rank]]>`
*   **Incremental Advancement**: The cache is tagged with the
    `latest_admin_rank`. When new Admin nodes are synced, the implementation
    incrementally updates this cache. It **MUST NOT** perform a full re-scan of
    history unless the cache is corrupted.
*   **Snapshot Optimization:** If an **Anchor Snapshot** is received, the
    implementation MAY use the snapshot's member list to reset the cache,
    skipping all preceding history and immediately advancing the
    `latest_admin_rank` to the snapshot rank.

### 6.4. Vouch Registry

The Vouch Registry is no longer a separate file. It is a **Volatile Index**
rebuilt by scanning the **Journal** (Section 4.1). This eliminates a global
locking bottleneck and improves write performance.

### 6.5. Blacklist Registries

1.  **Global Blacklist (`/storage/blacklist.bin`):** Stores system-wide bans
    (e.g., globally malicious devices). Updated via the **Global Lock**.
2.  **Local Blacklist (Conversation-Specific):**
    *   **Hot Path**: New bans specific to a conversation are appended to its
        **Journal** (Type 0x03).
    *   **Cold Path**: During compaction, these bans are moved into the **Index
        Record Flags** (Section 4.2.2) of all nodes authored by the banned
        device. This enables $O(1)$ rejection during history lookups without
        extra files.
    *   **Note**: Local bans authored via the protocol (e.g., by a group admin)
        MUST be validated against the DAG before being applied to the journal.

### 6.6. Conversation Keys (`/keys/`)

To support historical decryption after group key rotations, implementations
**MUST** persist the conversation keys ($K_{conv}$) for each generation.

*   **Format**: `[generation_hex].key` containing exactly 32 bytes of raw key
    data.
*   **Security**: These keys **MUST** be treated with the same forensic care as
    Ratchet Keys (Section 8).

### 6.7. Reconciliation Sketches (`/sketches/`)

To optimize synchronization, serialized sketches (like IBLTs) MAY be cached.

*   **Format**: `[range_start]_[range_end].bin` containing the serialized
    sketch.
*   **Volatility**: Sketches are considered cache data and MAY be deleted safely
    at any time to reclaim space.

## 7. Compaction & Maintenance

To ensure UI responsiveness, implementations **MUST** minimize the duration of
the Exclusive Lock. Maintenance follows the **Shadow Write Pattern**:

### 7.1. Incremental Compaction (Journal to Cold Tier)

1.  **Shadow Write**: Read all records from `journal.bin` (using `LOCK_SH`).
    *   Promote **Node** records to `packs/[id].pack`.
    *   **Vouch Pruning**: Discard any `Vouch` records for nodes that are now
        `VERIFIED`.
    *   **Ratchet Checkpoint**: Capture the **final** `ChainKey` and
        `last_sequence_number` for each sender found in the journal.
    *   **Carry Forward**: Retain only `Vouch` and `Blacklist` records for
        currently active speculative nodes.
    *   Write the new pack and index files to disk and `fsync()`.
2.  **Commit (Brief LOCK_EX)**:
    *   Acquire `LOCK_EX`.
    *   Atomic Switch: Update `state.bin` with the new pack ID and a new
        `active_journal_id`.
    *   Reclaim: Truncate `journal.bin` to 16 bytes (the header) and write the
        new generation ID.
    *   Release `LOCK_EX`.

### 7.2. Housekeeping (Pack Merging)

When merging multiple large packs to optimize lookups:

1.  **Shadow Write**: Read existing packs and write a new merged
    `packs/[new_id].pack` and index. This may take seconds and is done
    **without** an exclusive lock.
2.  **Commit (Brief LOCK_EX)**:
    *   Acquire `LOCK_EX`.
    *   Update `state.bin` to replace the old pack IDs with the new merged ID.
    *   Delete the old files.
    *   Release `LOCK_EX`.

**Result**: The UI thread is only blocked for the duration of an atomic metadata
update (~1ms), regardless of history size.

--------------------------------------------------------------------------------

## 8. Security Considerations

### 8.1. Forensic Erasure of Ratchet Keys

Standard file deletion or overwriting (shredding) is often ineffective on modern
SSDs due to Wear Leveling and the Flash Translation Layer (FTL). To ensure that
old `ChainKeys` cannot be recovered forensically:

1.  **System-Level Encryption**: It is strongly RECOMMENDED to store the
    Merkle-Tox storage root on a filesystem with Full Disk Encryption (FDE) or
    an encrypted container (e.g., LUKS, FileVault).
2.  **Cryptographic Erasure**: Future versions of this spec may mandate
    encrypting the `ratchets/` directory contents with a "Transient Storage Key"
    (TSK) kept in memory. Rotating this TSK would provide "Crypto-Shredding" of
    all deleted keys.
3.  **Minimize Persistence**: Implementations MUST delete a `ChainKey` file
    immediately after the ratchet has successfully advanced and the new key is
    persisted.

--------------------------------------------------------------------------------

## 9. Performance & Flash Endurance

To minimize I/O bottlenecks and extend flash lifespan on mobile devices,
implementations SHOULD employ the following optimizations:

### 9.1. Transactional Coalescing (Amortized Syncing)

Implementations SHOULD NOT call `fsync()` for every individual message in
high-throughput scenarios. Instead, they should coalesce multiple logical
updates into a single I/O barrier to protect battery life and flash endurance:

1.  **The Catch-up Batch**: During initial sync or after being offline, process
    messages in memory and append to the journal without intermediate `fsync`
    calls.
2.  **Idle-Sync Pattern**: Trigger the durability barrier (fsync + state update)
    only when the network event loop goes **idle**, or when a threshold is met
    (`DURABILITY_SYNC_MESSAGES = 50` or `DURABILITY_SYNC_MS = 2000`).
3.  **Battery Optimization**: By batching, implementations reduce the number of
    times the storage hardware must be powered up to full-write mode,
    significantly extending battery life on mobile devices.
4.  **Single Barrier**: Call `fdatasync()` on both file descriptors (or the
    directory) once at the end of the batch.
5.  **Atomic State Update**: Finally, update `state.bin` to commit the new heads
    and pack/journal IDs.

### 9.2. Security vs. Endurance Trade-off

*   **Maximum Security**: Sync every message. Provides immediate forward
    secrecy.
*   **Mobile Optimized**: Coalesce updates every 2 seconds or 20 messages.
    Reduces flash wear by 95% while keeping the "vulnerability window" for
    forensic recovery small.

### 9.3. Memory-Efficient Index Management

To prevent memory pressure when managing hundreds of conversations:

1.  **Lazy mmap**: Implementations **SHOULD** only `mmap()` the `index.idx`
    files for conversations that are actively being viewed or synchronized.
2.  **Idle Eviction**: When a conversation has been idle for a period
    (`IDLE_UNMAP_TIMEOUT_MS = 300000`), implementations SHOULD `munmap()` its
    indices to free up virtual memory and allow the kernel to reclaim physical
    pages.
3.  **Bloom Filter Density**: Bloom filters SHOULD be sized at ~10 bits per
    record. For a standard 10,000-node pack, this results in a tiny 12.5 KB
    footprint, ensuring that even under heavy multi-conversation load, the total
    metadata remains well within the limits of mobile hardware.

### 9.4. Desync Recovery

If a crash occurs during a batched update and the latest `ChainKey` is lost, the
implementation **MUST** be able to resume by requesting the missing nodes again
from the last parent `ChainKey` successfully persisted in `ratchet.bin`.

The C implementation remains simple and high-performance:

1.  **Hot Lookup:** Build a small hash map from `journal.bin` on startup ($O(N)$
    where $N \le 500$).
2.  **Cold Lookup:** $O(\log(N/256))$ binary search using the Fanout Table.
3.  **Efficiency:** Zero block waste for messages; minimal inode usage.

--------------------------------------------------------------------------------

## 11. Rejected Designs & Trade-offs (Architectural Decisions)

During the design phase, several complex optimizations were rejected in favor of
the **Simplicity First** principle. This section archives the reasoning for
these "push backs."

### 11.1. Full Write-Ahead Log (WAL)

*   **Suggestion:** Implement a unified WAL for all state changes (nodes, heads,
    keys).
*   **Push Back:** Too complex for a minimal C implementation.
*   **Decision:** Used the **Atomic Rename** pattern for metadata (including
    ratchets). These provide identical durability guarantees with significantly
    less code.

### 11.2. Materialized Registry Files

*   **Suggestion:** Keep separate `vouchers.bin` and `blacklist.bin` files for
    all hot state.
*   **Push Back:** Every extra file creates a new filesystem contention point
    and overhead (write amplification).
*   **Decision:** Unified all "Hot" conversation events into the **Multiplexed
    Journal**. This ensures $O(1)$ appends and zero-overhead recovery for all
    registries.

### 11.3. Linear Scavenging (Resynchronization)

*   **Suggestion:** Use Magic Markers (SYNC) to skip corrupted journal records
    and recover subsequent valid data.
*   **Push Back:** Linear searching is complex to implement safely in C and
    vulnerable to DoS loops via false-positives in encrypted payloads.
*   **Decision:** Used **Deterministic Forward Walking**. If a record is
    corrupt, the walk stops. Merkle-Tox's self-healing DAG naturally recovers
    the "lost" nodes from peers during the next sync session.

### 11.4. Global De-duplication on Startup

*   **Suggestion:** Handle partial compaction commits by checking every journal
    node against historical pack indices on startup.
*   **Push Back:** $O(N \log M)$ startup performance is unacceptable for large
    histories.
*   **Decision:** Introduced **Generation IDs**. By matching IDs between the
    journal and `state.bin`, stale data is identified and discarded in $O(1)$
    time.

### 11.5. Software-Level "Shredding"

*   **Suggestion:** Use multi-pass overwriting to erase old `ChainKeys`.
*   **Push Back:** FTL wear-leveling on SSDs renders software overwrites
    ineffective and deceptive.
*   **Decision:** Recommended **System-Level Encryption (FDE)** and defined a
    stable surface for future **Crypto-Shredding** (encrypting the table with a
    volatile RAM key).

### 11.6. Multi-Level B-Tree Indices

*   **Suggestion:** Use a B-Tree for pack indices to handle millions of nodes.
*   **Push Back:** Implementing a disk-backed B-Tree in C is a significant
    undertaking.
*   **Decision:** Used a **Bloom Filter + Scalable Fanout Table**. This provides
    the same $O(1)$ performance for lookups while keeping the file format flat,
    auditable, and `mmap`-friendly.

### 11.7. Replacing Bloom Filters with Large Fanout

*   **Suggestion:** Increase Fanout bits ($B$) to 24+ to achieve "Not Found"
    rejection without a Bloom Filter.
*   **Push Back:** A 24-bit fanout table requires 64MB of contiguous
    memory/disk, which is unacceptable for mobile and embedded C
    implementations.
*   **Decision:** Kept both. **Fanout** reduces the range for "Found" lookups,
    while **Bloom Filters** (typically 2KB) provide space-efficient rejection
    for "Not Found" lookups across multiple packs.

### 11.9. Topological Opaque Eviction

*   **Suggestion:** Evict opaque nodes based on Topological Rank (highest rank
    first) to prevent deleting "anchors" near the LLWM.
*   **Push Back:** Deleting the "future" (highest rank) makes the system
    vulnerable to Rank-Padding attacks, where an attacker stuffs the buffer with
    low-rank junk. It also requires maintaining a complex index for
    undecryptable data.
*   **Decision:** Used **Oldest-Arrival First** with **Root Carry-Forward**.
    Legitimate nodes are promoted quickly; stagnant data is purged. Protocol
    deadlocks are prevented by explicitly preserving `Admin` and `KeyWrap`
    anchors during eviction.

### 11.10. Atomic Rename for High-Frequency Files

*   **Suggestion:** Avoid the "Write-to-Temp + Rename" pattern for `ratchet.bin`
    and `journal.bin` to save inode allocation overhead, especially since
    `ratchet.bin` MUST be updated frequently (on every durability barrier) to
    preserve Forward Secrecy.
*   **Push Back:** While `journal.bin` can safely be append-only, in-place
    overwrites for `ratchet.bin` are not genuinely atomic on modern SSDs due to
    the Flash Translation Layer (FTL). A crash during an in-place write can
    result in page corruption.
*   **Decision:** Used **Append-Only** for `journal.bin` and standard **Atomic
    Rename** for `ratchet.bin`. While updating `ratchet.bin` via Rename every
    few seconds (during the Idle-Sync barrier) introduces slight directory-level
    I/O overhead, it guarantees crash-safety without sacrificing the strict
    deletion required for Forward Secrecy.

### 11.11. MessagePack for Structural Headers/Footers

*   **Suggestion:** Use MessagePack for `JournalHeader`, `index.idx` prefix, and
    `Tail-Commit Footer`.
*   **Push Back:**
    1.  **Random Access**: MessagePack is forward-only; it prevents jumping
        directly to a data offset (required for indices).
    2.  **Reverse Reading**: Finding a MessagePack object at the end of a file
        (required for footers) is complex and fragile in C.
    3.  **Bootstrapping**: Magic numbers and generation IDs must be readable
        with zero logic to ensure crash-safety and version detection.
*   **Decision:** Used **Fixed-Width Binary** for file-structure metadata and
    **MessagePack** for flexible logical metadata.

### 11.12. Manual Framing vs. MessagePack Stream for Journal

*   **Suggestion:** Use a raw stream of MessagePack objects for the journal
    instead of manual `[length][hash]` framing.
*   **Push Back:** Without a length prefix, the implementation cannot jump
    between records and must parse every byte to find the end. A single
    corrupted byte would make the remainder of the journal unreadable.
*   **Decision:** Used a **Binary Envelope** (Length + Hash) around
    **MessagePack Payloads**. This enables **Deterministic Walking** and
    cryptographic integrity checks before the parser is even invoked.
