# Merkle-Tox Sub-Design: Persistence

## Overview

Merkle-Tox abstracts its storage layer through traits. Storage interfaces have
two primary implementations: **SQLite** (complex queries) and **Filesystem
(FS)** (Git-style, durability optimized).

## 1. Storage Interfaces

Persistence backends implement traits in `merkle-tox-core`:

### `NodeStore` (DAG Index)

Handles storage and retrieval of Merkle nodes and relationships.

-   `put_node(conv_id, node, verified)`: Persists a node and its metadata.
-   `get_node(hash)`: Retrieves a full node.
-   `get_heads(conv_id)`: Returns current DAG tips.
-   `get_rank(hash)` / `get_type(hash)`: Efficiently fetch metadata for
    validation.

### `ObjectStore` (Content-Addressable Storage)

Handles large binary assets (Blobs) and undecryptable encrypted nodes (Opaque
Nodes).

-   `put_object(hash, data, status)`: Writes raw bytes to the store.
-   `get_object(hash)`: Retrieves raw bytes.
-   **Status Tags**: Objects are tagged as `Available`, `Opaque`, or `Pending`.
-   **Eviction Policy**: Opaque objects are subject to the 100MB
    **Contiguity-based Eviction** defined in `merkle-tox-sync.md`. Available
    blobs are persistent and only removed via explicit user pruning.

### Vouch Tracking

Vouch state is split into two layers:

-   **Persistence (per-node)**: When writing an opaque node, the `voucher_pk` of
    the first authorized peer is recorded. It survives restarts and informs
    eviction priority. For the file-based backend, this is the `voucher_pk`
    field in the Opaque Index record (`merkle-tox-storage-format.md` §4.3). For
    the SQLite backend, this is a column on the opaque nodes table.
-   **Runtime (in-memory)**: The bounded voucher set per hash (up to
    `MAX_VOUCHERS_PER_HASH = 3`) used for multi-peer request routing is
    maintained in memory and rebuilt from `SYNC_HEADS` exchanges upon
    reconnection. It is not persisted.

### `BlacklistRegistry` (Escalation Index)

-   **Persistence**: The **Blacklist Registry** MUST be persistent for
    escalation levels to survive restarts.
-   **Identity Independence**: Blacklist offenses are tied to the physical
    `sender_pk` (device key), not the room membership. If a device is revoked
    and later re-authorized, its previous escalation level MUST remain intact.

--------------------------------------------------------------------------------

## 2. Backend A: SQLite (`merkle-tox-sqlite`)

Provides indexing and transactional integrity. Recommended for complex querying.

### Schema Highlights

-   **`nodes`**: Stores MessagePack raw data + indexed metadata (rank,
    timestamp, author).
-   **`edges`**: Explicit mapping of `(parent_hash, child_hash)` for fast
    traversal.
-   **`cas_blobs`**: Tracks download progress via a bitmask of received chunks.

### Performance

-   Uses **Write-Ahead Logging (WAL)** for concurrent read/sync.
-   Optimized for complex queries like "find all messages from Alice in 2024."

--------------------------------------------------------------------------------

## 3. Backend B: Filesystem Store (`merkle-tox-fs`)

Mimics Git's object storage, utilizing Merkle-DAG immutability for
minimal-dependency durability.

### Storage Strategy: Loose vs. Packed

#### Loose Objects ("Hot" Store)

Each new node is written to an individual file. Loose objects are sharded into
`verified` and `speculative` subdirectories for indexless trust boundary
handling.

-   **Path**: `objects/{verified|speculative}/<prefix>/<hash_hex>`
-   **Atomicity**: Written to `.tmp` and moved via `rename()` to ensure no
    half-written nodes.

#### Packed Objects ("Cold" Store)

The FS backend MUST "bake" loose nodes into immutable pack files.

-   **`pack-<id>.data`**: Concatenated raw node data.
-   **`pack-<id>.idx`**: A sorted binary index mapping `Hash -> Offset`.
-   **Trigger**: Performed per-conversation once loose nodes exceed a strict
    threshold (`COMPACTION_THRESHOLD = 500 nodes`).
-   **Compaction**: To maintain efficiency, multiple pack files MUST be merged
    (compacted) into a single larger pack file when the number of active packs
    exceeds a threshold (`MAX_ACTIVE_PACKS = 10`), reducing file descriptor
    usage and improving binary search performance.

### Metadata Indexing

Since FS lacks SQL indices, it maintains a **Volatile Index** in memory:

-   **Lazy Loading**: To ensure fast startup, the volatile index for a specific
    conversation is populated upon **first access**.
-   The `loose/` and `.idx` files are scanned to populate a lightweight
    `HashMap<Hash, (Rank, NodeType)>`. The `.idx` file stores the `NodeType` and
    `Rank` alongside the `Hash` to allow single-pass indexing without reading
    the large `.data` files.
-   **Dynamic Permission Cache**: Because permissions are dynamic and
    causality-dependent, the storage layer **MUST** maintain a versioned cache
    of "Effective Permissions" for active devices relative to specific points in
    the causal history of the DAG. The cache memoizes trust-path validation,
    preventing $O(N^2)$ computational overhead during bulk Promotion Flows.
-   Ensures DAG validation and sync logic remain $O(1)$ or $O(\log N)$ without
    constant disk seeking.

--------------------------------------------------------------------------------

## 4. Blob Storage Strategy (Common)

Large binary assets are treated as **Content-Addressable Storage (CAS)**:

-   **De-duplication**: Multiple references to the same file hash point to the
    same single file in the `vault/`.
-   **Hybrid Storage**: Small blobs (`< IN_DB_BLOB_MAX_SIZE = 65536` bytes) may
    be stored directly in the database or as loose objects, while large files
    are always stored on the raw filesystem.

### 5. Blob Metadata (FS Backend)

For the Filesystem backend, which lacks a central SQL index, metadata for each
blob is stored in a companion file.

-   **Path**: `blobs/<hash_hex>.info`
-   **Format**: MessagePack encoded `BlobInfo` struct.
-   **Content**: Tracks the blob's `size`, `status` (Pending/Available), and the
    `received_mask` for in-progress downloads.

#### Outboard Storage (Bao)

To support incremental verification and "Swarm Sync" without re-hashing the
file, the FS backend stores Bao outboard data:

-   **Path**: `blobs/<hash_hex>.bao`
-   **Purpose**: Stores the pre-calculated Merkle tree of the blob's hashes,
    allowing for $O(\log N)$ proof generation and verification for any chunk.

--------------------------------------------------------------------------------

## 6. Concurrency & Thread Safety

To support high-performance synchronization from multiple peers simultaneously:

-   **Interior Mutability**: Storage traits (`NodeStore`, `BlobStore`) use
    `&self` for write operations. Implementations MUST handle internal
    synchronization.
-   **Lock Granularity**: Implementations SHOULD use `RwLock` or similar
    primitives to allow concurrent readers.
-   **Thread Safety**: All storage backends MUST be `Send + Sync` to allow the
    `MerkleToxEngine` to be shared across network worker threads.

## 7. Persistence Security

To protect chat history from forensic analysis:

-   **At-Rest Encryption**: Implementations SHOULD support encrypting the
    storage root (e.g., via SQLCipher for SQLite or an encrypted overlay for
    FS).
-   **Deniability**: Because content is already encrypted with the conversation
    key ($K_{conv}$), the raw data on disk is unreadable without the DAG
    handshake keys, even if the database itself is unencrypted.
-   **Metadata Decryption**: Searchable metadata (like `sender_pk`) is decrypted
    before indexing to allow local lookups while remaining obfuscated on the
    wire.
