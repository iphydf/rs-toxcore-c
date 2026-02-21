# Merkle-Tox Sub-Design: Persistence

## Overview

Merkle-Tox abstracts its storage layer through a set of traits, allowing for
different backends depending on the client's needs. This document defines the
storage interfaces and two primary implementations: **SQLite** (for scalability
and complex queries) and **Filesystem (FS)** (a simpler, Git-style
implementation optimized for durability).

## 1. Storage Interfaces

All persistence backends must implement the following traits located in
`merkle-tox-core`:

### `NodeStore` (DAG Index)

Handles the storage and retrieval of Merkle nodes and their relationships.

-   `put_node(conv_id, node, verified)`: Persists a node and its metadata.
-   `get_node(hash)`: Retrieves a full node.
-   `get_heads(conv_id)`: Returns current DAG tips.
-   `get_rank(hash)` / `get_type(hash)`: Efficiently fetch metadata for
    validation.

### `ObjectStore` (Content-Addressable Storage)

Handles both large binary assets (Blobs) and undecryptable encrypted nodes
(Opaque Nodes).

-   `put_object(hash, data, status)`: Writes raw bytes to the store.
-   `get_object(hash)`: Retrieves raw bytes.
-   **Status Tags**: Objects are tagged as `Available`, `Opaque`, or `Pending`.
-   **Eviction Policy**: Opaque objects are subject to the 100MB
    **Contiguity-based Eviction** defined in `merkle-tox-sync.md`. Available
    blobs are persistent and only removed via explicit user pruning.

### `VouchRegistry` (Trust Index)

Tracks which authorized peers have vouched for specific hashes.

-   `put_vouch(hash, peer_pk)`: Records a vouch from an authorized member.
-   `get_vouchers(hash)`: Returns a small list (up to `MAX_VOUCHERS_PER_HASH`)
    of authorized members who advertised this hash.
-   **Bounded Voucher Set**: To ensure scalability while preventing Data
    Withholding attacks, the registry only needs to persist a small, fixed
    maximum number of vouchers per hash.
-   **Persistence**: Both the **Vouch Registry** and the **Blacklist Registry**
    MUST be persistent to ensure that trust state and escalation levels survive
    application restarts.
-   **Identity Independence**: Blacklist offenses are tied to the physical
    `sender_pk` (device key), not the room membership. If a device is revoked
    and later re-authorized, its previous escalation level MUST remain intact.

--------------------------------------------------------------------------------

## 2. Backend A: SQLite (`merkle-tox-sqlite`)

Recommended for heavy users. It provides indexing and transactional integrity.

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

A simpler, "Tox-idiomatic" implementation that mimics Git's object storage. It
uses the immutability of the Merkle-DAG to provide high durability with minimal
dependencies.

### Storage Strategy: Loose vs. Packed

#### Loose Objects ("Hot" Store)

Every newly received or authored node is written to an individual file. To
handle trust boundaries efficiently without a formal index, loose objects are
sharded into `verified` and `speculative` subdirectories.

-   **Path**: `objects/{verified|speculative}/<prefix>/<hash_hex>`
-   **Atomicity**: Written to `.tmp` and moved via `rename()` to ensure no
    half-written nodes.

#### Packed Objects ("Cold" Store)

To avoid millions of tiny files, the FS backend MUST "bake" loose nodes into
immutable pack files.

-   **`pack-<id>.data`**: Concatenated raw node data.
-   **`pack-<id>.idx`**: A sorted binary index mapping `Hash -> Offset`.
-   **Trigger**: Performed per-conversation once loose nodes exceed a strict
    threshold (`COMPACTION_THRESHOLD = 500 nodes`).
-   **Compaction**: To maintain efficiency, multiple pack files MUST be merged
    (compacted) into a single larger pack file when the number of active packs
    exceeds a threshold (`MAX_ACTIVE_PACKS = 10`). This reduces file descriptor
    usage and improves binary search performance.

### Metadata Indexing

Since FS lacks SQL indices, it maintains a **Volatile Index** in memory:

-   **Lazy Loading**: To ensure fast startup with thousands of conversations,
    the volatile index for a specific conversation is only populated upon
    **first access**.
-   The `loose/` and `.idx` files are scanned to populate a lightweight
    `HashMap<Hash, (Rank, NodeType)>`. The `.idx` file stores the `NodeType` and
    `Rank` alongside the `Hash` to allow for single-pass indexing without
    reading the large `.data` files.
-   **Dynamic Permission Cache**: Because permissions are dynamic and
    causality-dependent, the storage layer **MUST** maintain a versioned cache
    of "Effective Permissions" for active devices relative to specific points in
    the causal history of the DAG. This cache prevents $O(N^2)$ computational
    overhead during bulk Promotion Flows by allowing trust-path validation to be
    memoized.
-   This ensures that DAG validation and sync logic remain $O(1)$ or $O(\log N)$
    without constant disk seeking.

--------------------------------------------------------------------------------

## 4. Blob Storage Strategy (Common)

Regardless of the backend, large binary assets are treated as
**Content-Addressable Storage (CAS)**:

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
    before indexing to allow for local lookups while remaining obfuscated on the
    wire.
