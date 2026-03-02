# Merkle-Tox Sub-Design: Content-Addressable Storage (CAS) & Streaming

## Overview

CAS handles binary assets too large for direct embedding in a Merkle node. Blobs
are identified by their **Bao root hash** and synchronized lazily.

## 1. Storage Strategy

-   **Deduplication**: Blobs are keyed by hash. Multiple references to the same
    file result in a single copy on disk.
-   **SQLite Index**: The `cas_blobs` table tracks status (Pending, Downloading,
    Available) and location (In-DB vs On-Disk).

## 2. Blob Synchronization Protocol

Blobs sync lazily via a **Multi-Source Swarm Protocol**.

### `BLOB_QUERY` (Message Type 0x06)

Checks if a peer has a specific blob.

-   Peer A sends `BLOB_QUERY(hash)`.
-   Peer B responds with `BLOB_AVAIL(hash, size, bao_root)` if they have it.

**Privacy Warning**: Sending a query reveals interest in the content.

-   **Unicast Only**: Queries MUST be sent via encrypted 1:1 `tox-sequenced`
    sessions.
-   **Targeting**: Clients SHOULD only query trusted peers (e.g., friends or
    verified admins) who signaled `CAS_INVENTORY` for the conversation.

### `BLOB_AVAIL` (Message Type 0x07)

Peer B confirms possession and provides:

-   `size`: Total size in bytes.
-   `bao_root`: The Bao root hash for incremental verification of chunks.
    -   **Security Rule (Anti-Download Bombing)**: The client MUST verify the
        peer's `bao_root` is **byte-for-byte identical** to the authoritative
        `hash` from the verified `MerkleNode` before initiating `BLOB_REQ`
        downloads. `Blob.hash` in the DAG is the Bao root hash (distinct from
        `blake3::hash()`), ensuring incremental verification of every 64KB
        chunk. Peers providing mismatching roots MUST be immediately
        blacklisted.

### `BLOB_REQ` (Message Type 0x08)

Requests a specific slice of the file.

-   `bao_root`: Bao root hash of the blob (from the DAG).
-   `offset`: Starting byte.
-   `length`: Requested size (typically 64KB).

### `BLOB_DATA` (Message Type 0x09)

Carries the requested chunk payload and **Bao proof** (intermediate hashes from
the outboard) needed to verify the chunk against `bao_root`.

## 3. Swarm Sync & Chunk Aggregation

-   **Discovery**: Peer A queries connected conversation members using
    `BLOB_QUERY`.
-   **Aggregation**: Peer A maintains a "Wanted Chunks" bitmask. It sends
    requests for different chunks to different peers simultaneously (e.g., Chunk
    1 to Peer B, Chunk 2 to Peer C).
-   **Pipelining**: Each peer relationship allows up to 4 in-flight `BLOB_REQ`
    messages to saturate the link without waiting for round-trips.
-   **Incremental Verification**: Using `bao_root` and provided proofs, Peer A
    verifies each 64KB chunk upon receipt. If a peer sends invalid data, they
    are blacklisted for that blob, and the chunk is re-requested.

## 4. Streaming & Direct-to-Disk I/O

-   **Chunked Reassembly**: `merkle-tox-sqlite` provides a streaming writer with
    random-access support for non-sequential chunks.
-   Upon `BLOB_DATA` reassembly, the logic layer validates the Bao proof and
    writes directly to the file offset.
-   **In-DB Optimization**: Small blobs are stored directly in SQLite. See
    **`merkle-tox-persistence.md`**.
-   **Finalization**: Once all chunks are Bao-verified, the file is marked
    "Available". No additional full-file hash check is required.

## 5. Privacy & Selective Downloading

-   Clients do not automatically download every blob.
-   **Thumbnails**: For images, a small (`MAX_THUMBNAIL_SIZE = 32768` bytes)
    thumbnail can be embedded in `MerkleNode` `metadata` or as a separate
    auto-downloaded small blob.
-   **User-Initiated**: Large blobs are downloaded upon user interaction.
-   **Status Tracking**: UI uses blob status (**Pending, Downloading, Available,
    Error**) for rendering.
