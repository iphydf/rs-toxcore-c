# Merkle-Tox Sub-Design: Content-Addressable Storage (CAS) & Streaming

## Overview

Content-Addressable Storage (CAS) handles large binary assets (images, videos,
files) that are too large to be embedded directly in a Merkle node. Blobs are
identified by their **Blake3** hash and synchronized lazily.

## 1. Storage Strategy

-   **Deduplication**: Since blobs are keyed by their hash, multiple references
    to the same file across different conversations only result in a single copy
    on disk.
-   **SQLite Index**: The `cas_blobs` table tracks the status of each blob
    (Pending, Downloading, Available) and its location (In-DB vs On-Disk).

## 2. Blob Synchronization Protocol

Unlike Merkle nodes, which are small and synced immediately, blobs are synced
**lazily** and via a **Multi-Source Swarm Protocol**.

### `BLOB_QUERY` (Message Type 0x06)

Used to check if a peer has a specific blob.

-   Peer A sends `BLOB_QUERY(hash)`.
-   Peer B responds with `BLOB_AVAIL(hash, size, bao_root)` if they have it.

**Privacy Warning**: Sending a query reveals interest in the content.

-   **Unicast Only**: Queries MUST be sent via encrypted 1:1 `tox-sequenced`
    sessions.
-   **Targeting**: Clients SHOULD only query peers who have signaled
    `CAS_INVENTORY` for the conversation and whom they trust (e.g., friends or
    verified admins).

### `BLOB_AVAIL` (Message Type 0x07)

Peer B confirms possession and provides:

-   `size`: Total size in bytes.
-   `bao_root`: (Optional) The Blake3-Merkle root of the Bao-style internal
    tree, allowing for incremental verification of chunks.
    -   **Security Rule (Anti-Download Bombing)**: If a peer provides a
        `bao_root`, the client MUST strictly verify that it is **byte-for-byte
        identical** to the authoritative `hash` from the verified `MerkleNode`
        before initiating any `BLOB_REQ` downloads. (Because Blake3 natively
        structures its hash as a Merkle tree, the root of the Bao outboard is
        exactly equal to the final Blake3 hash of the file). If a peer provides
        a mismatching root, they are attempting to stream a fake file and MUST
        be immediately blacklisted.

### `BLOB_REQ` (Message Type 0x08)

Requests a specific slice of the file.

-   `hash`: Blake3 of the full blob.
-   `offset`: Starting byte.
-   `length`: Requested size (typically 64KB).

### `BLOB_DATA` (Message Type 0x09)

Carries the payload of the requested chunk plus the **Bao proof** (the
intermediate hashes from the outboard) needed to verify the chunk against the
`bao_root`.

## 3. Swarm Sync & Chunk Aggregation

To maximize download speed, especially when joining a large group:

-   **Discovery**: Peer A queries all connected members of a conversation using
    `BLOB_QUERY`.
-   **Aggregation**: Peer A maintains a "Wanted Chunks" bitmask. It sends
    requests for different chunks to different peers simultaneously (e.g., Chunk
    1 to Peer B, Chunk 2 to Peer C).
-   **Pipelining**: Each peer relationship allows up to 4 in-flight `BLOB_REQ`
    messages to saturate the link without waiting for round-trips.
-   **Incremental Verification**: Using the `bao_root` and the provided proofs,
    Peer A verifies each 64KB chunk **immediately** upon receipt. If a peer
    sends invalid data, they are blacklisted for that blob, and the chunk is
    re-requested from another peer in the swarm.

## 4. Streaming & Direct-to-Disk I/O

To support large files (e.g., 1GB+) without high memory usage:

-   **Chunked Reassembly**: The `merkle-tox-sqlite` layer provides a streaming
    writer with random-access support for non-sequential chunk arrival.
-   As `tox-sequenced` completes the reassembly of a 64KB `BLOB_DATA` message,
    the logic layer validates the Bao proof and writes it directly to the
    correct offset in the temporary file in the `vault/`.
-   **In-DB Optimization**: Small blobs are stored directly in SQLite for
    performance. See **`merkle-tox-persistence.md`** for details.
-   **Finalization**: Once all chunks are received and verified, the file is
    marked "Available". The full-file Blake3 hash is computed as a final
    integrity check.

## 5. Privacy & Selective Downloading

-   Clients do not automatically download every blob they see in the history.
-   **Thumbnails**: For images, a small (`MAX_THUMBNAIL_SIZE = 32768` bytes)
    thumbnail can be embedded in the `MerkleNode`'s `metadata` or as a separate
    small blob that *is* auto-downloaded.
-   **User-Initiated**: Large blobs are only downloaded when the user interacts
    with the message (e.g., clicking "Download Image").
-   **Status Tracking**: The UI uses the blob status (**Pending, Downloading,
    Available, Error**) to display appropriate progress bars or retry buttons.
