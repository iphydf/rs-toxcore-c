# Merkle-Tox Sub-Design: Content-Addressable Storage (CAS) & Streaming

## Overview

CAS handles binary assets too large for direct embedding in a Merkle node. Blobs
are identified by their **chunk-Merkle root hash** and synchronized lazily.

## 1. Storage Strategy

-   **Deduplication**: Blobs are keyed by hash. Multiple references to the same
    file result in a single copy on disk.
-   **SQLite Index**: The `cas_blobs` table tracks status (Pending, Downloading,
    Available) and location (In-DB vs On-Disk).

## 2. Blob Synchronization Protocol

Blobs sync lazily via a **Multi-Source Swarm Protocol**.

### `BLOB_QUERY` (Message Type 0x06)

Checks if a peer has a specific blob (fully or partially).

-   Peer A sends `BLOB_QUERY(hash)`.
-   Peer B responds with `BLOB_AVAIL` if they have any pieces of the blob
    (status = `Available` or `Downloading`). Peers with status `Pending` (no
    pieces yet) MUST NOT respond.
-   The `BLOB_AVAIL` response includes `completed_ranges` indicating which
    64KB chunks the peer has. For fully available blobs, the ranges are
    `None` (meaning "all chunks"). See **Section 3** for how the requester
    uses these ranges for chunk-level swarming.

**Privacy Warning**: Sending a query reveals interest in the content.

-   **Unicast Only**: Queries MUST be sent via encrypted 1:1 `tox-sequenced`
    sessions.
-   **Targeting**: Clients SHOULD only query trusted peers (e.g., friends or
    verified admins) who signaled `CAS_INVENTORY` for the conversation.

### `BLOB_AVAIL` (Message Type 0x07)

Peer B confirms possession and provides:

-   `size`: Total size in bytes.
-   **Security Rule (Anti-Download Bombing)**: The blob `hash` IS the root
    of the chunk-Merkle tree over the blob's 64KB chunk leaves (see §3).
    Clients verify each received chunk against this root via an inclusion
    proof; no separate root advertisement is needed or trusted. Peers that
    serve data which fails to verify against the authoritative `hash` MUST
    be immediately blacklisted.
-   `completed_ranges`: Optional list of `(start_chunk, end_chunk)` pairs
    (inclusive) indicating which 64KB chunks the peer has fully verified.
    `None` means the peer has the complete blob. When present, the requester
    uses these ranges for chunk-level swarming decisions.

### `BLOB_FETCH` (Message Type 0x15)

Requests a seeder to begin streaming a blob.

-   `hash`: Blob hash.
-   `completed_ranges`: Optional list of `(start_chunk, end_chunk)` pairs
    the requester already has. `None` means the requester has no chunks yet.

Upon receiving `BLOB_FETCH`, the seeder begins pushing `BLOB_DATA` packets
for chunks the requester is missing (based on `completed_ranges`), paced by
the transport's congestion control. The seeder streams continuously using a
credit-based window (see Section 4).

### `BLOB_DATA` (Message Type 0x09)

Carries a single data piece as a **sequenced DATA packet**. Pieces are
buffered per active chunk on the receiver, verified together at the
64KB chunk boundary via a chunk-Merkle inclusion proof (see Section
3), and only then flushed to their file offset in a single `WriteChunk`
effect. This avoids a per-piece disk-syscall storm while still giving
the transport per-packet loss visibility.

-   `hash`: Blob hash.
-   `offset`: Byte offset within the blob.
-   `data`: Payload (variable length, up to ~1300 bytes).
-   `proof`: Optional chunk-Merkle inclusion proof. Included on the final
    piece of each 64KB chunk, authenticating that chunk's leaf hash against
    the blob root. Empty on all other pieces.

**Payload sizing**: The `data` and `proof` fields share the ~1350B packet
budget. Most pieces carry ~1300 bytes of data and no proof. The piece at
each 64KB chunk boundary carries a shorter data payload to make room for
the inclusion proof, which is `ceil(log2(num_chunks)) * 32` bytes
(e.g., 256 bytes for a 10 MB / 160-chunk blob, ~544 bytes for a 10 GB
blob). The sender MUST size the data field so that the total serialized
packet fits within `MAX_DATAGRAM_SIZE`.

Each `BLOB_DATA` packet is a single sequenced datagram with its own
sequence number. The transport tracks delivery via ACK bitmaps, giving the
congestion controller per-packet loss visibility — critical for accurate
bandwidth estimation on variable-quality P2P connections. The transport
does NOT retransmit lost blob pieces; the CAS layer handles retransmission
through `BLOB_PROGRESS` bitmask feedback.

**Piece size**: Each `BLOB_DATA` packet carries ~1300 bytes of blob data,
matching the transport's single-packet payload limit. This eliminates
fragmentation — every piece is one packet. A 10 MB blob has ~8000 pieces.

### `BLOB_PROGRESS` (Message Type 0x16)

Periodic progress update from receiver to seeder during an active transfer.
Uses **chunk-level ranges** for overall progress and **piece-level bitmasks**
for active chunks, keeping the message compact regardless of blob size.

-   `hash`: Blob hash.
-   `completed_ranges`: List of `(start_chunk, end_chunk)` pairs (inclusive)
    for fully received and Merkle-verified 64KB chunks. Cumulative and
    self-contained — each BLOB_PROGRESS carries the complete state, so lost
    progress messages are harmless.
-   `incomplete_chunks`: List of `(chunk_index, piece_mask)` pairs for chunks
    currently being received. `piece_mask` is a bitmask (~7 bytes for ~50
    pieces per 64KB chunk) indicating which pieces within that chunk have
    arrived.

**Size**: For a 100 GB blob downloaded sequentially: `completed_ranges` is
one pair (8 bytes). With 8 chunks in flight: `incomplete_chunks` is 8 × 11
= 88 bytes. Total: ~130 bytes. For swarming with 50 disjoint ranges: ~530
bytes. Fits in a single DATA packet for the vast majority of transfers.
In the pathological case of highly fragmented swarming (200+ disjoint
ranges), the message falls back to FRAGMENT (see transport spec,
Data/Frag).

The receiver SHOULD send `BLOB_PROGRESS` at least once per second during active
downloads, or immediately when a gap persists for more than `2 * RTT`.

`BLOB_PROGRESS` serves three purposes:
1.  **Flow control**: The seeder advances its piece-level credit window
    based on newly confirmed pieces (from both `incomplete_chunks` piece
    masks and `completed_ranges`).
2.  **Retransmission**: The seeder uses `incomplete_chunks` piece masks to
    identify and re-send only the specific missing pieces within active
    chunks, rather than re-pushing entire chunks.
3.  **Swarming coordination**: The seeder skips chunks the receiver obtained
    from other peers (visible in `completed_ranges`).

### `BLOB_CANCEL` (Message Type 0x17)

Sent by receiver to stop a push stream.

-   `hash`: Blob hash.

Upon receiving `BLOB_CANCEL`, the seeder MUST stop sending `BLOB_DATA`
packets for this blob.

### `BLOB_REQ` (Message Type 0x08)

Fallback pull-based request for a specific piece range. Used when push
streaming is unavailable or for targeted retransmission of specific pieces.

-   `hash`: Blob hash.
-   `offset`: Byte offset.
-   `length`: Requested length.

## 3. Swarm Sync & Chunk-Level Swarming

### Discovery

Peer A queries connected conversation members using `BLOB_QUERY`. Each
responder includes its `completed_ranges` in `BLOB_AVAIL`, telling Peer A
which chunks that peer can serve.

### Push-Based Streaming

After discovery, the receiver sends `BLOB_FETCH` to one or more seeders. Each
seeder begins pushing `BLOB_DATA` packets continuously, paced by the transport's
congestion control. Since each piece is a single packet, there is no
fragmentation and no head-of-line blocking — a lost packet wastes ~1300 bytes,
not 64KB.

When fetching from multiple seeders (swarming), the receiver sends
`BLOB_FETCH` to each seeder. All seeders begin pushing missing chunks
concurrently. De-duplication happens dynamically: as chunks arrive from
one seeder, the receiver's `BLOB_PROGRESS` updates to the other seeders
reflect the newly completed chunks, causing them to skip those chunks
automatically (see BLOB_PROGRESS purpose #3).

### Per-Seeder Chunk Tracking

The requester maintains a **per-seeder chunk range set** (from `completed_ranges`
in `BLOB_AVAIL`). When partitioning chunks across seeders, the requester MUST
only assign chunks to seeders whose ranges indicate they have them. Seeders with
`completed_ranges = None` (fully available) can serve any chunk.

### Proactive Re-Advertisement

Partial seeders (status = `Downloading`) MUST proactively re-send `BLOB_AVAIL`
with updated `completed_ranges` to session peers, so those peers can request
newly available chunks. Re-advertisements MUST be throttled to at most once per
second per peer.

### Incremental Verification

Blobs are authenticated by a **chunk-Merkle tree** — a domain-separated
blake3 binary Merkle tree whose leaves are the hashes of successive 64KB
chunks (the final chunk may be short). The tree root IS the blob `hash`
embedded in the authoring `MerkleNode`, so possession of a verified
content node is sufficient to authenticate every chunk individually; no
separate root advertisement or pre-shared digest is needed.

**Leaf hash.** For a 64KB chunk `c`:

    leaf_hash(c) = blake3(0x00 || c)

**Internal node hash.** For sibling hashes `L` and `R`:

    internal_hash(L, R) = blake3(0x01 || L || R)

The leading domain tag (`0x00` for leaves, `0x01` for internal nodes)
provides second-preimage resistance: an attacker cannot craft chunk bytes
whose leaf hash collides with any internal node hash.

**Unpaired-tail handling.** At every tree level with an odd node count
the last node is duplicated (paired with itself) before hashing the next
level. This keeps the construction simple and avoids depth-dependent
padding.

**Empty blob.** The empty blob's root is defined as `leaf_hash(&[])` —
i.e., blake3(`0x00`).

**Single-chunk blob.** A blob of one chunk has `root == leaf_hash(chunk)`
and an empty inclusion proof.

**Inclusion proof format.** A proof for chunk index `i` in an
`N`-chunk blob is the ordered sequence of sibling hashes walking from
the leaf to the root — exactly `ceil(log2(N))` entries of 32 bytes each
(0 bytes for `N == 1`). Whether a sibling is the left or right child at
each level is derived from the bit pattern of `i`, so the proof wire
format carries only the 32-byte hashes.

**Verification.** The receiver buffers pieces per active chunk. When a
full 64KB chunk is assembled AND the proof for that chunk has been
received (attached to the final piece of the chunk), the receiver
recomputes `leaf_hash(chunk)` and walks the proof to obtain a candidate
root, which must equal the authoritative blob `hash`. On success the
chunk is flushed to disk via a single `WriteChunk` effect. On failure —
tampered bytes, corrupted proof, wrong-root proof, or missing proof —
the receiver discards the chunk, un-marks its completion, removes the
offending seeder, and sends `BLOB_CANCEL`.

**Why a bespoke tree instead of bao.** bao is a SHA-2-based 1KB-chunk
Merkle tree whose streaming proofs interleave data and hashes at ~3KB
granularity — fundamentally too large to fit alongside a 1300-byte
BLOB_DATA piece inside a single 1350-byte datagram. The chunk-Merkle
scheme above uses blake3 (matching the rest of the Merkle-Tox protocol),
one leaf per 64KB chunk, and ships each inclusion proof out-of-band on
the final piece of its chunk.

## 4. Credit-Based Flow Control

Push streaming uses a **piece-level credit window** for flow control,
complementing the transport's congestion control. Credits track pieces
(~1300B transport units), not chunks (64KB verification units). This
decouples continuous data flow from chunk-level Merkle verification —
a single missing piece in a chunk does not stall the credit window.

### Sender (Seeder) Side

The seeder maintains:
-   `credits: usize` — Number of **pieces** the seeder may send before
    waiting for feedback. Initialized to `INITIAL_CREDITS` (256 pieces,
    ~300KB).
-   `max_credits: usize` — Upper bound on credits, grown based on delivery
    rate. Initialized to `INITIAL_CREDITS`. Capped at `MAX_CREDITS`
    (4096 pieces, ~4.8MB).

On each poll:
1.  While `credits > 0` and there are unsent pieces, send a `BLOB_DATA`
    packet. Decrement `credits`.
2.  When `BLOB_PROGRESS` arrives: count newly confirmed pieces by
    comparing the current `incomplete_chunks` piece masks against the
    previously seen state. Pieces that were 0 and are now 1, plus all
    pieces in newly completed chunks (from `completed_ranges`), count as
    confirmed. Add confirmed count to `credits`. Grow `max_credits` by
    `confirmed / 2` (additive increase).
3.  If a piece is missing across 2 consecutive `BLOB_PROGRESS` messages
    (same bit still 0 in an `incomplete_chunks` piece mask), retransmit
    that piece. Do not decrement `credits` for retransmissions.

The seeder pushes pieces chunk-sequentially (all ~50 pieces for chunk N,
then chunk N+1, etc.) but the credit window is piece-granular. If 200
pieces are in flight across 4 chunks and 4 are lost (one per chunk), the
seeder still has credits to send new pieces for chunk 5 while the 4
missing pieces await retransmission.

### Receiver Side

The receiver:
1.  Tracks received pieces per chunk in piece-level bitmasks.
2.  When all pieces for a 64KB chunk arrive, Merkle-verifies the chunk and
    adds it to `completed_ranges`.
3.  Sends `BLOB_PROGRESS` at least once per second, or immediately when
    gaps older than `2 * RTT` are detected. The message includes
    `completed_ranges` and `incomplete_chunks` with piece-level detail
    for the currently active chunks.

### Interaction with Transport Congestion Control

Piece-level credits and transport congestion control both apply. Credits
limit how many pieces the application queues; the transport's send window
and pacing limit how fast they leave the wire. The effective send rate is
`min(credit_rate, transport_rate)`. Credits prevent the application from
overloading the transport's send queue, while transport pacing prevents
overwhelming the network.

Since `BLOB_DATA` uses sequenced DATA packets, the transport's congestion
controller has full per-packet loss visibility. Lost blob pieces are
detected by the transport (via ACK bitmap gaps) and reported as
`DatagramLost(seq)` events, but the transport does NOT retransmit them.
The CAS layer handles retransmission based on `BLOB_PROGRESS` feedback,
which is more efficient because it accounts for pieces obtained from
other peers (swarming) and retransmits at piece granularity without
blocking the credit window.

### Advantages Over Transport-Level Retransmission

-   **No head-of-line blocking**: A lost piece does not stall other pieces.
-   **Application-aware retransmission**: Only pieces missing from the bitmask
    are retransmitted. The sender knows exactly what's needed.
-   **Swarming-aware**: Pieces obtained from other peers appear in the bitmask,
    and the seeder skips them automatically.
-   **Full CC visibility**: Each piece is a sequenced DATA packet, giving the
    congestion controller per-packet delivery and loss signals.
-   **No fragmentation overhead**: Each piece is one packet — no reassembly
    buffers, no per-fragment tracking, no message-level completion ACKs.

## 5. Streaming & Direct-to-Disk I/O

-   **Piece-Level I/O**: `merkle-tox-sqlite` provides a streaming writer
    with random-access support for non-sequential pieces.
-   Upon `BLOB_DATA` receipt, pieces are buffered per active chunk. When
    a complete 64KB chunk is assembled and its inclusion proof is
    verified, the chunk is flushed to its file offset via a single
    `WriteChunk` effect.
-   **In-DB Optimization**: Small blobs are stored directly in SQLite. See
    **`merkle-tox-persistence.md`**.
-   **Finalization**: Once all pieces are received and all chunks are
    Merkle-verified, the file is marked "Available". No additional
    full-file hash check is required — verifying each chunk against the
    committed root already authenticates the entire blob.

## 6. Privacy & Selective Downloading

-   Clients do not automatically download every blob.
-   **Thumbnails**: For images, a small (`MAX_THUMBNAIL_SIZE = 32768` bytes)
    thumbnail can be embedded in `MerkleNode` `metadata` or as a separate
    auto-downloaded small blob.
-   **User-Initiated**: Large blobs are downloaded upon user interaction.
-   **Status Tracking**: UI uses blob status (**Pending, Downloading, Available,
    Error**) for rendering.

## 7. Constants

| Constant               | Value    | Description                            |
| :--------------------- | :------- | :------------------------------------- |
| `MAX_PIECE_DATA`       | 1200B    | Maximum data per piece (no proof)      |
| `CHUNK_SIZE`           | 64KB     | Merkle leaf & tracking boundary        |
| `PIECES_PER_CHUNK`     | ~55      | `CHUNK_SIZE / MAX_PIECE_DATA`          |
| `INITIAL_CREDITS`      | 256      | Initial send window (pieces, ~300KB)   |
| `MAX_CREDITS`          | 4096     | Upper bound on send window (pieces, ~4.8MB) |
| `PROGRESS_INTERVAL`    | 100ms    | Minimum interval between BLOB_PROGRESS |
| `GAP_RETRANSMIT_THRESHOLD` | 2×RTT | Retransmit pieces missing this long   |
| `READVERTISE_INTERVAL` | 1s       | Re-advertisement throttle              |
| `FETCH_TIMEOUT`        | 15s      | Fallback pull request timeout          |

**Constant rationale**: The `INITIAL_CREDITS` / `MAX_CREDITS` /
`PROGRESS_INTERVAL` values were tuned empirically against real-Tox
loopback blob transfers. Earlier conservative values (64 / 512 / 1s)
left the credit window the binding constraint on throughput even when
the transport's cwnd had room. With 256 initial credits and a 100ms
progress cadence, the credit replenishment rate matches a sustained
multi-megabyte-per-second flow. The 100ms interval still honors the
original "at least once per second" requirement — it's a minimum
interval, not a maximum.
