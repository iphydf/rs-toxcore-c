# Merkle-Tox Sub-Design: Wire Format & Serialization

## Overview

Merkle-Tox uses **MessagePack** as its primary serialization format for all
non-trivial data structures. This provides a balance between binary efficiency,
speed, and developer ergonomics.

## 1. Serialization Standard: MessagePack

All structures (Packets, Nodes, Handshakes, etc.) MUST be serialized using
MessagePack via the `tox-proto` crate, which provides a unified interface and
the `ToxProto` derive macro.

### Wire Efficiency (Arrays vs. Maps)

To minimize the overhead within the limited ~1.3KB Tox packet size, Merkle-Tox
strictly uses **MessagePack Arrays** (positional serialization) for the wire
format.

-   **Rust Representation**: Named structs and enums are used in the code for
    clarity.
-   **Wire Representation**: Fields are serialized in the order they are defined
    in the Rust struct. Field names are NOT included in the binary stream.
-   **Implementation**: This is enforced by using `#[derive(ToxProto)]` on all
    protocol structures. The `tox-proto::serialize` and `tox-proto::deserialize`
    functions should be used as the primary entry points.

## 2. Transport Layer Framing (`tox-sequenced`)

The transport layer uses a **Flattened Positional Array** to minimize overhead.
The meaning of fields following the `packet_type` discriminator depends on the
type.

### `Packet` Variants

-   **DATA (0)**: `[0, [message_id, fragment_index, total_fragments, data]]`
-   **ACK (1)**: `[1, [message_id, base_index, bitmask, rwnd]]`
-   **NACK (2)**: `[2, [message_id, missing_ids]]`
-   **PING (3)**: `[3, t1_origin_timestamp]`
-   **PONG (4)**: `[4, [t1_origin_timestamp, t2_receive_timestamp,
    t3_transmit_timestamp]]`

**Field Definitions:**

-   `message_id`: `u32`
-   `fragment_index` / `base_index`: `u16`
-   `total_fragments`: `u16`
-   `bitmask`: `u64`
-   `rwnd`: `u16` (Remaining receive window in fragments)
-   `t1, t2, t3`: `i64` (Network time in ms)
-   `data`: `Vec<u8>` (Raw binary payload)
-   `missing_ids`: `Vec<u16>` (List of missing fragment indices)

## 3. Application Layer Serialization

When a `DATA` message is reassembled, the resulting byte stream is itself a
MessagePack-encoded object.

### Reassembled Payload Layout

1.  **Message Type Tag**: The first byte (or MsgPack tag) identifies the
    `MessageType` (e.g., `MerkleNode`, `SyncHeads`).
2.  **Payload Data**: The positional array representing the actual message
    content.

## 4. Optimized Binary Handling

To ensure cryptographic data (hashes, keys, signatures) and payloads are
serialized as efficient MessagePack **Binary** types rather than arrays of
integers, the following rules MUST be followed:

### `serde_bytes` for Dynamic Buffers

All dynamic byte buffers (e.g., `Vec<u8>` or `&[u8]`) representing raw data,
encrypted payloads, or file chunks MUST be serialized as MessagePack **Binary**
types.

-   **Why**: Without this, Serde serializes `Vec<u8>` as a MessagePack Array of
    individual integers, adding significant overhead (1-2 bytes per byte of
    data).
-   **Automatic Handling**: The `#[derive(ToxProto)]` macro automatically
    detects `Vec<u8>` and `&[u8]` fields and applies the `serde_bytes`
    optimization. Manually adding `#[serde(with = "serde_bytes")]` is not
    required when using `ToxProto`.

### `serde-big-array` for Fixed-Size Arrays

Fixed-size arrays larger than 32 bytes (most notably **Ed25519 Signatures**
which are 64 bytes) MUST use the `serde-big-array` crate.

-   **Why**: Standard Serde only supports traits for arrays up to size 32. For
    larger arrays, a custom serializer or `BigArray` helper is required to
    prevent compilation errors and ensure efficient binary encoding.

```rust
use serde_big_array::BigArray;

struct AdminNode {
    #[serde(with = "BigArray")]
    signature: [u8; 64],
}
```

## 5. Cryptographic Integers & Endianness

-   **Integers**: MessagePack handles integer width and endianness
    (Big-Endian/Network Byte Order) automatically. Implementations MUST use the
    smallest possible integer representation provided by MsgPack.
-   **Binary Blobs**: Hashes (Blake3), Public Keys (Ed25519), and encrypted
    payloads MUST be serialized as MessagePack **Binary** types (FixBin, Bin 8,
    Bin 16, or Bin 32) via the helpers mentioned above.

## 6. Message Padding (Anti-Traffic Analysis)

To mitigate side-channel leaks where an observer can guess the message content
based on its exact length (e.g., distinguishing between "Yes" and "No"),
Merkle-Tox implements **Power-of-2 Padding**.

### Padding Rule

Before encryption and serialization into a `WireNode`, the sensitive metadata
and content fields are logically combined into a single buffer.

1.  **Bundle Structure**: `[sender_pk (32B), sequence_number (8B), content
    (MsgPack), metadata (MsgPack)]`.
2.  **Target Sizes**: The reassembled payload MUST be padded to the next power
    of 2: 128, 256, 512, 1024, 2048, or 4096 bytes.
3.  **Scheme**: Merkle-Tox uses **ISO/IEC 7816-4** padding:
    -   A single `0x80` byte is appended to the data.
    -   `0x00` bytes are appended until the target power-of-2 boundary is
        reached.
4.  **Removal**: Upon decryption, the recipient finds the last `0x80` byte and
    truncates the buffer at that point to recover the original content.

**IMPORTANT**: Padding is a property of the **Wire Format** only. It is **not**
included in the serialization used to calculate a node's `hash()`. This ensures
that hash verification is consistent regardless of the transport-level padding
or compression used.

### Implementation

Padding is applied in the `merkle-tox-core` library within the `pack_wire`
function and removed in `unpack_wire`. This ensures that all content stored in
the CAS and sent over the wire is uniform in size.

## 7. Schema Evolution & Versioning

Since we are using positional arrays, schema evolution is sensitive to field
order.

1.  **Appending Fields**: New fields MUST only be appended to the end of
    existing structs.
2.  **Optional Fields**: Use `Option<T>` for new fields. If a field is missing
    in the received array (due to an older sender), `rmp-serde` will deserialize
    it as `None`.
3.  **No Deletions**: Fields MUST NOT be removed or reordered. If a field
    becomes obsolete, it should be kept as a "Reserved" or "Padding" field
    (e.g., `_unused: ()`) to maintain indices.
