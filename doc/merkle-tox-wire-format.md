# Merkle-Tox Sub-Design: Wire Format & Serialization

## Overview

Merkle-Tox uses **MessagePack** as its primary serialization format for
non-trivial data structures.

## 1. Serialization Standard: MessagePack

All structures (Packets, Nodes, Handshakes, etc.) MUST be serialized using
MessagePack via the `tox-proto` crate, which provides a unified interface and
the `ToxProto` derive macro.

### Wire Efficiency (Arrays vs. Maps)

To minimize overhead within the ~1.3KB Tox packet MTU, Merkle-Tox uses
**MessagePack Arrays** (positional serialization).

-   **Rust Representation**: Named structs and enums are used in code.
-   **Wire Representation**: Fields are serialized in definition order. Field
    names are omitted.
-   **Implementation**: Enforced via `#[derive(ToxProto)]`.

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

### WireNode Field Index

The `WireNode` is a MessagePack positional array with the following fields. The
`authentication` field (field 8) covers fields 1–7 via EphemeralSignature or
Signature.

| Index | Field               | Type           | Notes                    |
| :---- | :------------------ | :------------- | :----------------------- |
| 1     | `parents`           | `Vec<[u8;32]>` | Parent node hashes       |
| 2     | `sender_hint`       | `[u8; 4]`      | Per-message              |
:       :                     :                : ratchet-derived hint;    :
:       :                     :                : opaque to relays         :
| 3     | `encrypted_routing` | `Vec<u8>`      | Encrypted                |
:       :                     :                : `[sequence_number]`      :
:       :                     :                : (cleartext `[sender_pk,  :
:       :                     :                : seq]` for Admin nodes)   :
| 4     | `payload_data`      | `Vec<u8>`      | Encrypted and/or         |
:       :                     :                : compressed content       :
| 5     | `topological_rank`  | `u64`          | Covered by               |
:       :                     :                : authenticator;           :
:       :                     :                : relay-manipulation-proof :
| 6     | `flags`             | `u32`          | Covered by               |
:       :                     :                : authenticator;           :
:       :                     :                : relay-manipulation-proof :
| 7     | `authentication`    | `NodeAuth`     | EphemeralSignature       |
:       :                     :                : (content) or Signature   :
:       :                     :                : (admin/keywrap)          :

See `merkle-tox-dag.md` for the canonical signature input definition and
`merkle-tox-deniability.md` for key derivations.

## 4. Optimized Binary Handling

To serialize cryptographic data and payloads as MessagePack **Binary** types
rather than integer arrays, these rules MUST be followed:

### `serde_bytes` for Dynamic Buffers

All dynamic byte buffers (e.g., `Vec<u8>` or `&[u8]`) representing raw data,
encrypted payloads, or file chunks MUST be serialized as MessagePack **Binary**
types.

-   **Why**: Without this, Serde serializes `Vec<u8>` as a MessagePack Array of
    individual integers, adding significant overhead.
-   **Automatic Handling**: The `#[derive(ToxProto)]` macro automatically
    detects `Vec<u8>` and `&[u8]` fields and applies the `serde_bytes`
    optimization. Manually adding `#[serde(with = "serde_bytes")]` is not
    required when using `ToxProto`.

### `serde-big-array` for Fixed-Size Arrays

Fixed-size arrays larger than 32 bytes (most notably **Ed25519 Signatures**
which are 64 bytes) MUST use the `serde-big-array` crate.

-   **Why**: Standard Serde only supports traits for arrays up to size 32. For
    larger arrays, a custom serializer or `BigArray` helper is required to
    prevent compilation errors and ensure binary encoding.

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

To mitigate side-channel leaks where an observer guesses message content based
on exact length, Merkle-Tox implements **Power-of-2 Padding**.

### Padding Rule

Before encryption and serialization into a `WireNode`, the sensitive metadata
and content fields are logically combined into a single buffer.

1.  **Bundle Structure**: Padding is applied to the `payload_data` block only:
    `[network_timestamp (8B), content (MsgPack), metadata (MsgPack)]`. The
    `sender_hint` (field 3) and `encrypted_routing` (field 4) are **not**
    included in the padded bundle; they have fixed and bounded sizes
    respectively and do not benefit from padding.
2.  **Target Sizes**: The reassembled payload MUST be padded to the next power
    of 2 (128, 256, 512, ..., up to `MAX_MESSAGE_SIZE`). The minimum padded size
    is 128 bytes; the maximum is bounded by `MAX_MESSAGE_SIZE` (1MB).
3.  **Scheme**: Merkle-Tox uses **ISO/IEC 7816-4** padding:
    -   A single `0x80` byte is appended to the data.
    -   `0x00` bytes are appended until the target power-of-2 boundary is
        reached.
4.  **Removal**: Upon decryption, the recipient finds the last `0x80` byte and
    truncates the buffer at that point to recover the original content.

**IMPORTANT**: Padding is applied to the plaintext **before** encryption. The
resulting `payload_data` ciphertext (which embeds the padding) is what appears
in the `WireNode` and is covered by both the authenticator and the
content-addressable hash. Because ChaCha20 encryption MUST use a random 12-byte
nonce per message (see `merkle-tox-deniability.md`), the final ciphertext and
resulting `WireNode` hash will be randomized every time a message is encrypted,
even if the underlying padded plaintext is identical.

### Implementation

Padding is applied in the `merkle-tox-core` library within the `pack_wire`
function and removed in `unpack_wire`, ensuring content stored in the CAS and
sent over the wire is uniform in size.

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
