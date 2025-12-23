# ToxProto Serialization Specification

This document describes how `tox-proto` encodes Rust types into MessagePack.

## Default Encoding Rules

By default, `tox-proto` uses a strict mapping between Rust types and MessagePack markers.

| Rust Type | MessagePack Representation |
|-----------|---------------------------|
| `u8`..`u64` | Integer (fixint, u8, u16, u32, u64) |
| `i8`..`i64` | Integer (fixint, i8, i16, i32, i64) |
| `f32`, `f64` | Float 32/64 |
| `bool` | True / False |
| `String`, `&str` | String (fixstr, str8, str16, str32) |
| `[u8; N]`, `Vec<u8>` | Binary (bin8, bin16, bin32) |
| `[T; N]`, `Vec<T>` | Array (fixarray, array16, array32) |
| `HashMap`, `BTreeMap` | Map (fixmap, map16, map32) |
| `Option<T>` | Array of length 0 (None) or 1 (Some) |
| `Result<T, E>` | Array of length 2: `[0, Error]` or `[1, Ok]` |
| `Struct` | Array of field values (ordered by definition) |
| `Enum` | Array: `[VariantIndex, Field1, Field2, ...]` |

---

## The `#[tox(flat)]` Attribute

The `flat` attribute allows for specialized, compact encoding based on the structure of your data.

### 1. Transparent Wrapping (Single Field)
If a struct marked `#[tox(flat)]` contains exactly one field, it is encoded **transparently** as that field. The MsgPack array wrapper for the struct is omitted.

```rust
#[derive(ToxProto)]
#[tox(flat)]
struct MyId(u32); // Encoded as MsgPack Integer
```

### 2. Binary Concatenation (Byte-Like Fields)
If a struct marked `#[tox(flat)]` contains multiple fields, and **all** fields are "byte-like" (e.g., `u8`, `[u8; N]`, `Vec<u8>`, or other flat byte-like structs), they are concatenated into a single **Binary (bin)** blob.

```rust
#[derive(ToxProto)]
#[tox(flat)]
struct KeyPair {
    public: [u8; 32],
    secret: [u8; 32],
} // Encoded as a single 64-byte Binary blob
```

### 3. Trailing Dynamic Data
A flat, byte-like struct may contain one `Vec<u8>` or `String` at the **end** of the struct. This dynamic field is included in the total length of the binary blob.

```rust
#[derive(ToxProto)]
#[tox(flat)]
struct Packet {
    id: u32,       // NOT byte-like, falls back to Rule 4
    data: Vec<u8>
}

#[derive(ToxProto)]
#[tox(flat)]
struct BinaryMessage {
    header: [u8; 4],
    payload: Vec<u8>
} // Encoded as a single Binary blob (len = 4 + payload.len())
```

### 4. Default Fallback
If a `flat` struct has multiple fields but they are **not all byte-like**, it falls back to the default MsgPack array representation, effectively ignoring the `flat` attribute for binary concatenation purposes.

---

## Type Constraints

- **Fixed Size**: Flat binary concatenation requires that all fields except the last one have a fixed size known at compile time.
- **Transitivity**: A struct is "byte-like" if all its constituent parts are "byte-like".
