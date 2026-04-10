//! §ZDB adversarial coverage for the zstd decompression path.
//!
//! `MerkleNode::decode_payload` decompresses `payload_data` when the
//! `WireFlags::COMPRESSED` flag is set. Until this fix the
//! decompression used `zstd::decode_all`, which has no output-size
//! limit: a few KB of compressed zeros balloons to an arbitrary size,
//! giving any peer an OOM-DoS vector that bypasses every handler
//! guard (the node is rejected eventually, but only *after* the
//! decompressor has filled memory).
//!
//! The fix wraps the reader in `take(MAX_MESSAGE_SIZE)` — a classic
//! decompression-bomb mitigation: if the decompressed output exceeds
//! the protocol's hard ceiling, the decoder short-reads and we emit
//! a clean error instead of an OOM.

use merkle_tox_core::dag::{
    Ed25519Signature, MerkleNode, NodeAuth, PhysicalDevicePk, WireFlags, WireNode, apply_padding,
};

/// §ZDB-1: a `WireFlags::COMPRESSED` wire node whose compressed
/// payload expands to more than `MAX_MESSAGE_SIZE` must be rejected
/// without allocating the full decompressed size.
#[test]
fn compressed_payload_cannot_exceed_max_message_size() {
    // ~8 MB of highly compressible zeros. With default zstd level 3
    // this shrinks to a few hundred bytes, so we can fit the "bomb"
    // inside a normal tox packet budget.
    let raw = vec![0u8; 8 * 1024 * 1024];
    let mut compressed = zstd::encode_all(&raw[..], 3).expect("zstd encode");
    apply_padding(&mut compressed);

    // Exception-node routing: 32 B sender_pk + 8 B seq_no = 40 B
    let sender_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut routing = Vec::new();
    routing.extend_from_slice(sender_pk.as_bytes());
    routing.extend_from_slice(&0u64.to_be_bytes());

    let wire = WireNode {
        parents: tox_proto::BoundedVec::new(),
        sender_hint: [0u8; 4],
        encrypted_routing: routing,
        payload_data: compressed,
        topological_rank: 0,
        flags: WireFlags::COMPRESSED,
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
    };

    let result = std::panic::catch_unwind(|| MerkleNode::unpack_wire_exception(&wire));
    let inner = result.expect("unpack must not panic");
    assert!(
        inner.is_err(),
        "8 MB decompressed payload must be rejected by the cap, not accepted",
    );
    let msg = format!("{}", inner.err().unwrap());
    assert!(
        msg.contains("Decompression") || msg.contains("oversized") || msg.contains("exceeds"),
        "expected decompression-cap error, got: {}",
        msg,
    );
}

/// §ZDB-2: a legitimate compressed payload (well under the cap) must
/// still decompress successfully. The cap must not break normal use.
#[test]
fn small_compressed_payload_decompresses_normally() {
    // Original content: timestamp(8B) || serialized Content || metadata
    // A ~200-byte payload compresses to something tiny but decompresses
    // fine under the cap.
    let mut raw = Vec::new();
    raw.extend_from_slice(&0i64.to_be_bytes()); // timestamp
    // A minimal Content::Text variant. Borrow a helper: serialize via
    // tox_proto so we don't depend on internal Content variants changing.
    use merkle_tox_core::dag::Content;
    let text = Content::Text("hello".to_string());
    let content_bytes = tox_proto::serialize(&text).unwrap();
    raw.extend_from_slice(&content_bytes);

    let mut compressed = zstd::encode_all(&raw[..], 3).unwrap();
    apply_padding(&mut compressed);

    let sender_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut routing = Vec::new();
    routing.extend_from_slice(sender_pk.as_bytes());
    routing.extend_from_slice(&0u64.to_be_bytes());

    let wire = WireNode {
        parents: tox_proto::BoundedVec::new(),
        sender_hint: [0u8; 4],
        encrypted_routing: routing,
        payload_data: compressed,
        topological_rank: 0,
        flags: WireFlags::COMPRESSED,
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
    };

    let result = MerkleNode::unpack_wire_exception(&wire);
    assert!(
        result.is_ok(),
        "small compressed payload must decompress normally; got err: {:?}",
        result.err(),
    );
}
