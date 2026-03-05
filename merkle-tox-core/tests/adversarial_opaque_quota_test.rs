//! §3.2 Opaque Store Quota — adversarial flood coverage.
//!
//! A peer can send the victim `MerkleNode` messages whose wire bytes
//! can't be unpacked (encrypted content the victim has no keys for).
//! Those nodes are tracked in the opaque store pending future decryption.
//! Without bounds, an attacker could exhaust memory.
//!
//! The spec mitigations (merkle-tox-threat-model.md §3.2):
//!   1. Per-sender cap: `MAX_OPAQUE_REQUESTS_PER_VOUCHER` (500) bounds
//!      the number of opaque entries attributable to a single sender.
//!   2. Global cap: `OPAQUE_STORE_QUOTA` (100 MB) bounds total opaque
//!      bytes per conversation, with cold-first eviction on overflow.
//!
//! This test drives the *production* handler code path (not a
//! test-local eviction loop) by feeding unpackable wire nodes through
//! `handle_message`. A regression that removed either cap would make
//! `opaque_store_usage` grow unbounded and this test would fail.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ConversationId, Ed25519Signature, KConv, NodeAuth, NodeHash, PhysicalDevicePk, WireFlags,
    WireNode,
};
use merkle_tox_core::engine::conversation::{ConversationData, Established};
use merkle_tox_core::engine::{Conversation, MerkleToxEngine};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

fn make_engine() -> (MerkleToxEngine, InMemoryStore, ConversationId) {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp,
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0x55u8; 32]);
    // The MerkleNode handler now drops messages naming a conversation
    // we haven't joined (closes a fs-amplification attack). Seed the
    // conversation so this test exercises the legitimate opaque-store
    // quota path.
    let established =
        ConversationData::<Established>::new(conv_id, KConv::from([0x11u8; 32]), 1000);
    engine
        .conversations
        .insert(conv_id, Conversation::Established(established));
    (engine, store, conv_id)
}

/// Returns a wire node that the engine cannot unpack: ENCRYPTED flag set
/// with random-looking ciphertext bytes. The exact hash key is supplied
/// by the caller so each flooded entry has a distinct identity.
fn make_unpackable_wire(payload_len: usize) -> WireNode {
    WireNode {
        parents: tox_proto::BoundedVec::new(),
        sender_hint: [0u8; 4],
        encrypted_routing: vec![0xABu8; 64],
        payload_data: vec![0xCDu8; payload_len],
        topological_rank: 0,
        flags: WireFlags::ENCRYPTED,
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
    }
}

/// §3.2 guarantee 1 — per-sender opaque cap. Flooding 600 unpackable
/// wire nodes from the same sender must leave at most
/// `MAX_OPAQUE_REQUESTS_PER_VOUCHER` entries attributed to that sender.
#[test]
fn test_per_sender_opaque_cap_bounds_flood() {
    let (mut engine, store, conv_id) = make_engine();
    let attacker = PhysicalDevicePk::from([0xAAu8; 32]);
    let wire = make_unpackable_wire(1024); // 1 KB payloads — well under quota

    let cap = tox_proto::constants::MAX_OPAQUE_REQUESTS_PER_VOUCHER;
    let flood = cap + 100;

    for i in 0..flood {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let hash = NodeHash::from(hash_bytes);
        engine
            .handle_message(
                attacker,
                ProtocolMessage::MerkleNode {
                    conversation_id: conv_id,
                    hash,
                    node: wire.clone(),
                },
                &store,
                None,
            )
            .expect("handle_message");
    }

    let (_, entries) = engine
        .opaque_store_usage
        .get(&conv_id)
        .expect("opaque_store_usage entry for the flooded conversation");
    let from_attacker = entries
        .iter()
        .filter(|(_, _, _, spk)| *spk == attacker)
        .count();
    assert!(
        from_attacker <= cap,
        "per-sender opaque cap exceeded: attacker accumulated {} entries \
         but MAX_OPAQUE_REQUESTS_PER_VOUCHER = {}. A regression here lets \
         a single malicious peer exhaust memory by flooding unpackable \
         wire nodes (§3.2).",
        from_attacker,
        cap,
    );
}

/// §3.2 guarantee 2 — global 100 MB cap with eviction. Two attackers
/// each flood below their per-sender cap but with large enough payloads
/// that the combined total blows past `OPAQUE_STORE_QUOTA`. The engine
/// must evict until `total <= quota`.
#[test]
fn test_global_opaque_quota_triggers_eviction() {
    let (mut engine, store, conv_id) = make_engine();
    let attacker_a = PhysicalDevicePk::from([0xAAu8; 32]);
    let attacker_b = PhysicalDevicePk::from([0xBBu8; 32]);

    // Each payload is ~256 KB. Per-sender cap = 500. We'll send 300 per
    // attacker → 600 * 256 KB ≈ 150 MB → must trip the 100 MB global
    // eviction loop.
    let per_entry_payload = 256 * 1024;
    let wire = make_unpackable_wire(per_entry_payload);
    let per_sender_count = 300;

    let mut seq: u64 = 0;
    for attacker in [attacker_a, attacker_b] {
        for _ in 0..per_sender_count {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&seq.to_le_bytes());
            hash_bytes[8] = attacker.as_bytes()[0]; // disambiguate across attackers
            seq += 1;
            let hash = NodeHash::from(hash_bytes);
            engine
                .handle_message(
                    attacker,
                    ProtocolMessage::MerkleNode {
                        conversation_id: conv_id,
                        hash,
                        node: wire.clone(),
                    },
                    &store,
                    None,
                )
                .expect("handle_message");
        }
    }

    let (total, _entries) = engine
        .opaque_store_usage
        .get(&conv_id)
        .expect("opaque_store_usage entry");
    assert!(
        *total <= tox_proto::constants::OPAQUE_STORE_QUOTA,
        "global opaque-store quota exceeded after flood: total={} bytes, \
         quota={} bytes. The eviction loop in the MerkleNode handler must \
         keep opaque_store_usage[total] bounded — §3.2 guarantee 2.",
        total,
        tox_proto::constants::OPAQUE_STORE_QUOTA,
    );
}
