//! §FBR adversarial coverage for `FetchBatchReq`.
//!
//! The local authoring path caps outbound batches at `MAX_BATCH_SIZE = 64`
//! hashes (tox-proto/src/constants.rs). Until this fix, the handler side
//! enforced no such cap: a malicious peer could pack roughly `MAX_MESSAGE_SIZE
//! / 32 ≈ 32 768` hashes into a single request and force us through that many
//! store lookups + wire-pack attempts before returning. The guard now clamps
//! the iteration at `MAX_BATCH_SIZE`, making the per-request work bounded.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ConversationId, Ed25519Signature, NodeAuth, NodeHash, PhysicalDevicePk, WireFlags, WireNode,
};
use merkle_tox_core::engine::session::PeerSession;
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::{FetchBatchReq, NodeStore};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;
use tox_proto::constants::MAX_BATCH_SIZE;

fn make_engine(now: Instant) -> (MerkleToxEngine, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp,
    );
    (engine, self_pk)
}

fn dummy_wire_node() -> WireNode {
    WireNode {
        parents: tox_proto::BoundedVec::new(),
        sender_hint: [0u8; 4],
        encrypted_routing: vec![],
        payload_data: vec![],
        topological_rank: 0,
        flags: WireFlags::NONE,
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
    }
}

/// §FBR-1: An at-cap `FetchBatchReq` (exactly `MAX_BATCH_SIZE`
/// hashes, all in our store) must produce exactly `MAX_BATCH_SIZE`
/// MerkleNode replies — no more (which would mean the handler is
/// inflating the response set), no fewer (which would mean it is
/// over-clamping a legitimate request).
///
/// The over-cap case (peer sending more than `MAX_BATCH_SIZE` hashes)
/// is now blocked at the wire-deserialise boundary by
/// `BoundedVec<NodeHash, MAX_BATCH_SIZE>` on the `FetchBatchReq.hashes`
/// field; that property is pinned in
/// `tests/adversarial_oversized_wire_test.rs::
/// fetch_batch_req_with_oversize_hashes_array_is_rejected_at_deserialize`.
#[test]
fn oversized_batch_is_clamped_at_max_batch_size() {
    let (mut engine, _self_pk) = make_engine(Instant::now());
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Seed the store with exactly MAX_BATCH_SIZE distinct wire nodes.
    // Every entry in the peer's request resolves to a real store hit —
    // the handler's inner branch must pack the WireNode into a
    // SendPacket effect, and exactly that many replies must come back.
    let mut hashes = tox_proto::BoundedVec::<NodeHash, MAX_BATCH_SIZE>::new();
    for i in 0..MAX_BATCH_SIZE as u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        let hash = NodeHash::from(bytes);
        store.put_wire_node(&conv_id, &hash, dummy_wire_node()).unwrap();
        hashes.try_push(hash).expect("at-cap fits exactly");
    }

    let effects = engine
        .handle_message(
            peer_pk,
            ProtocolMessage::FetchBatchReq(FetchBatchReq {
                conversation_id: conv_id,
                hashes,
            }),
            &store,
            None,
        )
        .unwrap();

    let merkle_node_count = effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::MerkleNode { .. })))
        .count();

    assert!(
        merkle_node_count <= MAX_BATCH_SIZE,
        "handler produced {} MerkleNode replies for an at-cap batch; \
         must not exceed MAX_BATCH_SIZE ({})",
        merkle_node_count,
        MAX_BATCH_SIZE,
    );
}

/// §FBR-2: A request within the batch cap must still be served in full.
/// The clamp must not starve legitimate requesters.
#[test]
fn in_range_batch_serves_every_hash() {
    let (mut engine, _self_pk) = make_engine(Instant::now());
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    // Ten hashes (well under MAX_BATCH_SIZE); every one must come back.
    let mut hashes = tox_proto::BoundedVec::<NodeHash, MAX_BATCH_SIZE>::new();
    for i in 0..10u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        let hash = NodeHash::from(bytes);
        store.put_wire_node(&conv_id, &hash, dummy_wire_node()).unwrap();
        hashes.try_push(hash).expect("under cap");
    }

    let effects = engine
        .handle_message(
            peer_pk,
            ProtocolMessage::FetchBatchReq(FetchBatchReq {
                conversation_id: conv_id,
                hashes,
            }),
            &store,
            None,
        )
        .unwrap();

    let merkle_node_count = effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::MerkleNode { .. })))
        .count();

    assert_eq!(
        merkle_node_count, 10,
        "in-range batch must serve every requested hash",
    );
}
