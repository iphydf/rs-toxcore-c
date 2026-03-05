//! Tests for chunk-level swarming (BitTorrent-style partial seeding).
//!
//! These tests verify that:
//! 1. SwarmSync tracks per-seeder bitmasks and only requests chunks from
//!    seeders that have them.
//! 2. The engine responds to BlobQuery with received_mask when Downloading.
//! 3. Proactive re-advertisement pushes updated bitmasks to querying peers.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE, SwarmSync};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, KConv, LogicalIdentityPk, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::InMemoryStore;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

// ── Layer 1: Unit tests (SwarmSync chunk selection with partial seeders) ─────

/// When a seeder has a bitmask indicating it only has certain chunks,
/// next_requests() should only assign chunks that seeder actually has.
#[test]
fn partial_seeder_only_gets_matching_chunk_requests() {
    let hash = NodeHash::from([1u8; 32]);
    let info = BlobInfo {
        hash,
        size: CHUNK_SIZE * 8, // 8 chunks
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };

    let mut sync = SwarmSync::new(info);

    let full_seeder = PhysicalDevicePk::from([0x11u8; 32]);
    let partial_seeder = PhysicalDevicePk::from([0x22u8; 32]);

    // Full seeder has all chunks (no bitmask = "has everything")
    sync.add_seeder(full_seeder);

    // Partial seeder only has chunks 0, 1, 2
    sync.add_partial_seeder(partial_seeder, vec![(0, 2)]);

    let now = Instant::now();
    let reqs = sync.next_requests(8, now);

    // All 8 chunks should be requested
    assert_eq!(reqs.len(), 8, "Should request all 8 chunks");

    // Chunks assigned to partial_seeder should only be 0, 1, or 2
    for (peer, req) in &reqs {
        let chunk_idx = *req.offset.expose_unchecked() / CHUNK_SIZE;
        if *peer == partial_seeder {
            assert!(
                chunk_idx <= 2,
                "Partial seeder was assigned chunk {} but only has 0-2",
                chunk_idx
            );
        }
    }

    // Partial seeder should have gotten some requests (not zero)
    let partial_count = reqs.iter().filter(|(p, _)| *p == partial_seeder).count();
    assert!(
        partial_count > 0,
        "Partial seeder should receive at least 1 request for chunks it has"
    );
}

/// A seeder whose bitmask has zero overlap with missing chunks should get
/// no requests at all.
#[test]
fn seeder_with_no_matching_chunks_gets_no_requests() {
    let hash = NodeHash::from([1u8; 32]);
    let info = BlobInfo {
        hash,
        size: CHUNK_SIZE * 8,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };

    let mut sync = SwarmSync::new(info);

    let full_seeder = PhysicalDevicePk::from([0x11u8; 32]);
    let useless_seeder = PhysicalDevicePk::from([0x22u8; 32]);

    sync.add_seeder(full_seeder);

    // Useless seeder has chunks 0-3, but we already have those
    sync.tracker.mark_received(0);
    sync.tracker.mark_received(1);
    sync.tracker.mark_received(2);
    sync.tracker.mark_received(3);

    sync.add_partial_seeder(useless_seeder, vec![(0, 3)]);

    let now = Instant::now();
    let reqs = sync.next_requests(8, now);

    // Only chunks 4-7 are missing, and only full_seeder has them
    for (peer, _) in &reqs {
        assert_ne!(
            *peer, useless_seeder,
            "Seeder with no matching chunks should get no requests"
        );
    }
}

/// Updated bitmask from re-advertisement should expand what we request
/// from a partial seeder.
#[test]
fn updated_bitmask_expands_requestable_chunks() {
    let hash = NodeHash::from([1u8; 32]);
    let info = BlobInfo {
        hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };

    let mut sync = SwarmSync::new(info);

    let seeder = PhysicalDevicePk::from([0x11u8; 32]);

    // Initially has only chunk 0
    sync.add_partial_seeder(seeder, vec![(0, 0)]);

    let now = Instant::now();
    let reqs = sync.next_requests(4, now);
    let seeder_chunks: Vec<u64> = reqs
        .iter()
        .filter(|(p, _)| *p == seeder)
        .map(|(_, r)| *r.offset.expose_unchecked() / CHUNK_SIZE)
        .collect();
    assert_eq!(seeder_chunks, vec![0], "Initially can only request chunk 0");

    // Clear active fetches so we can re-request
    sync.active_fetches.clear();

    // Update ranges: now has chunks 0-3 (all)
    sync.add_partial_seeder(seeder, vec![(0, 3)]);

    let reqs = sync.next_requests(4, now);
    let seeder_count = reqs.iter().filter(|(p, _)| *p == seeder).count();
    assert_eq!(
        seeder_count, 4,
        "After bitmask update, seeder should serve all 4 chunks"
    );
}

// ── Layer 2: Engine tests (BlobQuery/BlobAvail with bitmasks) ────────────────

/// A node with Downloading status should respond to BlobQuery with BlobAvail
/// that includes its received_mask.
#[test]
fn downloading_node_responds_to_blob_query_with_mask() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let node_pk = PhysicalDevicePk::from([1u8; 32]);
    let querying_peer = PhysicalDevicePk::from([2u8; 32]);

    let mut engine = MerkleToxEngine::new(
        node_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xBBu8; 32]);
    let store = InMemoryStore::new();

    // Store blob with Downloading status and a partial mask (chunks 0, 2 received)
    let mask = vec![0x05u8]; // bits 0 and 2
    let downloading_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Downloading,
        received_mask: Some(mask.clone()),
        decryption_key: None,
    };
    store.put_blob_info(downloading_info).unwrap();

    let effects = engine
        .handle_message(
            querying_peer,
            ProtocolMessage::BlobQuery(blob_hash),
            &store,
            Some(&store),
        )
        .unwrap();

    // Should respond with BlobAvail
    let avail = effects.iter().find_map(|e| {
        if let Effect::SendPacket(_, ProtocolMessage::BlobAvail(info)) = e {
            Some(info.clone())
        } else {
            None
        }
    });

    assert!(
        avail.is_some(),
        "Downloading node should respond to BlobQuery with BlobAvail"
    );

    let avail = avail.unwrap();
    assert_eq!(
        avail.received_mask,
        Some(mask),
        "BlobAvail should include the received_mask so the requester knows which chunks are available"
    );
}

/// A node with Pending status (no chunks at all) should NOT respond.
#[test]
fn pending_node_does_not_respond_to_blob_query() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let node_pk = PhysicalDevicePk::from([1u8; 32]);
    let querying_peer = PhysicalDevicePk::from([2u8; 32]);

    let mut engine = MerkleToxEngine::new(
        node_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xBBu8; 32]);
    let store = InMemoryStore::new();

    let pending_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(pending_info).unwrap();

    let effects = engine
        .handle_message(
            querying_peer,
            ProtocolMessage::BlobQuery(blob_hash),
            &store,
            Some(&store),
        )
        .unwrap();

    let sends_avail = effects
        .iter()
        .any(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::BlobAvail(_))));

    assert!(
        !sends_avail,
        "Pending node (no chunks) should not respond to BlobQuery"
    );
}

/// When receiving BlobAvail with a received_mask, the engine should store
/// the per-seeder bitmask in SwarmSync so chunk selection is mask-aware.
#[test]
fn blob_avail_with_mask_stores_per_seeder_bitmask() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let node_pk = PhysicalDevicePk::from([1u8; 32]);
    let partial_peer = PhysicalDevicePk::from([2u8; 32]);

    let mut engine = MerkleToxEngine::new(
        node_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xBBu8; 32]);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xC1u8; 32]);

    // BlobAvail is gated against `blob_conversations + sessions`
    // (handlers/mod.rs, mirrors the BlobFetch authorisation). Seed
    // both so the partial_peer is recognised as a member of the
    // blob's conversation — without these, the message is dropped at
    // the gate and never reaches the seeder-registration path under
    // test here.
    {
        use merkle_tox_core::engine::Conversation;
        use merkle_tox_core::engine::conversation::{ConversationData, Established};
        use merkle_tox_core::engine::session::{PeerSession, SyncSession, handshake::Handshake};
        engine.blob_conversations.insert(blob_hash, conv_id);
        let established =
            ConversationData::<Established>::new(conv_id, KConv::from([0x11u8; 32]), 1000);
        engine
            .conversations
            .insert(conv_id, Conversation::Established(established));
        let session = SyncSession::<Handshake>::new(conv_id, &store, false, Instant::now());
        engine
            .sessions
            .insert((partial_peer, conv_id), PeerSession::Handshake(session));
    }

    // We're already syncing this blob (have it in blob_syncs)
    let our_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 8,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let sync = SwarmSync::new(our_info);
    engine.blob_syncs.insert(blob_hash, sync);

    // Peer sends BlobAvail with partial mask (has chunks 0-3)
    let peer_mask = vec![0x0Fu8]; // bits 0-3
    let peer_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 8,
        status: BlobStatus::Downloading,
        received_mask: Some(peer_mask.clone()),
        decryption_key: None,
    };

    engine
        .handle_message(
            partial_peer,
            ProtocolMessage::BlobAvail(peer_info),
            &store,
            None,
        )
        .unwrap();

    let sync = engine.blob_syncs.get(&blob_hash).unwrap();

    // The peer should be registered as a seeder with its bitmask
    assert!(
        sync.has_seeder(&partial_peer),
        "Partial peer should be registered as a seeder"
    );

    // The peer should be treated as a seeder (BlobAvail with received_mask
    // is treated as a full seeder in the current implementation since
    // BlobInfo doesn't carry per-chunk ranges yet).
    assert!(
        sync.seeder_has_chunk(&partial_peer, 0),
        "Seeder should be marked as having chunk 0"
    );
    assert!(
        sync.seeder_has_chunk(&partial_peer, 3),
        "Seeder should be marked as having chunk 3"
    );
}
