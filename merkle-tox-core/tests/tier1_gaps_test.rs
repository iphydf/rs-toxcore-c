use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobInfo, BlobStatus, SwarmSync};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, LogicalIdentityPk, NodeHash, NodeLookup, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestRoom, apply_effects, create_msg, create_signed_content_node,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// Sets up a TestRoom with engine + store, handling genesis node through the engine.
fn setup_room() -> (TestRoom, MerkleToxEngine, InMemoryStore) {
    let room = TestRoom::new(2);
    let store = InMemoryStore::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );
    room.setup_engine(&mut engine, &store);

    // Ensure Genesis is verified in engine (it was added to store in setup_engine)
    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    (room, engine, store)
}

/// Gets merged heads (content + admin) so content nodes have auth node ancestors.
/// This ensures causal context includes the authorization records.
fn get_all_heads(
    store: &InMemoryStore,
    conv_id: &merkle_tox_core::dag::ConversationId,
) -> Vec<NodeHash> {
    let mut heads: Vec<NodeHash> = store.get_heads(conv_id);
    for admin_head in store.get_admin_heads(conv_id) {
        if !heads.contains(&admin_head) {
            heads.push(admin_head);
        }
    }
    heads
}

/// Gets the max rank across all merged heads.
fn get_max_rank(store: &InMemoryStore, conv_id: &merkle_tox_core::dag::ConversationId) -> u64 {
    get_all_heads(store, conv_id)
        .iter()
        .filter_map(|h| store.get_rank(h))
        .max()
        .unwrap_or(0)
}

// ── Gap 1: Edit Node Validation ──────────────────────────────────────────

#[test]
fn test_edit_must_target_text() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Create a Blob node (non-Text)
    let blob_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads.clone(),
        Content::Blob {
            hash: NodeHash::from([0xBBu8; 32]),
            name: "test.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
            size: 1024,
            metadata: vec![],
        },
        parent_rank + 1,
        2,
        2000,
    );
    let blob_hash = blob_node.hash();
    let effects = engine
        .handle_node(room.conv_id, blob_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Create an Edit targeting the Blob → should be rejected
    let edit_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        vec![blob_hash],
        Content::Edit {
            target_hash: blob_hash,
            new_text: "edited".to_string(),
        },
        parent_rank + 2,
        3,
        3000,
    );

    let result = engine.handle_node(room.conv_id, edit_node, &store, None);
    assert!(
        result.is_err(),
        "Edit targeting a Blob node should be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        format!("{}", err).contains("Edit target must reference a Text node"),
        "Expected InvalidEditTarget, got: {}",
        err
    );
}

#[test]
fn test_edit_author_must_match() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let bob = &room.identities[1];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Alice sends a text
    let text_node = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "hello",
        parent_rank + 1,
        2,
        2000,
    );
    let text_hash = text_node.hash();
    let effects = engine
        .handle_node(room.conv_id, text_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Bob tries to edit Alice's text → should be rejected
    let edit_heads = get_all_heads(&store, &room.conv_id);
    let edit_rank = get_max_rank(&store, &room.conv_id);
    let edit_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        bob.master_pk,
        bob.device_pk,
        edit_heads,
        Content::Edit {
            target_hash: text_hash,
            new_text: "tampered".to_string(),
        },
        edit_rank + 1,
        3,
        3000,
    );

    let result = engine.handle_node(room.conv_id, edit_node, &store, None);
    assert!(
        result.is_err(),
        "Edit by different author should be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        format!("{}", err).contains("Edit author must match"),
        "Expected EditAuthorMismatch, got: {}",
        err
    );
}

#[test]
fn test_edit_unknown_target_speculative() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Edit targeting a hash that doesn't exist in the store → should be accepted speculatively
    let unknown_target = NodeHash::from([0xFFu8; 32]);
    let edit_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads.clone(),
        Content::Edit {
            target_hash: unknown_target,
            new_text: "speculative edit".to_string(),
        },
        parent_rank + 1,
        2,
        2000,
    );

    let result = engine.handle_node(room.conv_id, edit_node, &store, None);
    assert!(
        result.is_ok(),
        "Edit with unknown target should be accepted speculatively, got: {:?}",
        result.err()
    );
}

// ── Gap 2: BLOB_AVAIL bao_root Validation ───────────────────────────────

#[test]
fn test_blob_avail_mismatching_root_blacklists() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        PhysicalDevicePk::from([1u8; 32]),
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xAAu8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);
    let store = InMemoryStore::new();

    // Pre-populate blob_syncs with a known bao_root
    let info = BlobInfo {
        hash: blob_hash,
        size: 1024,
        bao_root: Some([0x11u8; 32]),
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync = SwarmSync::new(info.clone());
    sync.add_seeder(peer_pk);
    engine.blob_syncs.insert(blob_hash, sync);

    // Peer sends BlobAvail with WRONG bao_root
    let bad_info = BlobInfo {
        hash: blob_hash,
        size: 1024,
        bao_root: Some([0x22u8; 32]), // Mismatching!
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };

    let _effects = engine
        .handle_message(peer_pk, ProtocolMessage::BlobAvail(bad_info), &store, None)
        .unwrap();

    // The peer should have been removed as seeder
    let sync = engine.blob_syncs.get(&blob_hash).unwrap();
    assert!(
        !sync.seeders.contains(&peer_pk),
        "Peer with mismatching bao_root should be blacklisted (removed as seeder)"
    );

    // Verify with matching bao_root: peer added back
    let good_info = BlobInfo {
        hash: blob_hash,
        size: 1024,
        bao_root: Some([0x11u8; 32]), // Matching
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };

    let _ = engine
        .handle_message(peer_pk, ProtocolMessage::BlobAvail(good_info), &store, None)
        .unwrap();

    let sync = engine.blob_syncs.get(&blob_hash).unwrap();
    assert!(
        sync.seeders.contains(&peer_pk),
        "Peer with matching bao_root should be added as seeder"
    );
}

// ── Gap 3: SyncHeads anchor_hash ─────────────────────────────────────────

#[test]
fn test_sync_heads_includes_anchor() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();

    // Start a sync session
    engine.start_sync(room.conv_id, Some(room.identities[1].device_pk), &store);

    // Get admin heads from store. TestRoom sets them up via genesis.
    let admin_heads = store.get_admin_heads(&room.conv_id);
    assert!(
        !admin_heads.is_empty(),
        "TestRoom should set up admin heads"
    );

    // Activate the session by sending CapsAnnounce
    let effects = engine
        .handle_message(
            room.identities[1].device_pk,
            ProtocolMessage::CapsAnnounce {
                version: 1,
                features: 0,
            },
            &store,
            None,
        )
        .unwrap();

    // Find the SyncHeads in effects
    let sync_heads: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::SendPacket(_, ProtocolMessage::SyncHeads(h)) = e {
                Some(h)
            } else {
                None
            }
        })
        .collect();

    assert!(
        !sync_heads.is_empty(),
        "Should have sent SyncHeads on handshake"
    );
    assert_eq!(
        sync_heads[0].anchor_hash,
        admin_heads.first().cloned(),
        "SyncHeads should include anchor_hash from admin heads"
    );
}

// ── Gap 4: Effective Timestamp ───────────────────────────────────────────

#[test]
fn test_effective_timestamp() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Node A: timestamp = 5000
    let node_a = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "msg A",
        parent_rank + 1,
        2,
        5000,
    );
    let hash_a = node_a.hash();
    let effects = engine
        .handle_node(room.conv_id, node_a.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Node B: timestamp = 3000 (before A), parent = A
    // T_eff(B) should be max(3000, T_eff(A)) = max(3000, 5000) = 5000
    let node_b = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        vec![hash_a],
        "msg B",
        parent_rank + 2,
        3,
        3000,
    );
    let effects = engine
        .handle_node(room.conv_id, node_b.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let t_eff_a = merkle_tox_core::dag::effective_timestamp(&node_a, &store);
    let t_eff_b = merkle_tox_core::dag::effective_timestamp(&node_b, &store);

    assert_eq!(t_eff_a, 5000, "T_eff(A) should be its own timestamp");
    assert_eq!(
        t_eff_b, 5000,
        "T_eff(B) should be max(3000, 5000) = 5000 (inherits parent's effective timestamp)"
    );
}
