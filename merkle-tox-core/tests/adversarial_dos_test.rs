use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{Content, ConversationId, KConv, LogicalIdentityPk, PhysicalDevicePk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, create_signed_content_node};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;
use tox_proto::constants::MAX_SPECULATIVE_NODES_PER_CONVERSATION;
use tox_reconcile::{IbltSketch, Tier};

#[test]
fn test_speculative_node_flooding_limit() {
    let self_pk = PhysicalDevicePk::from([1u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine =
        MerkleToxEngine::new(self_pk, self_pk.to_logical(), StdRng::seed_from_u64(0), tp);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);

    // Flood the engine with speculative nodes
    for i in 0..MAX_SPECULATIVE_NODES_PER_CONVERSATION {
        let mut pk_bytes = [0u8; 32];
        pk_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        let pk = PhysicalDevicePk::from(pk_bytes);
        let author_pk = LogicalIdentityPk::from(pk_bytes);

        let node = create_signed_content_node(
            &conv_id,
            &ConversationKeys::derive(&KConv::from([0u8; 32])), // Random keys (MAC will fail)
            author_pk,
            pk,
            vec![],
            Content::Text(format!("Spam {}", i)),
            0, // All roots must have rank 0
            1, // Sequence number
            1000 + i as i64,
        );
        let effects = engine.handle_node(conv_id, node, &store, None).unwrap();
        if i % 100 == 0 {
            println!("Processed {} nodes, effects: {}", i, effects.len());
        }
        merkle_tox_core::testing::apply_effects(effects, &store);
    }

    let (_, spec_count) = store.get_node_counts(&conv_id);
    assert_eq!(spec_count, MAX_SPECULATIVE_NODES_PER_CONVERSATION);

    // 1001st node should be rejected
    let extra_pk = PhysicalDevicePk::from([0xFFu8; 32]);
    let extra_author = LogicalIdentityPk::from([0xFFu8; 32]);
    let extra_node = create_signed_content_node(
        &conv_id,
        &ConversationKeys::derive(&KConv::from([0u8; 32])),
        extra_author,
        extra_pk,
        vec![],
        Content::Text("Extra Spam".to_string()),
        0, // Root nodes must have rank 0
        1,
        99999,
    );
    let res = engine.handle_node(conv_id, extra_node, &store, None);
    assert!(res.is_err(), "1001st speculative node should be rejected");
    assert!(
        matches!(
            res.unwrap_err(),
            merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::TooManySpeculativeNodes
            )
        ),
        "Expected TooManySpeculativeNodes error"
    );
}

#[test]
fn test_sequence_number_replay_attack() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = merkle_tox_core::testing::TestRoom::new(2);
    let alice = &room.identities[0];
    let observer = &room.identities[1];

    let mut engine = MerkleToxEngine::new(
        observer.device_pk,
        observer.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 1. Receive a valid message with seq 1
    let msg1 = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        vec![room.conv_id.to_node_hash()],
        Content::Text("Original Message".to_string()),
        1,
        1,
        1000,
    );
    let effects = engine
        .handle_node(room.conv_id, msg1.clone(), &store, None)
        .unwrap();
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));

    // 2. Try to replay with a DIFFERENT node but same sequence number
    let msg1_replay = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        vec![room.conv_id.to_node_hash()],
        Content::Text("Replayed Sequence Number".to_string()),
        1,
        1,
        1001,
    );
    let res = engine.handle_node(room.conv_id, msg1_replay, &store, None);
    // V1 Ratchet rule: A client MUST NOT accept a message with a sequence_number
    // lower than or EQUAL TO the current known ratchet index for that sender.
    assert!(
        res.is_err(),
        "Message with duplicate sequence number should be rejected"
    );
}

#[test]
fn test_authorized_node_flooding_limit() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = merkle_tox_core::testing::TestRoom::new(2);
    let alice = &room.identities[0];
    let observer = &room.identities[1];

    let mut engine = MerkleToxEngine::new(
        observer.device_pk,
        observer.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Flood up to the limit
    let mut last_hash = room.conv_id.to_node_hash();
    for i in 1..tox_proto::constants::MAX_VERIFIED_NODES_PER_DEVICE {
        let node = create_signed_content_node(
            &room.conv_id,
            &room.keys,
            alice.master_pk,
            alice.device_pk,
            vec![last_hash],
            Content::Text(format!("Authorized Flood {}", i)),
            i,
            i + 1, // Start from 2
            1000 + i as i64,
        );
        last_hash = node.hash();
        engine
            .handle_node(room.conv_id, node, &store, None)
            .unwrap();
    }

    // Next node should be rejected
    let extra_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        vec![last_hash],
        Content::Text("One too many".to_string()),
        tox_proto::constants::MAX_VERIFIED_NODES_PER_DEVICE,
        tox_proto::constants::MAX_VERIFIED_NODES_PER_DEVICE + 1,
        999999,
    );
    let res = engine.handle_node(room.conv_id, extra_node, &store, None);
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        merkle_tox_core::error::MerkleToxError::Validation(
            merkle_tox_core::dag::ValidationError::TooManyVerifiedNodes
        )
    ));
}

#[test]
fn test_iblt_peeling_torture() {
    // Create a large sketch that is mathematically designed to be non-decodable.
    // We can do this by inserting many elements into a small tier, or by manually
    // corrupting cells so they look pure but fail checksum.

    let mut sketch = IbltSketch::new(Tier::Large.cell_count());

    // Fill every cell with count 2. No cell will ever be pure.
    for cell in &mut sketch.cells {
        cell.count = 2;
        cell.id_sum = [0xAAu8; 32];
        cell.hash_sum = 12345;
    }

    let res = sketch.decode();

    assert!(res.is_err(), "Corrupted sketch should fail decoding");

    if let Err(tox_reconcile::iblt::ReconciliationError::DecodingFailed(stats)) = res {
        // We expect:
        // 1. Initial scan: Tier::Large.cell_count() iterations (1024)
        // 2. Peeling: 0 iterations (no pure cells)
        // 3. Final check: scans until it finds the first non-empty cell (iteration 1, so total 1025)
        assert_eq!(stats.cells_peeled, 0);
        assert_eq!(stats.iterations, 1025);
    } else {
        panic!("Expected DecodingFailed error");
    }
}
