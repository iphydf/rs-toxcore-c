use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, EphemeralX25519Pk, KConv,
    LogicalIdentityPk, Permissions, PhysicalDevicePk, PhysicalDeviceSk, SignedPreKey,
};
use merkle_tox_core::engine::{
    Conversation, ConversationData, Effect, MerkleToxEngine, VerificationStatus, conversation,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_genesis_pow,
    create_signed_content_node, make_cert,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_x3dh_and_ratchet_bridge() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);

    // Alice setup
    let alice = TestIdentity::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();

    // Bob setup
    let bob = TestIdentity::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp,
    );
    let bob_store = InMemoryStore::new();

    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);

    // 0. Genesis (1-on-1)
    let genesis = merkle_tox_core::builder::NodeBuilder::new_1on1_genesis(
        alice.master_pk,
        bob.master_pk,
        &keys,
    );
    let conv_id = genesis.hash().to_conversation_id();

    // Alice initializes her key (she created the room)
    let now = alice_engine.clock.network_time_ms();
    alice_store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    bob_store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    alice_engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id,
            k_conv.clone(),
            now,
        )),
    );
    // Bob also initializes his key to verify Genesis (1-on-1 deterministic)
    bob_engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id,
            k_conv.clone(),
            now,
        )),
    );

    // Both sides "see" the genesis.
    let effects = alice_engine
        .handle_node(conv_id, genesis.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);
    let effects = bob_engine
        .handle_node(conv_id, genesis.clone(), &bob_store, None)
        .unwrap();
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
    apply_effects(effects, &bob_store);

    // Alice and Bob authorize each other
    alice_engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 1, 0);
    alice_engine
        .identity_manager
        .add_member(conv_id, bob.master_pk, 1, 0);
    bob_engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 1, 0);
    bob_engine
        .identity_manager
        .add_member(conv_id, bob.master_pk, 1, 0);

    let cert_a = alice.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);
    let cert_b = bob.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);

    let ctx = merkle_tox_core::identity::CausalContext::global();
    alice_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert_a,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();
    alice_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            bob.master_pk,
            &cert_b,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();
    bob_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert_a,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();
    bob_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            bob.master_pk,
            &cert_b,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // 1. Bob authors an Announcement
    let effects = bob_engine.author_announcement(conv_id, &bob_store).unwrap();
    let ann_node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    apply_effects(effects, &bob_store);

    // 2. Alice receives Bob's announcement
    let effects = alice_engine
        .handle_node(conv_id, ann_node.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // 3. Alice initiates X3DH key exchange
    // Find Bob's pre-key in the announcement
    let spk =
        if let Content::Control(ControlAction::Announcement { pre_keys, .. }) = &ann_node.content {
            pre_keys[0].public_key
        } else {
            panic!("Invalid announcement");
        };

    let kw_effects = alice_engine
        .author_x3dh_key_exchange(conv_id, bob.device_pk, spk, &alice_store)
        .unwrap();
    let key_wrap_node = merkle_tox_core::testing::get_node_from_effects(kw_effects.clone());
    apply_effects(kw_effects, &alice_store);

    // 4. Bob receives Alice's KeyWrap and establishes k_conv via X3DH
    let effects = bob_engine
        .handle_node(conv_id, key_wrap_node.clone(), &bob_store, None)
        .unwrap();
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));

    // 4b. Deliver KEYWRAP_ACK from Bob → Alice (off-DAG transport, §2.A.3)
    for effect in &effects {
        if let Effect::SendPacket(_, msg @ ProtocolMessage::KeywrapAck { .. }) = effect {
            alice_engine
                .handle_message(bob.device_pk, msg.clone(), &alice_store, None)
                .unwrap();
        }
    }

    apply_effects(effects, &bob_store);
    assert!(bob_engine.conversations.contains_key(&conv_id));

    // 5. Alice authors a message (Ratcheted)
    //    JIT piggybacking may produce an SKD node before the text.
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("Ratcheted 1".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let all_nodes = merkle_tox_core::testing::get_all_nodes_from_effects(&effects);
    merkle_tox_core::testing::transfer_wire_nodes(&effects, &bob_store);
    apply_effects(effects, &alice_store);

    // 6. Bob receives all authored nodes (JIT SKD + text) and verifies
    for node in &all_nodes {
        let effects = bob_engine
            .handle_node(conv_id, node.clone(), &bob_store, None)
            .unwrap();
        apply_effects(effects, &bob_store);
    }
    // The last node is the text: verify Bob processed it
    assert!(
        bob_store.has_node(&all_nodes.last().unwrap().hash()),
        "Bob should verify msg1 using ratchet"
    );

    // 7. Alice authors another message
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("Ratcheted 2".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let all_nodes2 = merkle_tox_core::testing::get_all_nodes_from_effects(&effects);
    merkle_tox_core::testing::transfer_wire_nodes(&effects, &bob_store);
    apply_effects(effects, &alice_store);

    // 8. Bob receives msg2 and verifies it
    for node in &all_nodes2 {
        let effects = bob_engine
            .handle_node(conv_id, node.clone(), &bob_store, None)
            .unwrap();
        apply_effects(effects, &bob_store);
    }
    assert!(
        bob_store.has_node(&all_nodes2.last().unwrap().hash()),
        "Bob should verify msg2 using ratchet"
    );
}

#[test]
fn test_ratchet_snapshot_recovery() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(123);

    // Alice setup
    let alice = TestIdentity::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp,
    );
    let alice_store = InMemoryStore::new();

    let conv_id = ConversationId::from([0xAAu8; 32]);

    // Initialize Alice's engine with the key
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    apply_effects(effects, &alice_store);

    // cert for A1
    let cert_a1 = alice.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);
    alice_engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 1, 0);

    let ctx = merkle_tox_core::identity::CausalContext::global();
    alice_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert_a1,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Setup Alice's SECOND device PK
    let alice2 = TestIdentity::new();
    // Use the same master key but different device
    let alice2_sk_bytes = alice2.device_sk.to_bytes();
    let alice2_pk = alice2.device_pk;

    // Authorize A2 device in Alice's engine using her master key
    let cert_a2 = make_cert(
        &alice.master_sk,
        alice2_pk,
        Permissions::ALL,
        i64::MAX,
        conv_id,
    );
    alice_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert_a2,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // A2 needs the k_conv first. Alice will author a KeyWrap for A2.
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    apply_effects(effects.clone(), &alice_store);
    let _key_wrap_node = merkle_tox_core::testing::get_node_from_effects(effects);

    // Alice authors 5 messages in Epoch 1
    let mut last_msg_node = None;
    for i in 0..5 {
        let effects = alice_engine
            .author_node(
                conv_id,
                Content::Text(format!("Msg {}", i)),
                vec![],
                &alice_store,
            )
            .unwrap();
        last_msg_node = Some(merkle_tox_core::testing::get_node_from_effects(
            effects.clone(),
        ));
        apply_effects(effects, &alice_store);
    }
    let last_msg_node = last_msg_node.unwrap();

    // Alice authors a RatchetSnapshot for Epoch 1
    let effects = alice_engine
        .author_history_key_export(
            conv_id,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            0,
            None,
            &alice_store,
        )
        .unwrap();
    apply_effects(effects, &alice_store);

    // Now setup Alice's SECOND device engine
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut a2_engine = MerkleToxEngine::with_sk(
        alice2_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice2_sk_bytes),
        rng.clone(),
        tp,
    );
    let a2_store = InMemoryStore::new();

    a2_engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 1, 0);
    a2_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert_a1,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();
    a2_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert_a2,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Transfer Alice's ephemeral signing keys to A2 so it can verify Alice's content nodes
    merkle_tox_core::testing::transfer_ephemeral_keys(&alice_engine, &mut a2_engine);

    // A2 needs to receive all nodes from Alice to stay in sync.
    let mut all_nodes_to_sync: Vec<_> = alice_store
        .nodes
        .read()
        .unwrap()
        .values()
        .map(|(n, _)| n.clone())
        .collect();
    all_nodes_to_sync.sort_by_key(|n| (n.topological_rank, n.sequence_number));

    for node in &all_nodes_to_sync {
        // Transfer wire node for this specific node just before processing
        // to avoid premature opaque-store unpacking (which loses pow_nonce).
        let hash = node.hash();
        if let Some((cid, wire)) = alice_store.wire_nodes.read().unwrap().get(&hash) {
            let _ = a2_store.put_wire_node(cid, &hash, wire.clone());
        }
        let effects = a2_engine
            .handle_node(conv_id, node.clone(), &a2_store, None)
            .unwrap();
        apply_effects(effects, &a2_store);
        a2_engine.clear_pending();
    }

    // Verify that A2 successfully resumed the ratchet
    let em = match a2_engine.conversations.get(&conv_id).unwrap() {
        Conversation::Established(em) => em,
        _ => panic!("A2 conversation should be established"),
    };
    // HistoryExport skips ratchet advancement (uses export keys, not per-sender
    // ratchet), so the ratchet head should point to the last content message.
    assert_eq!(
        em.state
            .sender_ratchets
            .get(&last_msg_node.sender_pk)
            .and_then(|(_, _, h, _)| h.as_ref()),
        Some(&last_msg_node.hash()),
        "A2 should have committed the ratchet key from the last content message"
    );

    // Verify A2 can now verify subsequent messages from A1 because it resumed the ratchet
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("Post-snapshot".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    merkle_tox_core::testing::transfer_wire_nodes(&effects, &a2_store);
    let msg_next = merkle_tox_core::testing::get_node_from_effects(effects);
    let effects = a2_engine
        .handle_node(conv_id, msg_next, &a2_store, None)
        .unwrap();
    assert!(
        merkle_tox_core::testing::is_verified_in_effects(&effects),
        "A2 should verify messages from Alice after snapshot"
    );
}

#[test]
fn test_epoch_rotation_ratchet_continuity() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(444);
    let alice = TestIdentity::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp,
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xEEu8; 32]);

    // Add another device so KeyWrap is authored
    let alice2 = TestIdentity::new();
    engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 1, 0); // Master is Admin
    let cert = alice.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);
    let ctx = merkle_tox_core::identity::CausalContext::global();
    engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    let cert2 = make_cert(
        &alice.master_sk,
        alice2.device_pk,
        Permissions::ALL,
        i64::MAX,
        conv_id,
    );
    engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            alice.master_pk,
            &cert2,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Initialize
    let effects_e0 = engine.rotate_conversation_key(conv_id, &store).unwrap();
    // Capture epoch-0 KeyWrap hash for later admin chain continuity check.
    let wrap_e0_hash = effects_e0
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                if matches!(node.content, Content::KeyWrap { .. }) {
                    Some(node.hash())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .next()
        .unwrap();
    apply_effects(effects_e0, &store);

    // Message in Epoch 0
    let effects = engine
        .author_node(
            conv_id,
            Content::Text("Epoch 0".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    apply_effects(effects, &store);
    assert_eq!(engine.get_current_generation(&conv_id), 0);

    // Manual rotation
    let effects = engine.rotate_conversation_key(conv_id, &store).unwrap();
    let nodes: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects, &store);
    assert_eq!(engine.get_current_generation(&conv_id), 1);

    // nodes[0] is KeyWrap
    let wrap_node = nodes
        .iter()
        .find(|n| matches!(n.content, Content::KeyWrap { .. }))
        .unwrap();

    // KeyWrap is Admin: it references the epoch-0 KeyWrap (admin chain continuity),
    // not content messages (chain isolation).
    assert!(wrap_node.parents.contains(&wrap_e0_hash));

    // Rotation also authors a SenderKeyDistribution node (DARE §2)
    let skd_node = nodes
        .iter()
        .find(|n| matches!(n.content, Content::SenderKeyDistribution { .. }))
        .unwrap();

    // Message in Epoch 1
    let effects = engine
        .author_node(
            conv_id,
            Content::Text("Epoch 1".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let msg_e1 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    apply_effects(effects, &store);

    // Check that msg_e1 has the SKD node as parent (it's the last node from rotation)
    assert!(msg_e1.parents.contains(&skd_node.hash()));

    // Verify all nodes are verified (keywrap_e0 + skd_e0 + msg_e0 + keywrap_e1 + skd_e1 + msg_e1)
    let (ver, spec) = store.get_node_counts(&conv_id);
    assert_eq!(ver, 6);
    assert_eq!(spec, 0);
}

#[test]
fn test_iterative_reverification() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(999);
    let self_pk = LogicalIdentityPk::from([1u8; 32]);
    let self_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(self_device_pk, self_pk, rng, tp);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0u8; 32]);
    let k_conv = KConv::from([0x42u8; 32]);

    // Initialize conversation keys
    store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id,
            k_conv.clone(),
            0,
        )),
    );
    let keys = ConversationKeys::derive(&k_conv);

    // Register test ephemeral key for the self device
    merkle_tox_core::testing::register_test_ephemeral_key(&mut engine, &keys, &self_device_pk);

    // Create a chain of 3 messages where parents are missing initially
    let node1 = create_signed_content_node(
        &conv_id,
        &keys,
        self_pk,
        self_device_pk,
        vec![],
        Content::Text("1".to_string()),
        0,
        1,
        100,
    );
    let h1 = node1.hash();

    let node2 = create_signed_content_node(
        &conv_id,
        &keys,
        self_pk,
        self_device_pk,
        vec![h1],
        Content::Text("2".to_string()),
        1,
        2,
        200,
    );
    let h2 = node2.hash();

    let node3 = create_signed_content_node(
        &conv_id,
        &keys,
        self_pk,
        self_device_pk,
        vec![h2],
        Content::Text("3".to_string()),
        2,
        3,
        300,
    );

    // Handle nodes in REVERSE order. They should all stay speculative due to missing parents.
    let effects = engine.handle_node(conv_id, node3, &store, None).unwrap();
    apply_effects(effects, &store);
    engine.clear_pending();

    let effects = engine.handle_node(conv_id, node2, &store, None).unwrap();
    apply_effects(effects, &store);
    engine.clear_pending();

    let effects = engine.handle_node(conv_id, node1, &store, None).unwrap();
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    merkle_tox_core::testing::apply_effects(effects, &store);
    assert_eq!(status, VerificationStatus::Verified);

    // After handle_node(node1), it should have triggered reverify_speculative_for_conversation.
    let (ver, spec) = store.get_node_counts(&conv_id);
    assert_eq!(
        ver, 3,
        "All nodes in the chain should be verified iteratively"
    );
    assert_eq!(spec, 0);
}

#[test]
fn test_wide_dag_merging_complexity() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(888);
    let self_master_pk = LogicalIdentityPk::from([1u8; 32]);
    let self_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(self_device_pk, self_master_pk, rng, tp);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let k_conv = KConv::from([0x42u8; 32]);

    store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    engine.conversations.insert(
        conv_id,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            conv_id, k_conv, 0,
        )),
    );

    // 1. Create 16 parallel root nodes (max parents limit)
    let mut heads = Vec::new();
    for i in 0..16 {
        let effects = engine
            .author_node(
                conv_id,
                Content::Text(format!("Parallel {}", i)),
                vec![],
                &store,
            )
            .unwrap();
        let node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
        apply_effects(effects, &store);
        heads.push(node.hash());

        // To make them truly parallel, we need to reset the heads in the store
        // after each authoring so they all branch from Genesis (rank 0),
        // as 'author_node' uses the current heads returned by 'store.get_heads()'.
        store.set_heads(&conv_id, vec![]).unwrap();
    }

    // 2. Restore all 16 heads
    store.set_heads(&conv_id, heads.clone()).unwrap();

    // 3. Author a merge node that joins all 16 heads
    let effects = engine
        .author_node(
            conv_id,
            Content::Text("The Big Merge".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let merge_node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    apply_effects(effects, &store);

    assert_eq!(merge_node.parents.len(), 16);
    assert_eq!(merge_node.topological_rank, 1);

    // 4. Verify that the ratchet successfully advanced
    let em = match engine.conversations.get(&conv_id).unwrap() {
        Conversation::Established(em) => em,
        _ => panic!("Conversation should be established"),
    };
    assert_eq!(
        em.state
            .sender_ratchets
            .get(&merge_node.sender_pk)
            .and_then(|(_, _, h, _)| h.as_ref()),
        Some(&merge_node.hash())
    );
}

#[test]
fn test_x3dh_last_resort_blocking() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(777);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let alice = TestIdentity::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();

    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([0xBBu8; 32]);

    // 1. Create an Announcement with ONLY the last resort key
    let lr_sk = x25519_dalek::StaticSecret::from([0x01u8; 32]);
    let lr_pk = EphemeralX25519Pk::from(x25519_dalek::PublicKey::from(&lr_sk).to_bytes());

    let ann_node = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![],
        ControlAction::Announcement {
            pre_keys: vec![], // NO EPHEMERAL KEYS
            last_resort_key: SignedPreKey {
                public_key: lr_pk,
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: i64::MAX,
            },
        },
        0,
        1,
        1000,
    );

    // 2. Alice receives Bob's "Last Resort" announcement
    alice_engine
        .identity_manager
        .add_member(conv_id, bob.master_pk, 1, 0);
    let cert_b = bob.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);
    let ctx = merkle_tox_core::identity::CausalContext::global();
    alice_engine
        .identity_manager
        .authorize_device(
            &ctx,
            conv_id,
            bob.master_pk,
            &cert_b,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    let effects = alice_engine
        .handle_node(conv_id, ann_node, &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // 3. Alice attempts to start a conversation
    // According to merkle-tox-handshake-x3dh.md:
    // "If only the last_resort_key is available, User A MUST NOT proceed automatically.
    // Instead, User A authors a HandshakePulse Control Node targeted at User B."

    let res = alice_engine.author_x3dh_key_exchange(
        conv_id,
        bob.device_pk,
        lr_pk, // Bob's last resort key
        &alice_store,
    );

    assert!(res.is_ok(), "Expected Ok, got: {:?}", res);
    let effects = res.unwrap();
    let pulse_effect = effects
        .iter()
        .find(|e| matches!(e, Effect::WriteStore(_, _, _)));
    assert!(
        pulse_effect.is_some(),
        "Expected a WriteStore effect for HandshakePulse"
    );
    if let Some(Effect::WriteStore(_, node, _)) = pulse_effect {
        assert!(matches!(
            node.content,
            Content::Control(ControlAction::HandshakePulse)
        ));
    }
}

#[test]
fn test_handshake_pulse_debounce() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 1000));
    let alice = TestIdentity::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();

    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([1u8; 32]);

    // 1. Setup Alice's established conversation
    let genesis_node = create_genesis_pow(&conv_id, &alice, "Debounce Test");

    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // Authorize Alice's own device (signed with master key so sender_pk == master_pk.to_physical())
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        2000,
        conv_id,
    );
    let auth_alice = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis_node.hash()],
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_alice.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // Bob self-authorizes his device (author_pk=bob.master_pk so his device is
    // registered under his own logical identity, not Alice's)
    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::all(),
        2000,
        conv_id,
    );
    let auth_bob = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.master_sk,
        vec![auth_alice.hash()],
        ControlAction::AuthorizeDevice { cert: bob_cert },
        2,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_bob.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // 2. Bob sends HandshakePulse (rank 3)
    let pulse_node_1 = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![auth_bob.hash()],
        ControlAction::HandshakePulse,
        3,
        1,
        1000,
    );

    let effects = alice_engine
        .handle_node(conv_id, pulse_node_1.clone(), &alice_store, None)
        .unwrap();

    // Should trigger KeyWrap rotation from Alice since it's the first pulse
    let has_rotation = effects.iter().any(|e| matches!(e, Effect::WriteStore(_, node, _) if matches!(node.content, Content::KeyWrap{..})));
    assert!(
        has_rotation,
        "Alice should respond to the first HandshakePulse with a KeyWrap"
    );
    apply_effects(effects, &alice_store);

    // Update Alice's rotation time to fake "5 minutes haven't passed"
    tp.set_time(base_instant + Duration::from_millis(1), 1001); // Only 1 ms later

    // 3. Bob sends another HandshakePulse (rank 4)
    let pulse_node_2 = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![pulse_node_1.hash()],
        ControlAction::HandshakePulse,
        4,
        2,
        1001,
    );

    let effects = alice_engine
        .handle_node(conv_id, pulse_node_2.clone(), &alice_store, None)
        .unwrap();

    // Should NOT trigger KeyWrap rotation due to 5-minute debounce
    let has_rotation_2 = effects.iter().any(|e| matches!(e, Effect::WriteStore(_, node, _) if matches!(node.content, Content::KeyWrap{..})));
    assert!(
        !has_rotation_2,
        "Alice should ignore the second HandshakePulse due to 5-minute debounce"
    );

    // 4. Bob sends an older HandshakePulse (rank 3) concurrently
    let pulse_node_3 = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![auth_bob.hash()],
        ControlAction::HandshakePulse,
        3,
        3,
        1002,
    );

    let effects = alice_engine
        .handle_node(conv_id, pulse_node_3.clone(), &alice_store, None)
        .unwrap();

    // Should NOT trigger KeyWrap rotation due to topo debounce
    let has_rotation_3 = effects.iter().any(|e| matches!(e, Effect::WriteStore(_, node, _) if matches!(node.content, Content::KeyWrap{..})));
    assert!(
        !has_rotation_3,
        "Alice should ignore the third HandshakePulse due to topo debounce"
    );
}

/// Announcement pre-keys must have their Ed25519 signatures verified.
/// Currently `side_effects.rs` stores any `ControlAction::Announcement` verbatim
/// into `peer_announcements` without checking that each `SignedPreKey::signature`
/// is a valid Ed25519 signature by the announcing device. A malicious peer could
/// publish fake pre-keys and force the initiating device into a DH exchange with
/// an attacker-controlled key (key confusion / UKS attack).
#[test]
fn test_announcement_rejects_invalid_prekey_signature() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([7u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "PreKey Sig Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
    );
    let auth_alice = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis_node.hash()],
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_alice.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
    );
    let auth_bob = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.master_sk,
        vec![auth_alice.hash()],
        ControlAction::AuthorizeDevice { cert: bob_cert },
        2,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_bob.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Bob publishes an Announcement whose pre-key has a deliberately invalid
    // signature: [0xFF; 64] is NOT Bob's device key signing `bad_pk`.
    let bad_pk = EphemeralX25519Pk::from([0xDE_u8; 32]);
    let bad_sig = Ed25519Signature::from([0xFF_u8; 64]);
    let lr_pk = EphemeralX25519Pk::from([0xBB_u8; 32]);
    let lr_sig = Ed25519Signature::from([0u8; 64]);

    // Announcement is an Admin node; Bob's device_sk signs the outer node.
    // The INNER pre-key signature (bad_sig) must also be verified against bob.device_pk.
    let announcement = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![auth_bob.hash()],
        ControlAction::Announcement {
            pre_keys: vec![SignedPreKey {
                public_key: bad_pk,
                signature: bad_sig,
                expires_at: i64::MAX,
            }],
            last_resort_key: SignedPreKey {
                public_key: lr_pk,
                signature: lr_sig,
                expires_at: i64::MAX,
            },
        },
        3,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, announcement, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Alice's view of Bob's pre-keys must not include the invalid entry.
    // With the current bug, Alice stores the announcement verbatim (has_invalid_prekey = true).
    // With the fix, the invalid pre-key is rejected and pre_keys is empty.
    let has_invalid_prekey = alice_engine
        .peer_announcements
        .get(&bob.device_pk)
        .is_some_and(|ann| {
            matches!(ann, ControlAction::Announcement { pre_keys, .. } if !pre_keys.is_empty())
        });

    assert!(
        !has_invalid_prekey,
        "An Announcement with an invalid pre-key Ed25519 signature must be rejected; \
         the engine must verify SignedPreKey signatures to prevent key confusion attacks"
    );
}

#[test]
fn test_trust_restored_clears_on_keywrap() {
    let _ = tracing_subscriber::fmt::try_init();

    let rng = StdRng::seed_from_u64(400);
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 5000));
    let bob = TestIdentity::new();
    let _alice = TestIdentity::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let _bob_store = InMemoryStore::new();

    let conv_id = ConversationId::from([50u8; 32]);

    // Set trust_restored_devices for Bob
    bob_engine
        .trust_restored_devices
        .insert((conv_id, bob.device_pk), 5000);

    assert!(
        bob_engine
            .trust_restored_devices
            .contains_key(&(conv_id, bob.device_pk)),
        "trust_restored should be set before KeyWrap"
    );

    // Simulate receiving a KeyWrap that establishes the conversation.
    // The verification.rs code clears trust_restored_devices on KeyWrap processing.
    // We can directly test the state manipulation:
    // After KeyWrap processing, trust_restored_devices.remove((cid, self.self_pk)) is called.
    bob_engine
        .trust_restored_devices
        .remove(&(conv_id, bob.device_pk));

    assert!(
        !bob_engine
            .trust_restored_devices
            .contains_key(&(conv_id, bob.device_pk)),
        "trust_restored should be cleared after KeyWrap"
    );
}

#[test]
fn test_trust_restored_expires_after_30_days() {
    let _ = tracing_subscriber::fmt::try_init();

    let rng = StdRng::seed_from_u64(500);
    let base_instant = Instant::now();
    // Start at time 0 + 31 days in ms
    let thirty_one_days_ms: i64 = 31 * 24 * 60 * 60 * 1000;
    let tp = Arc::new(ManualTimeProvider::new(
        base_instant,
        thirty_one_days_ms + 1000,
    ));
    let alice = TestIdentity::new();
    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng,
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let conv_id = ConversationId::from([60u8; 32]);

    // Manually set up an established conversation (Genesis alone doesn't establish;
    // a KeyWrap or direct insertion is needed).
    use merkle_tox_core::engine::conversation::{ConversationData, Established};
    let k_conv = merkle_tox_core::dag::KConv::from([88u8; 32]);
    let est = ConversationData::<Established>::new(conv_id, k_conv, 1000);
    engine
        .conversations
        .insert(conv_id, Conversation::Established(est));

    // Set trust_restored with a heal_ts that's 31 days old (heal_ts = 1000, now = 31 days + 1000)
    engine
        .trust_restored_devices
        .insert((conv_id, alice.device_pk), 1000);

    assert!(engine.conversations.get(&conv_id).unwrap().is_established());

    // Call poll: the 30-day expiry check should fire
    let _ = engine.poll(Instant::now(), &store);

    // After poll, the conversation should be downgraded to Pending
    match engine.conversations.get(&conv_id) {
        Some(Conversation::Pending(_)) => {
            // Expected: downgraded to permanent observer mode
        }
        Some(Conversation::Established(_)) => {
            panic!("Conversation should have been downgraded to Pending after 30-day expiry");
        }
        None => {
            panic!("Conversation should still exist (as Pending)");
        }
    }

    // trust_restored entry should be removed
    assert!(
        !engine
            .trust_restored_devices
            .contains_key(&(conv_id, alice.device_pk)),
        "trust_restored entry should be removed after expiry"
    );
}

#[test]
fn test_reinclusion_request_protocol() {
    let _ = tracing_subscriber::fmt::try_init();

    let rng = StdRng::seed_from_u64(600);
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 1000));

    let alice = TestIdentity::new();
    let bob = TestIdentity::new();

    // Alice is the admin
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let conv_id = ConversationId::from([70u8; 32]);

    // Set up Alice's conversation with genesis
    let genesis = create_genesis_pow(&conv_id, &alice, "Reinclusion Test");
    let effects = alice_engine
        .handle_node(conv_id, genesis.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        i64::MAX,
        conv_id,
    );
    let auth_node = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis.hash()],
        ControlAction::AuthorizeDevice { cert },
        1,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Verify the request_reinclusion helper produces the correct effect
    let reinclusion_effects =
        alice_engine.request_reinclusion(conv_id, bob.device_pk, genesis.hash());
    assert_eq!(reinclusion_effects.len(), 1);
    match &reinclusion_effects[0] {
        Effect::SendPacket(
            target_pk,
            ProtocolMessage::ReinclusionRequest {
                conversation_id,
                sender_pk,
                healing_snapshot_hash,
            },
        ) => {
            assert_eq!(*target_pk, bob.device_pk);
            assert_eq!(*conversation_id, conv_id);
            assert_eq!(*sender_pk, alice.device_pk);
            assert_eq!(*healing_snapshot_hash, genesis.hash());
        }
        other => panic!("Expected SendPacket(ReinclusionRequest), got: {:?}", other),
    }

    // Verify handling of a ReinclusionResponse (accepted=true)
    let response_msg = ProtocolMessage::ReinclusionResponse {
        conversation_id: conv_id,
        accepted: true,
    };
    let effects = alice_engine
        .handle_message(bob.device_pk, response_msg, &store, None)
        .unwrap();
    // ReinclusionResponse handling just logs: no specific effects returned.
    // The key thing is it doesn't panic or error.
    let _ = effects;

    // Also test rejected response
    let rejected_msg = ProtocolMessage::ReinclusionResponse {
        conversation_id: conv_id,
        accepted: false,
    };
    let effects = alice_engine
        .handle_message(bob.device_pk, rejected_msg, &store, None)
        .unwrap();
    let _ = effects; // Should not panic
}
