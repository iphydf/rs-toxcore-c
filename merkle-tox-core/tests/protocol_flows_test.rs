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
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_signed_content_node,
    make_cert,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

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

    let cert_a = alice.make_device_cert(Permissions::ALL, i64::MAX);
    let cert_b = bob.make_device_cert(Permissions::ALL, i64::MAX);

    alice_engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert_a, 0, 0)
        .unwrap();
    alice_engine
        .identity_manager
        .authorize_device(conv_id, bob.master_pk, &cert_b, 0, 0)
        .unwrap();
    bob_engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert_a, 0, 0)
        .unwrap();
    bob_engine
        .identity_manager
        .authorize_device(conv_id, bob.master_pk, &cert_b, 0, 0)
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
        .author_x3dh_key_exchange(conv_id, bob.device_pk, spk, k_conv.clone(), &alice_store)
        .unwrap();
    let key_wrap_node = merkle_tox_core::testing::get_node_from_effects(kw_effects.clone());
    apply_effects(kw_effects, &alice_store);

    // 4. Bob receives Alice's KeyWrap and establishes k_conv via X3DH
    let effects = bob_engine
        .handle_node(conv_id, key_wrap_node.clone(), &bob_store, None)
        .unwrap();
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
    apply_effects(effects, &bob_store);
    assert!(bob_engine.conversations.contains_key(&conv_id));

    // 5. Alice authors a message (Ratcheted)
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("Ratcheted 1".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let msg1 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    apply_effects(effects, &alice_store);

    // 6. Bob receives msg1 and verifies it using the ratchet
    let effects = bob_engine
        .handle_node(conv_id, msg1.clone(), &bob_store, None)
        .unwrap();
    assert!(
        merkle_tox_core::testing::is_verified_in_effects(&effects),
        "Bob should verify msg1 using ratchet"
    );
    apply_effects(effects, &bob_store);

    // 7. Alice authors another message
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("Ratcheted 2".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let msg2 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    apply_effects(effects, &alice_store);

    // 8. Bob receives msg2 and verifies it
    let effects = bob_engine
        .handle_node(conv_id, msg2, &bob_store, None)
        .unwrap();
    assert!(
        merkle_tox_core::testing::is_verified_in_effects(&effects),
        "Bob should verify msg2 using ratchet"
    );
    apply_effects(effects, &bob_store);
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
    let cert_a1 = alice.make_device_cert(Permissions::ALL, i64::MAX);
    alice_engine
        .identity_manager
        .add_member(conv_id, alice.master_pk, 1, 0);

    alice_engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert_a1, 0, 0)
        .unwrap();

    // Setup Alice's SECOND device PK
    let alice2 = TestIdentity::new();
    // Use the same master key but different device
    let alice2_sk_bytes = alice2.device_sk.to_bytes();
    let alice2_pk = alice2.device_pk;

    // Authorize A2 device in Alice's engine using her master key
    let cert_a2 = make_cert(&alice.master_sk, alice2_pk, Permissions::ALL, i64::MAX);
    alice_engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert_a2, 0, 0)
        .unwrap();

    // A2 needs the k_conv first. Alice will author a KeyWrap for A2.
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    apply_effects(effects.clone(), &alice_store);
    let _key_wrap_node = merkle_tox_core::testing::get_node_from_effects(effects);

    // Alice authors 5 messages in Epoch 1
    for i in 0..5 {
        let effects = alice_engine
            .author_node(
                conv_id,
                Content::Text(format!("Msg {}", i)),
                vec![],
                &alice_store,
            )
            .unwrap();
        apply_effects(effects, &alice_store);
    }

    // Alice authors a RatchetSnapshot for Epoch 1
    let effects = alice_engine
        .author_ratchet_snapshot(conv_id, &alice_store)
        .unwrap();
    let snapshot_node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
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
        .authorize_device(conv_id, alice.master_pk, &cert_a1, 0, 0)
        .unwrap();
    a2_engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert_a2, 0, 0)
        .unwrap();

    // A2 needs to receive all nodes from Alice to stay in sync.
    let mut all_nodes_to_sync: Vec<_> = alice_store
        .nodes
        .read()
        .unwrap()
        .values()
        .map(|(n, _)| n.clone())
        .collect();
    all_nodes_to_sync.sort_by_key(|n| (n.topological_rank, n.sequence_number));

    for node in all_nodes_to_sync {
        let effects = a2_engine
            .handle_node(conv_id, node, &a2_store, None)
            .unwrap();
        apply_effects(effects, &a2_store);
        a2_engine.clear_pending();
    }

    // Verify that A2 successfully resumed the ratchet
    let em = match a2_engine.conversations.get(&conv_id).unwrap() {
        Conversation::Established(em) => em,
        _ => panic!("A2 conversation should be established"),
    };
    assert!(
        em.state.head_chains.contains_key(&snapshot_node.hash()),
        "A2 should have committed the ratchet key from the snapshot"
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
    let cert = alice.make_device_cert(Permissions::ALL, i64::MAX);
    engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert, 0, 0)
        .unwrap();

    let cert2 = make_cert(
        &alice.master_sk,
        alice2.device_pk,
        Permissions::ALL,
        i64::MAX,
    );
    engine
        .identity_manager
        .authorize_device(conv_id, alice.master_pk, &cert2, 0, 0)
        .unwrap();

    // Initialize
    let effects = engine.rotate_conversation_key(conv_id, &store).unwrap();
    apply_effects(effects, &store);

    // Message in Epoch 0
    let effects = engine
        .author_node(
            conv_id,
            Content::Text("Epoch 0".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let msg_e0 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    apply_effects(effects, &store);
    assert_eq!(engine.get_current_epoch(&conv_id), 0);

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
    assert_eq!(engine.get_current_epoch(&conv_id), 1);

    // nodes[0] is Rekey, nodes[1] is KeyWrap
    let rekey_node = nodes
        .iter()
        .find(|n| matches!(n.content, Content::Control(ControlAction::Rekey { .. })))
        .unwrap();
    let wrap_node = nodes
        .iter()
        .find(|n| matches!(n.content, Content::KeyWrap { .. }))
        .unwrap();

    // Check that Rekey node does NOT have parents from Epoch 0 (Admin Track Isolation)
    assert!(!rekey_node.parents.contains(&msg_e0.hash()));

    // Check that KeyWrap node DOES have parents from Epoch 0 (it merges the tracks)
    assert!(wrap_node.parents.contains(&msg_e0.hash()));
    assert!(wrap_node.parents.contains(&rekey_node.hash()));

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

    // Check that msg_e1 has wrap_node as parent (ensuring ratchet chain continuity)
    assert!(msg_e1.parents.contains(&wrap_node.hash()));

    // Verify all nodes are verified (MAC checks passed)
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
        // after each authoring so they all branch from Genesis (rank 0).
        // Actually, author_node uses store.get_heads().
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

    // 4. Verify that the ratchet successfully merged 16 parent keys
    let em = match engine.conversations.get(&conv_id).unwrap() {
        Conversation::Established(em) => em,
        _ => panic!("Conversation should be established"),
    };
    assert!(em.state.head_chains.contains_key(&merge_node.hash()));
}

#[test]
fn test_x3dh_last_resort_blocking() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(777);
    let alice_pk = PhysicalDevicePk::from([1u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine =
        MerkleToxEngine::new(alice_pk, alice_pk.to_logical(), rng.clone(), tp.clone());
    let alice_store = InMemoryStore::new();

    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([0xBBu8; 32]);
    let k_conv = KConv::from([0x42u8; 32]);

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
    let cert_b = bob.make_device_cert(Permissions::ALL, i64::MAX);
    alice_engine
        .identity_manager
        .authorize_device(conv_id, bob.master_pk, &cert_b, 0, 0)
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
        k_conv,
        &alice_store,
    );

    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("last resort key blocked")
    );
}
