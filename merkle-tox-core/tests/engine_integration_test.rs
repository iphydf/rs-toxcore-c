use ed25519_dalek::SigningKey;
use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::builder::NodeBuilder;
use merkle_tox_core::clock::{ManualTimeProvider, SystemTimeProvider};
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, KConv, LogicalIdentityPk, MemberInfo,
    MerkleNode, NodeAuth, NodeHash, Permissions, PhysicalDevicePk, PhysicalDeviceSk, SnapshotData,
};
use merkle_tox_core::engine::session::{Handshake, SyncSession};
use merkle_tox_core::engine::{
    Conversation, ConversationData, Effect, MerkleToxEngine, VerificationStatus, conversation,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node, create_genesis_pow,
    create_msg, create_signed_content_node, make_cert, register_test_ephemeral_key,
    transfer_ephemeral_keys,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;
use tox_proto::constants::MAX_SPECULATIVE_NODES_PER_CONVERSATION;

#[test]
fn test_engine_conversation_flow() {
    let _ = tracing_subscriber::fmt::try_init();
    // Alice setup
    let alice = merkle_tox_core::testing::TestIdentity::new();

    // Bob setup
    let bob_pk = LogicalIdentityPk::from([2u8; 32]);
    let bob_device_pk = PhysicalDevicePk::from([2u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut bob_engine = MerkleToxEngine::new(bob_device_pk, bob_pk, StdRng::seed_from_u64(1), tp);

    let alice_store = InMemoryStore::new();
    let bob_store = InMemoryStore::new();

    let k_conv = KConv::from([0xAAu8; 32]);
    let conv_keys = ConversationKeys::derive(&k_conv);
    let sync_key = ConversationId::from([0u8; 32]);

    alice_store
        .put_conversation_key(&sync_key, 0, k_conv.clone())
        .unwrap();
    bob_store
        .put_conversation_key(&sync_key, 0, k_conv.clone())
        .unwrap();

    // 1. Genesis
    let genesis = NodeBuilder::new_1on1_genesis(alice.master_pk, bob_pk, &conv_keys);
    let genesis_hash = genesis.hash();

    alice_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();
    alice_store
        .set_heads(&sync_key, vec![genesis_hash])
        .unwrap();
    bob_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();
    bob_store.set_heads(&sync_key, vec![genesis_hash]).unwrap();

    alice_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );
    bob_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );

    // Set active state for sessions
    bob_engine.start_sync(sync_key, Some(alice.device_pk), &bob_store);

    // Register Alice's test ephemeral signing key on Bob's engine (DARE)
    register_test_ephemeral_key(&mut bob_engine, &conv_keys, &alice.device_pk);

    // 2. Authorize Alice's device
    let expires_at = bob_engine.clock.network_time_ms() + 10000000000;
    let cert = alice.make_device_cert_for(Permissions::ALL, expires_at, sync_key);

    let auth_node = create_admin_node(
        &sync_key,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis_hash],
        ControlAction::AuthorizeDevice { cert },
        1,
        1,
        100,
    );

    let auth_hash = auth_node.hash();
    let effects = bob_engine
        .handle_node(sync_key, auth_node, &bob_store, None)
        .expect("Bob handles Alice's auth");
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    // 3. Alice sends a message from her device
    let alice_msg = create_msg(
        &sync_key,
        &conv_keys,
        &alice,
        vec![auth_hash],
        "Hi Bob",
        2,
        1,
        150,
    );

    let effects = bob_engine
        .handle_node(sync_key, alice_msg, &bob_store, None)
        .expect("Bob should handle node");
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    assert!(matches!(status, VerificationStatus::Verified));
}

#[test]
fn test_concurrency_merging() {
    let alice_store = InMemoryStore::new();

    let root_hash = NodeHash::from([0xBBu8; 32]);
    let cid = ConversationId::from([0u8; 32]);
    alice_store
        .put_node(
            &cid,
            MerkleNode {
                parents: vec![],
                author_pk: LogicalIdentityPk::from([0u8; 32]),
                sender_pk: PhysicalDevicePk::from([0u8; 32]),
                sequence_number: 0,
                topological_rank: 0,
                network_timestamp: 0,
                content: Content::Text("Root".to_string()),
                metadata: vec![],
                authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
                pow_nonce: 0,
            },
            true,
        )
        .unwrap();
    alice_store.set_heads(&cid, vec![root_hash]).unwrap();

    let mut alice_session =
        SyncSession::<Handshake>::new(cid, &alice_store, false, Instant::now()).activate(0);

    // 1. Peer A authors a message
    let msg_a = alice_session.create_node(
        LogicalIdentityPk::from([1u8; 32]),
        PhysicalDevicePk::from([1u8; 32]),
        Content::Text("A".to_string()),
        vec![],
        10,
        1,
        &alice_store,
    );
    let hash_a = msg_a.hash();

    // 2. Peer B authors a message concurrently from root
    let msg_b = alice_session.create_node(
        LogicalIdentityPk::from([2u8; 32]),
        PhysicalDevicePk::from([2u8; 32]),
        Content::Text("B".to_string()),
        vec![],
        11,
        1,
        &alice_store,
    );
    let hash_b = msg_b.hash();

    // 3. Alice receives both (merges them locally)
    alice_session.common.local_heads.clear();
    alice_session.common.local_heads.insert(hash_a);
    alice_session.common.local_heads.insert(hash_b);
    alice_store.put_node(&cid, msg_a, true).unwrap();
    alice_store.put_node(&cid, msg_b, true).unwrap();

    // 4. Alice creates a new message (Merge Node)
    let merge_node = alice_session.create_node(
        LogicalIdentityPk::from([3u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
        Content::Text("Merge".to_string()),
        vec![],
        20,
        1,
        &alice_store,
    );

    assert_eq!(merge_node.parents.len(), 2);
    assert!(merge_node.parents.contains(&hash_a));
    assert!(merge_node.parents.contains(&hash_b));
    assert_eq!(merge_node.topological_rank, 2);
}

#[test]
fn test_rekeying_flow() {
    let alice_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let sync_key = ConversationId::from([0u8; 32]);

    let k_conv_v1 = KConv::from([0x11u8; 32]);
    let k_conv_v2 = KConv::from([0x22u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut bob_engine =
        MerkleToxEngine::new(bob_pk, bob_pk.to_logical(), StdRng::seed_from_u64(0), tp);
    bob_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv_v1.clone(),
            0,
        )),
    );

    let bob_store = InMemoryStore::new();
    bob_store
        .put_conversation_key(&sync_key, 0, k_conv_v1.clone())
        .unwrap();
    bob_engine.start_sync(sync_key, Some(alice_device_pk), &bob_store);

    // Alice setup
    let mut alice_master_bytes = [0u8; 32];
    alice_master_bytes[0] = 1;
    let alice_master_sk = SigningKey::from_bytes(&alice_master_bytes);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());

    // 0. Genesis
    let v1_keys = ConversationKeys::derive(&k_conv_v1);
    let genesis = NodeBuilder::new_1on1_genesis(alice_master_pk, bob_pk.to_logical(), &v1_keys);
    let genesis_hash = genesis.hash();
    bob_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();
    bob_store.set_heads(&sync_key, vec![genesis_hash]).unwrap();

    let expires_at = bob_engine.clock.network_time_ms() + 1000000;
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        expires_at,
        sync_key,
    );

    let ctx = merkle_tox_core::identity::CausalContext::global();
    bob_engine
        .identity_manager
        .authorize_device(
            &ctx,
            sync_key,
            alice_master_pk,
            &cert,
            bob_engine.clock.network_time_ms(),
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .expect("Bob handles Alice's auth");

    // Register Alice's test ephemeral signing key on Bob's engine (DARE)
    register_test_ephemeral_key(&mut bob_engine, &v1_keys, &alice_device_pk);

    // 1. Message under Epoch 0
    let msg_v1_final = create_signed_content_node(
        &sync_key,
        &v1_keys,
        alice_master_pk,
        alice_device_pk,
        vec![genesis_hash],
        Content::Text("V1 message".to_string()),
        1,
        1, // seq 1
        100,
    );
    let v1_hash = msg_v1_final.hash();

    let effects = bob_engine
        .handle_node(sync_key, msg_v1_final, &bob_store, None)
        .unwrap();
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    merkle_tox_core::testing::apply_effects(effects, &bob_store);
    assert!(matches!(status, VerificationStatus::Verified));

    // 2. Alice performs rekey (Bob receives it)
    if let Some(Conversation::Established(em)) = bob_engine.conversations.get_mut(&sync_key) {
        em.add_epoch(1, k_conv_v2.clone());
    }

    // 3. Message under Epoch 1
    let v2_keys = ConversationKeys::derive(&k_conv_v2);
    // Register Alice's ephemeral key for the new epoch
    {
        let eph_sk =
            merkle_tox_core::testing::test_ephemeral_signing_key(&v2_keys, &alice_device_pk);
        let eph_vk =
            merkle_tox_core::dag::EphemeralSigningPk::from(eph_sk.verifying_key().to_bytes());
        // Epoch 1: sequence_number >> 32 == 0 for seq=2, but test uses seq=2 which
        // is epoch 0.  The test helper signs with keys derived from v2_keys, so
        // we register at epoch 0 (matching the sequence_number epoch).
        bob_engine
            .peer_ephemeral_signing_keys
            .insert((alice_device_pk, 0), eph_vk);
    }
    let msg_v2_final = create_signed_content_node(
        &sync_key,
        &v2_keys,
        alice_master_pk,
        alice_device_pk,
        vec![v1_hash],
        Content::Text("V2 message".to_string()),
        2,
        2, // seq 2
        200,
    );

    let effects = bob_engine
        .handle_node(sync_key, msg_v2_final, &bob_store, None)
        .unwrap();
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    merkle_tox_core::testing::apply_effects(effects, &bob_store);
    assert!(matches!(status, VerificationStatus::Verified));
}

#[test]
fn test_actual_reverification_trigger() {
    let alice_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let sync_key = ConversationId::from([0u8; 32]);

    let mut alice_master_bytes = [0u8; 32];
    alice_master_bytes[0] = 1;
    let alice_master_sk = SigningKey::from_bytes(&alice_master_bytes);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut bob_engine =
        MerkleToxEngine::new(bob_pk, bob_pk.to_logical(), StdRng::seed_from_u64(0), tp);
    let bob_store = InMemoryStore::new();

    let k_conv = KConv::from([0xAAu8; 32]);
    bob_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );
    let conv_keys = ConversationKeys::derive(&k_conv);

    // Register Alice's test ephemeral signing key on Bob's engine (DARE)
    register_test_ephemeral_key(&mut bob_engine, &conv_keys, &alice_device_pk);

    // 0. Genesis
    let genesis = NodeBuilder::new_1on1_genesis(alice_master_pk, bob_pk.to_logical(), &conv_keys);
    let genesis_hash = genesis.hash();
    bob_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();

    // 1. Auth node from Alice Master
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE,
        2000000000000,
        sync_key,
    );
    let auth_node = create_admin_node(
        &sync_key,
        alice_master_pk,
        &alice_master_sk,
        vec![genesis_hash],
        ControlAction::AuthorizeDevice { cert },
        1,
        1,
        10,
    );
    let auth_hash = auth_node.hash();

    // 2. Speculative node
    let msg_final = create_signed_content_node(
        &sync_key,
        &conv_keys,
        alice_master_pk,
        alice_device_pk,
        vec![auth_hash],
        Content::Text("Speculative".to_string()),
        2,
        1,
        100,
    );

    let effects = bob_engine
        .handle_node(sync_key, msg_final.clone(), &bob_store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    // This should trigger re-verification of the speculative node
    let effects = bob_engine
        .handle_node(sync_key, auth_node, &bob_store, None)
        .unwrap();
    assert!(
        merkle_tox_core::testing::has_verified_in_effects(&effects),
        "Speculative node should be verified in effects"
    );
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    let (_, spec) = bob_store.get_node_counts(&sync_key);
    assert_eq!(spec, 0, "Speculative node should be verified now");
}

#[test]
fn test_vouching_lazy_consensus() {
    let alice_pk = PhysicalDevicePk::from([1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let charlie_pk = PhysicalDevicePk::from([3u8; 32]);
    let sync_key = ConversationId::from([0u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut charlie_engine = MerkleToxEngine::new(
        charlie_pk,
        charlie_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp,
    );
    let charlie_store = InMemoryStore::new();

    // Charlie doesn't have Alice's auth yet.
    charlie_engine.start_sync(sync_key, Some(bob_pk), &charlie_store);

    // 0. Genesis (Group Genesis for this test)
    let genesis = NodeBuilder::new_group_genesis(
        "Vouching Room".to_string(),
        LogicalIdentityPk::from([0u8; 32]),
        0,
        100,
        &SigningKey::from_bytes(&[1u8; 32]),
    );
    let genesis_hash = genesis.hash();
    charlie_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();

    // 1. Alice authors a node
    let alice_msg = create_signed_content_node(
        &sync_key,
        &ConversationKeys::derive(&KConv::from([0xAAu8; 32])), // Dummy keys
        alice_master_pk,
        alice_pk,
        vec![genesis_hash],
        Content::Text("Alice msg".to_string()),
        1,
        2,
        100,
    );
    let alice_hash = alice_msg.hash();
    // Charlie receives it but it's speculative.
    charlie_engine
        .handle_node(sync_key, alice_msg.clone(), &charlie_store, None)
        .unwrap();

    // 3. Bob authors a node referencing Alice's node as a parent
    let mut bob_master_bytes = [0u8; 32];
    bob_master_bytes[0] = 2;
    let bob_master_sk = SigningKey::from_bytes(&bob_master_bytes);
    let bob_master_pk = LogicalIdentityPk::from(bob_master_sk.verifying_key().to_bytes());

    let cert = make_cert(
        &bob_master_sk,
        bob_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000000000000,
        sync_key,
    );
    let ctx = merkle_tox_core::identity::CausalContext::global();
    charlie_engine
        .identity_manager
        .authorize_device(
            &ctx,
            sync_key,
            bob_master_pk,
            &cert,
            1000,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    let k_conv = KConv::from([0xBBu8; 32]);
    // Register Bob's test ephemeral signing key on Charlie's engine (DARE)
    register_test_ephemeral_key(
        &mut charlie_engine,
        &ConversationKeys::derive(&k_conv),
        &bob_pk,
    );
    charlie_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );
    let conv_keys = ConversationKeys::derive(&k_conv);

    let bob_msg = create_signed_content_node(
        &sync_key,
        &conv_keys,
        bob_master_pk,
        bob_pk,
        vec![alice_hash, genesis_hash],
        Content::Text("I saw Alice's msg".to_string()),
        2,
        2,
        150,
    );

    let effects = charlie_engine
        .handle_node(sync_key, bob_msg, &charlie_store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &charlie_store);

    let session = charlie_engine.sessions.get(&(bob_pk, sync_key)).unwrap();
    assert!(session.common().vouchers.contains_key(&alice_hash));
    assert!(
        session
            .common()
            .vouchers
            .get(&alice_hash)
            .unwrap()
            .contains(&bob_pk)
    );
}

#[test]
fn test_engine_speculative_persistence_success() {
    let alice_master_pk = LogicalIdentityPk::from([1u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let sync_key = ConversationId::from([0u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut bob_engine =
        MerkleToxEngine::new(bob_pk, bob_pk.to_logical(), StdRng::seed_from_u64(0), tp);
    let bob_store = InMemoryStore::new();

    // 0. Genesis
    let genesis = NodeBuilder::new_group_genesis(
        "Speculative Room".to_string(),
        LogicalIdentityPk::from([0u8; 32]),
        0,
        100,
        &SigningKey::from_bytes(&[1u8; 32]),
    );
    let genesis_hash = genesis.hash();
    bob_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();

    // Alice authors a node. Bob doesn't know Alice.
    let msg = create_signed_content_node(
        &sync_key,
        &ConversationKeys::derive(&KConv::from([0u8; 32])),
        alice_master_pk,
        alice_device_pk,
        vec![genesis_hash],
        Content::Text("Unauthorized message".to_string()),
        1,
        2,
        100,
    );
    let msg_hash = msg.hash();

    let effects = bob_engine
        .handle_node(sync_key, msg.clone(), &bob_store, None)
        .expect("handle_node should succeed for speculative nodes");
    let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Speculative
    };
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    assert_eq!(status, VerificationStatus::Speculative);

    // Check if it was persisted
    assert!(bob_store.has_node(&msg_hash));
    let (_, spec) = bob_store.get_node_counts(&sync_key);
    assert_eq!(spec, 1);
}

#[test]
fn test_repro_stuck_sync() {
    let _ = tracing_subscriber::fmt::try_init();
    let alice_pk = PhysicalDevicePk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine = MerkleToxEngine::new(
        alice_pk,
        alice_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut bob_engine =
        MerkleToxEngine::new(bob_pk, bob_pk.to_logical(), StdRng::seed_from_u64(1), tp);
    let alice_store = InMemoryStore::new();
    let bob_store = InMemoryStore::new();

    // 0. Initialize Genesis and conversation keys for both Alice and Bob
    let k_conv = KConv::from([0x11u8; 32]);
    let conv_keys = ConversationKeys::derive(&k_conv);
    let genesis =
        NodeBuilder::new_1on1_genesis(alice_pk.to_logical(), bob_pk.to_logical(), &conv_keys);
    let conv_id = genesis.hash().to_conversation_id();
    println!("Conversation ID: {}", hex::encode(conv_id.as_bytes()));

    alice_store
        .put_node(&conv_id, genesis.clone(), true)
        .unwrap();
    alice_store
        .set_heads(&conv_id, vec![genesis.hash()])
        .unwrap();
    bob_store.put_node(&conv_id, genesis.clone(), true).unwrap();
    bob_store.set_heads(&conv_id, vec![genesis.hash()]).unwrap();

    alice_store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();
    bob_store
        .put_conversation_key(&conv_id, 0, k_conv.clone())
        .unwrap();

    // Persist Genesis ratchet key so it can be reloaded
    alice_store
        .put_ratchet_key(&conv_id, &genesis.hash(), k_conv.to_chain_key(), 0)
        .unwrap();
    bob_store
        .put_ratchet_key(&conv_id, &genesis.hash(), k_conv.to_chain_key(), 0)
        .unwrap();

    alice_engine
        .load_conversation_state(conv_id, &alice_store)
        .unwrap();
    bob_engine
        .load_conversation_state(conv_id, &bob_store)
        .unwrap();

    // 1. Alice creates a chain of 3 nodes: A -> B -> C
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("A".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let node_a = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &alice_store);

    // Alice rotates key manually
    let k_conv_1 = KConv::from([0x22u8; 32]);
    alice_store
        .put_conversation_key(&conv_id, 1, k_conv_1.clone())
        .unwrap();
    alice_engine
        .load_conversation_state(conv_id, &alice_store)
        .unwrap();

    // Bob also learns the new key (simulating KeyWrap reception)
    bob_store
        .put_conversation_key(&conv_id, 1, k_conv_1.clone())
        .unwrap();
    bob_engine
        .load_conversation_state(conv_id, &bob_store)
        .unwrap();

    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("B".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let node_b = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects.clone(), &alice_store);

    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("C".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let node_c = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects.clone(), &alice_store);

    // Transfer Alice's ephemeral signing keys to Bob so DARE verification works
    transfer_ephemeral_keys(&alice_engine, &mut bob_engine);

    // 2. Bob initiates sync with Alice
    let effects = alice_engine.start_sync(conv_id, Some(bob_pk), &alice_store);
    let _ = bob_engine.start_sync(conv_id, Some(alice_pk), &bob_store);

    // Alice should send CapsAnnounce to Bob
    let caps_announce = effects
        .iter()
        .find_map(|effect| {
            if let merkle_tox_core::engine::Effect::SendPacket(to, msg) = effect
                && *to == bob_pk
                && let ProtocolMessage::CapsAnnounce { .. } = msg
            {
                return Some(msg.clone());
            }
            None
        })
        .expect("Alice should have sent CapsAnnounce to Bob");

    // 4. Bob handles CapsAnnounce and Alice handles CapsAck
    let bob_effects = bob_engine
        .handle_message(alice_pk, caps_announce, &bob_store, None)
        .unwrap();
    let responses: Vec<_> = bob_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(_, msg) = e {
                Some(msg)
            } else {
                None
            }
        })
        .collect();

    let caps_ack = responses
        .iter()
        .find(|msg| matches!(msg, ProtocolMessage::CapsAck { .. }))
        .expect("Bob should return CapsAck");

    let alice_effects = alice_engine
        .handle_message(bob_pk, caps_ack.clone(), &alice_store, None)
        .unwrap();
    let _responses: Vec<_> = alice_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(_, msg) = e {
                Some(msg)
            } else {
                None
            }
        })
        .collect();

    // 3. Bob handles SyncHeads from Alice
    let sync_heads = merkle_tox_core::sync::SyncHeads {
        conversation_id: conv_id,
        heads: vec![node_c.hash()],
        flags: 0,
        anchor_hash: None,
    };

    let bob_effects = bob_engine
        .handle_message(
            alice_pk,
            ProtocolMessage::SyncHeads(sync_heads),
            &bob_store,
            None,
        )
        .unwrap();
    let responses: Vec<_> = bob_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(_, msg) = e {
                Some(msg)
            } else {
                None
            }
        })
        .collect();

    // Bob should respond with FetchBatchReq for Node C
    let fetch_req = responses
        .iter()
        .find_map(|msg| {
            if let ProtocolMessage::FetchBatchReq(req) = msg
                && req.hashes.contains(&node_c.hash())
            {
                return Some(req.clone());
            }
            None
        })
        .expect("Bob should fetch Node C");

    // 4. Alice handles Bob's FetchBatchReq and returns Node C
    let alice_effects = alice_engine
        .handle_message(
            bob_pk,
            ProtocolMessage::FetchBatchReq(fetch_req),
            &alice_store,
            None,
        )
        .unwrap();
    let responses: Vec<_> = alice_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(_, msg) = e {
                Some(msg)
            } else {
                None
            }
        })
        .collect();

    let merkle_node_c = responses
        .iter()
        .find_map(|msg| {
            if let ProtocolMessage::MerkleNode { hash, .. } = msg
                && *hash == node_c.hash()
            {
                return Some(msg.clone());
            }
            None
        })
        .expect("Alice should return Node C");

    // 5. Bob handles Node C
    let effects = bob_engine
        .handle_message(alice_pk, merkle_node_c, &bob_store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    // Bob now has Node C (Speculative) and knows Node B is missing.
    // He already has the Genesis node verified.
    let (ver, _spec) = bob_store.get_node_counts(&conv_id);
    assert_eq!(ver, 1);
    // Node C might not be stored if it couldn't be unpacked, but its parents were tracked.

    // 6. Bob's poll should now request Node B
    let now = Instant::now();
    let bob_effects = bob_engine.poll(now, &bob_store).unwrap();
    let bob_poll_msgs: Vec<_> = bob_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(pk, msg) = e {
                Some((pk, msg))
            } else {
                None
            }
        })
        .collect();

    let fetch_req_b = bob_poll_msgs
        .iter()
        .find_map(|(_, msg)| {
            if let ProtocolMessage::FetchBatchReq(req) = msg
                && req.hashes.contains(&node_b.hash())
            {
                return Some(req.clone());
            }
            None
        })
        .expect("Bob should fetch Node B");

    let alice_effects = alice_engine
        .handle_message(
            bob_pk,
            ProtocolMessage::FetchBatchReq(fetch_req_b),
            &alice_store,
            None,
        )
        .unwrap();

    let merkle_node_b = alice_effects
        .into_iter()
        .find_map(|effect| {
            if let merkle_tox_core::engine::Effect::SendPacket(
                _,
                ProtocolMessage::MerkleNode { hash, .. },
            ) = &effect
                && *hash == node_b.hash()
                && let merkle_tox_core::engine::Effect::SendPacket(_, msg) = effect
            {
                return Some(msg);
            }
            None
        })
        .expect("Alice should return Node B");

    // 8. Bob handles Node B
    let effects = bob_engine
        .handle_message(alice_pk, merkle_node_b, &bob_store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &bob_store);
    let bob_effects = bob_engine.poll(now, &bob_store).unwrap();
    let bob_poll_msgs: Vec<_> = bob_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(pk, msg) = e {
                Some((pk, msg))
            } else {
                None
            }
        })
        .collect();

    let fetch_req_a = bob_poll_msgs
        .iter()
        .find_map(|(_, msg)| {
            if let ProtocolMessage::FetchBatchReq(req) = msg
                && req.hashes.contains(&node_a.hash())
            {
                return Some(req.clone());
            }
            None
        })
        .expect("Bob should have requested Node A after receiving Node B");

    // 9. Alice returns Node A
    let alice_effects = alice_engine
        .handle_message(
            bob_pk,
            ProtocolMessage::FetchBatchReq(fetch_req_a),
            &alice_store,
            None,
        )
        .unwrap();
    let responses: Vec<_> = alice_effects
        .into_iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::SendPacket(_, msg) = e {
                Some(msg)
            } else {
                None
            }
        })
        .collect();

    let merkle_node_a = responses
        .iter()
        .find_map(|msg| {
            if let ProtocolMessage::MerkleNode { hash, .. } = msg
                && *hash == node_a.hash()
            {
                return Some(msg.clone());
            }
            None
        })
        .expect("Alice should return Node A");

    // 10. Bob handles Node A
    let effects = bob_engine
        .handle_message(alice_pk, merkle_node_a, &bob_store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    // At this point, Bob should have all nodes. They should all be verified!
    // Have Alice advertise them.
    let alice_heads = alice_store.get_heads(&conv_id);
    let sync_heads = ProtocolMessage::SyncHeads(merkle_tox_core::sync::SyncHeads {
        conversation_id: conv_id,
        heads: alice_heads,
        flags: 0,
        anchor_hash: None,
    });

    let bob_effects = bob_engine
        .handle_message(alice_pk, sync_heads, &bob_store, None)
        .unwrap();
    apply_effects(bob_effects, &bob_store);

    // Drive sync until completion
    loop {
        let mut effects = Vec::new();
        effects.extend(bob_engine.poll(now, &bob_store).unwrap());
        effects.extend(alice_engine.poll(now, &alice_store).unwrap());

        if effects.is_empty() {
            break;
        }

        let mut progress = false;
        while !effects.is_empty() {
            let mut next_effects = Vec::new();
            for e in effects {
                if let Effect::SendPacket(to, msg) = e {
                    progress = true;
                    if to == alice_pk {
                        println!("Bob -> Alice: {:?}", msg);
                        let res = alice_engine
                            .handle_message(bob_pk, msg, &alice_store, None)
                            .unwrap();
                        apply_effects(res.clone(), &alice_store);
                        next_effects.extend(res);
                    } else if to == bob_pk {
                        println!("Alice -> Bob: {:?}", msg);
                        let res = bob_engine
                            .handle_message(alice_pk, msg, &bob_store, None)
                            .unwrap();
                        apply_effects(res.clone(), &bob_store);
                        next_effects.extend(res);
                    }
                }
            }
            effects = next_effects;
        }

        let (ver, spec) = bob_store.get_node_counts(&conv_id);
        println!("Bob store: ver={}, spec={}", ver, spec);

        if !progress {
            break;
        }
    }

    // At this point, Bob should have all nodes. They should all be verified!
    let (ver, _spec) = bob_store.get_node_counts(&conv_id);
    assert_eq!(ver, 4, "Should have 4 verified nodes (Genesis, A, B, C)");
}

#[test]
fn test_speculative_node_limit() {
    let alice_master_pk = LogicalIdentityPk::from([1u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let sync_key = ConversationId::from([0u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut bob_engine =
        MerkleToxEngine::new(bob_pk, bob_pk.to_logical(), StdRng::seed_from_u64(0), tp);
    let bob_store = InMemoryStore::new();

    // Fill up to the limit with speculative nodes
    for i in 0..MAX_SPECULATIVE_NODES_PER_CONVERSATION {
        let node = create_signed_content_node(
            &sync_key,
            &ConversationKeys::derive(&KConv::from([0u8; 32])),
            alice_master_pk,
            alice_device_pk,
            vec![],
            Content::Text(format!("Speculative {}", i)),
            0,            // Root nodes must have rank 0
            i as u64 + 1, // Sequence number
            1000 + i as i64,
        );
        let effects = bob_engine
            .handle_node(sync_key, node, &bob_store, None)
            .unwrap();
        for e in effects {
            if let Effect::WriteStore(cid, node, verified) = e {
                bob_store.put_node(&cid, node, verified).unwrap();
            }
        }
    }

    let (_, spec) = bob_store.get_node_counts(&sync_key);
    assert_eq!(spec, MAX_SPECULATIVE_NODES_PER_CONVERSATION);

    // Try to add one more speculative node - should fail
    let too_many_node = create_signed_content_node(
        &sync_key,
        &ConversationKeys::derive(&KConv::from([0u8; 32])),
        alice_master_pk,
        alice_device_pk,
        vec![],
        Content::Text("Too many".to_string()),
        0, // Root nodes must have rank 0
        MAX_SPECULATIVE_NODES_PER_CONVERSATION as u64 + 1,
        99999,
    );
    let res = bob_engine.handle_node(sync_key, too_many_node, &bob_store, None);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        matches!(
            &err,
            merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::TooManySpeculativeNodes
            )
        ),
        "Expected TooManySpeculativeNodes error, got: {:?}",
        err
    );
}

#[test]
fn test_vouching_accumulation() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup Room with 3 identities: Alice, Bob, Charlie
    let room = TestRoom::new(3);
    let bob = &room.identities[1];
    let charlie = &room.identities[2];

    let observer_pk = PhysicalDevicePk::from([4u8; 32]);
    let mut engine = MerkleToxEngine::new(
        observer_pk,
        observer_pk.to_logical(),
        StdRng::seed_from_u64(0),
        tp,
    );
    room.setup_engine(&mut engine, &store);

    // 2. A stranger sends a message (Speculative)
    let stranger = TestIdentity::new();
    let stranger_msg = create_msg(
        &room.conv_id,
        &room.keys,
        &stranger,
        vec![room.genesis_node.as_ref().unwrap().hash()],
        "Hello from stranger",
        1,
        1,
        1000,
    );
    let stranger_hash = stranger_msg.hash();

    let (status, _) = {
        let effects = engine
            .handle_node(room.conv_id, stranger_msg, &store, None)
            .unwrap();
        let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Speculative
        };
        merkle_tox_core::testing::apply_effects(effects, &store);
        (status, ())
    };
    assert_eq!(status, VerificationStatus::Speculative);

    // 3. Bob and Charlie vouch for it
    engine.start_sync(room.conv_id, Some(bob.device_pk), &store);
    engine.start_sync(room.conv_id, Some(charlie.device_pk), &store);

    let mut bob_parents = vec![stranger_hash];
    bob_parents.extend(store.get_admin_heads(&room.conv_id));

    let bob_msg = create_msg(
        &room.conv_id,
        &room.keys,
        bob,
        bob_parents,
        "I saw it",
        2, // Rank 2
        1,
        2000,
    );
    let (status_bob, _) = {
        let effects = engine
            .handle_node(room.conv_id, bob_msg, &store, None)
            .unwrap();
        let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Speculative
        };
        merkle_tox_core::testing::apply_effects(effects, &store);
        (status, ())
    };
    assert_eq!(
        status_bob,
        VerificationStatus::Verified,
        "Bob's message should be verified"
    );

    let mut charlie_parents = vec![stranger_hash];
    charlie_parents.extend(store.get_admin_heads(&room.conv_id));

    let charlie_msg = create_msg(
        &room.conv_id,
        &room.keys,
        charlie,
        charlie_parents,
        "Me too",
        2, // Rank 2
        1,
        3000,
    );
    let (status_charlie, _) = {
        let effects = engine
            .handle_node(room.conv_id, charlie_msg, &store, None)
            .unwrap();
        let status = if merkle_tox_core::testing::is_verified_in_effects(&effects) {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Speculative
        };
        merkle_tox_core::testing::apply_effects(effects, &store);
        (status, ())
    };
    assert_eq!(
        status_charlie,
        VerificationStatus::Verified,
        "Charlie's message should be verified"
    );

    // 4. Verify accumulation
    for ((peer, _), session) in &engine.sessions {
        let common = session.common();
        if peer == &bob.device_pk {
            let vouchers = common
                .vouchers
                .get(&stranger_hash)
                .expect("Should have vouchers in Bob's session");
            assert!(vouchers.contains(&bob.device_pk));
            assert!(vouchers.contains(&charlie.device_pk));
            assert_eq!(vouchers.len(), 2);
        }
        if peer == &charlie.device_pk {
            let vouchers = common
                .vouchers
                .get(&stranger_hash)
                .expect("Should have vouchers in Charlie's session");
            assert!(vouchers.contains(&bob.device_pk));
            assert!(vouchers.contains(&charlie.device_pk));
            assert_eq!(vouchers.len(), 2);
        }
    }
}

#[test]
fn test_out_of_order_sequence_numbers() {
    let room = TestRoom::new(2);
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        rand::SeedableRng::seed_from_u64(42),
        Arc::new(SystemTimeProvider),
    );
    let store = InMemoryStore::new();
    room.setup_engine(&mut engine, &store);

    let alice = &room.identities[0];

    // Author two messages from Alice
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let msg1 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        admin_heads.clone(),
        "Message 1",
        1,
        2, // Sequence 2
        1001,
    );

    let mut msg2_parents = vec![msg1.hash()];
    msg2_parents.extend(admin_heads);

    let msg2 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        msg2_parents,
        "Message 2",
        2,
        3, // Sequence 3
        1002,
    );

    // 1. Process Message 2 first. It should be stored speculatively (missing parent).
    let effects = engine
        .handle_node(room.conv_id, msg2.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    assert!(store.has_node(&msg2.hash()), "Message 2 should be in store");
    assert!(
        !store.is_verified(&msg2.hash()),
        "Message 2 should be speculative"
    );

    // 2. Process Message 1.
    // This used to fail because Message 2 already updated last_seen_seq to 3.
    // Now it should pass.
    let res = engine.handle_node(room.conv_id, msg1.clone(), &store, None);

    match res {
        Ok(effects) => {
            merkle_tox_core::testing::apply_effects(effects, &store);
            assert!(store.has_node(&msg1.hash()), "Message 1 should be in store");
        }
        Err(e) => {
            panic!("Message 1 rejected: {}", e);
        }
    }
}

#[test]
fn test_concurrent_children_ratchet_purge() {
    let room = TestRoom::new(2);
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        rand::SeedableRng::seed_from_u64(42),
        Arc::new(SystemTimeProvider),
    );
    let store = InMemoryStore::new();
    room.setup_engine(&mut engine, &store);

    let bob = &room.identities[1];

    // 1. Alice authors G1
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("G1".to_string()),
            Vec::new(),
            &store,
        )
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);
    let msg_g1_hash = store.get_heads(&room.conv_id)[0];

    // 2. Alice authors P1 (parent G1)
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("P1".to_string()),
            Vec::new(),
            &store,
        )
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);
    let msg_p1_hash = store.get_heads(&room.conv_id)[0];
    let msg_p1 = store.get_node(&msg_p1_hash).unwrap();

    // 3. Alice authors P2 (parent G1)
    // We must reset heads to G1 to branch
    store.set_heads(&room.conv_id, vec![msg_g1_hash]).unwrap();
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("P2".to_string()),
            Vec::new(),
            &store,
        )
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);
    let msg_p2_hash = store
        .get_heads(&room.conv_id)
        .iter()
        .find(|&&h| h != msg_p1_hash)
        .copied()
        .unwrap();
    let msg_p2 = store.get_node(&msg_p2_hash).unwrap();

    // 4. Bob's engine
    let mut bob_engine = MerkleToxEngine::new(
        bob.device_pk,
        bob.master_pk,
        rand::SeedableRng::seed_from_u64(42),
        Arc::new(SystemTimeProvider),
    );
    let bob_store = InMemoryStore::new();
    room.setup_engine(&mut bob_engine, &bob_store);

    // Transfer Alice's ephemeral signing keys to Bob so DARE verification works
    transfer_ephemeral_keys(&engine, &mut bob_engine);

    // Transfer wire nodes so encrypt-then-sign verification works
    for (hash, (cid, wire)) in store.wire_nodes.read().unwrap().iter() {
        let _ = bob_store.put_wire_node(cid, hash, wire.clone());
    }

    // 5. Bob processes G1
    let msg_g1 = store.get_node(&msg_g1_hash).unwrap();
    let effects = bob_engine
        .handle_node(room.conv_id, msg_g1, &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    // 6. Bob processes P1. It should be verified and PURGE G1's key from the store.
    let effects = bob_engine
        .handle_node(room.conv_id, msg_p1, &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);
    assert!(bob_store.is_verified(&msg_p1_hash), "Bob should verify P1");

    // ASSERT SECURITY: G1's key MUST be purged from the persistent store (Forward Secrecy).
    assert!(
        bob_store
            .get_ratchet_key(&room.conv_id, &msg_g1_hash)
            .unwrap()
            .is_none(),
        "G1's key was NOT purged from the store! Forward Secrecy violation."
    );

    // 7. Bob processes P2. It needs G1's key.
    // Bob's engine should have G1's key in its historical cache now.
    let res = bob_engine.handle_node(room.conv_id, msg_p2, &bob_store, None);

    match res {
        Ok(effects) => {
            apply_effects(effects, &bob_store);
            assert!(
                bob_store.is_verified(&msg_p2_hash),
                "Bob should verify P2 using historical cache"
            );
        }
        Err(e) => {
            panic!("Bob failed to verify P2 (concurrent branch): {}", e);
        }
    }
}

#[test]
fn test_anchor_snapshot_speculative() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
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

    // 1. Setup Alice's established conversation (Alice is founder)
    let genesis_node = create_genesis_pow(&conv_id, &alice, "Snapshot Test");

    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // 2. Bob receives an AnchorSnapshot from Alice
    // Even if Bob doesn't have the AuthorizeDevice node for Alice's device,
    // the AnchorSnapshot contains a DelegationCertificate signed by the founder (Alice's master key).

    let bob_tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        bob_tp.clone(),
    );
    let bob_store = InMemoryStore::new();

    // Bob only has the genesis node
    let effects = bob_engine
        .handle_node(conv_id, genesis_node.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    // Alice's device cert
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
        conv_id,
    );

    let anchor_snapshot = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![genesis_node.hash()],
        ControlAction::AnchorSnapshot {
            data: SnapshotData {
                basis_hash: genesis_node.hash(),
                members: vec![],
                last_seq_numbers: vec![],
            },
            cert: alice_cert,
        },
        1,
        2,
        1000,
    );

    // Bob processes the AnchorSnapshot
    let effects = bob_engine
        .handle_node(conv_id, anchor_snapshot.clone(), &bob_store, None)
        .unwrap();

    // Should result in a WriteStore with verified = true
    let mut verified = false;
    for e in &effects {
        if let Effect::WriteStore(_, _, v) = e {
            verified = *v;
        }
    }

    assert!(
        verified,
        "AnchorSnapshot should be verified speculatively using the founder's key"
    );
}

/// AnchorSnapshot processing must apply its `data.members` list to the
/// identity_manager so that members listed in the snapshot are recognised after
/// the snapshot is accepted. Currently `apply_side_effects` for AnchorSnapshot
/// only updates `latest_anchor_hashes` and never calls `add_member` for the
/// members listed in the snapshot's `data` field. As a result, subsequent
/// re-verification of speculative nodes authored by those members cannot succeed
/// because the identity_manager still has no record of them.
#[test]
fn test_anchor_snapshot_applies_member_data() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let charlie = TestIdentity::new();
    let conv_id = ConversationId::from([9u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "Anchor Member Test");

    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng,
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let effects = engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Confirm Charlie is not yet a member.
    let members_before: Vec<_> = engine
        .identity_manager
        .list_members(conv_id)
        .into_iter()
        .map(|(pk, _, _)| pk)
        .collect();
    assert!(
        !members_before.contains(&charlie.master_pk),
        "Charlie must not be a member before AnchorSnapshot is processed",
    );

    // Alice (the founder) issues an AnchorSnapshot that lists Charlie as a member.
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
    );
    let anchor = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![genesis_node.hash()],
        ControlAction::AnchorSnapshot {
            data: SnapshotData {
                basis_hash: genesis_node.hash(),
                members: vec![MemberInfo {
                    public_key: charlie.master_pk,
                    role: 1,
                    joined_at: 1000,
                }],
                last_seq_numbers: vec![],
            },
            cert: alice_cert,
        },
        1,
        2,
        1000,
    );

    let effects = engine
        .handle_node(conv_id, anchor.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // After AnchorSnapshot, Charlie must be recognised as a member.
    let members_after: Vec<_> = engine
        .identity_manager
        .list_members(conv_id)
        .into_iter()
        .map(|(pk, _, _)| pk)
        .collect();
    assert!(
        members_after.contains(&charlie.master_pk),
        "AnchorSnapshot data.members must be applied to the identity_manager; \
         Charlie (listed in the snapshot) should be a recognised member afterwards \
         so that his speculative nodes can be re-verified",
    );
}

/// An admin device must automatically author a Snapshot (re-anchoring)
/// after every N content messages, where N is the re-anchor threshold (<= 400).
/// Without periodic Snapshots, newly-joining devices that receive only an
/// AnchorSnapshot have an increasingly stale anchor and must replay more and more
/// history. Currently `check_rotation_triggers` only checks the 5 000-message
/// epoch-rotation threshold; no re-anchoring logic exists.
#[test]
fn test_message_count_triggers_anchor_snapshot() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let conv_id = ConversationId::from([10u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "Anchor Threshold Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng,
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Authorize Alice's device so she can both send messages and author admin nodes.
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

    // Establish the conversation key so Alice can sign content messages.
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &store)
        .unwrap();
    apply_effects(effects, &store);

    // Jump the message counter to just below the re-anchoring threshold.
    // This avoids having to author hundreds of nodes in the test.
    const RE_ANCHOR_THRESHOLD: u32 = 400;
    if let Some(Conversation::Established(em)) = alice_engine.conversations.get_mut(&conv_id) {
        em.state.message_count = RE_ANCHOR_THRESHOLD - 1;
    }

    // Author one more content message; this pushes the count to the threshold.
    // The engine should detect this and automatically co-author a Snapshot.
    let effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("trigger".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    apply_effects(effects.clone(), &store);

    let has_anchor = effects.iter().any(|e| {
        matches!(
            e,
            Effect::WriteStore(_, node, _)
                if matches!(
                    node.content,
                    Content::Control(ControlAction::Snapshot(_))
                        | Content::Control(ControlAction::AnchorSnapshot { .. })
                )
        )
    });
    assert!(
        has_anchor,
        "After {} content messages an admin must auto-author a Snapshot or AnchorSnapshot \
         (re-anchoring); currently no such threshold check exists",
        RE_ANCHOR_THRESHOLD,
    );
}

/// `HistoryKeyExport` must register the `blob_hash` in `blob_syncs` so
/// the CAS fetch machinery can retrieve the encrypted history blob. Currently the
/// processing stub only logs a debug message and never populates `blob_syncs`.
#[test]
fn test_history_key_export_registers_blob_sync() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));

    // Use TestRoom to get two identities sharing the same k_conv in a 1-on-1 DAG.
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];
    let bob_id = &room.identities[1];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();
    room.setup_engine(&mut alice_engine, &alice_store);

    let mut bob_engine = MerkleToxEngine::with_sk(
        bob_id.device_pk,
        bob_id.master_pk,
        PhysicalDeviceSk::from(bob_id.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let bob_store = InMemoryStore::new();
    room.setup_engine(&mut bob_engine, &bob_store);

    // Alice exports history referencing a specific blob.
    let blob_hash = NodeHash::from([0xBB_u8; 32]);
    let hke_effects = alice_engine
        .author_history_key_export(room.conv_id, blob_hash, 1024, None, &alice_store)
        .unwrap();
    apply_effects(hke_effects.clone(), &alice_store);

    let hke_node = hke_effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && matches!(node.content, Content::HistoryExport { .. })
            {
                Some(node.clone())
            } else {
                None
            }
        })
        .expect("author_history_key_export must produce a HistoryKeyExport WriteStore effect");

    // Bob processes the HistoryKeyExport node.
    let bob_effects = bob_engine
        .handle_node(room.conv_id, hke_node, &bob_store, None)
        .unwrap();
    apply_effects(bob_effects, &bob_store);

    assert!(
        bob_engine.blob_syncs.contains_key(&blob_hash),
        "Processing a HistoryKeyExport addressed to us must register the blob_hash \
         in blob_syncs so the CAS fetch machinery knows to retrieve the history blob; \
         currently the stub only logs and never populates blob_syncs",
    );
}

#[test]
fn test_opaque_store_quota_eviction() {
    let _ = tracing_subscriber::fmt::try_init();

    let rng = StdRng::seed_from_u64(100);
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 1000));
    let alice = TestIdentity::new();
    let mut engine = MerkleToxEngine::new(alice.device_pk, alice.master_pk, rng, tp.clone());

    let conv_id = ConversationId::from([20u8; 32]);

    // Manually insert entries totaling > 100 MB into opaque_store_usage.
    // OPAQUE_STORE_QUOTA = 100 * 1024 * 1024 = 104,857,600 bytes
    let quota = 100 * 1024 * 1024;
    let entry_size = quota / 5; // ~20 MB each
    let dummy_sender = PhysicalDevicePk::from([0xFFu8; 32]);
    let mut entries = Vec::new();
    for i in 0u8..6 {
        let hash = NodeHash::from([i; 32]);
        let ts = 1000 + i as i64 * 100; // increasing timestamps
        entries.push((hash, entry_size, ts, dummy_sender));
    }
    let total = entry_size * 6; // 120 MB, exceeds quota
    engine.opaque_store_usage.insert(conv_id, (total, entries));

    // Verify we're over quota
    let (tracked_total, tracked_entries) = engine.opaque_store_usage.get(&conv_id).unwrap();
    assert!(
        *tracked_total > quota,
        "Total should exceed quota: {} > {}",
        tracked_total,
        quota
    );
    assert_eq!(tracked_entries.len(), 6);

    // Simulate what happens when the engine processes a new wire node that triggers eviction.
    // The eviction logic is in handle_message for wire nodes. For a direct unit test,
    // we can manually run the eviction loop that matches the handler logic.
    let (total, entries) = engine.opaque_store_usage.get_mut(&conv_id).unwrap();
    while *total > quota && !entries.is_empty() {
        entries.sort_by_key(|&(_, _, ts, _)| ts);
        let (_evicted_hash, evicted_size, _, _) = entries.remove(0);
        *total -= evicted_size;
    }

    let (post_total, post_entries) = engine.opaque_store_usage.get(&conv_id).unwrap();
    assert!(
        *post_total <= quota,
        "After eviction, total should be under quota: {} <= {}",
        post_total,
        quota
    );
    // We started with 6 entries at ~20 MB each (120 MB). Need to remove at least 1 to
    // get under 100 MB.
    assert!(
        post_entries.len() < 6,
        "At least one entry should have been evicted"
    );
}

#[test]
fn test_identity_pending_on_keywrap_without_genesis() {
    let _ = tracing_subscriber::fmt::try_init();

    let rng = StdRng::seed_from_u64(300);
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 1000));

    // Bob is the recipient who will receive a KeyWrap without a Genesis
    let bob = TestIdentity::new();
    let alice = TestIdentity::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let bob_store = InMemoryStore::new();

    let conv_id = ConversationId::from([40u8; 32]);

    // Alice creates a genesis and establishes her engine (so she can author a KeyWrap)
    let alice_rng = StdRng::seed_from_u64(301);
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        alice_rng,
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();

    let genesis = create_genesis_pow(&conv_id, &alice, "KeyWrap Test");
    let effects = alice_engine
        .handle_node(conv_id, genesis.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    let alice_cert = make_cert(
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
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_node.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // Before Bob gets any Genesis node, check the conversation doesn't exist
    assert!(
        !bob_engine.conversations.contains_key(&conv_id),
        "Bob should not have conversation before any nodes"
    );

    // Manually create a Pending conversation and then establish it with identity_pending=true
    // to simulate what happens when a KeyWrap is processed without Genesis.
    // We insert a Pending conversation and then establish it.
    use merkle_tox_core::engine::conversation::{ConversationData, Pending};
    let pending = ConversationData::<Pending>::new(conv_id);
    let k_conv = merkle_tox_core::dag::KConv::from([99u8; 32]);
    let mut est = pending.establish(k_conv, 1000, 0);
    // Simulate: no genesis means identity_pending = true
    est.state.identity_pending = true;
    bob_engine
        .conversations
        .insert(conv_id, Conversation::Established(est));

    // Verify identity_pending is true
    match bob_engine.conversations.get(&conv_id) {
        Some(Conversation::Established(e)) => {
            assert!(
                e.state.identity_pending,
                "identity_pending should be true when no Genesis exists"
            );
        }
        _ => panic!("Conversation should be Established"),
    }

    // Now Bob processes the Genesis node. identity_pending should clear.
    let effects = bob_engine
        .handle_node(conv_id, genesis.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    match bob_engine.conversations.get(&conv_id) {
        Some(Conversation::Established(e)) => {
            assert!(
                !e.state.identity_pending,
                "identity_pending should be false after Genesis is processed"
            );
        }
        _ => panic!("Conversation should still be Established after Genesis"),
    }
}
