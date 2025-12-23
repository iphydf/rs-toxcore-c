use ed25519_dalek::SigningKey;
use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::builder::NodeBuilder;
use merkle_tox_core::clock::{ManualTimeProvider, SystemTimeProvider};
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, KConv, LogicalIdentityPk, MerkleNode, NodeAuth,
    NodeHash, NodeMac, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::engine::session::{Handshake, SyncSession};
use merkle_tox_core::engine::{
    Conversation, ConversationData, Effect, MerkleToxEngine, VerificationStatus, conversation,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node, create_msg,
    create_signed_content_node, make_cert,
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

    // 2. Authorize Alice's device
    let expires_at = bob_engine.clock.network_time_ms() + 10000000000;
    let cert = alice.make_device_cert(Permissions::ALL, expires_at);

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

    let effects = bob_engine
        .handle_node(sync_key, auth_node, &bob_store, None)
        .expect("Bob handles Alice's auth");
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    // 3. Alice sends a message from her device
    let alice_msg = create_msg(
        &sync_key,
        &conv_keys,
        &alice,
        vec![genesis_hash],
        "Hi Bob",
        1,
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
                authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
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
    );

    bob_engine
        .identity_manager
        .authorize_device(
            sync_key,
            alice_master_pk,
            &cert,
            bob_engine.clock.network_time_ms(),
            0,
        )
        .expect("Bob handles Alice's auth");

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

    // 0. Genesis
    let genesis = NodeBuilder::new_1on1_genesis(alice_master_pk, bob_pk.to_logical(), &conv_keys);
    let genesis_hash = genesis.hash();
    bob_store
        .put_node(&sync_key, genesis.clone(), true)
        .unwrap();

    // 1. Speculative node
    let msg_final = create_signed_content_node(
        &sync_key,
        &conv_keys,
        alice_master_pk,
        alice_device_pk,
        vec![genesis_hash],
        Content::Text("Speculative".to_string()),
        1,
        1,
        100,
    );

    let effects = bob_engine
        .handle_node(sync_key, msg_final.clone(), &bob_store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &bob_store);

    // 2. Auth node from Alice Master
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE,
        2000000000000,
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
    );
    charlie_engine
        .identity_manager
        .authorize_device(sync_key, bob_master_pk, &cert, 1000, 0)
        .unwrap();

    let k_conv = KConv::from([0xBBu8; 32]);
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
        .put_ratchet_key(&conv_id, &genesis.hash(), k_conv.to_chain_key())
        .unwrap();
    bob_store
        .put_ratchet_key(&conv_id, &genesis.hash(), k_conv.to_chain_key())
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

    let bob_msg = create_msg(
        &room.conv_id,
        &room.keys,
        bob,
        vec![stranger_hash],
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

    let charlie_msg = create_msg(
        &room.conv_id,
        &room.keys,
        charlie,
        vec![stranger_hash],
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
    let msg1 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        vec![room.genesis_node.as_ref().unwrap().hash()],
        "Message 1",
        1,
        2, // Sequence 2
        1001,
    );

    let msg2 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        vec![msg1.hash()],
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
