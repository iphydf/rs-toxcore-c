use blake3::derive_key;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, KConv, PhysicalDeviceSk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, TestRoom};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_ratchet_forward_secrecy_one_wayness() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 1. Author 4 messages to advance the ratchet
    let mut hashes = Vec::new();
    for i in 0..4 {
        let effects = engine
            .author_node(
                room.conv_id,
                Content::Text(format!("Msg {}", i)),
                vec![],
                &store,
            )
            .unwrap();
        let node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
        merkle_tox_core::testing::apply_effects(effects, &store);
        hashes.push(node.hash());
    }

    // 2. Extract ChainKey for Message 4 (index 3) while it is still a head
    let k_chain_4 = store
        .get_ratchet_key(&room.conv_id, &hashes[3])
        .unwrap()
        .expect("Key for Msg 4 missing");

    // 3. Author Message 5 (index 4) which will advance from Msg 4 and delete its key
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Msg 4".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node_5 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let hash_5 = node_5.hash();
    let k_chain_5 = store
        .get_ratchet_key(&room.conv_id, &hash_5)
        .unwrap()
        .expect("Key for Msg 5 missing");

    // 4. Verify that K_chain_5 is derived from K_chain_4
    let expected_k_chain_5 = derive_key("merkle-tox v1 ratchet-step", k_chain_4.as_bytes());
    assert_eq!(
        *k_chain_5.as_bytes(),
        expected_k_chain_5,
        "Ratchet step logic mismatch"
    );

    // 5. Verify that K_chain_4 was indeed deleted from storage
    assert!(
        store
            .get_ratchet_key(&room.conv_id, &hashes[3])
            .unwrap()
            .is_none(),
        "Old ratchet key was not deleted!"
    );

    // 6. Extract MessageKey for Message 4
    let k_msg_4_actual = derive_key("merkle-tox v1 message-key", k_chain_4.as_bytes());

    // 5. ATTEMPT TO BACKTRACK: Try to derive k_msg_4 from k_chain_5
    // Since Blake3 is a one-way function, this should be impossible.
    // In this test, we demonstrate that there is no obvious way to get k_msg_4 from k_chain_5
    // and that simply trying to use k_chain_5 as if it were k_chain_4 fails.

    let k_msg_4_from_k_chain_5 = derive_key("merkle-tox v1 message-key", k_chain_5.as_bytes());
    assert_ne!(
        k_msg_4_actual, k_msg_4_from_k_chain_5,
        "Ratchet leaked previous message key!"
    );

    // 6. Verify that k_chain_4 is NOT derivable from k_chain_5 using the same KDF
    let k_chain_4_from_k_chain_5 = derive_key("merkle-tox v1 ratchet-step", k_chain_5.as_bytes());
    assert_ne!(
        *k_chain_4.as_bytes(),
        k_chain_4_from_k_chain_5,
        "Ratchet is reversible!"
    );
}

#[test]
fn test_ratchet_state_isolation_after_rotation() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 1. Author a message in Epoch 0
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Epoch 0".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node_e0 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let k_chain_e0 = store
        .get_ratchet_key(&room.conv_id, &node_e0.hash())
        .unwrap()
        .unwrap();

    // 2. Perform rotation to Epoch 1
    let effects = engine
        .rotate_conversation_key(room.conv_id, &store)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 3. Author a message in Epoch 1
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Epoch 1".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node_e1 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let k_chain_e1 = store
        .get_ratchet_key(&room.conv_id, &node_e1.hash())
        .unwrap()
        .unwrap();

    // 4. Verify that Epoch 1 ratchet is NOT derived from Epoch 0 ratchet
    // (Epoch 1 starts fresh from the new k_conv)
    let k_chain_e1_from_e0 = derive_key("merkle-tox v1 ratchet-step", k_chain_e0.as_bytes());
    assert_ne!(
        *k_chain_e1.as_bytes(),
        k_chain_e1_from_e0,
        "Epoch rotation leaked previous ratchet state"
    );
}

#[test]
fn test_ratchet_purge_after_merge() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 1. Create two parallel heads
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Branch A".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node_a = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let hash_a = node_a.hash();

    // To make them parallel, we reset the heads to genesis before authoring B
    let genesis_hash = room.genesis_node.as_ref().unwrap().hash();
    store.set_heads(&room.conv_id, vec![genesis_hash]).unwrap();

    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Branch B".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node_b = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let hash_b = node_b.hash();

    // Restore both heads
    store
        .set_heads(&room.conv_id, vec![hash_a, hash_b])
        .unwrap();

    // Verify both have ratchet keys
    assert!(
        store
            .get_ratchet_key(&room.conv_id, &hash_a)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get_ratchet_key(&room.conv_id, &hash_b)
            .unwrap()
            .is_some()
    );

    // 2. Author a merge node
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Merge".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let merge_node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let merge_hash = merge_node.hash();

    // 3. AUDIT: Merge node key should exist, but BOTH parent keys should be purged
    assert!(
        store
            .get_ratchet_key(&room.conv_id, &merge_hash)
            .unwrap()
            .is_some(),
        "Merge node ratchet key missing"
    );

    assert!(
        store
            .get_ratchet_key(&room.conv_id, &hash_a)
            .unwrap()
            .is_none(),
        "Parent A ratchet key was not purged after merge!"
    );
    assert!(
        store
            .get_ratchet_key(&room.conv_id, &hash_b)
            .unwrap()
            .is_none(),
        "Parent B ratchet key was not purged after merge!"
    );
}

#[test]
fn test_immediate_forward_secrecy_vulnerability() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 1. Alice authors a secret message
    let effects = engine
        .author_node(
            room.conv_id,
            Content::Text("Top Secret".to_string()),
            vec![],
            &store,
        )
        .unwrap();
    let node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store);
    let hash = node.hash();

    // 2. ATTACKER COMPROMISES DATABASE
    // We extract the ratchet key Alice just persisted for this node.
    let k_chain_from_db = store
        .get_ratchet_key(&room.conv_id, &hash)
        .unwrap()
        .expect("Ratchet key missing from DB");

    // 3. TRY TO RECOVER MESSAGE KEY
    // If the implementation is vulnerable, k_chain_from_db is the one used for the current message.
    let k_msg_derived = derive_key("merkle-tox v1 message-key", k_chain_from_db.as_bytes());
    let derived_keys =
        merkle_tox_core::crypto::ConversationKeys::derive(&KConv::from(k_msg_derived));

    // 4. VERIFY FORWARD SECRECY
    // We attempt to unpack the wire format using the derived key.
    // DESIGN: This MUST FAIL because the key in the DB should already be one step ahead.
    let wire = node.pack_wire(&derived_keys, false).unwrap();
    let result = merkle_tox_core::dag::MerkleNode::unpack_wire(&wire, &derived_keys, &room.conv_id);

    assert!(
        result.is_err(),
        "SECURITY VULNERABILITY: Stolen database state allowed decryption of the most recent message. Immediate Forward Secrecy is NOT enforced."
    );
}
