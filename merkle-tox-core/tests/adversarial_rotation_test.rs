use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, ControlAction, Permissions, PhysicalDeviceSk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, create_admin_node, make_cert, sign_content_node,
};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_pcs_exclusion_adversarial() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store_alice = InMemoryStore::new();
    let store_bob = InMemoryStore::new();
    let store_malicious = InMemoryStore::new();

    // 1. Setup Room with Alice, Bob, and Malicious
    let room = TestRoom::new(3);
    let alice_id = &room.identities[0];
    let bob_id = &room.identities[1];
    let malicious_id = &room.identities[2];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob_id.device_pk,
        bob_id.master_pk,
        PhysicalDeviceSk::from(bob_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(1),
        tp.clone(),
    );
    let mut malicious_engine = MerkleToxEngine::with_sk(
        malicious_id.device_pk,
        malicious_id.master_pk,
        PhysicalDeviceSk::from(malicious_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(2),
        tp.clone(),
    );

    room.setup_engine(&mut alice_engine, &store_alice);
    room.setup_engine(&mut bob_engine, &store_bob);
    room.setup_engine(&mut malicious_engine, &store_malicious);

    // All share Epoch 0 key initially
    assert_eq!(alice_engine.get_current_epoch(&room.conv_id), 0);
    assert_eq!(bob_engine.get_current_epoch(&room.conv_id), 0);
    assert_eq!(malicious_engine.get_current_epoch(&room.conv_id), 0);

    // 2. Alice performs Epoch Rotation (Epoch 1)
    // First, Alice should revoke Malicious to ensure they are excluded from the new KeyWrap.
    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Control(ControlAction::RevokeDevice {
                target_device_pk: malicious_id.device_pk,
                reason: "Evil".to_string(),
            }),
            vec![],
            &store_alice,
        )
        .unwrap();
    let revoke_node = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store_alice);

    // Bob and Malicious receive revocation
    let effects = bob_engine
        .handle_node(room.conv_id, revoke_node.clone(), &store_bob, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store_bob);

    let effects = malicious_engine
        .handle_node(room.conv_id, revoke_node.clone(), &store_malicious, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store_malicious);

    // Now Alice rotates
    let effects = alice_engine
        .rotate_conversation_key(room.conv_id, &store_alice)
        .unwrap();
    let rotation_nodes: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    merkle_tox_core::testing::apply_effects(effects, &store_alice);

    // Bob receives rotation
    for node in &rotation_nodes {
        let effects = bob_engine
            .handle_node(room.conv_id, node.clone(), &store_bob, None)
            .unwrap();
        merkle_tox_core::testing::apply_effects(effects, &store_bob);
    }

    // Malicious receives rotation
    for node in &rotation_nodes {
        let effects = malicious_engine
            .handle_node(room.conv_id, node.clone(), &store_malicious, None)
            .unwrap();
        merkle_tox_core::testing::apply_effects(effects, &store_malicious);
    }

    // Verify Bob is at Epoch 1
    assert_eq!(bob_engine.get_current_epoch(&room.conv_id), 1);
    // Verify Malicious is STILL at Epoch 0 because they couldn't unwrap the KeyWrap (revoked)
    assert_eq!(malicious_engine.get_current_epoch(&room.conv_id), 0);

    // 3. Alice authors a message in Epoch 1
    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Secret in Epoch 1".to_string()),
            vec![],
            &store_alice,
        )
        .unwrap();
    let msg_e1 = merkle_tox_core::testing::get_node_from_effects(effects.clone());
    merkle_tox_core::testing::apply_effects(effects, &store_alice);

    // 4. Bob receives and verifies successfully
    let effects = bob_engine
        .handle_node(room.conv_id, msg_e1.clone(), &store_bob, None)
        .unwrap();
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
    merkle_tox_core::testing::apply_effects(effects, &store_bob);

    // 5. Malicious receives but FAILS to verify (remains Speculative)
    let effects = malicious_engine
        .handle_node(room.conv_id, msg_e1.clone(), &store_malicious, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects.clone(), &store_malicious);
    assert!(
        !merkle_tox_core::testing::is_verified_in_effects(&effects),
        "Malicious should not be able to verify Epoch 1 message"
    );

    // 6. Malicious attempts to inject their own node into the DAG using the leaked Epoch 0 key
    let mut evil_node = merkle_tox_core::testing::test_node();
    evil_node.author_pk = malicious_id.master_pk;
    evil_node.sender_pk = malicious_id.device_pk;
    evil_node.parents = vec![msg_e1.hash()];
    evil_node.topological_rank = msg_e1.topological_rank + 1;
    evil_node.content = Content::Text("I am still here!".to_string());

    // Malicious uses the Epoch 0 key they still have
    sign_content_node(&mut evil_node, &room.conv_id, &room.keys);

    // Alice receives and REJECTS with PermissionDenied because the sender is known to be revoked
    let res_alice = alice_engine.handle_node(room.conv_id, evil_node, &store_alice, None);
    assert!(
        matches!(
            res_alice,
            Err(merkle_tox_core::error::MerkleToxError::PermissionDenied { .. })
        ),
        "Alice should reject node from revoked device with PermissionDenied"
    );
}

#[test]
fn test_zombie_device_rotation_exclusion() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup Room with 2 identities (ensures Genesis node is created)
    let room = TestRoom::new(2);
    let alice_id = &room.identities[0];
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_id.device_pk,
        alice_id.master_pk,
        PhysicalDeviceSk::from(alice_id.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &store);
    let genesis_hash = room.genesis_node.as_ref().unwrap().hash();

    // 2. Alice authorizes Admin A
    let admin_a = TestIdentity::new();
    let cert_a = make_cert(
        &alice_id.master_sk,
        admin_a.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        i64::MAX,
    );
    let auth_a_node = create_admin_node(
        &room.conv_id,
        alice_id.master_pk,
        &alice_id.master_sk,
        vec![genesis_hash],
        ControlAction::AuthorizeDevice { cert: cert_a },
        1,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(room.conv_id, auth_a_node.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 3. Admin A authorizes Device B (Participant)
    let device_b = TestIdentity::new();
    let cert_b = make_cert(
        &admin_a.device_sk,
        device_b.device_pk,
        Permissions::MESSAGE,
        i64::MAX,
    );
    let auth_b_node = create_admin_node(
        &room.conv_id,
        alice_id.master_pk,
        &admin_a.device_sk,
        vec![auth_a_node.hash()],
        ControlAction::AuthorizeDevice { cert: cert_b },
        2,
        1,
        2000,
    );
    let effects = alice_engine
        .handle_node(room.conv_id, auth_b_node.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);
    alice_engine.clear_pending();

    // Verify B is authorized
    assert!(alice_engine.identity_manager.is_authorized(
        room.conv_id,
        &device_b.device_pk,
        &alice_id.master_pk,
        2500,
        2
    ));

    // 4. Master Alice revokes Admin A
    let revoke_a_node = create_admin_node(
        &room.conv_id,
        alice_id.master_pk,
        &alice_id.master_sk,
        vec![auth_b_node.hash()],
        ControlAction::RevokeDevice {
            target_device_pk: admin_a.device_pk,
            reason: "Revoked".to_string(),
        },
        3,
        2,
        3000,
    );
    let effects = alice_engine
        .handle_node(room.conv_id, revoke_a_node.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // Verify B is now a "Zombie" (path broken via A)
    assert!(!alice_engine.identity_manager.is_authorized(
        room.conv_id,
        &device_b.device_pk,
        &alice_id.master_pk,
        3500,
        3
    ));

    // 5. Alice performs Epoch Rotation
    let effects = alice_engine
        .rotate_conversation_key(room.conv_id, &store)
        .unwrap();
    let rotation_nodes: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    merkle_tox_core::testing::apply_effects(effects, &store);

    let wrap_node = rotation_nodes
        .iter()
        .find(|n| matches!(n.content, Content::KeyWrap { .. }))
        .unwrap();

    // 6. Verify Device B is NOT among recipients of the KeyWrap
    if let Content::KeyWrap { wrapped_keys, .. } = &wrap_node.content {
        let b_received = wrapped_keys
            .iter()
            .any(|k| k.recipient_pk == device_b.device_pk);
        assert!(
            !b_received,
            "Zombie Device B should have been excluded from KeyWrap recipients"
        );

        let a_received = wrapped_keys
            .iter()
            .any(|k| k.recipient_pk == admin_a.device_pk);
        assert!(
            !a_received,
            "Revoked Admin A should have been excluded from KeyWrap recipients"
        );
    } else {
        panic!("KeyWrap node missing");
    }
}
