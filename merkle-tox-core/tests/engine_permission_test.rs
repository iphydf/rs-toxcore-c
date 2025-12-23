use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, ControlAction, Permissions};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node,
    create_signed_content_node, make_cert,
};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_strict_permission_intersection_enforcement() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup Room
    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let mut engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Ensure Genesis is verified in engine (it was added to store in setup_engine)
    if let Some(genesis) = &room.genesis_node {
        engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
    }

    // 2. Alice authorizes Admin A with ONLY ADMIN (NO MESSAGE)
    let admin_a = TestIdentity::new();
    let cert_a = make_cert(
        &alice.master_sk,
        admin_a.device_pk,
        Permissions::ADMIN,
        2000,
    );
    let auth_a_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![room.conv_id.to_node_hash()],
        ControlAction::AuthorizeDevice { cert: cert_a },
        1,
        1,
        100,
    );
    let auth_a_hash = auth_a_node.hash();
    engine
        .handle_node(room.conv_id, auth_a_node, &store, None)
        .unwrap();

    // 3. Admin A authorizes Device B with MESSAGE
    // (This is a "Privilege Escalation" attempt, as A doesn't have MESSAGE)
    let device_b = TestIdentity::new();
    let cert_b = make_cert(
        &admin_a.device_sk,
        device_b.device_pk,
        Permissions::MESSAGE,
        2000,
    );
    let auth_b_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![auth_a_hash],
        ControlAction::AuthorizeDevice { cert: cert_b },
        2,
        1,
        200,
    );
    let _auth_b_hash = auth_b_node.hash();

    // Admin A has ADMIN, so the auth node is validly signed,
    // but it should be REJECTED because A is trying to delegate MESSAGE which it lacks.
    let res_auth = engine.handle_node(room.conv_id, auth_b_node, &store, None);
    assert!(
        res_auth.is_err(),
        "Escalated AuthorizeDevice node should be rejected immediately"
    );
    if let Err(merkle_tox_core::error::MerkleToxError::Identity(
        merkle_tox_core::identity::IdentityError::PermissionEscalation,
    )) = res_auth
    {
        // Success
    } else {
        panic!("Expected PermissionEscalation error, got {:?}", res_auth);
    }
}

#[test]
fn test_circular_delegation_denial() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let mut engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Ensure Genesis is verified in engine (it was added to store in setup_engine)
    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    // Admin A authorized by Master
    let admin_a = TestIdentity::new();
    let cert_ma = make_cert(
        &alice.master_sk,
        admin_a.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
    );
    let node_ma = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![room.conv_id.to_node_hash()],
        ControlAction::AuthorizeDevice { cert: cert_ma },
        1,
        1,
        100,
    );
    let hash_ma = node_ma.hash();
    let effects = engine
        .handle_node(room.conv_id, node_ma, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Admin B authorized by Admin A
    let admin_b = TestIdentity::new();
    let cert_ab = make_cert(
        &admin_a.device_sk,
        admin_b.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
    );
    let node_ab = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![hash_ma],
        ControlAction::AuthorizeDevice { cert: cert_ab },
        2,
        1,
        200,
    );
    let hash_ab = node_ab.hash();
    let effects = engine
        .handle_node(room.conv_id, node_ab, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Admin A re-authorized by Admin B (Circular!)
    let cert_ba = make_cert(
        &admin_b.device_sk,
        admin_a.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
    );
    let node_ba = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_b.device_sk,
        vec![hash_ab],
        ControlAction::AuthorizeDevice { cert: cert_ba },
        3,
        2,
        300,
    );
    let hash_ba = node_ba.hash();
    let effects = engine
        .handle_node(room.conv_id, node_ba.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Now Revoke Admin A's original path (Master -> A)
    let revoke_ma = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![hash_ba],
        ControlAction::RevokeDevice {
            target_device_pk: admin_a.device_pk,
            reason: "Testing".to_string(),
        },
        4,
        2,
        400,
    );
    let hash_revoke = revoke_ma.hash();
    let effects = engine
        .handle_node(room.conv_id, revoke_ma, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Now A and B only have paths through each other (Circular).
    // They should both be unauthorized.

    let msg_a = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        admin_a.device_pk,
        vec![hash_revoke],
        Content::Text("A?".to_string()),
        5,
        3,
        500,
    );
    let res_a = engine.handle_node(room.conv_id, msg_a, &store, None);
    assert!(
        res_a.is_err(),
        "Admin A should be unauthorized due to circular dependency"
    );

    let msg_b = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        admin_b.device_pk,
        vec![hash_revoke],
        Content::Text("B?".to_string()),
        6,
        2,
        600,
    );
    let res_b = engine.handle_node(room.conv_id, msg_b, &store, None);
    assert!(
        res_b.is_err(),
        "Admin B should be unauthorized because its path was broken via A"
    );
}
