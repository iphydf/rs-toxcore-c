use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, ControlAction, Permissions};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, create_admin_node, create_signed_content_node, make_cert,
};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_multi_path_authorization_resilience() {
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

    if let Some(genesis) = &room.genesis_node {
        engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
    }

    // 2. Alice authorizes Admin A
    let admin_a = TestIdentity::new();
    let cert_a = make_cert(
        &alice.master_sk,
        admin_a.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
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

    // 3. Alice authorizes Admin B
    let admin_b = TestIdentity::new();
    let cert_b = make_cert(
        &alice.master_sk,
        admin_b.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
    );
    let auth_b_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![auth_a_hash],
        ControlAction::AuthorizeDevice { cert: cert_b },
        2,
        2,
        110,
    );
    let auth_b_hash = auth_b_node.hash();
    engine
        .handle_node(room.conv_id, auth_b_node, &store, None)
        .unwrap();

    // 4. Admin A authorizes Device C
    let device_c = TestIdentity::new();
    let cert_c1 = make_cert(
        &admin_a.device_sk,
        device_c.device_pk,
        Permissions::MESSAGE,
        2000,
    );
    let auth_c1_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![auth_b_hash],
        ControlAction::AuthorizeDevice { cert: cert_c1 },
        3,
        1,
        200,
    );
    let auth_c1_hash = auth_c1_node.hash();
    engine
        .handle_node(room.conv_id, auth_c1_node, &store, None)
        .unwrap();

    // 5. Admin B authorizes Device C (Second path!)
    let cert_c2 = make_cert(
        &admin_b.device_sk,
        device_c.device_pk,
        Permissions::MESSAGE,
        2000,
    );
    let auth_c2_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_b.device_sk,
        vec![auth_c1_hash],
        ControlAction::AuthorizeDevice { cert: cert_c2 },
        4,
        1,
        210,
    );
    let auth_c2_hash = auth_c2_node.hash();
    engine
        .handle_node(room.conv_id, auth_c2_node, &store, None)
        .unwrap();

    // 6. Revoke Admin B (One of the paths for C)
    let revoke_b = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![auth_c2_hash],
        ControlAction::RevokeDevice {
            target_device_pk: admin_b.device_pk,
            reason: "Revoke B".to_string(),
        },
        5,
        3,
        300,
    );
    let revoke_b_hash = revoke_b.hash();
    engine
        .handle_node(room.conv_id, revoke_b, &store, None)
        .unwrap();

    // 7. Device C should STILL be authorized via Admin A
    let msg_c = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        device_c.device_pk,
        vec![revoke_b_hash],
        Content::Text("Still here!".to_string()),
        6,
        1,
        400,
    );

    let res = engine.handle_node(room.conv_id, msg_c, &store, None);
    assert!(
        res.is_ok(),
        "Device C should remain authorized via Admin A even after Admin B is revoked. Error: {:?}",
        res.err()
    );
}
