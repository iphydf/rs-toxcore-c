use merkle_tox_core::clock::{ManualTimeProvider, SystemTimeProvider};
use merkle_tox_core::dag::{Content, ControlAction, Permissions};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, TestIdentity, TestRoom, apply_effects, make_cert};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_revalidation_preserves_history() {
    let rng = rand::rngs::StdRng::seed_from_u64(42);
    let time_provider = Arc::new(SystemTimeProvider);
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        rng,
        time_provider.clone(),
    );

    room.setup_engine(&mut engine, &store);

    let identity = &room.identities[0];

    // 1. Author messages using the engine to ensure the ratchet is used correctly.
    for i in 0..100 {
        let content = Content::Text(format!("Message {}", i));
        let effects = engine
            .author_node(room.conv_id, content, Vec::new(), &store)
            .unwrap();
        apply_effects(effects, &store);
    }

    let (verified_before, _) = store.get_node_counts(&room.conv_id);
    // 100 messages + 1 genesis = 101 verified nodes
    assert_eq!(verified_before, 101);

    // 2. Trigger re-validation by authorizing a new device
    let new_device = TestIdentity::new();
    let cert = make_cert(
        &identity.master_sk,
        new_device.device_pk,
        Permissions::MESSAGE,
        i64::MAX,
    );

    let admin_heads = store.get_admin_heads(&room.conv_id);

    let auth_node = merkle_tox_core::testing::create_admin_node(
        &room.conv_id,
        identity.master_pk,
        &identity.master_sk,
        admin_heads,
        ControlAction::AuthorizeDevice { cert },
        1,     // topological_rank
        200,   // sequence_number
        20000, // timestamp
    );

    // This call will trigger revalidate_all_verified_nodes()
    let effects = engine
        .handle_node(room.conv_id, auth_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let (verified_after, _) = store.get_node_counts(&room.conv_id);

    // This assertion is EXPECTED to FAIL if the bug exists.
    // History should be preserved, so verified nodes should be 101 + 1 = 102.
    // If bug 1 exists, it will be much lower (~66).
    assert_eq!(
        verified_after, 102,
        "History was purged during re-validation! Before: {}, After: {}",
        verified_before, verified_after
    );
}

#[test]
fn test_historical_authorization_verification() {
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);

    let identity = &room.identities[0];
    let genesis_hash = room.genesis_node.as_ref().unwrap().hash();

    // 1. Create a device authorization that was valid at T=1200 but expires at T=1500.
    let historical_device = TestIdentity::new();
    let cert = make_cert(
        &identity.master_sk,
        historical_device.device_pk,
        Permissions::MESSAGE,
        1500,
    );

    let auth_node = merkle_tox_core::testing::create_admin_node(
        &room.conv_id,
        identity.master_pk,
        &identity.master_sk,
        vec![genesis_hash],
        ControlAction::AuthorizeDevice { cert },
        1,
        10,
        1100,
    );
    let auth_hash = auth_node.hash();

    // A message from that device at T=1200
    // We sign it with the epoch key for simplicity, as we just want to test identity verification here.
    let mut msg = merkle_tox_core::testing::test_node();
    msg.author_pk = identity.master_pk; // FIXED: Must match the identity that authorized the device
    msg.sender_pk = historical_device.device_pk;
    msg.parents = vec![auth_hash];
    msg.content = Content::Text("I was authorized when I sent this".to_string());
    msg.topological_rank = 2;
    msg.sequence_number = 1;
    msg.network_timestamp = 1200;
    merkle_tox_core::testing::sign_content_node(&mut msg, &room.conv_id, &room.keys);

    // 2. Now a new peer joins at T=2000 and tries to sync this history.
    let now = Instant::now();
    let manual_time = Arc::new(ManualTimeProvider::new(now, 2000));

    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        rand::rngs::StdRng::seed_from_u64(42),
        manual_time,
    );

    // Load conversation keys and genesis
    store
        .put_conversation_key(
            &room.conv_id,
            0,
            merkle_tox_core::dag::KConv::from(room.k_conv),
        )
        .unwrap();
    store
        .put_node(
            &room.conv_id,
            room.genesis_node.as_ref().unwrap().clone(),
            true,
        )
        .unwrap();
    store.set_heads(&room.conv_id, vec![genesis_hash]).unwrap();
    store
        .set_admin_heads(&room.conv_id, vec![genesis_hash])
        .unwrap();
    engine
        .load_conversation_state(room.conv_id, &store)
        .unwrap();

    // 3. Process the historical auth node.
    let res = engine.handle_node(room.conv_id, auth_node, &store, None);
    assert!(
        res.is_ok(),
        "Historical AuthorizeDevice node should be accepted even if cert is expired NOW. Got error: {:?}",
        res.err()
    );

    let effects = res.unwrap();
    let verified = merkle_tox_core::testing::is_verified_in_effects(&effects);
    assert!(
        verified,
        "Historical AuthorizeDevice node should be verified"
    );
    apply_effects(effects, &store);

    // 4. Process the message.
    let effects = engine.handle_node(room.conv_id, msg, &store, None).unwrap();
    let verified = merkle_tox_core::testing::is_verified_in_effects(&effects);

    assert!(
        verified,
        "Historical message should be verified if the device was authorized at the time of sending"
    );
}
