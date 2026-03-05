use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Permissions, PhysicalDeviceSk, SnapshotData,
};
use merkle_tox_core::engine::{Conversation, Effect, MerkleToxEngine};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node, create_genesis_pow,
    create_signed_content_node, make_cert,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
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
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        merkle_tox_core::testing::apply_effects(effects, &store);
    }

    // 2. Alice authorizes Admin A with ONLY ADMIN (NO MESSAGE)
    let admin_a = TestIdentity::new();
    let cert_a = make_cert(
        &alice.master_sk,
        admin_a.device_pk,
        Permissions::ADMIN,
        2000,
        room.conv_id,
    );
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let auth_a_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        admin_heads,
        ControlAction::AuthorizeDevice { cert: cert_a },
        2,
        2,
        100,
    );
    let auth_a_hash = auth_a_node.hash();
    let effects = engine
        .handle_node(room.conv_id, auth_a_node, &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 3. Admin A authorizes Device B with MESSAGE
    // (This is a "Privilege Escalation" attempt, as A doesn't have MESSAGE)
    let device_b = TestIdentity::new();
    let cert_b = make_cert(
        &admin_a.device_sk,
        device_b.device_pk,
        Permissions::MESSAGE,
        2000,
        room.conv_id,
    );
    let auth_b_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![auth_a_hash],
        ControlAction::AuthorizeDevice { cert: cert_b },
        3,
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
        room.conv_id,
    );
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let node_ma = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        admin_heads,
        ControlAction::AuthorizeDevice { cert: cert_ma },
        2,
        2,
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
        room.conv_id,
    );
    let node_ab = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![hash_ma],
        ControlAction::AuthorizeDevice { cert: cert_ab },
        3,
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
        room.conv_id,
    );
    let node_ba = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_b.device_sk,
        vec![hash_ab],
        ControlAction::AuthorizeDevice { cert: cert_ba },
        4,
        1,
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
        5,
        3,
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
        6,
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

/// AnchorSnapshot cert must grant ADMIN permissions.
/// The doc says it "MUST be signed by a Level 1 Admin Device." A cert signed by
/// the founder that only grants MESSAGE permissions must be rejected.
#[test]
fn test_anchor_snapshot_rejects_message_only_cert() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([2u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "Cert Permission Test");

    // Bob's engine: starts with only the genesis node (shallow sync scenario)
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let bob_store = InMemoryStore::new();
    let effects = bob_engine
        .handle_node(conv_id, genesis_node.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    // Alice creates an AnchorSnapshot but with only MESSAGE permission (not ADMIN).
    // This must be rejected: the spec requires a Level 1 Admin cert.
    let message_only_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::MESSAGE, // not ADMIN
        9_999_999,
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
            cert: message_only_cert,
        },
        1,
        2,
        1000,
    );

    let effects = bob_engine
        .handle_node(conv_id, anchor_snapshot, &bob_store, None)
        .unwrap();

    // A cert granting only MESSAGE must not unlock speculative trust.
    let verified = effects
        .iter()
        .any(|e| matches!(e, Effect::WriteStore(_, _, true)));
    assert!(
        !verified,
        "AnchorSnapshot with a MESSAGE-only cert should be rejected; \
         speculative trust requires an ADMIN-level certificate"
    );
}

/// `author_node` must not author admin control actions when the local
/// conversation is in Pending state (no established K_conv). A device that has
/// not yet received a KeyWrap is in observer-only / Identity-Pending mode and
/// must not be able to inject admin actions into the shared DAG.
#[test]
fn test_pending_conversation_blocks_admin_authoring() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([6u8; 32]);

    // Alice's genesis provides the anchor; Bob processes only the genesis so he
    // ends up in Conversation::Pending (no K_conv, no established epoch).
    let genesis_node = create_genesis_pow(&conv_id, &alice, "Observer Mode Test");

    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let bob_store = InMemoryStore::new();

    let effects = bob_engine
        .handle_node(conv_id, genesis_node.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    // Confirm Bob is indeed in Pending state.
    assert!(
        matches!(
            bob_engine.conversations.get(&conv_id),
            Some(Conversation::Pending(_))
        ),
        "Bob should be in Conversation::Pending after processing only the genesis"
    );

    // Bob (in Pending mode) attempts to author an admin control action.
    let result = bob_engine.author_node(
        conv_id,
        Content::Control(ControlAction::SetTitle("Hacked by Observer".to_string())),
        vec![],
        &bob_store,
    );

    // With the current bug, author_node succeeds and emits WriteStore(_, _, true).
    // With the fix: the call should return Err or produce no verified WriteStore.
    let authored_admin = match &result {
        Ok(effects) => effects
            .iter()
            .any(|e| matches!(e, Effect::WriteStore(_, _, true))),
        Err(_) => false,
    };
    assert!(
        !authored_admin,
        "author_node must not produce a verified WriteStore for admin nodes when the \
         conversation is in Pending state; Identity-Pending devices must not author admin actions"
    );
}

// ── DelegationCertificate conversation_id scoping (speculative paths) ────

#[test]
fn test_anchor_snapshot_rejects_wrong_conv_id_cert() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([3u8; 32]);
    let wrong_conv_id = ConversationId::from([4u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "AnchorSnapshot ConvId Test");

    // Bob's engine: shallow sync (only genesis), so AnchorSnapshot uses speculative path.
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let bob_store = InMemoryStore::new();
    let effects = bob_engine
        .handle_node(conv_id, genesis_node.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    // Alice creates an AnchorSnapshot with ADMIN cert but scoped to WRONG conversation.
    let wrong_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        9_999_999,
        wrong_conv_id,
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
            cert: wrong_cert,
        },
        1,
        2,
        1000,
    );

    let effects = bob_engine
        .handle_node(conv_id, anchor_snapshot, &bob_store, None)
        .unwrap();

    let verified = effects
        .iter()
        .any(|e| matches!(e, Effect::WriteStore(_, _, true)));
    assert!(
        !verified,
        "AnchorSnapshot with cert scoped to a different conversation must be rejected"
    );
}

#[test]
fn test_soft_anchor_rejects_wrong_conv_id_cert() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([5u8; 32]);
    let wrong_conv_id = ConversationId::from([6u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "SoftAnchor ConvId Test");

    // Bob's engine: shallow sync (only genesis), so SoftAnchor uses speculative path.
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let bob_store = InMemoryStore::new();
    let effects = bob_engine
        .handle_node(conv_id, genesis_node.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    // Alice creates a SoftAnchor with MESSAGE cert scoped to WRONG conversation.
    let wrong_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::MESSAGE,
        9_999_999,
        wrong_conv_id,
    );
    let soft_anchor = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![genesis_node.hash()],
        ControlAction::SoftAnchor {
            basis_hash: genesis_node.hash(),
            cert: wrong_cert,
        },
        1,
        2,
        1000,
    );

    let effects = bob_engine
        .handle_node(conv_id, soft_anchor, &bob_store, None)
        .unwrap();

    let verified = effects
        .iter()
        .any(|e| matches!(e, Effect::WriteStore(_, _, true)));
    assert!(
        !verified,
        "SoftAnchor with cert scoped to a different conversation must be rejected"
    );
}
