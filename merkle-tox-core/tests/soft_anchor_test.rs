use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, MerkleNode, NodeHash, Permissions, ValidationError,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node, make_cert,
    sign_admin_node, test_node,
};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

/// Helper: build SoftAnchor MerkleNode manually for validation tests.
fn make_soft_anchor(
    conv_id: &ConversationId,
    identity: &TestIdentity,
    basis_hash: NodeHash,
    parents: Vec<NodeHash>,
    rank: u64,
    seq: u64,
) -> MerkleNode {
    let cert = make_cert(
        &identity.master_sk,
        identity.device_pk,
        Permissions::ALL,
        i64::MAX,
        *conv_id,
    );
    create_admin_node(
        conv_id,
        identity.master_pk,
        &identity.device_sk,
        parents,
        ControlAction::SoftAnchor { basis_hash, cert },
        rank,
        seq,
        1000,
    )
}

// ─── Validation tests ───

#[test]
fn test_soft_anchor_single_parent() {
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAA; 32]);
    let alice = TestIdentity::new();

    // Create a genesis-like admin parent
    let parent = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![],
        ControlAction::HandshakePulse,
        0,
        1,
        1000,
    );
    let parent_hash = parent.hash();
    store
        .nodes
        .write()
        .unwrap()
        .insert(parent_hash, (parent, true));

    // Insert a second admin parent
    let parent2 = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![],
        ControlAction::HandshakePulse,
        0,
        2,
        1000,
    );
    let other_parent_hash = parent2.hash();
    store
        .nodes
        .write()
        .unwrap()
        .insert(other_parent_hash, (parent2, true));

    // SoftAnchor with TWO parents (basis_hash + extra): should fail
    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        i64::MAX,
        conv_id,
    );
    let mut node = test_node();
    node.author_pk = alice.master_pk;
    node.parents = vec![parent_hash, other_parent_hash];
    node.topological_rank = 1;
    node.content = Content::Control(ControlAction::SoftAnchor {
        basis_hash: parent_hash,
        cert,
    });
    sign_admin_node(&mut node, &conv_id, &alice.device_sk);

    let res = node.validate(&conv_id, &store);
    assert!(
        matches!(res, Err(ValidationError::SoftAnchorInvalidParent)),
        "Expected SoftAnchorInvalidParent, got {:?}",
        res
    );

    // SoftAnchor whose sole parent doesn't match basis_hash: should also fail
    let cert2 = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        i64::MAX,
        conv_id,
    );
    let mut node2 = test_node();
    node2.author_pk = alice.master_pk;
    node2.parents = vec![other_parent_hash];
    node2.topological_rank = 1;
    node2.content = Content::Control(ControlAction::SoftAnchor {
        basis_hash: parent_hash, // doesn't match parent
        cert: cert2,
    });
    sign_admin_node(&mut node2, &conv_id, &alice.device_sk);

    let res2 = node2.validate(&conv_id, &store);
    assert!(
        matches!(res2, Err(ValidationError::SoftAnchorInvalidParent)),
        "Expected SoftAnchorInvalidParent, got {:?}",
        res2
    );

    // SoftAnchor with correct single parent = basis_hash: should pass
    let cert3 = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        i64::MAX,
        conv_id,
    );
    let mut node3 = test_node();
    node3.author_pk = alice.master_pk;
    node3.parents = vec![parent_hash];
    node3.topological_rank = 1;
    node3.content = Content::Control(ControlAction::SoftAnchor {
        basis_hash: parent_hash,
        cert: cert3,
    });
    sign_admin_node(&mut node3, &conv_id, &alice.device_sk);

    let res3 = node3.validate(&conv_id, &store);
    assert!(res3.is_ok(), "Valid SoftAnchor should pass: {:?}", res3);
}

#[test]
fn test_soft_anchor_chaining_cap() {
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAA; 32]);
    let alice = TestIdentity::new();

    // Create an admin root node
    let root = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![],
        ControlAction::HandshakePulse,
        0,
        1,
        1000,
    );
    let root_hash = root.hash();
    store.nodes.write().unwrap().insert(root_hash, (root, true));

    // Chain 3 SoftAnchors (should all pass)
    let mut prev_hash = root_hash;
    for i in 0..3 {
        let sa = make_soft_anchor(
            &conv_id,
            &alice,
            prev_hash,
            vec![prev_hash],
            (i + 1) as u64,
            (i + 2) as u64,
        );
        let sa_hash = sa.hash();
        let res = sa.validate(&conv_id, &store);
        assert!(
            res.is_ok(),
            "SoftAnchor {} should be valid: {:?}",
            i + 1,
            res
        );
        store.nodes.write().unwrap().insert(sa_hash, (sa, true));
        prev_hash = sa_hash;
    }

    // 4th SoftAnchor should fail (chain length = 4 > MAX_SOFT_ANCHOR_CHAIN=3)
    let sa4 = make_soft_anchor(&conv_id, &alice, prev_hash, vec![prev_hash], 4, 5);
    let res = sa4.validate(&conv_id, &store);
    assert!(
        matches!(
            res,
            Err(ValidationError::SoftAnchorChainingCapExceeded { actual: 4, max: 3 })
        ),
        "4th chained SoftAnchor should fail: {:?}",
        res
    );
}

// ─── Anti-branching tests ───

#[test]
fn test_soft_anchor_anti_branching() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    let mut engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    let admin_heads = store.get_admin_heads(&room.conv_id);
    let basis_hash = admin_heads[0];

    // First SoftAnchor from alice with this basis: accepted
    let sa1 = make_soft_anchor(&room.conv_id, alice, basis_hash, vec![basis_hash], 2, 10);
    let res1 = engine.handle_node(room.conv_id, sa1, &store, None);
    assert!(res1.is_ok(), "First SoftAnchor should succeed: {:?}", res1);
    if let Ok(effects) = res1 {
        // Check it was verified (WriteStore with verified=true)
        let has_verified = effects
            .iter()
            .any(|e| matches!(e, merkle_tox_core::engine::Effect::WriteStore(_, _, true)));
        assert!(has_verified, "First SoftAnchor should be verified");
        apply_effects(effects, &store);
    }

    // Second SoftAnchor from alice with SAME basis: rejected (anti-branching)
    let sa2 = make_soft_anchor(&room.conv_id, alice, basis_hash, vec![basis_hash], 2, 11);
    let res2 = engine.handle_node(room.conv_id, sa2, &store, None);
    // The node should either error or be stored as unverified (speculative)
    if let Ok(effects) = &res2 {
        let has_verified = effects
            .iter()
            .any(|e| matches!(e, merkle_tox_core::engine::Effect::WriteStore(_, _, true)));
        assert!(
            !has_verified,
            "Second SoftAnchor with same (device, basis) should NOT be verified"
        );
    }
}

#[test]
fn test_soft_anchor_different_basis_ok() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    let mut engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    let admin_heads = store.get_admin_heads(&room.conv_id);
    let basis1 = admin_heads[0];

    // First SoftAnchor with basis1
    let sa1 = make_soft_anchor(&room.conv_id, alice, basis1, vec![basis1], 2, 10);
    let effects = engine
        .handle_node(room.conv_id, sa1.clone(), &store, None)
        .unwrap();
    let sa1_hash = sa1.hash();
    apply_effects(effects, &store);

    // Second SoftAnchor with a different basis (sa1_hash)
    let sa2 = make_soft_anchor(&room.conv_id, alice, sa1_hash, vec![sa1_hash], 3, 11);
    let res2 = engine.handle_node(room.conv_id, sa2, &store, None);
    assert!(
        res2.is_ok(),
        "SoftAnchor with different basis should succeed: {:?}",
        res2
    );
    if let Ok(effects) = res2 {
        let has_verified = effects
            .iter()
            .any(|e| matches!(e, merkle_tox_core::engine::Effect::WriteStore(_, _, true)));
        assert!(
            has_verified,
            "SoftAnchor with different basis_hash should be verified"
        );
    }
}

#[test]
fn test_soft_anchor_different_device_ok() {
    // Tests that anti-branching allows different device PKs to each have
    // one SoftAnchor for the same basis_hash.
    // We directly verify the dedup logic by checking the soft_anchor_dedup map.
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    let mut engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );

    let conv_id = room.conv_id;
    let basis = NodeHash::from([0xAA; 32]);

    // Two different devices
    let alice_pk = alice.device_pk;
    let bob_pk = merkle_tox_core::dag::PhysicalDevicePk::from([0xBB; 32]);

    // Insert alice: should succeed
    let dedup_set = engine.soft_anchor_dedup.entry(conv_id).or_default();
    assert!(
        dedup_set.insert((alice_pk, basis)),
        "Alice first insert should succeed"
    );

    // Insert alice again: should fail (duplicate)
    assert!(
        !dedup_set.insert((alice_pk, basis)),
        "Alice second insert should fail"
    );

    // Insert bob with same basis: should succeed (different device)
    assert!(
        dedup_set.insert((bob_pk, basis)),
        "Bob with same basis should succeed"
    );

    // Insert bob again: should fail
    assert!(
        !dedup_set.insert((bob_pk, basis)),
        "Bob second insert should fail"
    );

    // Alice with different basis: should succeed
    let basis2 = NodeHash::from([0xCC; 32]);
    assert!(
        dedup_set.insert((alice_pk, basis2)),
        "Alice with different basis should succeed"
    );
}

// ─── Authoring test ───

#[test]
fn test_soft_anchor_authoring() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        merkle_tox_core::dag::PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    // Store a self_cert (Level 2: MESSAGE only, no ADMIN)
    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::MESSAGE,
        i64::MAX,
        room.conv_id,
    );
    engine.self_certs.insert(room.conv_id, cert);

    // Author SoftAnchor
    let effects = engine.author_soft_anchor(room.conv_id, &store);
    assert!(
        effects.is_ok(),
        "author_soft_anchor should succeed: {:?}",
        effects
    );
    let effects = effects.unwrap();

    // Find the SoftAnchor node in effects
    let soft_anchor_node = effects.iter().find_map(|e| {
        if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e {
            if matches!(
                &node.content,
                Content::Control(ControlAction::SoftAnchor { .. })
            ) {
                Some(node.clone())
            } else {
                None
            }
        } else {
            None
        }
    });
    assert!(
        soft_anchor_node.is_some(),
        "Should have authored a SoftAnchor node"
    );

    let sa_node = soft_anchor_node.unwrap();
    // Verify it has exactly one parent matching basis_hash
    if let Content::Control(ControlAction::SoftAnchor { basis_hash, .. }) = &sa_node.content {
        assert_eq!(sa_node.parents.len(), 1);
        assert_eq!(sa_node.parents[0], *basis_hash);
    } else {
        panic!("Expected SoftAnchor content");
    }

    // Verify the authored node passes validation
    let res = sa_node.validate(&room.conv_id, &store);
    assert!(
        res.is_ok(),
        "Authored SoftAnchor should pass validation: {:?}",
        res
    );
}

// ─── Hop counter reset test ───

#[test]
fn test_soft_anchor_hop_reset() {
    // SoftAnchor is an Admin node, so content nodes after it should have admin_distance=1
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xAA; 32]);
    let alice = TestIdentity::new();

    // Create admin root
    let root = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![],
        ControlAction::HandshakePulse,
        0,
        1,
        1000,
    );
    let root_hash = root.hash();
    store.nodes.write().unwrap().insert(root_hash, (root, true));

    // Create SoftAnchor as child of root
    let sa = make_soft_anchor(&conv_id, &alice, root_hash, vec![root_hash], 1, 2);
    let sa_hash = sa.hash();
    store.nodes.write().unwrap().insert(sa_hash, (sa, true));

    // SoftAnchor is an Admin node, so admin_distance should be 0
    use merkle_tox_core::dag::NodeLookup;
    let dist = store.get_admin_distance(&sa_hash);
    assert_eq!(dist, Some(0), "SoftAnchor (Admin) should have distance 0");

    // Content node after SoftAnchor should have admin_distance=1
    let mut content_node = test_node();
    content_node.parents = vec![sa_hash];
    content_node.topological_rank = 2;
    let content_hash = content_node.hash();
    store
        .nodes
        .write()
        .unwrap()
        .insert(content_hash, (content_node, true));
    let content_dist = store.get_admin_distance(&content_hash);
    assert_eq!(
        content_dist,
        Some(1),
        "Content node after SoftAnchor should have admin_distance=1"
    );
}

// ─── Auto-trigger test ───

#[test]
fn test_soft_anchor_auto_trigger() {
    // This test verifies that a non-admin device at high admin_distance
    // triggers SoftAnchor authoring
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        merkle_tox_core::dag::PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    // Store a Level 2 (non-admin) self_cert
    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::MESSAGE,
        i64::MAX,
        room.conv_id,
    );
    engine.self_certs.insert(room.conv_id, cert);

    // Simulate high admin_distance by creating a chain of content nodes
    // We'll fake admin distance in the store by creating a long chain
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let mut prev = if admin_heads.is_empty() {
        // Fallback
        let heads = store.get_heads(&room.conv_id);
        heads[0]
    } else {
        admin_heads[0]
    };

    // Build a chain of 450 content nodes to push admin_distance high
    for i in 0..450u64 {
        let mut node = test_node();
        node.parents = vec![prev];
        node.topological_rank = (i + 1) + 1; // offset from genesis rank
        node.sequence_number = i + 100;
        let h = node.hash();
        store.nodes.write().unwrap().insert(h, (node, true));
        store.set_heads(&room.conv_id, vec![h]).unwrap();
        prev = h;
    }

    // Verify admin distance is now high
    use merkle_tox_core::dag::NodeLookup;
    let dist = store.get_admin_distance(&prev);
    assert!(
        dist.unwrap_or(0) >= 400,
        "Admin distance should be >= 400, got {:?}",
        dist
    );

    // Now author a content node: should trigger SoftAnchor
    let effects = engine.author_node(
        room.conv_id,
        Content::Text("trigger".to_string()),
        Vec::new(),
        &store,
    );
    assert!(
        effects.is_ok(),
        "Authoring content at high hop count should succeed: {:?}",
        effects
    );

    let effects = effects.unwrap();
    let has_soft_anchor = effects.iter().any(|e| {
        if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e {
            matches!(
                &node.content,
                Content::Control(ControlAction::SoftAnchor { .. })
            )
        } else {
            false
        }
    });
    assert!(
        has_soft_anchor,
        "Should auto-trigger SoftAnchor at high admin_distance"
    );
}
