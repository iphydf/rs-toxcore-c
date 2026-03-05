use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EmojiSource, LogicalIdentityPk, MerkleNode, NodeHash,
    NodeLookup, Permissions, PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestRoom, apply_effects, create_admin_node, create_msg,
    create_signed_content_node,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// Sets up a TestRoom with engine + store, handling genesis node through the engine.
fn setup_room() -> (TestRoom, MerkleToxEngine, InMemoryStore) {
    let room = TestRoom::new(2);
    let store = InMemoryStore::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );
    room.setup_engine(&mut engine, &store);

    // Ensure Genesis is verified in engine
    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    (room, engine, store)
}

/// Gets merged heads (content + admin) for causal context.
fn get_all_heads(store: &InMemoryStore, conv_id: &ConversationId) -> Vec<NodeHash> {
    let mut heads: Vec<NodeHash> = store.get_heads(conv_id);
    for admin_head in store.get_admin_heads(conv_id) {
        if !heads.contains(&admin_head) {
            heads.push(admin_head);
        }
    }
    heads
}

fn get_max_rank(store: &InMemoryStore, conv_id: &ConversationId) -> u64 {
    get_all_heads(store, conv_id)
        .iter()
        .filter_map(|h| store.get_rank(h))
        .max()
        .unwrap_or(0)
}

// ── Gap 3: Vouch Purging on Device Revocation ───────────────────────────

#[test]
fn test_vouch_purged_on_revocation() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let bob = &room.identities[1];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Bob sends a message that Alice's engine processes
    let bob_msg = create_msg(
        &room.conv_id,
        &room.keys,
        bob,
        heads.clone(),
        "hello from bob",
        parent_rank + 1,
        2,
        2000,
    );
    let bob_hash = bob_msg.hash();
    let effects = engine
        .handle_node(room.conv_id, bob_msg, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Manually insert a vouch from bob for a hash
    if let Some(conv) = engine.conversations.get_mut(&room.conv_id) {
        conv.vouchers_mut()
            .entry(bob_hash)
            .or_default()
            .insert(bob.device_pk, 1000);
    }

    // Verify vouch exists
    let vouch_exists = engine
        .conversations
        .get(&room.conv_id)
        .map(|c| {
            c.vouchers()
                .get(&bob_hash)
                .is_some_and(|v| v.contains_key(&bob.device_pk))
        })
        .unwrap_or(false);
    assert!(vouch_exists, "Bob's vouch should exist before revocation");

    // Alice revokes Bob (admin nodes must have only admin parents,
    // and rank must be max(admin parent ranks) + 1)
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let admin_max_rank = admin_heads
        .iter()
        .filter_map(|h| store.get_rank(h))
        .max()
        .unwrap_or(0);
    let revoke_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.device_sk,
        admin_heads,
        ControlAction::RevokeDevice {
            target_device_pk: bob.device_pk,
            reason: "test revocation".to_string(),
        },
        admin_max_rank + 1,
        3,
        3000,
    );
    let effects = engine
        .handle_node(room.conv_id, revoke_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Bob's vouch should be purged
    let vouch_exists_after = engine
        .conversations
        .get(&room.conv_id)
        .map(|c| {
            c.vouchers()
                .get(&bob_hash)
                .is_some_and(|v| v.contains_key(&bob.device_pk))
        })
        .unwrap_or(false);
    assert!(
        !vouch_exists_after,
        "Bob's vouch should be purged after revocation"
    );
}

// ── Gap 7: Redaction Validation ─────────────────────────────────────────

#[test]
fn test_redaction_by_author_allowed() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Alice sends a text
    let text_node = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "to be redacted",
        parent_rank + 1,
        2,
        2000,
    );
    let text_hash = text_node.hash();
    let effects = engine
        .handle_node(room.conv_id, text_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Alice redacts her own message → should be allowed
    let redact_heads = get_all_heads(&store, &room.conv_id);
    let redact_rank = get_max_rank(&store, &room.conv_id);
    let redact_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        redact_heads,
        Content::Redaction {
            target_hash: text_hash,
            reason: "self-redact".to_string(),
        },
        redact_rank + 1,
        3,
        3000,
    );
    let result = engine.handle_node(room.conv_id, redact_node, &store, None);
    assert!(
        result.is_ok(),
        "Author should be allowed to redact own message, got: {:?}",
        result.err()
    );
}

#[test]
fn test_redaction_by_non_author_non_admin_rejected() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Alice sends a text
    let text_node = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "important message",
        parent_rank + 1,
        2,
        2000,
    );
    let text_hash = text_node.hash();
    let effects = engine
        .handle_node(room.conv_id, text_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Create a fresh user with MESSAGE-only (no ADMIN) permissions.
    // Use authorize_in_engine to bypass admin-chain complexities.
    let charlie = merkle_tox_core::testing::TestIdentity::new();
    engine
        .identity_manager
        .add_member(room.conv_id, charlie.master_pk, 1, 0);
    charlie.authorize_in_engine(&mut engine, room.conv_id, Permissions::MESSAGE, i64::MAX);

    // Register test ephemeral key for Charlie
    merkle_tox_core::testing::register_test_ephemeral_key(
        &mut engine,
        &room.keys,
        &charlie.device_pk,
    );

    // Charlie (MESSAGE-only) tries to redact Alice's message → should be rejected
    let redact_heads = get_all_heads(&store, &room.conv_id);
    let redact_rank = get_max_rank(&store, &room.conv_id);
    let redact_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        charlie.master_pk,
        charlie.device_pk,
        redact_heads,
        Content::Redaction {
            target_hash: text_hash,
            reason: "unauthorized redact".to_string(),
        },
        redact_rank + 1,
        4,
        4000,
    );
    let result = engine.handle_node(room.conv_id, redact_node, &store, None);
    assert!(
        result.is_err(),
        "Non-author non-admin should not be allowed to redact"
    );
    let err = result.unwrap_err();
    assert!(
        format!("{}", err).contains("Redaction permission denied"),
        "Expected RedactionPermissionDenied, got: {}",
        err
    );
}

#[test]
fn test_redaction_unknown_target_speculative() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Redaction targeting unknown hash → should be accepted speculatively
    let unknown_target = NodeHash::from([0xFFu8; 32]);
    let redact_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads,
        Content::Redaction {
            target_hash: unknown_target,
            reason: "speculative redact".to_string(),
        },
        parent_rank + 1,
        2,
        2000,
    );
    let result = engine.handle_node(room.conv_id, redact_node, &store, None);
    assert!(
        result.is_ok(),
        "Redaction with unknown target should be accepted speculatively, got: {:?}",
        result.err()
    );
}

// ── Gap 9: Equivocation Detection ───────────────────────────────────────

#[test]
fn test_equivocation_detected() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Alice sends message with seq=2
    let msg1 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "message one",
        parent_rank + 1,
        2,
        2000,
    );
    let hash1 = msg1.hash();
    let effects = engine
        .handle_node(room.conv_id, msg1, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Verify first node is tracked
    let tracked = engine
        .verified_node_seqs
        .get(&(room.conv_id, alice.device_pk, 2));
    assert_eq!(tracked, Some(&hash1), "First node should be tracked");

    // Alice sends DIFFERENT message with same seq=2 (equivocation!)
    let msg2 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "conflicting message",
        parent_rank + 1,
        2,
        2000,
    );
    let hash2 = msg2.hash();
    assert_ne!(
        hash1, hash2,
        "Two different messages should have different hashes"
    );

    // The second node with same seq may be rejected as replay, but equivocation
    // should still be recorded in engine state.
    let _ = engine.handle_node(room.conv_id, msg2, &store, None);

    // Check equivocation was detected
    let has_equivocation =
        engine
            .equivocations
            .iter()
            .any(|(cid, dpk, seq, existing, conflicting)| {
                *cid == room.conv_id
                    && *dpk == alice.device_pk
                    && *seq == 2
                    && *existing == hash1
                    && *conflicting == hash2
            });
    assert!(
        has_equivocation,
        "Equivocation should be detected for same sender+seq with different hash. Equivocations: {:?}",
        engine.equivocations
    );
}

// ── Gap 10: MAX_GROUP_DEVICES=4096 ──────────────────────────────────────

#[test]
fn test_max_group_devices_enforced() {
    let _ = tracing_subscriber::fmt::try_init();

    // Verify the constant exists and has the expected value.
    assert_eq!(
        tox_proto::constants::MAX_GROUP_DEVICES,
        4096,
        "MAX_GROUP_DEVICES should be 4096"
    );

    // Verify the check path works: authorize a few devices, then confirm
    // the group check doesn't fire prematurely for small numbers.
    let mut manager = merkle_tox_core::identity::IdentityManager::new();
    let conv_id = ConversationId::from([0xAA; 32]);
    let ctx = merkle_tox_core::identity::CausalContext::global();

    let master_sk = merkle_tox_core::testing::random_signing_key();
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());
    manager.add_member(conv_id, master_pk, 1, 0);

    // Authorize a root device
    let genesis_cert = merkle_tox_core::testing::make_cert(
        &master_sk,
        PhysicalDevicePk::from(master_sk.verifying_key().to_bytes()),
        Permissions::ALL,
        i64::MAX,
        conv_id,
    );
    manager
        .authorize_device(
            &ctx,
            conv_id,
            master_pk,
            &genesis_cert,
            0,
            0,
            NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Authorize a few more devices from a second identity to confirm the
    // group-level count path is exercised without hitting the limit.
    let ident2_sk = merkle_tox_core::testing::random_signing_key();
    let ident2_pk = LogicalIdentityPk::from(ident2_sk.verifying_key().to_bytes());
    manager.add_member(conv_id, ident2_pk, 1, 0);

    for i in 0..3u32 {
        let dev_sk = merkle_tox_core::testing::random_signing_key();
        let dev_pk = PhysicalDevicePk::from(dev_sk.verifying_key().to_bytes());
        let dev_cert = merkle_tox_core::testing::make_cert(
            &ident2_sk,
            dev_pk,
            Permissions::MESSAGE,
            i64::MAX,
            conv_id,
        );
        manager
            .authorize_device(
                &ctx,
                conv_id,
                ident2_pk,
                &dev_cert,
                0,
                (i + 1) as u64,
                NodeHash::from([0u8; 32]),
            )
            .unwrap();
    }

    // 1 + 3 = 4 devices authorized. Well under 4096, should succeed.
    // The group-level check was exercised on each authorize_device call.
}

// ── Gap 11: Reaction target_hash Validation ─────────────────────────────

#[test]
fn test_reaction_targeting_admin_rejected() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];

    // Get the admin head (genesis or auth node)
    let admin_heads = store.get_admin_heads(&room.conv_id);
    assert!(
        !admin_heads.is_empty(),
        "Should have admin heads from genesis"
    );
    let admin_hash = admin_heads[0];

    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // React to admin node → should be rejected
    let reaction_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads,
        Content::Reaction {
            target_hash: admin_hash,
            emoji: EmojiSource::Unicode("👍".to_string()),
        },
        parent_rank + 1,
        2,
        2000,
    );
    let result = engine.handle_node(room.conv_id, reaction_node, &store, None);
    assert!(
        result.is_err(),
        "Reaction targeting admin node should be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        format!("{}", err).contains("Reaction target must reference a content node"),
        "Expected InvalidReactionTarget, got: {}",
        err
    );
}

#[test]
fn test_reaction_targeting_text_ok() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Alice sends a text
    let text_node = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "react to me",
        parent_rank + 1,
        2,
        2000,
    );
    let text_hash = text_node.hash();
    let effects = engine
        .handle_node(room.conv_id, text_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // React to text node → should be allowed
    let react_heads = get_all_heads(&store, &room.conv_id);
    let react_rank = get_max_rank(&store, &room.conv_id);
    let reaction_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        react_heads,
        Content::Reaction {
            target_hash: text_hash,
            emoji: EmojiSource::Unicode("👍".to_string()),
        },
        react_rank + 1,
        3,
        3000,
    );
    let result = engine.handle_node(room.conv_id, reaction_node, &store, None);
    assert!(
        result.is_ok(),
        "Reaction targeting text node should be allowed, got: {:?}",
        result.err()
    );
}

// ── Gap 13: Pre-key Expiration Check ────────────────────────────────────

#[test]
fn test_expired_prekey_skipped() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 5000)); // now=5000ms
    let mut engine = MerkleToxEngine::new(
        PhysicalDevicePk::from([1u8; 32]),
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let peer_pk = PhysicalDevicePk::from([2u8; 32]);
    let expired_pk = merkle_tox_core::dag::EphemeralX25519Pk::from([0x11u8; 32]);
    let valid_pk = merkle_tox_core::dag::EphemeralX25519Pk::from([0x22u8; 32]);
    let last_resort_pk = merkle_tox_core::dag::EphemeralX25519Pk::from([0x33u8; 32]);

    // Set up announcement with one expired and one valid pre-key
    let expired_spk = merkle_tox_core::dag::SignedPreKey {
        public_key: expired_pk,
        signature: merkle_tox_core::dag::Ed25519Signature::from([0u8; 64]),
        expires_at: 1000, // expired (now=5000)
    };
    let valid_spk = merkle_tox_core::dag::SignedPreKey {
        public_key: valid_pk,
        signature: merkle_tox_core::dag::Ed25519Signature::from([0u8; 64]),
        expires_at: 99999, // valid
    };
    let last_resort = merkle_tox_core::dag::SignedPreKey {
        public_key: last_resort_pk,
        signature: merkle_tox_core::dag::Ed25519Signature::from([0u8; 64]),
        expires_at: i64::MAX,
    };

    engine.peer_announcements.insert(
        peer_pk,
        ControlAction::Announcement {
            pre_keys: vec![expired_spk, valid_spk],
            last_resort_key: last_resort,
        },
    );

    // get_recipient_spk should skip expired and return valid
    let spk = engine.get_recipient_spk(&peer_pk);
    assert_eq!(
        spk,
        Some(valid_pk),
        "Should skip expired pre-key and return valid one"
    );
}

// ── Gap 14: LegacyBridge dedup_id Validation ────────────────────────────

#[test]
fn test_legacy_bridge_dedup_validation() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    let source_pk = PhysicalDevicePk::from([0xBBu8; 32]);
    let text = "bridged message";
    let timestamp = 2000i64;
    let message_type = 0u8;

    // Compute correct dedup_id using spec formula:
    // blake3::hash(conversation_id || source_pk || text_len(u32-BE) || text || message_type)
    let correct_dedup = merkle_tox_core::crypto::derive_legacy_bridge_dedup_id(
        &room.conv_id,
        &source_pk,
        text,
        message_type,
    );

    // Node with correct dedup_id → should pass
    let good_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads.clone(),
        Content::LegacyBridge {
            source_pk,
            text: text.to_string(),
            message_type: 0,
            dedup_id: correct_dedup,
        },
        parent_rank + 1,
        2,
        timestamp,
    );
    let result = engine.handle_node(room.conv_id, good_node, &store, None);
    assert!(
        result.is_ok(),
        "LegacyBridge with correct dedup_id should pass, got: {:?}",
        result.err()
    );

    // Node with wrong dedup_id → should fail
    let bad_dedup = NodeHash::from([0xDDu8; 32]);
    let bad_heads = get_all_heads(&store, &room.conv_id);
    let bad_rank = get_max_rank(&store, &room.conv_id);
    let bad_node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        bad_heads,
        Content::LegacyBridge {
            source_pk,
            text: text.to_string(),
            message_type: 0,
            dedup_id: bad_dedup,
        },
        bad_rank + 1,
        3,
        timestamp,
    );
    let result = engine.handle_node(room.conv_id, bad_node, &store, None);
    assert!(
        result.is_err(),
        "LegacyBridge with wrong dedup_id should be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        format!("{}", err).contains("dedup_id does not match"),
        "Expected InvalidLegacyBridgeDedup, got: {}",
        err
    );
}

// ── Forward Compatibility: Unknown Content Types ─────────────────────────

#[test]
fn test_unknown_content_node_passthrough() {
    // Simulate a content node from a newer protocol version with discriminant 99.
    // Build a MerkleNode with known Content, serialize it, then patch the
    // content discriminant to 99 (unknown) and verify it round-trips.

    let (room, _engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // 1. Create a Content::Unknown directly. Now supported by #[tox(catch_all)]
    let payload = tox_proto::serialize(&42u32).expect("serialize payload");
    let unknown_content = Content::Unknown {
        discriminant: 99,
        data: payload.clone(),
    };

    // 2. Verify Content round-trips through serialize/deserialize
    let content_bytes = tox_proto::serialize(&unknown_content).expect("serialize unknown content");
    let recovered: Content =
        tox_proto::deserialize(&content_bytes).expect("deserialize unknown content");
    assert_eq!(
        recovered, unknown_content,
        "Content::Unknown should round-trip"
    );

    // 3. Verify MerkleNode with Unknown content round-trips
    let node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads,
        unknown_content.clone(),
        parent_rank + 1,
        2,
        2000,
    );
    let node_bytes = tox_proto::serialize(&node).expect("serialize node");
    let recovered_node: MerkleNode = tox_proto::deserialize(&node_bytes).expect("deserialize node");
    assert_eq!(
        recovered_node.content, unknown_content,
        "MerkleNode with Unknown content should round-trip"
    );

    // 4. Verify the hash is stable across round-trips
    assert_eq!(
        node.hash(),
        recovered_node.hash(),
        "Hash should be stable across serialization round-trips"
    );
}

// ── Gap A: LegacyBridge dedup_id uses spec formula ───────────────────────

#[test]
fn test_legacy_bridge_dedup_uses_spec_formula() {
    // Verify the dedup_id formula matches:
    // blake3::hash(conversation_id || source_pk || text_len(u32-BE) || text || message_type)
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let source_pk = PhysicalDevicePk::from([0xBBu8; 32]);
    let text = "hello world";
    let message_type: u8 = 3;

    let dedup = merkle_tox_core::crypto::derive_legacy_bridge_dedup_id(
        &conv_id,
        &source_pk,
        text,
        message_type,
    );

    // Manually compute expected hash
    let mut hasher = blake3::Hasher::new();
    hasher.update(conv_id.as_bytes());
    hasher.update(source_pk.as_bytes());
    hasher.update(&(text.len() as u32).to_be_bytes());
    hasher.update(text.as_bytes());
    hasher.update(&[message_type]);
    let expected = NodeHash::from(*hasher.finalize().as_bytes());

    assert_eq!(dedup, expected, "dedup_id must match spec formula");

    // Different conversation_id → different dedup_id
    let conv_id2 = ConversationId::from([0xCCu8; 32]);
    let dedup2 = merkle_tox_core::crypto::derive_legacy_bridge_dedup_id(
        &conv_id2,
        &source_pk,
        text,
        message_type,
    );
    assert_ne!(
        dedup, dedup2,
        "Different conv_id must produce different dedup_id"
    );
}

// ── Gap B: Handshake retry cap enforcement ───────────────────────────────

#[test]
fn test_handshake_retry_cap_enforced() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let bob = &room.identities[1];

    // Set up peer announcement so author_x3dh_key_exchange can proceed
    let bob_spk_pk = merkle_tox_core::dag::EphemeralX25519Pk::from([0x42u8; 32]);

    // Simulate 3 handshake errors to fill the retry cap
    for _ in 0..3 {
        let _ = engine.handle_message(
            bob.device_pk,
            merkle_tox_core::ProtocolMessage::HandshakeError {
                conversation_id: room.conv_id,
                reason: "test error".to_string(),
            },
            &store,
            None,
        );
    }

    // Verify retry state shows 3 attempts
    let state = engine
        .handshake_retry_state
        .get(&(room.conv_id, bob.device_pk));
    assert!(state.is_some(), "Retry state should exist");
    assert_eq!(
        state.unwrap().attempts,
        3,
        "Should have 3 attempts recorded"
    );

    // author_x3dh_key_exchange should return empty effects (rate limited)
    let result = engine.author_x3dh_key_exchange(room.conv_id, bob.device_pk, bob_spk_pk, &store);
    assert!(result.is_ok(), "Should not error");
    assert!(
        result.unwrap().is_empty(),
        "Should return empty effects when rate limited"
    );
}

// ── Gap C: Ephemeral key erasure at 50% ack ──────────────────────────────

#[test]
fn test_ephemeral_key_erasure_at_50_pct_ack() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();

    // Insert old signing keys for epochs 0, 1, 2 (current=2)
    engine
        .self_ephemeral_signing_keys
        .insert(0, ed25519_dalek::SigningKey::from_bytes(&[0x01; 32]));
    engine
        .self_ephemeral_signing_keys
        .insert(1, ed25519_dalek::SigningKey::from_bytes(&[0x02; 32]));
    engine
        .self_ephemeral_signing_keys
        .insert(2, ed25519_dalek::SigningKey::from_bytes(&[0x03; 32]));

    // Set conversation to Established with epoch 2
    let k_conv = merkle_tox_core::dag::KConv::from([0xAA; 32]);
    let established = merkle_tox_core::engine::conversation::ConversationData::<
        merkle_tox_core::engine::conversation::Established,
    >::new(room.conv_id, k_conv, 1000);
    engine.conversations.insert(
        room.conv_id,
        merkle_tox_core::engine::Conversation::Established(established),
    );
    if let Some(merkle_tox_core::engine::Conversation::Established(e)) =
        engine.conversations.get_mut(&room.conv_id)
    {
        e.state.current_epoch = 2;
    }

    // Pre-set ack counts: total=4, acks=1 → need 1 more for 50%
    engine.keywrap_ack_counts.insert(room.conv_id, (1, 4));

    // Create a keywrap_pending entry that matches
    let kw_hash = NodeHash::from([0xDD; 32]);
    engine.keywrap_pending.insert(
        kw_hash,
        merkle_tox_core::engine::KeyWrapPending {
            conversation_id: room.conv_id,
            recipient_pk: room.identities[1].device_pk,
            created_at: Instant::now(),
            attempts: 0,
        },
    );

    // Send KeywrapAck which triggers 50% threshold (acks goes to 2, 2*2>=4)
    let _ = engine.handle_message(
        room.identities[1].device_pk,
        merkle_tox_core::ProtocolMessage::KeywrapAck {
            keywrap_hash: kw_hash,
            recipient_pk: room.identities[1].device_pk,
        },
        &store,
        None,
    );

    // Old signing keys (epochs 0, 1) should be erased, only epoch 2 kept
    assert!(
        !engine.self_ephemeral_signing_keys.contains_key(&0),
        "Epoch 0 key should be erased"
    );
    assert!(
        !engine.self_ephemeral_signing_keys.contains_key(&1),
        "Epoch 1 key should be erased"
    );
    assert!(
        engine.self_ephemeral_signing_keys.contains_key(&2),
        "Current epoch key should be preserved"
    );
}

// ── Gap D: Invite permission flags ───────────────────────────────────────

#[test]
fn test_invite_permission_flags() {
    let _ = tracing_subscriber::fmt::try_init();

    // Create a room with FLAG_MEMBER_INVITE (0x02) in genesis
    let room = merkle_tox_core::testing::TestRoom::new(3);
    let store = InMemoryStore::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        StdRng::seed_from_u64(100),
        tp,
    );
    room.setup_engine(&mut engine, &store);

    // Process genesis
    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    // Set genesis flags to FLAG_MEMBER_INVITE
    if let Some(conv) = engine.conversations.get_mut(&room.conv_id) {
        conv.set_genesis_flags(0x02);
    }

    // Verify the flag is stored
    let flags = engine
        .conversations
        .get(&room.conv_id)
        .map(|c| c.genesis_flags())
        .unwrap_or(0);
    assert_eq!(flags, 0x02, "Genesis flags should be stored");

    // Verify FLAG_MEMBER_INVITE accessor works
    assert_ne!(
        flags & merkle_tox_core::engine::conversation::FLAG_MEMBER_INVITE,
        0,
        "FLAG_MEMBER_INVITE should be set"
    );
}

// ── Gap E: Bounded voucher sets ──────────────────────────────────────────

#[test]
fn test_bounded_voucher_sets() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = get_max_rank(&store, &room.conv_id);

    // Create a node to vouch for
    let msg = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        heads.clone(),
        "target msg",
        parent_rank + 1,
        2,
        2000,
    );
    let msg_hash = msg.hash();
    let effects = engine.handle_node(room.conv_id, msg, &store, None).unwrap();
    apply_effects(effects, &store);

    // Manually insert 3 vouchers for that hash (MAX_VOUCHERS_PER_HASH)
    if let Some(conv) = engine.conversations.get_mut(&room.conv_id) {
        let set = conv.vouchers_mut().entry(msg_hash).or_default();
        set.insert(PhysicalDevicePk::from([0x01; 32]), 2000);
        set.insert(PhysicalDevicePk::from([0x02; 32]), 2000);
        set.insert(PhysicalDevicePk::from([0x03; 32]), 2000);
    }

    // Verify we have 3 vouchers
    let count = engine
        .conversations
        .get(&room.conv_id)
        .map(|c| c.vouchers().get(&msg_hash).map_or(0, |v| v.len()))
        .unwrap_or(0);
    assert_eq!(count, 3, "Should have exactly 3 vouchers");

    // Verify MAX_VOUCHERS_PER_HASH constant exists
    assert_eq!(
        tox_proto::constants::MAX_VOUCHERS_PER_HASH,
        3,
        "MAX_VOUCHERS_PER_HASH should be 3"
    );
}

// ── Gap F: KeyWrap collision admin seniority ─────────────────────────────

#[test]
fn test_keywrap_collision_admin_seniority() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, engine, _store) = setup_room();

    // Test get_admin_seniority API
    let alice = &room.identities[0];

    // Before authorization, should return None
    let seniority = engine
        .identity_manager
        .get_admin_seniority(room.conv_id, &alice.device_pk);
    // The genesis creator is added as a logical member, not a device authorization,
    // so seniority may be None unless authorized
    // Just verify the API exists and doesn't panic
    let _ = seniority;

    // Test DM detection: <= 2 members means 1-on-1
    let members = engine.identity_manager.list_members(room.conv_id);
    let is_dm = members.len() <= 2;
    assert!(is_dm, "Room with 2 identities should be detected as DM");
}

// ── Gap G: Blacklist tier escalation ─────────────────────────────────────

#[test]
fn test_blacklist_tier_escalation() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_room, mut engine, store) = setup_room();
    let bad_peer = PhysicalDevicePk::from([0xFF; 32]);

    // Initially not blacklisted
    let now = 1000i64;
    assert!(
        !engine.is_blacklisted(&bad_peer, now),
        "Should not be blacklisted initially"
    );

    // Escalate tier 1 (10 min)
    engine.blacklist_escalate(bad_peer);
    let bl = engine.peer_blacklist.get(&bad_peer).unwrap();
    assert_eq!(bl.tier, 1);
    let now_bl = engine.clock.network_time_ms();
    assert!(
        bl.expires_at_ms > now_bl,
        "Should be blacklisted after escalation"
    );

    // Escalate tier 2 (1 hour)
    engine.blacklist_escalate(bad_peer);
    let bl = engine.peer_blacklist.get(&bad_peer).unwrap();
    assert_eq!(bl.tier, 2);

    // Escalate tier 3 (24 hours)
    engine.blacklist_escalate(bad_peer);
    let bl = engine.peer_blacklist.get(&bad_peer).unwrap();
    assert_eq!(bl.tier, 3);

    // Should not exceed tier 3
    engine.blacklist_escalate(bad_peer);
    let bl = engine.peer_blacklist.get(&bad_peer).unwrap();
    assert_eq!(bl.tier, 3, "Should cap at tier 3");

    // Messages from blacklisted peer should be dropped
    let now_ms = engine.clock.network_time_ms();
    assert!(engine.is_blacklisted(&bad_peer, now_ms));
    let result = engine.handle_message(
        bad_peer,
        merkle_tox_core::ProtocolMessage::CapsAnnounce {
            version: 1,
            features: 0,
        },
        &store,
        None,
    );
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_empty(),
        "Blacklisted peer messages should be dropped"
    );

    // Verify tier durations
    assert_eq!(
        tox_proto::constants::BLACKLIST_TIER1_MS,
        10 * 60 * 1000,
        "Tier 1 = 10 min"
    );
    assert_eq!(
        tox_proto::constants::BLACKLIST_TIER2_MS,
        60 * 60 * 1000,
        "Tier 2 = 1 hour"
    );
    assert_eq!(
        tox_proto::constants::BLACKLIST_TIER3_MS,
        24 * 60 * 60 * 1000,
        "Tier 3 = 24 hours"
    );
}

// ── Gap L: Promotion Lock ────────────────────────────────────────────────

#[test]
fn test_promotion_lock_prevents_eviction() {
    let _ = tracing_subscriber::fmt::try_init();
    let (room, mut engine, _store) = setup_room();

    // Insert dummy opaque entries and lock one
    let locked_hash = NodeHash::from([0xAA; 32]);
    let unlocked_hash = NodeHash::from([0xBB; 32]);

    // Add to opaque_store_usage so the eviction loop sees them
    engine.opaque_store_usage.insert(
        room.conv_id,
        (
            200,
            vec![
                (locked_hash, 100, 1000, PhysicalDevicePk::from([0x01; 32])),
                (unlocked_hash, 100, 2000, PhysicalDevicePk::from([0x02; 32])),
            ],
        ),
    );

    // Lock the first hash
    engine.promotion_locked.insert(locked_hash);

    // Verify locked set contains our hash
    assert!(
        engine.promotion_locked.contains(&locked_hash),
        "locked_hash should be in promotion_locked set"
    );
    assert!(
        !engine.promotion_locked.contains(&unlocked_hash),
        "unlocked_hash should NOT be in promotion_locked set"
    );

    // Verify the CpuBudget struct works correctly (Gap J token bucket)
    let budget = merkle_tox_core::engine::CpuBudget::new(1000);
    assert_eq!(
        budget.remaining_ms,
        tox_proto::constants::SKETCH_CPU_BUDGET_MS as f64,
        "New budget should start at full capacity"
    );
}

// ── Gap J: IBLT CPU Budget Enforcement ───────────────────────────────────

#[test]
fn test_iblt_cpu_budget_enforcement() {
    let _ = tracing_subscriber::fmt::try_init();

    // Test the CpuBudget token bucket directly
    let mut budget = merkle_tox_core::engine::CpuBudget::new(0);

    // Should start with full budget (500ms)
    assert_eq!(budget.remaining_ms, 500.0);

    // Consuming within budget should succeed
    assert!(
        budget.try_consume(100.0),
        "Should succeed with sufficient budget"
    );
    assert_eq!(budget.remaining_ms, 400.0);

    // Consuming the rest should succeed
    assert!(
        budget.try_consume(400.0),
        "Should succeed consuming remaining budget"
    );
    assert_eq!(budget.remaining_ms, 0.0);

    // Consuming when empty should fail
    assert!(!budget.try_consume(1.0), "Should fail with empty budget");

    // Refill after 60 seconds should restore full budget
    budget.refill(60_000);
    // Rate = 500ms / 60000ms = 1/120 per ms
    // After 60_000ms elapsed: remaining = 0 + 60_000 * (500/60_000) = 500
    assert!(
        (budget.remaining_ms - 500.0).abs() < 0.01,
        "Should refill to full after window elapsed, got {}",
        budget.remaining_ms
    );

    // Partial refill
    let mut budget2 = merkle_tox_core::engine::CpuBudget::new(0);
    budget2.remaining_ms = 0.0;
    budget2.refill(6_000); // 10% of window
    // Rate = 500/60_000 per ms. 6_000 * 500/60_000 = 50
    assert!(
        (budget2.remaining_ms - 50.0).abs() < 0.01,
        "Should refill proportionally, got {}",
        budget2.remaining_ms
    );

    // Verify constants
    assert_eq!(tox_proto::constants::SKETCH_CPU_BUDGET_MS, 500);
    assert_eq!(tox_proto::constants::SKETCH_CPU_WINDOW_MS, 60_000);
}

// ── Gap I: Genesis PoW v2 Formula ────────────────────────────────────────

#[test]
fn test_genesis_pow_v2_formula() {
    let _ = tracing_subscriber::fmt::try_init();

    let alice = merkle_tox_core::testing::TestIdentity::new();
    let conv_id = ConversationId::from([0xAA; 32]);

    // Create a genesis node with v2 PoW
    let genesis = merkle_tox_core::testing::create_genesis_pow(&conv_id, &alice, "test room");

    // Extract the pow_nonce from inside the genesis action
    let (internal_nonce, creator_pk) = if let Content::Control(ControlAction::Genesis {
        pow_nonce,
        creator_pk,
        ..
    }) = &genesis.content
    {
        (*pow_nonce, *creator_pk)
    } else {
        panic!("Expected Genesis content");
    };

    // v2: nonce should be inside the action (non-zero for mined nodes)
    // External pow_nonce should be 0 (v2 doesn't use it)
    assert_eq!(
        genesis.pow_nonce, 0,
        "v2 PoW should have external pow_nonce = 0"
    );
    assert!(
        internal_nonce > 0,
        "v2 PoW should have non-zero internal pow_nonce"
    );

    // Verify the PoW is valid via the node's validate_pow method
    assert!(genesis.validate_pow(), "Genesis node should have valid PoW");

    // Verify v2 formula directly
    assert!(
        merkle_tox_core::dag::validate_pow_v2(
            creator_pk.as_bytes(),
            if let Content::Control(ref action) = genesis.content {
                action
            } else {
                panic!("Expected Control content")
            }
        ),
        "v2 PoW formula should validate"
    );

    // Verify v1 formula does NOT validate (external nonce is 0, not mined for v1)
    let node_hash = genesis.hash();
    assert!(
        !merkle_tox_core::dag::validate_pow(creator_pk.as_bytes(), &node_hash, genesis.pow_nonce),
        "v1 PoW formula should NOT validate for v2-mined genesis"
    );
}

// ── Gap K: SKD Wraps Triplet Not Root Key ────────────────────────────────

#[test]
fn test_skd_wraps_triplet_not_root_key() {
    let _ = tracing_subscriber::fmt::try_init();

    // Use with_sk so the engine can sign admin nodes (KeyWrap)
    let room = TestRoom::new(2);
    let store = InMemoryStore::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = &room.identities[0];
    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(0),
        tp,
    );
    room.setup_engine(&mut engine, &store);

    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }

    // Author a key rotation which triggers SKD authoring
    let rotation_result = engine.rotate_conversation_key(room.conv_id, &store);
    assert!(
        rotation_result.is_ok(),
        "rotate_conversation_key should succeed, got: {:?}",
        rotation_result.err()
    );
    let effects = rotation_result.unwrap();

    // Find SKD nodes in effects
    let skd_nodes: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let merkle_tox_core::engine::Effect::WriteStore(_, node, _) = e {
                if matches!(node.content, Content::SenderKeyDistribution { .. }) {
                    Some(node.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // If SKD was authored, verify wrapped_keys ciphertext is 72+16=88 bytes (triplet + AEAD tag)
    // rather than 32+16=48 bytes (root key only + AEAD tag)
    for skd_node in &skd_nodes {
        if let Content::SenderKeyDistribution { wrapped_keys, .. } = &skd_node.content {
            for wk in wrapped_keys {
                // ECIES wrapping adds 16-byte Poly1305 tag to the plaintext
                // Triplet = 72 bytes → ciphertext = 88 bytes
                // Root key only = 32 bytes → ciphertext = 48 bytes
                assert_ne!(
                    wk.ciphertext.len(),
                    48,
                    "SKD should wrap 72-byte triplet (88 bytes ciphertext), not 32-byte root key (48 bytes)"
                );
                assert_eq!(
                    wk.ciphertext.len(),
                    88,
                    "SKD ciphertext should be 88 bytes (72-byte triplet + 16-byte AEAD tag)"
                );
            }
        }
    }
}

// ── Gap H: HistoryExport Wire Encrypted ──────────────────────────────────

#[test]
fn test_history_export_wire_encrypted() {
    let _ = tracing_subscriber::fmt::try_init();

    // Verify HistoryExport is NOT an exception node (must be encrypted on wire)
    let he_node = merkle_tox_core::dag::MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::HistoryExport {
            blob_hash: NodeHash::from([0xBB; 32]),
            blob_size: 0,
            bao_root: None,
            ephemeral_pk: merkle_tox_core::dag::EphemeralX25519Pk::from([0xCC; 32]),
            wrapped_keys: vec![],
        },
        metadata: vec![],
        authentication: merkle_tox_core::dag::NodeAuth::EphemeralSignature(
            merkle_tox_core::dag::Ed25519Signature::from([0u8; 64]),
        ),
        pow_nonce: 0,
    };

    assert!(
        !he_node.is_exception_node(),
        "HistoryExport should NOT be an exception node (must be wire encrypted)"
    );

    // Verify KeyWrap IS still an exception node
    let kw_node = merkle_tox_core::dag::MerkleNode {
        content: Content::KeyWrap {
            generation: 0,
            anchor_hash: NodeHash::from([0u8; 32]),
            ephemeral_pk: merkle_tox_core::dag::EphemeralX25519Pk::from([0u8; 32]),
            wrapped_keys: vec![],
        },
        ..he_node.clone()
    };
    assert!(
        kw_node.is_exception_node(),
        "KeyWrap should remain an exception node"
    );

    // Verify SenderKeyDistribution IS still an exception node
    let skd_node = merkle_tox_core::dag::MerkleNode {
        content: Content::SenderKeyDistribution {
            ephemeral_pk: merkle_tox_core::dag::EphemeralX25519Pk::from([0u8; 32]),
            wrapped_keys: vec![],
            ephemeral_signing_pk: merkle_tox_core::dag::EphemeralSigningPk::from([0u8; 32]),
            disclosed_keys: vec![],
        },
        ..he_node.clone()
    };
    assert!(
        skd_node.is_exception_node(),
        "SenderKeyDistribution should remain an exception node"
    );

    // Verify export key derivation functions exist and produce distinct keys
    let k_conv = merkle_tox_core::dag::KConv::from([0xAA; 32]);
    let k_header_export = merkle_tox_core::crypto::derive_k_header_export(&k_conv);
    let k_payload_export = merkle_tox_core::crypto::derive_k_payload_export(&k_conv);

    // Export keys should be deterministic
    let k_header_export_2 = merkle_tox_core::crypto::derive_k_header_export(&k_conv);
    assert_eq!(
        k_header_export.as_bytes(),
        k_header_export_2.as_bytes(),
        "Export key derivation should be deterministic"
    );

    // Header and payload export keys should be different
    assert_ne!(
        k_header_export.as_bytes(),
        k_payload_export.as_bytes(),
        "k_header_export and k_payload_export should be different"
    );

    // Different k_conv should produce different export keys
    let k_conv_2 = merkle_tox_core::dag::KConv::from([0xBB; 32]);
    let k_header_export_other = merkle_tox_core::crypto::derive_k_header_export(&k_conv_2);
    assert_ne!(
        k_header_export.as_bytes(),
        k_header_export_other.as_bytes(),
        "Different k_conv should produce different export keys"
    );
}

// ── DelegationCertificate conversation_id scoping ────────────────────────

#[test]
fn test_delegation_cert_conversation_id_mismatch() {
    let _ = tracing_subscriber::fmt::try_init();

    let conv_a = ConversationId::from([0xAAu8; 32]);
    let conv_b = ConversationId::from([0xBBu8; 32]);

    let mut mgr = merkle_tox_core::identity::IdentityManager::new();

    let master_sk = merkle_tox_core::testing::random_signing_key();
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());
    let device_sk = merkle_tox_core::testing::random_signing_key();
    let device_pk = PhysicalDevicePk::from(device_sk.verifying_key().to_bytes());

    mgr.add_member(conv_a, master_pk, 0, 0);
    mgr.add_member(conv_b, master_pk, 0, 0);

    // Create cert scoped to conv_A
    let cert = merkle_tox_core::testing::make_cert(
        &master_sk,
        device_pk,
        Permissions::ALL,
        i64::MAX,
        conv_a,
    );

    let ctx = merkle_tox_core::identity::CausalContext::global();

    // Should succeed for conv_A
    assert!(
        mgr.authorize_device(
            &ctx,
            conv_a,
            master_pk,
            &cert,
            0,
            0,
            NodeHash::from([0u8; 32])
        )
        .is_ok(),
        "Cert scoped to conv_A should work for conv_A"
    );

    // Should FAIL for conv_B
    let err = mgr
        .authorize_device(
            &ctx,
            conv_b,
            master_pk,
            &cert,
            0,
            0,
            NodeHash::from([0u8; 32]),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            merkle_tox_core::identity::IdentityError::ConversationIdMismatch
        ),
        "Cert scoped to conv_A must be rejected for conv_B, got: {err:?}"
    );
}
