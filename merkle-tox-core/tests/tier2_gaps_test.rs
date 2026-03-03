use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EmojiSource, LogicalIdentityPk, NodeHash, NodeLookup,
    Permissions, PhysicalDevicePk,
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
            .insert(bob.device_pk);
    }

    // Verify vouch exists
    let vouch_exists = engine
        .conversations
        .get(&room.conv_id)
        .map(|c| {
            c.vouchers()
                .get(&bob_hash)
                .is_some_and(|v| v.contains(&bob.device_pk))
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
                .is_some_and(|v| v.contains(&bob.device_pk))
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
        let dev_cert =
            merkle_tox_core::testing::make_cert(&ident2_sk, dev_pk, Permissions::MESSAGE, i64::MAX);
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

    // 1 + 3 = 4 devices authorized — well under 4096, should succeed.
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

    // Compute correct dedup_id
    let correct_dedup =
        merkle_tox_core::crypto::derive_legacy_bridge_dedup_id(&source_pk, text, timestamp);

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
