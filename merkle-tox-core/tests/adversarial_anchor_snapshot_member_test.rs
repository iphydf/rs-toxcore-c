//! Adversarial: `AnchorSnapshot` speculative-trust path lets an admin
//! displace the founder anchor by injecting a role-0 member.
//!
//! ## Attack
//!
//! `AnchorSnapshot` is a bootstrap exception: when a peer joins late,
//! they may not have replayed the full admin chain. The speculative
//! branch at `engine/processor/verification.rs:832-864` accepts an
//! `AnchorSnapshot` whose `cert` verifies against
//! `IdentityManager::get_founder(conversation_id)` even when the
//! authoring device hasn't yet been authorized in the late-joiner's
//! view. `apply_side_effects` then unconditionally
//! `identity_manager.add_member(...)` for every entry in
//! `data.members` — including any role-0 entry the attacker chose to
//! list there.
//!
//! Combined with `get_founder`'s lex-smallest-LogicalIdentityPk
//! selection (`identity.rs:301-312`), an admin who picks an
//! attacker-controlled `LogicalIdentityPk` smaller than the real
//! founder's can supplant the founder slot. After that:
//! - `verify_delegation` for downstream AnchorSnapshots
//!   (`verification.rs:838`) and SoftAnchors (`verification.rs:869`)
//!   verifies against the attacker's key instead of the real
//!   founder's, granting full admin escalation against the
//!   late-joiner's view.
//! - `latest_anchor_hashes` is overwritten with the attacker's
//!   AnchorSnapshot hash.
//!
//! The same fix shape as the Genesis dedup applies: the founder
//! slot is closed once Genesis has set it. AnchorSnapshot may not
//! introduce a *new* role-0 logical PK; only `Genesis` is allowed
//! to assign role 0.
//!
//! Found in audit round 7 (design-level bootstrap-exception trust
//! audit).

use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ConversationId, ControlAction, LogicalIdentityPk, MemberInfo, Permissions, SnapshotData,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_genesis_pow, make_cert,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

/// §AS-1 — Speculative AnchorSnapshot must not introduce a *new*
/// role-0 logical_pk to a conversation that already has a founder.
/// Pre-fix the speculative branch admits any cert-validated
/// AnchorSnapshot and side_effects unconditionally inserts every
/// member of `data.members` into `identity_manager.logical_members`
/// — letting a (legitimately) admin-credentialed peer displace the
/// founder slot.
#[test]
fn test_anchor_snapshot_cannot_introduce_new_founder() {
    let _ = tracing_subscriber::fmt::try_init();

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new(); // legitimate founder
    let bob = TestIdentity::new(); // legitimate admin (cert from Alice)
    let conv_id = ConversationId::from([0xC1u8; 32]);
    let rng = StdRng::seed_from_u64(0xA5_A5);

    // Carol = late joiner. She's processed Genesis (knows Alice as
    // founder) but has NOT yet processed Bob's AuthorizeDevice node,
    // so Bob's AnchorSnapshot will arrive on the speculative path.
    let mut carol_engine = MerkleToxEngine::new(
        TestIdentity::new().device_pk,
        TestIdentity::new().master_pk,
        rng,
        tp,
    );
    let carol_store = InMemoryStore::new();
    let alice_genesis = create_genesis_pow(&conv_id, &alice, "Conv X");
    let alice_genesis_hash = alice_genesis.hash();
    let effects = carol_engine
        .handle_node(conv_id, alice_genesis.clone(), &carol_store, None)
        .expect("Alice's Genesis must verify");
    apply_effects(effects, &carol_store);

    assert_eq!(
        carol_engine.identity_manager.get_founder(&conv_id),
        Some(alice.master_pk),
        "Setup precondition: Carol knows Alice as founder",
    );

    // Bob has a real ADMIN cert from Alice (not yet revoked in
    // Carol's view, but the fix should not depend on that).
    let bob_cert = make_cert(
        &alice.master_sk,
        bob.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        i64::MAX, // far-future expiry
        conv_id,
    );

    // The exploit's lex-smaller "alt founder" key. We don't need
    // its secret key for this attack — the AnchorSnapshot is signed
    // by Bob's *device*; the role-0 member-list entry just claims
    // alt_logical exists. All-zero bytes guarantees it lex-precedes
    // any real Ed25519 PK.
    let alt_founder = LogicalIdentityPk::from([0u8; 32]);
    assert!(
        alt_founder < alice.master_pk,
        "alt_founder must be lex-smaller than Alice for the BTreeMap-based \
         get_founder selection to return alt_founder once added",
    );

    // Bob mints an AnchorSnapshot listing alt_founder with role=0.
    // The cert is real; data is the malicious payload.
    let bob_anchor = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![alice_genesis_hash],
        ControlAction::AnchorSnapshot {
            data: SnapshotData {
                basis_hash: alice_genesis_hash,
                members: tox_proto::BoundedVec::try_from_iter(vec![MemberInfo {
                    public_key: alt_founder,
                    role: 0, // <- the attack: claim role-0 founder slot
                    joined_at: 0,
                }])
                .expect("one member fits"),
                last_seq_numbers: tox_proto::BoundedVec::new(),
            },
            cert: bob_cert,
        },
        1,
        1,
        1000,
    );

    // Carol verifies Bob's AnchorSnapshot via the speculative path.
    let effects = carol_engine
        .handle_node(conv_id, bob_anchor, &carol_store, None)
        .expect("handle_node must not error on adversarial input");
    apply_effects(effects, &carol_store);

    // Post-fix assertions: Carol's founder pointer is unchanged, and
    // alt_founder was not registered as a role-0 member.
    assert_eq!(
        carol_engine.identity_manager.get_founder(&conv_id),
        Some(alice.master_pk),
        "After Bob's malicious AnchorSnapshot, get_founder must still \
         return Alice. Pre-fix: the speculative trust path admitted \
         the snapshot and side_effects inserted alt_founder with role=0; \
         BTreeMap iteration yields alt_founder (lex-smallest) and every \
         downstream verify_delegation for AnchorSnapshot/SoftAnchor \
         verifies against alt_founder's key — full admin escalation \
         against Carol's view."
    );

    // Belt-and-braces: alt_founder must not appear as a role-0
    // member at all. This catches a fix that protects get_founder's
    // return value but still pollutes the member list.
    let members = carol_engine.identity_manager.list_members(conv_id);
    let alt_founder_role: Option<u8> = members
        .iter()
        .find(|(pk, _, _)| *pk == alt_founder)
        .map(|(_, role, _)| *role);
    assert!(
        alt_founder_role.is_none() || alt_founder_role != Some(0),
        "alt_founder must not be registered with role=0. Observed: {:?}",
        alt_founder_role,
    );
}

/// §AS-2 — Honest baseline: an `AnchorSnapshot` whose `data.members`
/// contains ONLY non-role-0 entries (or an entry matching the
/// existing founder) must still be accepted. Without this guard the
/// fix could degenerate to "reject all AnchorSnapshot" and pass
/// §AS-1 trivially.
#[test]
fn test_anchor_snapshot_with_legitimate_members_still_accepted() {
    let _ = tracing_subscriber::fmt::try_init();

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let alice_logical = alice.master_pk;
    let conv_id = ConversationId::from([0xC2u8; 32]);
    let rng = StdRng::seed_from_u64(0xA5_A6);

    let mut carol_engine = MerkleToxEngine::new(
        TestIdentity::new().device_pk,
        TestIdentity::new().master_pk,
        rng,
        tp,
    );
    let carol_store = InMemoryStore::new();
    let alice_genesis = create_genesis_pow(&conv_id, &alice, "Conv Y");
    let alice_genesis_hash = alice_genesis.hash();
    let effects = carol_engine
        .handle_node(conv_id, alice_genesis, &carol_store, None)
        .unwrap();
    apply_effects(effects, &carol_store);

    let bob_cert = make_cert(
        &alice.master_sk,
        bob.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        i64::MAX,
        conv_id,
    );

    // Honest member list: Alice (existing role-0 founder, OK to
    // restate) plus a regular member with role=1.
    let regular_member = TestIdentity::new();
    let bob_anchor = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk,
        vec![alice_genesis_hash],
        ControlAction::AnchorSnapshot {
            data: SnapshotData {
                basis_hash: alice_genesis_hash,
                members: tox_proto::BoundedVec::try_from_iter(vec![
                    MemberInfo {
                        public_key: alice_logical,
                        role: 0,
                        joined_at: 1000,
                    },
                    MemberInfo {
                        public_key: regular_member.master_pk,
                        role: 1,
                        joined_at: 1500,
                    },
                ])
                .expect("two members fit"),
                last_seq_numbers: tox_proto::BoundedVec::new(),
            },
            cert: bob_cert,
        },
        1,
        1,
        1000,
    );

    let effects = carol_engine
        .handle_node(conv_id, bob_anchor, &carol_store, None)
        .expect("legitimate AnchorSnapshot must verify");
    apply_effects(effects, &carol_store);

    assert_eq!(
        carol_engine.identity_manager.get_founder(&conv_id),
        Some(alice_logical),
        "Founder still Alice (member list reaffirms her, no displacement)",
    );
}
