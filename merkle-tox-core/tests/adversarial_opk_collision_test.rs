//! §3.8 OPK Collision History Erasure — Admin Seniority tie-breaker.
//!
//! When two admins author competing KeyWraps targeting the same OPK
//! (same `opk_id`), the collision must be resolved by Admin Seniority —
//! the admin with the lexicographically smaller `(auth_rank, auth_hash)`
//! tuple wins, regardless of arrival order. This prevents a malicious
//! admin from grinding an ephemeral key to win on demand and
//! retroactively orphan the senior admin's KeyWrap + its descendants.
//!
//! The collision resolution in `engine/processor/verification.rs` relies
//! on two primitives:
//!   - `identity_manager.list_members(conv).len() > 2` — selects the
//!     group tie-breaker branch (vs 1-on-1 sender_pk ordering).
//!   - `identity_manager.get_admin_seniority(conv, pk)` — returns the
//!     `(auth_rank, auth_hash)` tuple compared to decide the winner.
//!
//! These tests pin both primitives. A regression in either would let a
//! junior admin win a collision depending on arrival order, re-opening
//! the §3.8 attack surface.

use merkle_tox_core::dag::DelegationCertificate;
use merkle_tox_core::dag::{
    ConversationId, LogicalIdentityPk, NodeHash, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::identity::{CausalContext, IdentityManager};
use merkle_tox_core::testing::{TestIdentity, make_cert};

fn setup_manager(
    conv_id: ConversationId,
    alice: &TestIdentity,
    bob: &TestIdentity,
    charlie: &TestIdentity,
    alice_auth_hash: NodeHash,
    bob_auth_hash: NodeHash,
) -> IdentityManager {
    let mut mgr = IdentityManager::new();

    // Three members: alice, bob, charlie — group, not DM.
    mgr.add_member(conv_id, alice.master_pk, 1, 0);
    mgr.add_member(conv_id, bob.master_pk, 1, 0);
    mgr.add_member(conv_id, charlie.master_pk, 1, 0);

    // Founder authorization of alice as ADMIN at rank 0.
    let alice_cert: DelegationCertificate = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    let ctx = CausalContext::global();
    mgr.authorize_device(
        &ctx,
        conv_id,
        alice.master_pk,
        &alice_cert,
        0,
        0,
        alice_auth_hash,
    )
    .expect("alice founder auth");

    // Junior admin bob authorized by alice at rank 1.
    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    mgr.authorize_device(&ctx, conv_id, bob.master_pk, &bob_cert, 0, 1, bob_auth_hash)
        .expect("bob junior admin auth");

    // Charlie is a plain member (MESSAGE only).
    let charlie_cert = make_cert(
        &charlie.master_sk,
        charlie.device_pk,
        Permissions::MESSAGE,
        9_999_999,
        conv_id,
    );
    mgr.authorize_device(
        &ctx,
        conv_id,
        charlie.master_pk,
        &charlie_cert,
        0,
        2,
        NodeHash::from([0x33u8; 32]),
    )
    .expect("charlie member auth");

    mgr
}

/// Group detection: >2 logical members triggers the Admin Seniority
/// branch of OPK collision resolution, not the 1-on-1 sender_pk branch.
#[test]
fn test_group_tiebreaker_branch_selected_for_3plus_members() {
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let charlie = TestIdentity::new();
    let conv_id = ConversationId::from([0x17u8; 32]);

    let mgr = setup_manager(
        conv_id,
        &alice,
        &bob,
        &charlie,
        NodeHash::from([0x11u8; 32]),
        NodeHash::from([0x22u8; 32]),
    );

    assert!(
        mgr.list_members(conv_id).len() > 2,
        "OPK collision uses the group tie-breaker only when list_members() \
         > 2. A regression that collapsed this check to <=2 for a 3-member \
         group would re-enable the §3.8 grinding attack via the DM \
         sender_pk branch.",
    );
}

/// Admin seniority ordering is deterministic and rank-first: alice at
/// rank 0 must dominate bob at rank 1 regardless of which auth_hash
/// happens to be larger.
#[test]
fn test_admin_seniority_rank_dominates_hash() {
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let charlie = TestIdentity::new();
    let conv_id = ConversationId::from([0x18u8; 32]);

    // Give alice the *larger* hash so the rank check must override any
    // hash-first comparison. If anyone swaps the tuple order of
    // (auth_rank, auth_hash) in get_admin_seniority or the tie-breaker,
    // this assertion flips.
    let alice_hash = NodeHash::from([0xFFu8; 32]);
    let bob_hash = NodeHash::from([0x01u8; 32]);

    let mgr = setup_manager(conv_id, &alice, &bob, &charlie, alice_hash, bob_hash);

    let alice_sen = mgr
        .get_admin_seniority(conv_id, &alice.device_pk)
        .expect("alice seniority");
    let bob_sen = mgr
        .get_admin_seniority(conv_id, &bob.device_pk)
        .expect("bob seniority");

    assert!(
        alice_sen < bob_sen,
        "rank-0 admin must be senior to rank-1 admin regardless of \
         auth_hash. alice={:?} bob={:?}",
        alice_sen,
        bob_sen,
    );
}

/// At equal rank, the lexicographically smaller auth_hash wins. This is
/// the non-grindable tie-breaker from §3.8: an attacker cannot influence
/// another admin's historical auth_hash (set when the
/// AuthorizeDevice node landed in the DAG), so the winner is stable.
#[test]
fn test_admin_seniority_hash_breaks_rank_tie() {
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let charlie = TestIdentity::new();
    let conv_id = ConversationId::from([0x19u8; 32]);

    // Equal rank for alice and bob; alice has the smaller hash.
    let alice_hash = NodeHash::from([0x01u8; 32]);
    let bob_hash = NodeHash::from([0x02u8; 32]);

    let mut mgr = IdentityManager::new();
    mgr.add_member(conv_id, alice.master_pk, 1, 0);
    mgr.add_member(conv_id, bob.master_pk, 1, 0);
    mgr.add_member(conv_id, charlie.master_pk, 1, 0);

    let ctx = CausalContext::global();
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    mgr.authorize_device(
        &ctx,
        conv_id,
        alice.master_pk,
        &alice_cert,
        0,
        1,
        alice_hash,
    )
    .unwrap();

    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    mgr.authorize_device(&ctx, conv_id, bob.master_pk, &bob_cert, 0, 1, bob_hash)
        .unwrap();

    let alice_sen = mgr
        .get_admin_seniority(conv_id, &alice.device_pk)
        .expect("alice seniority");
    let bob_sen = mgr
        .get_admin_seniority(conv_id, &bob.device_pk)
        .expect("bob seniority");

    assert_eq!(alice_sen.0, bob_sen.0, "equal-rank precondition");
    assert!(
        alice_sen < bob_sen,
        "at equal rank the smaller auth_hash must win — this is the \
         non-grindable historical value §3.8 relies on",
    );
}

/// Non-admin members have no seniority. A voting member (MESSAGE only)
/// must not accidentally match a `get_admin_seniority` lookup — if they
/// did, a non-admin could hijack the tie-breaker with an arbitrary
/// auth_hash and impersonate "the senior admin" in a collision.
#[test]
fn test_non_admin_member_has_no_seniority() {
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let charlie = TestIdentity::new();
    let conv_id = ConversationId::from([0x1Au8; 32]);

    let mgr = setup_manager(
        conv_id,
        &alice,
        &bob,
        &charlie,
        NodeHash::from([0x11u8; 32]),
        NodeHash::from([0x22u8; 32]),
    );

    assert!(
        mgr.get_admin_seniority(conv_id, &charlie.device_pk)
            .is_none(),
        "charlie holds MESSAGE only — the admin-seniority tie-breaker \
         must refuse to return a tuple for non-admins, otherwise a \
         regular member could hijack the §3.8 tie-breaker",
    );
}

// Avoid an "unused" warning for the helper if someone prunes a test.
#[allow(dead_code)]
fn _unused_check_pk_types(_pk: &PhysicalDevicePk, _lpk: &LogicalIdentityPk) {}
