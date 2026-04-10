//! §3.12 Rapid Authorization Churn — transitive revocation cascade
//! stress tests.
//!
//! The threat model's §3.12 mitigation claims:
//!   "Transitive Revocation (revoking the compromised admin immediately
//!    invalidates all their downstream actions and ghost authorizations)."
//!
//! `identity_hierarchy_test.rs::test_long_authorization_chain` covers
//! the basic linear cascade (5-admin chain, revoke middle). This file
//! exercises adversarial shapes where a compromised admin has fanned
//! out widely *and* deeply before revocation:
//!
//!   - Wide fan-out: one compromised admin authorizes many downstream
//!     devices. Revoking the admin must invalidate ALL of them, not
//!     just the most recent.
//!   - Deep mixed: branching chain where some leaves trace through the
//!     compromised admin and others do not. The revocation must prune
//!     only the contaminated sub-tree, leaving uncontaminated siblings
//!     authorized.
//!   - Ghost authorizations: devices authorized by the compromised
//!     admin that never subsequently acted. Per §3.12, these must also
//!     be invalidated — a compromise that stays dormant until after
//!     detection should not preserve attacker reach.

use ed25519_dalek::SigningKey;
use merkle_tox_core::dag::{
    ConversationId, LogicalIdentityPk, NodeHash, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::identity::{CausalContext, IdentityManager};
use merkle_tox_core::testing::make_cert;
use rand::{RngCore, SeedableRng};

fn fresh_device(rng: &mut impl RngCore) -> (SigningKey, PhysicalDevicePk) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk = SigningKey::from_bytes(&bytes);
    let pk = PhysicalDevicePk::from(sk.verifying_key().to_bytes());
    (sk, pk)
}

fn fresh_master(rng: &mut impl RngCore) -> (SigningKey, LogicalIdentityPk) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk = SigningKey::from_bytes(&bytes);
    let pk = LogicalIdentityPk::from(sk.verifying_key().to_bytes());
    (sk, pk)
}

/// Wide fan-out: a compromised admin grants ADMIN|MESSAGE permissions to
/// 20 downstream devices at increasing ranks. Revoking the admin must
/// invalidate every one of them, not just the most recent.
#[test]
fn test_wide_fanout_revocation_cascade() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
    let mut mgr = IdentityManager::new();
    let conv_id = ConversationId::from([0x3Cu8; 32]);
    let ctx = CausalContext::global();
    let now_ms = 1000;

    let (master_sk, master_pk) = fresh_master(&mut rng);
    let (admin_sk, admin_pk) = fresh_device(&mut rng);

    // Master authorizes Admin at rank 1.
    let admin_cert = make_cert(&master_sk, admin_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &admin_cert, now_ms, 1, NodeHash::from([0x01u8; 32]))
        .expect("admin auth");

    // Admin authorizes 20 downstream devices at ranks 2..22.
    let mut downstream: Vec<PhysicalDevicePk> = Vec::new();
    for i in 0u64..20 {
        let (_, dev_pk) = fresh_device(&mut rng);
        let cert = make_cert(&admin_sk, dev_pk, Permissions::ALL, 9_999_999, conv_id);
        let mut auth_hash = [0u8; 32];
        auth_hash[0..8].copy_from_slice(&i.to_le_bytes());
        mgr.authorize_device(&ctx, conv_id, master_pk, &cert, now_ms, 2 + i, NodeHash::from(auth_hash))
            .expect("downstream auth");
        downstream.push(dev_pk);
    }

    // All downstream devices are authorized at rank 22.
    for (i, pk) in downstream.iter().enumerate() {
        assert!(
            mgr.is_authorized(&ctx, conv_id, pk, &master_pk, now_ms, 22),
            "downstream #{i} must be authorized before revocation"
        );
    }

    // Master revokes the admin at rank 30.
    mgr.revoke_device(
        conv_id,
        master_pk.to_physical(),
        master_pk,
        admin_pk,
        30,
        now_ms,
        NodeHash::from([0xF1u8; 32]),
    );

    // §3.12 cascade: every downstream device must lose authorization.
    for (i, pk) in downstream.iter().enumerate() {
        assert!(
            !mgr.is_authorized(&ctx, conv_id, pk, &master_pk, now_ms, 31),
            "downstream #{i} must be cascaded-invalidated after the \
             compromised admin is revoked. A regression here would let \
             an attacker preserve reach by pre-authorizing many devices \
             before detection."
        );
    }
    assert!(
        !mgr.is_authorized(&ctx, conv_id, &admin_pk, &master_pk, now_ms, 31),
        "admin itself must be revoked at the revocation rank"
    );
}

/// Deep mixed topology: two parallel chains rooted at Master. Revoking
/// the intermediate admin on one chain must invalidate its entire
/// sub-tree while leaving the uncontaminated chain authorized.
#[test]
fn test_mixed_topology_cascade_only_prunes_contaminated_subtree() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xFACE);
    let mut mgr = IdentityManager::new();
    let conv_id = ConversationId::from([0x4Du8; 32]);
    let ctx = CausalContext::global();
    let now_ms = 1000;

    let (master_sk, master_pk) = fresh_master(&mut rng);

    // Contaminated chain: Master -> AdminX -> MidY -> LeafZ.
    let (admin_x_sk, admin_x_pk) = fresh_device(&mut rng);
    let (mid_y_sk, mid_y_pk) = fresh_device(&mut rng);
    let (_, leaf_z_pk) = fresh_device(&mut rng);

    let cert_x = make_cert(&master_sk, admin_x_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &cert_x, now_ms, 1, NodeHash::from([0x11u8; 32]))
        .unwrap();
    let cert_y = make_cert(&admin_x_sk, mid_y_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &cert_y, now_ms, 2, NodeHash::from([0x12u8; 32]))
        .unwrap();
    let cert_z = make_cert(&mid_y_sk, leaf_z_pk, Permissions::MESSAGE, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &cert_z, now_ms, 3, NodeHash::from([0x13u8; 32]))
        .unwrap();

    // Clean chain: Master -> AdminP -> MidQ -> LeafR.
    let (admin_p_sk, admin_p_pk) = fresh_device(&mut rng);
    let (mid_q_sk, mid_q_pk) = fresh_device(&mut rng);
    let (_, leaf_r_pk) = fresh_device(&mut rng);

    let cert_p = make_cert(&master_sk, admin_p_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &cert_p, now_ms, 1, NodeHash::from([0x21u8; 32]))
        .unwrap();
    let cert_q = make_cert(&admin_p_sk, mid_q_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &cert_q, now_ms, 2, NodeHash::from([0x22u8; 32]))
        .unwrap();
    let cert_r = make_cert(&mid_q_sk, leaf_r_pk, Permissions::MESSAGE, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &cert_r, now_ms, 3, NodeHash::from([0x23u8; 32]))
        .unwrap();

    // Baseline: both leaves authorized at rank 5.
    assert!(mgr.is_authorized(&ctx, conv_id, &leaf_z_pk, &master_pk, now_ms, 5));
    assert!(mgr.is_authorized(&ctx, conv_id, &leaf_r_pk, &master_pk, now_ms, 5));

    // Master revokes AdminX at rank 10.
    mgr.revoke_device(
        conv_id,
        master_pk.to_physical(),
        master_pk,
        admin_x_pk,
        10,
        now_ms,
        NodeHash::from([0xF2u8; 32]),
    );

    // Contaminated sub-tree: every node rooted through AdminX must be
    // invalidated at rank > 10.
    for (name, pk) in [("admin_x", admin_x_pk), ("mid_y", mid_y_pk), ("leaf_z", leaf_z_pk)] {
        assert!(
            !mgr.is_authorized(&ctx, conv_id, &pk, &master_pk, now_ms, 11),
            "{name} on contaminated chain must cascade-invalidate"
        );
    }

    // Clean sub-tree: completely independent, must remain authorized.
    for (name, pk) in [("admin_p", admin_p_pk), ("mid_q", mid_q_pk), ("leaf_r", leaf_r_pk)] {
        assert!(
            mgr.is_authorized(&ctx, conv_id, &pk, &master_pk, now_ms, 11),
            "{name} on the clean chain must NOT be affected by revoking an unrelated admin"
        );
    }
}

/// Ghost authorizations: a compromised admin grants permissions to
/// devices that never subsequently acted. §3.12 specifies those dormant
/// grants must still be invalidated when the issuer is revoked — a
/// silent compromise must not survive detection by going quiet.
#[test]
fn test_ghost_authorizations_cascade() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD);
    let mut mgr = IdentityManager::new();
    let conv_id = ConversationId::from([0x5Eu8; 32]);
    let ctx = CausalContext::global();
    let now_ms = 1000;

    let (master_sk, master_pk) = fresh_master(&mut rng);
    let (admin_sk, admin_pk) = fresh_device(&mut rng);
    let admin_cert = make_cert(&master_sk, admin_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &admin_cert, now_ms, 1, NodeHash::from([0x31u8; 32]))
        .unwrap();

    // "Ghost" device: authorized but never does anything after.
    let (_, ghost_pk) = fresh_device(&mut rng);
    let ghost_cert = make_cert(&admin_sk, ghost_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &ghost_cert, now_ms, 2, NodeHash::from([0x32u8; 32]))
        .unwrap();

    assert!(
        mgr.is_authorized(&ctx, conv_id, &ghost_pk, &master_pk, now_ms, 2),
        "ghost device authorized before revocation"
    );

    // Revoke the admin at rank 50 — the ghost has still never acted.
    mgr.revoke_device(
        conv_id,
        master_pk.to_physical(),
        master_pk,
        admin_pk,
        50,
        now_ms,
        NodeHash::from([0xF3u8; 32]),
    );

    assert!(
        !mgr.is_authorized(&ctx, conv_id, &ghost_pk, &master_pk, now_ms, 51),
        "ghost authorization must cascade even though the device never \
         acted after being granted. §3.12 explicitly names ghost \
         authorizations as part of the transitive-revocation guarantee."
    );
}

/// Retroactive invariant: after revoking an admin at rank R, its
/// downstream leaves must still be considered authorized at rank <= R-1
/// (retroactive content authored before the revocation remains valid).
/// Pairs with the cascade: the SAME leaf is authorized at R-1 and
/// unauthorized at R+1.
#[test]
fn test_cascade_respects_revocation_rank_boundary() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xBEEF);
    let mut mgr = IdentityManager::new();
    let conv_id = ConversationId::from([0x6Fu8; 32]);
    let ctx = CausalContext::global();
    let now_ms = 1000;

    let (master_sk, master_pk) = fresh_master(&mut rng);
    let (admin_sk, admin_pk) = fresh_device(&mut rng);
    let (_, leaf_pk) = fresh_device(&mut rng);

    let admin_cert = make_cert(&master_sk, admin_pk, Permissions::ALL, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &admin_cert, now_ms, 1, NodeHash::from([0x41u8; 32]))
        .unwrap();
    let leaf_cert = make_cert(&admin_sk, leaf_pk, Permissions::MESSAGE, 9_999_999, conv_id);
    mgr.authorize_device(&ctx, conv_id, master_pk, &leaf_cert, now_ms, 2, NodeHash::from([0x42u8; 32]))
        .unwrap();

    mgr.revoke_device(
        conv_id,
        master_pk.to_physical(),
        master_pk,
        admin_pk,
        100,
        now_ms,
        NodeHash::from([0xF4u8; 32]),
    );

    assert!(
        mgr.is_authorized(&ctx, conv_id, &leaf_pk, &master_pk, now_ms, 50),
        "pre-revocation: leaf must still authorize content authored at \
         rank 50 — retroactive content stays valid even after the issuer \
         is revoked at rank 100",
    );
    assert!(
        !mgr.is_authorized(&ctx, conv_id, &leaf_pk, &master_pk, now_ms, 101),
        "post-revocation: leaf must be unauthorized starting at \
         rank 101",
    );
}
