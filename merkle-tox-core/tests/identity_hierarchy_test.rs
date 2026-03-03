use ed25519_dalek::SigningKey;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::PhysicalDeviceSk;
use merkle_tox_core::dag::{
    ControlAction, ConversationId, LogicalIdentityPk, NodeHash, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::identity::{CausalContext, IdentityManager};
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_genesis_pow, make_cert,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tox_proto::constants::MAX_AUTH_DEPTH;

#[test]
fn test_hierarchical_delegation_and_revocation() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);

    // Level 0: Master
    let mut master_bytes = [0u8; 32];
    csprng.fill_bytes(&mut master_bytes);
    let master_sk = SigningKey::from_bytes(&master_bytes);
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    // Level 1: Admin Device
    let mut admin_bytes = [0u8; 32];
    csprng.fill_bytes(&mut admin_bytes);
    let admin_sk = SigningKey::from_bytes(&admin_bytes);
    let admin_pk = PhysicalDevicePk::from(admin_sk.verifying_key().to_bytes());

    // Level 2: User Device
    let mut user_bytes = [0u8; 32];
    csprng.fill_bytes(&mut user_bytes);
    let user_sk = SigningKey::from_bytes(&user_bytes);
    let user_pk = PhysicalDevicePk::from(user_sk.verifying_key().to_bytes());

    let now = 1000;
    let mut manager = IdentityManager::new();
    let sync_key = ConversationId::from([0xAAu8; 32]);
    let ctx = merkle_tox_core::identity::CausalContext::global();

    // 1. Authorize Admin from Master
    let cert1 = make_cert(
        &master_sk,
        admin_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert1,
            now,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .expect("Master should auth Admin");

    // 2. Authorize User from Admin
    let cert2 = make_cert(&admin_sk, user_pk, Permissions::MESSAGE, 2000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert2,
            now,
            1,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .expect("Admin should auth User");

    // Verify both are authorized
    assert!(manager.is_authorized(&ctx, sync_key, &admin_pk, &master_pk, now, 1));
    assert!(manager.is_authorized(&ctx, sync_key, &user_pk, &master_pk, now, 1));

    // 3. Revoke Admin
    manager.revoke_device(
        sync_key,
        master_pk.to_physical(),
        master_pk,
        admin_pk,
        2,
        now,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    // Admin should be unauthorized at rank 2
    assert!(!manager.is_authorized(&ctx, sync_key, &admin_pk, &master_pk, now, 2));

    // User should ALSO be unauthorized because its trust path is broken
    assert!(!manager.is_authorized(&ctx, sync_key, &user_pk, &master_pk, now, 2));

    // But they should still be authorized at rank 1
    assert!(manager.is_authorized(&ctx, sync_key, &admin_pk, &master_pk, now, 1));
    assert!(manager.is_authorized(&ctx, sync_key, &user_pk, &master_pk, now, 1));
}

#[test]
fn test_long_authorization_chain() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut manager = IdentityManager::new();
    let now = 1000;
    let sync_key = ConversationId::from([0xAAu8; 32]);
    let ctx = merkle_tox_core::identity::CausalContext::global();

    // Root
    let mut root_bytes = [0u8; 32];
    csprng.fill_bytes(&mut root_bytes);
    let root_sk = SigningKey::from_bytes(&root_bytes);
    let root_pk = LogicalIdentityPk::from(root_sk.verifying_key().to_bytes());

    let mut current_sk = root_sk;

    let mut chain_pks = Vec::new();

    // Create a chain of 5 admins
    for i in 0..5 {
        let mut next_bytes = [0u8; 32];
        csprng.fill_bytes(&mut next_bytes);
        let next_sk = SigningKey::from_bytes(&next_bytes);
        let next_pk = PhysicalDevicePk::from(next_sk.verifying_key().to_bytes());

        let cert = make_cert(
            &current_sk,
            next_pk,
            Permissions::ADMIN | Permissions::MESSAGE,
            2000000000000,
        );
        manager
            .authorize_device(
                &ctx,
                sync_key,
                root_pk,
                &cert,
                now,
                i as u64,
                merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            )
            .unwrap();

        chain_pks.push(next_pk);
        current_sk = next_sk;
    }

    // End device (not an admin)
    let mut end_bytes = [0u8; 32];
    csprng.fill_bytes(&mut end_bytes);
    let end_pk = PhysicalDevicePk::from(
        SigningKey::from_bytes(&end_bytes)
            .verifying_key()
            .to_bytes(),
    );
    let end_cert = make_cert(&current_sk, end_pk, Permissions::MESSAGE, 2000000000000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            root_pk,
            &end_cert,
            now,
            5,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    assert!(manager.is_authorized(&ctx, sync_key, &end_pk, &root_pk, now, 5));

    // Revoke the middle admin at rank 6
    manager.revoke_device(
        sync_key,
        root_pk.to_physical(),
        root_pk,
        chain_pks[2],
        6,
        now,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    assert!(
        !manager.is_authorized(&ctx, sync_key, &end_pk, &root_pk, now, 6),
        "Revoking middle of chain should invalidate end"
    );
    assert!(!manager.is_authorized(&ctx, sync_key, &chain_pks[3], &root_pk, now, 6));
    assert!(
        manager.is_authorized(&ctx, sync_key, &chain_pks[1], &root_pk, now, 6),
        "Preceding admins should stay authorized"
    );
}

#[test]
fn test_permission_intersection_chain() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut manager = IdentityManager::new();
    let now = 1000;
    let sync_key = ConversationId::from([0xAAu8; 32]);

    // Root (has ALL)
    let mut root_bytes = [0u8; 32];
    csprng.fill_bytes(&mut root_bytes);
    let root_sk = SigningKey::from_bytes(&root_bytes);
    let root_pk = LogicalIdentityPk::from(root_sk.verifying_key().to_bytes());

    // Admin 1: ALL permissions
    let mut a1_bytes = [0u8; 32];
    csprng.fill_bytes(&mut a1_bytes);
    let a1_sk = SigningKey::from_bytes(&a1_bytes);
    let a1_pk = PhysicalDevicePk::from(a1_sk.verifying_key().to_bytes());
    let cert1 = merkle_tox_core::identity::sign_delegation(
        &root_sk,
        a1_pk,
        Permissions::ALL,
        2000,
        sync_key,
    );
    let ctx = merkle_tox_core::identity::CausalContext::global();
    manager
        .authorize_device(
            &ctx,
            sync_key,
            root_pk,
            &cert1,
            now,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Admin 2: ADMIN and SYNC (No MESSAGE)
    let mut a2_bytes = [0u8; 32];
    csprng.fill_bytes(&mut a2_bytes);
    let a2_sk = SigningKey::from_bytes(&a2_bytes);
    let a2_pk = PhysicalDevicePk::from(a2_sk.verifying_key().to_bytes());
    let cert2 = merkle_tox_core::identity::sign_delegation(
        &a1_sk,
        a2_pk,
        Permissions::ADMIN | Permissions::SYNC,
        2000,
        sync_key,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            root_pk,
            &cert2,
            now,
            1,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Admin 3: Tries to claim ADMIN and MESSAGE but should be capped by A2 on MESSAGE
    let mut a3_bytes = [0u8; 32];
    csprng.fill_bytes(&mut a3_bytes);
    let a3_sk = SigningKey::from_bytes(&a3_bytes);
    let a3_pk = PhysicalDevicePk::from(a3_sk.verifying_key().to_bytes());

    // A3 cannot delegate MESSAGE because it doesn't have it
    let cert3 = merkle_tox_core::identity::sign_delegation(
        &a2_sk,
        a3_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
        sync_key,
    );
    let res = manager.authorize_device(
        &ctx,
        sync_key,
        root_pk,
        &cert3,
        now,
        2,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );
    assert!(res.is_err(), "A2 cannot delegate MESSAGE");

    // A2 delegates SYNC
    let cert3_ok = merkle_tox_core::identity::sign_delegation(
        &a2_sk,
        a3_pk,
        Permissions::SYNC,
        2000,
        sync_key,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            root_pk,
            &cert3_ok,
            now,
            2,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Check effective permissions
    let perms = manager
        .get_permissions(&ctx, sync_key, &a3_pk, &root_pk, now, 2)
        .unwrap();
    assert_eq!(perms, Permissions::SYNC);
    assert!(!perms.contains(Permissions::ADMIN));
    assert!(!perms.contains(Permissions::MESSAGE));
}

#[test]
fn test_unauthorized_issuer() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut master_bytes = [0u8; 32];
    csprng.fill_bytes(&mut master_bytes);
    let master_sk = SigningKey::from_bytes(&master_bytes);
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    let mut rogue_bytes = [0u8; 32];
    csprng.fill_bytes(&mut rogue_bytes);
    let rogue_sk = SigningKey::from_bytes(&rogue_bytes);

    let mut user_bytes = [0u8; 32];
    csprng.fill_bytes(&mut user_bytes);
    let user_sk = SigningKey::from_bytes(&user_bytes);
    let user_pk = PhysicalDevicePk::from(user_sk.verifying_key().to_bytes());

    let now = 1000;
    let mut manager = IdentityManager::new();
    let sync_key = ConversationId::from([0xAAu8; 32]);
    let ctx = merkle_tox_core::identity::CausalContext::global();

    // Rogue device (not authorized) tries to authorize User
    let cert = make_cert(&rogue_sk, user_pk, Permissions::MESSAGE, 2000);
    let res = manager.authorize_device(
        &ctx,
        sync_key,
        master_pk,
        &cert,
        now,
        0,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    assert!(res.is_err(), "Unauthorized issuer should fail");
    assert!(!manager.is_authorized(&ctx, sync_key, &user_pk, &master_pk, now, 0));
}

#[test]
fn test_permission_escalation() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut master_bytes = [0u8; 32];
    csprng.fill_bytes(&mut master_bytes);
    let master_sk = SigningKey::from_bytes(&master_bytes);
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    let mut admin_bytes = [0u8; 32];
    csprng.fill_bytes(&mut admin_bytes);
    let admin_sk = SigningKey::from_bytes(&admin_bytes);
    let admin_pk = PhysicalDevicePk::from(admin_sk.verifying_key().to_bytes());

    let mut user_bytes = [0u8; 32];
    csprng.fill_bytes(&mut user_bytes);
    let _user_sk = SigningKey::from_bytes(&user_bytes);
    let user_pk = PhysicalDevicePk::from(_user_sk.verifying_key().to_bytes());

    let now = 1000;
    let mut manager = IdentityManager::new();
    let sync_key = ConversationId::from([0xAAu8; 32]);
    let ctx = merkle_tox_core::identity::CausalContext::global();

    // 1. Authorize Admin with only MESSAGE permission (no ADMIN)
    let cert1 = make_cert(&master_sk, admin_pk, Permissions::MESSAGE, 2000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert1,
            now,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .expect("Master should auth Admin");

    // 2. Admin tries to authorize User (should fail because Admin doesn't have ADMIN)
    let cert2 = make_cert(&admin_sk, user_pk, Permissions::MESSAGE, 2000);
    let res = manager.authorize_device(
        &ctx,
        sync_key,
        master_pk,
        &cert2,
        now,
        1,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );
    assert!(res.is_err());

    // 3. Now authorize Admin with ADMIN but not SYNC
    let cert1_v2 = make_cert(
        &master_sk,
        admin_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert1_v2,
            now,
            2,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .expect("Master should auth Admin v2");

    // 4. Admin tries to authorize User with SYNC (escalation)
    let cert3 = make_cert(
        &admin_sk,
        user_pk,
        Permissions::MESSAGE | Permissions::SYNC,
        2000,
    );
    let res = manager.authorize_device(
        &ctx,
        sync_key,
        master_pk,
        &cert3,
        now,
        3,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );
    assert!(
        res.is_err(),
        "Admin cannot delegate SYNC if it doesn't have it"
    );
}

#[test]
fn test_auth_depth_limit() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut manager = IdentityManager::new();
    let now = 1000;

    // Root
    let mut root_bytes = [0u8; 32];
    csprng.fill_bytes(&mut root_bytes);
    let root_sk = SigningKey::from_bytes(&root_bytes);
    let root_pk = LogicalIdentityPk::from(root_sk.verifying_key().to_bytes());

    let mut current_sk = root_sk;
    let sync_key = ConversationId::from([0xAAu8; 32]);

    // Create a chain that reaches the limit
    let ctx = merkle_tox_core::identity::CausalContext::global();
    for i in 0..MAX_AUTH_DEPTH {
        let mut next_bytes = [0u8; 32];
        csprng.fill_bytes(&mut next_bytes);
        let next_sk = SigningKey::from_bytes(&next_bytes);
        let next_pk = PhysicalDevicePk::from(next_sk.verifying_key().to_bytes());

        let cert = make_cert(
            &current_sk,
            next_pk,
            Permissions::ADMIN | Permissions::MESSAGE,
            2000000000000,
        );
        manager
            .authorize_device(
                &ctx,
                sync_key,
                root_pk,
                &cert,
                now,
                i as u64,
                merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            )
            .unwrap();

        current_sk = next_sk;
    }

    // Try to add one more - should fail
    let mut too_deep_bytes = [0u8; 32];
    csprng.fill_bytes(&mut too_deep_bytes);
    let too_deep_sk = SigningKey::from_bytes(&too_deep_bytes);
    let too_deep_pk = PhysicalDevicePk::from(too_deep_sk.verifying_key().to_bytes());

    let cert = make_cert(
        &current_sk,
        too_deep_pk,
        Permissions::MESSAGE,
        2000000000000,
    );
    let res = manager.authorize_device(
        &ctx,
        sync_key,
        root_pk,
        &cert,
        now,
        100,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    assert!(
        matches!(
            res,
            Err(merkle_tox_core::identity::IdentityError::ChainTooDeep)
        ),
        "Should fail with ChainTooDeep"
    );
}

#[test]
fn test_identity_multi_path_authorization() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);

    // Level 0: Master
    let mut master_bytes = [0u8; 32];
    csprng.fill_bytes(&mut master_bytes);
    let master_sk = SigningKey::from_bytes(&master_bytes);
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    // Level 1: Admin A
    let mut a_bytes = [0u8; 32];
    csprng.fill_bytes(&mut a_bytes);
    let a_sk = SigningKey::from_bytes(&a_bytes);
    let a_pk = PhysicalDevicePk::from(a_sk.verifying_key().to_bytes());

    // Level 1: Admin B
    let mut b_bytes = [0u8; 32];
    csprng.fill_bytes(&mut b_bytes);
    let b_sk = SigningKey::from_bytes(&b_bytes);
    let b_pk = PhysicalDevicePk::from(b_sk.verifying_key().to_bytes());

    // Level 2: Device D
    let mut d_bytes = [0u8; 32];
    csprng.fill_bytes(&mut d_bytes);
    let d_pk = PhysicalDevicePk::from(SigningKey::from_bytes(&d_bytes).verifying_key().to_bytes());

    let now = 1000;
    let mut manager = IdentityManager::new();
    let sync_key = ConversationId::from([0xAAu8; 32]);
    let ctx = merkle_tox_core::identity::CausalContext::global();

    // 1. Master authorizes Admin A and Admin B
    let cert_a = make_cert(
        &master_sk,
        a_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        5000,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_a,
            now,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    let cert_b = make_cert(
        &master_sk,
        b_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        5000,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_b,
            now,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // 2. Admin A authorizes Device D
    let cert_ad = make_cert(&a_sk, d_pk, Permissions::MESSAGE, 5000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_ad,
            now,
            1,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // 3. Admin B also authorizes Device D
    let cert_bd = make_cert(&b_sk, d_pk, Permissions::MESSAGE, 5000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_bd,
            now,
            1,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Verify D is authorized
    assert!(manager.is_authorized(&ctx, sync_key, &d_pk, &master_pk, now, 1));

    // 4. Revoke Admin A
    manager.revoke_device(
        sync_key,
        master_pk.to_physical(),
        master_pk,
        a_pk,
        2,
        now,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    // D should STILL be authorized via Admin B
    assert!(
        manager.is_authorized(&ctx, sync_key, &d_pk, &master_pk, now, 2),
        "Device D should remain authorized via Admin B after Admin A is revoked"
    );

    // 5. Revoke Admin B
    manager.revoke_device(
        sync_key,
        master_pk.to_physical(),
        master_pk,
        b_pk,
        3,
        now,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    // Now D should be unauthorized
    assert!(
        !manager.is_authorized(&ctx, sync_key, &d_pk, &master_pk, now, 3),
        "Device D should be unauthorized after both paths are broken"
    );
}

#[test]
fn test_identity_circular_delegation() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut manager = IdentityManager::new();
    let now = 1000;
    let sync_key = ConversationId::from([0xAAu8; 32]);

    // Master
    let mut master_bytes = [0u8; 32];
    csprng.fill_bytes(&mut master_bytes);
    let master_sk = SigningKey::from_bytes(&master_bytes);
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    // Admin A
    let mut a_bytes = [0u8; 32];
    csprng.fill_bytes(&mut a_bytes);
    let a_sk = SigningKey::from_bytes(&a_bytes);
    let a_pk = PhysicalDevicePk::from(a_sk.verifying_key().to_bytes());

    // Admin B
    let mut b_bytes = [0u8; 32];
    csprng.fill_bytes(&mut b_bytes);
    let b_sk = SigningKey::from_bytes(&b_bytes);
    let b_pk = PhysicalDevicePk::from(b_sk.verifying_key().to_bytes());
    let ctx = merkle_tox_core::identity::CausalContext::global();

    // 1. Master -> A
    let cert_ma = make_cert(
        &master_sk,
        a_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        5000,
    );
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_ma,
            now,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // 2. A -> B
    let cert_ab = make_cert(&a_sk, b_pk, Permissions::ADMIN | Permissions::MESSAGE, 5000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_ab,
            now,
            1,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // 3. B -> A (Circular!)
    let cert_ba = make_cert(&b_sk, a_pk, Permissions::ADMIN | Permissions::MESSAGE, 5000);
    manager
        .authorize_device(
            &ctx,
            sync_key,
            master_pk,
            &cert_ba,
            now,
            2,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // 4. Revoke Master -> A original path
    // This leaves A only with the circular path Master -> A -> B -> A
    manager.revoke_device(
        sync_key,
        master_pk.to_physical(),
        master_pk,
        a_pk,
        3,
        now,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    // 5. A -> C (using the circular path)
    let mut c_bytes = [0u8; 32];
    csprng.fill_bytes(&mut c_bytes);
    let c_pk = PhysicalDevicePk::from(SigningKey::from_bytes(&c_bytes).verifying_key().to_bytes());
    let cert_ac = make_cert(&a_sk, c_pk, Permissions::MESSAGE, 5000);
    let res_ac = manager.authorize_device(
        &ctx,
        sync_key,
        master_pk,
        &cert_ac,
        now,
        4,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    // C should be REJECTED because its issuer (A) now only has a circular path
    // and thus has no effective permissions to delegate.
    assert!(
        res_ac.is_err(),
        "A should not be able to authorize C while in a broken cycle"
    );

    // 6. Verify that Admin A and B are also unauthorized
    assert!(!manager.is_authorized(&ctx, sync_key, &a_pk, &master_pk, now, 4));
    assert!(!manager.is_authorized(&ctx, sync_key, &b_pk, &master_pk, now, 4));
}

#[test]
fn test_identity_expired_certificate() {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut manager = IdentityManager::new();
    let now = 1000;
    let sync_key = ConversationId::from([0xAAu8; 32]);

    // Master
    let mut master_bytes = [0u8; 32];
    csprng.fill_bytes(&mut master_bytes);
    let master_sk = SigningKey::from_bytes(&master_bytes);
    let master_pk = LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    // Device A
    let mut a_bytes = [0u8; 32];
    csprng.fill_bytes(&mut a_bytes);
    let a_pk = PhysicalDevicePk::from(SigningKey::from_bytes(&a_bytes).verifying_key().to_bytes());

    // Expired certificate (expires_at < now)
    let cert = make_cert(&master_sk, a_pk, Permissions::MESSAGE, 500);
    let ctx = merkle_tox_core::identity::CausalContext::global();
    let res = manager.authorize_device(
        &ctx,
        sync_key,
        master_pk,
        &cert,
        now,
        0,
        merkle_tox_core::dag::NodeHash::from([0u8; 32]),
    );

    assert!(res.is_err(), "Expired certificate should not be accepted");
    assert!(!manager.is_authorized(&ctx, sync_key, &a_pk, &master_pk, now, 0));
}

/// Concurrent "mutually assured destruction" (MAD) revocations must be
/// resolved deterministically using Admin Seniority. When two admins authorized
/// at the same topological rank simultaneously revoke each other, only the
/// *junior* admin (the one whose AuthorizeDevice node has the lexicographically
/// larger hash) should be revoked. The senior admin survives.
#[test]
fn test_concurrent_mad_revocation_respects_seniority_hash() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([3u8; 32]);

    // --- Setup: both admins authorized at the same topological rank (1) ---
    let genesis_node = create_genesis_pow(&conv_id, &alice, "MAD Test");

    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let effects = engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // auth_alice and auth_bob are both at rank 1 (same parent = genesis).
    // Their AuthorizeDevice node hashes will be different but at equal rank.
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
    );
    let auth_alice = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis_node.hash()],
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1,
        1,
        1000,
    );
    let effects = engine
        .handle_node(conv_id, auth_alice.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let bob_cert = make_cert(&bob.master_sk, bob.device_pk, Permissions::all(), 9_999_999);
    let auth_bob = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.master_sk,
        vec![genesis_node.hash()], // same parent -> same rank as auth_alice
        ControlAction::AuthorizeDevice { cert: bob_cert },
        1,
        1,
        1000,
    );
    let effects = engine
        .handle_node(conv_id, auth_bob.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // --- Concurrent mutual revocations ---
    // Both revocations share the same parents so neither is an ancestor of the other.
    // seq=2: alice.device_sk already signed genesis at seq=1.
    let revoke_bob = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk, // alice's device signs -> revoker_seniority uses auth_alice's auth_hash
        vec![auth_alice.hash(), auth_bob.hash()],
        ControlAction::RevokeDevice {
            target_device_pk: bob.device_pk,
            reason: "MAD".to_string(),
        },
        2,
        2,
        1000,
    );
    let effects = engine
        .handle_node(conv_id, revoke_bob.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let revoke_alice = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.device_sk, // bob's device signs -> revoker_seniority uses auth_bob's auth_hash
        vec![auth_alice.hash(), auth_bob.hash()],
        ControlAction::RevokeDevice {
            target_device_pk: alice.device_pk,
            reason: "MAD".to_string(),
        },
        2,
        1,
        1000,
    );
    let effects = engine
        .handle_node(conv_id, revoke_alice.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // --- Evaluate authorization from a hypothetical future node that has seen
    //     *both* revocations in its causal history. ---
    let mut admin_ancestors = HashSet::new();
    admin_ancestors.insert(genesis_node.hash());
    admin_ancestors.insert(auth_alice.hash());
    admin_ancestors.insert(auth_bob.hash());
    admin_ancestors.insert(revoke_bob.hash());
    admin_ancestors.insert(revoke_alice.hash());

    let ctx = CausalContext {
        evaluating_node_hash: merkle_tox_core::dag::NodeHash::from([0x99u8; 32]),
        admin_ancestor_hashes: admin_ancestors,
    };

    let alice_perms = engine.identity_manager.get_permissions(
        &ctx,
        conv_id,
        &alice.device_pk,
        &alice.master_pk,
        1000,
        3,
    );
    let bob_perms = engine.identity_manager.get_permissions(
        &ctx,
        conv_id,
        &bob.device_pk,
        &bob.master_pk,
        1000,
        3,
    );

    // The senior admin (lower auth_hash) must survive; the junior must be revoked.
    // With the current rank-only comparison both are revoked -- this test should fail.
    let alice_is_senior = auth_alice.hash().as_bytes() < auth_bob.hash().as_bytes();
    if alice_is_senior {
        assert!(
            alice_perms.is_some(),
            "Senior admin (Alice, lower auth_hash) should still be authorized"
        );
        assert!(
            bob_perms.is_none(),
            "Junior admin (Bob, higher auth_hash) should be revoked"
        );
    } else {
        assert!(
            bob_perms.is_some(),
            "Senior admin (Bob, lower auth_hash) should still be authorized"
        );
        assert!(
            alice_perms.is_none(),
            "Junior admin (Alice, higher auth_hash) should be revoked"
        );
    }
}

/// The identity manager must enforce a maximum number of devices per logical
/// identity. A 33rd device authorized via Level 2 should be rejected.
#[test]
fn test_max_devices_per_identity_enforced() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut id_mgr = IdentityManager::new();
    let conv_id = ConversationId::from([10u8; 32]);

    // Use a single logical identity (master key)
    let master_sk = merkle_tox_core::testing::random_signing_key();
    let master_pk =
        merkle_tox_core::dag::LogicalIdentityPk::from(master_sk.verifying_key().to_bytes());

    let ctx = CausalContext::global();

    // Register the logical identity as a member so recursive permission lookups work
    id_mgr.add_member(conv_id, master_pk, 0, 1000);

    // Authorize one admin device via Level 1 (master key) -- this always succeeds
    let admin_sk = merkle_tox_core::testing::random_signing_key();
    let admin_pk = PhysicalDevicePk::from(admin_sk.verifying_key().to_bytes());
    let admin_cert = make_cert(&master_sk, admin_pk, Permissions::all(), i64::MAX);
    id_mgr
        .authorize_device(
            &ctx,
            conv_id,
            master_pk,
            &admin_cert,
            1000,
            0,
            NodeHash::from([0u8; 32]),
        )
        .unwrap();

    // Now use Level 1 (master key signed) to fill up to 32 devices total.
    // Level 1 bypasses the device count check, so we can fill up.
    let mut signing_keys = vec![admin_sk.clone()];
    for i in 1u32..32 {
        let dev_sk = merkle_tox_core::testing::random_signing_key();
        let dev_pk = PhysicalDevicePk::from(dev_sk.verifying_key().to_bytes());
        let cert = make_cert(&master_sk, dev_pk, Permissions::all(), i64::MAX);
        let auth_hash = NodeHash::from({
            let mut h = [0u8; 32];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            h
        });
        let result =
            id_mgr.authorize_device(&ctx, conv_id, master_pk, &cert, 1000, i as u64, auth_hash);
        assert!(result.is_ok(), "Level 1 device {} should be authorized", i);
        signing_keys.push(dev_sk);
    }

    // Now we have 32 devices. Try to authorize a 33rd via Level 2 (signed by the admin device).
    // The Level 2 path enforces the MAX_DEVICES_PER_IDENTITY check.
    let dev_sk_33 = merkle_tox_core::testing::random_signing_key();
    let dev_pk_33 = PhysicalDevicePk::from(dev_sk_33.verifying_key().to_bytes());
    let cert_33 = make_cert(&admin_sk, dev_pk_33, Permissions::all(), i64::MAX);
    let result = id_mgr.authorize_device(
        &ctx,
        conv_id,
        master_pk,
        &cert_33,
        1000,
        33,
        NodeHash::from([33u8; 32]),
    );
    assert!(
        result.is_err(),
        "33rd device via Level 2 should be rejected"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Too many devices"),
        "Error should mention too many devices, got: {err_msg}"
    );
}

// end of file
