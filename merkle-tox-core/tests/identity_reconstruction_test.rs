use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{ControlAction, ConversationId, KConv, Permissions, PhysicalDevicePk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, TestIdentity, create_admin_node, make_cert};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_identity_reconstruction() {
    let _ = tracing_subscriber::fmt::try_init();
    let alice = TestIdentity::new();
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let conv_id = ConversationId::from([0xAAu8; 32]);
    let k_conv = KConv::from([0x11u8; 32]);
    let _conv_keys = ConversationKeys::derive(&k_conv);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup engine and create Genesis + Auth nodes
    {
        // Manual Genesis (since NodeBuilder might not match exactly what we want to test)
        let genesis = create_admin_node(
            &conv_id,
            alice.master_pk,
            &alice.master_sk,
            vec![],
            ControlAction::Genesis {
                title: "Test Room".to_string(),
                creator_pk: alice.master_pk,
                permissions: Permissions::ALL,
                flags: 0,
                created_at: 1000,
                pow_nonce: 0,
            },
            0,
            1,
            1000,
        );
        let genesis_hash = genesis.hash();
        store.put_node(&conv_id, genesis, true).unwrap();

        // Auth node for Alice's device
        let cert = alice.make_device_cert(Permissions::MESSAGE, 2000000);
        let auth_node = create_admin_node(
            &conv_id,
            alice.master_pk,
            &alice.master_sk,
            vec![genesis_hash],
            ControlAction::AuthorizeDevice { cert },
            1,
            2,
            1100,
        );
        store.put_node(&conv_id, auth_node, true).unwrap();

        // Auth node for Bob's device (issued by Alice)
        let cert_bob = make_cert(&alice.master_sk, bob_pk, Permissions::MESSAGE, 2000000);
        let auth_bob = create_admin_node(
            &conv_id,
            alice.master_pk,
            &alice.master_sk,
            vec![genesis_hash],
            ControlAction::AuthorizeDevice { cert: cert_bob },
            1,
            3,
            1200,
        );
        store.put_node(&conv_id, auth_bob, true).unwrap();

        store.put_conversation_key(&conv_id, 0, k_conv).unwrap();
    }

    // 2. Create a NEW engine and load state
    let mut new_engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        StdRng::seed_from_u64(1),
        tp,
    );
    new_engine.load_conversation_state(conv_id, &store).unwrap();

    // 3. Verify IdentityManager is populated
    assert!(
        new_engine
            .identity_manager
            .resolve_logical_pk(conv_id, &alice.device_pk)
            .is_some()
    );
    assert_eq!(
        new_engine
            .identity_manager
            .resolve_logical_pk(conv_id, &alice.device_pk)
            .unwrap(),
        alice.master_pk
    );

    assert!(
        new_engine
            .identity_manager
            .resolve_logical_pk(conv_id, &bob_pk)
            .is_some()
    );
    assert_eq!(
        new_engine
            .identity_manager
            .resolve_logical_pk(conv_id, &bob_pk)
            .unwrap(),
        alice.master_pk
    );

    let members = new_engine.identity_manager.list_members(conv_id);
    assert!(members.iter().any(|(pk, _, _)| pk == &alice.master_pk));
}
