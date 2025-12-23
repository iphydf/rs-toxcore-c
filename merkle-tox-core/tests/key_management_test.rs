use ed25519_dalek::SigningKey;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, KConv, LogicalIdentityPk, Permissions,
    PhysicalDevicePk, PhysicalDeviceSk,
};
use merkle_tox_core::engine::{
    Conversation, ConversationData, Effect, MerkleToxEngine, conversation,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, apply_effects, get_node_from_effects, is_verified_in_effects, make_cert,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

#[test]
fn test_per_device_sequence_numbers() {
    init();
    let alice_pk = LogicalIdentityPk::from([1u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from([1u8; 32]);
    let sync_key = ConversationId::from([0u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine =
        MerkleToxEngine::new(alice_device_pk, alice_pk, StdRng::seed_from_u64(0), tp);
    let alice_store = InMemoryStore::new();

    // First node
    let effects = alice_engine
        .author_node(
            sync_key,
            Content::Text("Msg 1".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let node1 = get_node_from_effects(effects.clone());
    apply_effects(effects, &alice_store);
    assert_eq!(node1.sequence_number, 1);

    // Second node
    let effects = alice_engine
        .author_node(
            sync_key,
            Content::Text("Msg 2".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let node2 = get_node_from_effects(effects.clone());
    apply_effects(effects, &alice_store);
    assert_eq!(node2.sequence_number, 2);

    // Check that store returns correct last sequence number
    assert_eq!(
        alice_store.get_last_sequence_number(&sync_key, &alice_device_pk),
        2
    );
}

#[test]
fn test_automatic_key_rotation_on_message_count() {
    init();
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
    let mut alice_sk_bytes = [0u8; 32];
    csprng.fill_bytes(&mut alice_sk_bytes);
    let alice_sk_key = SigningKey::from_bytes(&alice_sk_bytes);
    let alice_pk = LogicalIdentityPk::from(alice_sk_key.verifying_key().to_bytes());
    let alice_device_pk = PhysicalDevicePk::from(alice_sk_key.verifying_key().to_bytes());

    let sync_key = ConversationId::from([0u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_device_pk,
        alice_pk,
        PhysicalDeviceSk::from(alice_sk_bytes),
        StdRng::seed_from_u64(0),
        tp,
    );
    let alice_store = InMemoryStore::new();

    let k_conv = KConv::from([0xAAu8; 32]);
    alice_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key, k_conv, 0,
        )),
    );

    // Author many messages to trigger rotation
    // MESSAGES_PER_EPOCH is 5000.
    // Set the count to 5000.
    if let Some(Conversation::Established(em)) = alice_engine.conversations.get_mut(&sync_key) {
        em.state.message_count = 5000;
    }

    // Author message 5001 to trigger rotation
    let effects = alice_engine
        .author_node(
            sync_key,
            Content::Text("Trigger".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    apply_effects(effects, &alice_store);

    // After this, epoch should be 1
    assert_eq!(alice_engine.get_current_epoch(&sync_key), 1);

    // There should be Rekey node in the store.
    let rekey_node_found = alice_store.nodes.read().unwrap().values().any(|(n, _)| {
        matches!(
            n.content,
            Content::Control(ControlAction::Rekey { new_epoch: 1 })
        )
    });
    assert!(rekey_node_found);
}

#[test]
fn test_key_wrap_distribution_and_unwrapping() {
    init();
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);

    // Alice setup: generate real Ed25519 keys
    let mut alice_sk_bytes = [0u8; 32];
    csprng.fill_bytes(&mut alice_sk_bytes);
    let alice_signing_key = SigningKey::from_bytes(&alice_sk_bytes);
    let alice_pk = LogicalIdentityPk::from(alice_signing_key.verifying_key().to_bytes());
    let alice_device_pk = PhysicalDevicePk::from(alice_signing_key.verifying_key().to_bytes());
    let alice_sk = alice_sk_bytes;

    // Bob setup: generate real Ed25519 keys
    let mut bob_sk_bytes = [0u8; 32];
    csprng.fill_bytes(&mut bob_sk_bytes);
    let bob_signing_key = SigningKey::from_bytes(&bob_sk_bytes);
    let bob_pk = LogicalIdentityPk::from(bob_signing_key.verifying_key().to_bytes());
    let bob_device_pk = PhysicalDevicePk::from(bob_signing_key.verifying_key().to_bytes());
    let bob_sk = bob_sk_bytes;

    let sync_key = ConversationId::from([0u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice_device_pk,
        alice_pk,
        PhysicalDeviceSk::from(alice_sk),
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob_device_pk,
        bob_pk,
        PhysicalDeviceSk::from(bob_sk),
        StdRng::seed_from_u64(1),
        tp,
    );

    let alice_store = InMemoryStore::new();
    let bob_store = InMemoryStore::new();

    let k_conv_v1 = KConv::from([0x11u8; 32]);
    alice_store
        .put_conversation_key(&sync_key, 0, k_conv_v1.clone())
        .unwrap();
    bob_store
        .put_conversation_key(&sync_key, 0, k_conv_v1.clone())
        .unwrap();
    alice_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv_v1.clone(),
            0,
        )),
    );
    bob_engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key, k_conv_v1, 0,
        )),
    );

    // Authorize Bob's device in Alice's engine
    alice_engine
        .identity_manager
        .add_member(sync_key, bob_pk, 1, 0);
    let cert = make_cert(
        &alice_signing_key,
        bob_device_pk,
        Permissions::MESSAGE,
        2000000000000,
    );
    alice_engine
        .identity_manager
        .authorize_device(sync_key, alice_pk, &cert, 0, 0)
        .unwrap();

    // Trigger rotation in Alice's engine
    let effects = alice_engine
        .rotate_conversation_key(sync_key, &alice_store)
        .unwrap();
    apply_effects(effects.clone(), &alice_store);
    let nodes: Vec<_> = effects
        .into_iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node)
            } else {
                None
            }
        })
        .collect();

    // Simulate network transfer: Bob receives all nodes generated by Alice's rotation
    for node in &nodes {
        let effects = bob_engine
            .handle_node(sync_key, node.clone(), &bob_store, None)
            .unwrap();
        apply_effects(effects, &bob_store);
    }

    // Bob should now have Epoch 1
    assert_eq!(bob_engine.get_current_epoch(&sync_key), 1);

    // Verify Bob can decrypt/verify a node from Alice under the new key
    let effects = alice_engine
        .author_node(
            sync_key,
            Content::Text("New key msg".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let alice_msg = get_node_from_effects(effects.clone());
    apply_effects(effects, &alice_store);
    let effects = bob_engine
        .handle_node(sync_key, alice_msg, &bob_store, None)
        .unwrap();
    apply_effects(effects.clone(), &bob_store);

    assert!(is_verified_in_effects(&effects));
}

#[test]
fn test_conversation_keys_derivation_alignment() {
    use blake3::derive_key;
    use merkle_tox_core::crypto::ConversationKeys;
    let k_conv = KConv::from([0x42u8; 32]);
    let keys = ConversationKeys::derive(&k_conv);

    let expected_k_enc = derive_key("merkle-tox v1 enc", k_conv.as_bytes());
    let expected_k_mac = derive_key("merkle-tox v1 mac", k_conv.as_bytes());

    assert_eq!(
        *keys.k_enc.as_bytes(),
        expected_k_enc,
        "Encryption key derivation does not match design (merkle-tox.md)"
    );
    assert_eq!(
        *keys.k_mac.as_bytes(),
        expected_k_mac,
        "MAC key derivation does not match design (merkle-tox.md)"
    );
}
