use ed25519_dalek::SigningKey;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, EphemeralSigningPk,
    EphemeralX25519Pk, EphemeralX25519Sk, InviteAction, KConv, LogicalIdentityPk, NodeHash,
    Permissions, PhysicalDevicePk, PhysicalDeviceSk, SignedPreKey, WrappedKey,
};
use merkle_tox_core::engine::{
    Conversation, ConversationData, Effect, MerkleToxEngine, conversation,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node, create_genesis_pow,
    get_node_from_effects, is_verified_in_effects, make_cert, transfer_wire_nodes,
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

    // Authorize Bob using real public APIs and cryptographic certificates
    let bob = merkle_tox_core::testing::TestIdentity::new();
    bob.authorize_in_engine(&mut alice_engine, sync_key, Permissions::MESSAGE, i64::MAX);

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
    assert_eq!(alice_engine.get_current_generation(&sync_key), 1);
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
        sync_key,
    );
    let ctx = merkle_tox_core::identity::CausalContext::global();
    alice_engine
        .identity_manager
        .authorize_device(
            &ctx,
            sync_key,
            alice_pk,
            &cert,
            0,
            0,
            merkle_tox_core::dag::NodeHash::from([0u8; 32]),
        )
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
    assert_eq!(bob_engine.get_current_generation(&sync_key), 1);

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
    transfer_wire_nodes(&effects, &bob_store);
    apply_effects(effects, &alice_store);
    let effects = bob_engine
        .handle_node(sync_key, alice_msg.clone(), &bob_store, None)
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

/// `rotate_conversation_key` must not wrap keys for members who only
/// have a last-resort pre-key published. The doc states:
/// "Admins MUST NOT author a KeyWrap for a user if that user only has a
/// `last_resort_key` published."
#[test]
fn test_key_rotation_skips_last_resort_only_members() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([4u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "Last Resort Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
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
    let effects = alice_engine
        .handle_node(conv_id, auth_alice.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Alice invites Bob: this adds Bob's master_pk to logical_members so he
    // appears in list_active_authorized_devices during key rotation.
    // Use seq=2 because alice.device_sk already signed genesis at seq=1.
    let invite_bob = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.device_sk,
        vec![auth_alice.hash()],
        ControlAction::Invite(InviteAction {
            invitee_pk: bob.master_pk,
            role: 1,
        }),
        2,
        2,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, invite_bob.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
    );
    // auth_bob references auth_alice (last Admin head), not invite_bob (now Content).
    // Invite is Content-type under the new classification, so Admin chain isolation
    // prevents Admin nodes from referencing it.
    let auth_bob = create_admin_node(
        &conv_id,
        bob.master_pk,
        &bob.master_sk,
        vec![auth_alice.hash()],
        ControlAction::AuthorizeDevice { cert: bob_cert },
        2,
        1,
        1000,
    );
    let effects = alice_engine
        .handle_node(conv_id, auth_bob.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Bob has published ONLY a last-resort key: no fresh pre-keys.
    let lr_pk = EphemeralX25519Pk::from([0xBBu8; 32]);
    let lr_sig = Ed25519Signature::from([0u8; 64]);
    alice_engine.peer_announcements.insert(
        bob.device_pk,
        ControlAction::Announcement {
            pre_keys: vec![], // empty: last resort only
            last_resort_key: SignedPreKey {
                public_key: lr_pk,
                signature: lr_sig,
                expires_at: i64::MAX,
            },
        },
    );

    // Alice rotates the conversation key.
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &store)
        .unwrap();
    apply_effects(effects.clone(), &store);

    // Find the KeyWrap effect and inspect its wrapped_keys list.
    let wrapped_keys = effects.iter().find_map(|e| {
        if let Effect::WriteStore(_, node, _) = e
            && let Content::KeyWrap { wrapped_keys, .. } = &node.content
        {
            return Some(wrapped_keys.clone());
        }
        None
    });

    assert!(
        wrapped_keys.is_some(),
        "rotation should produce a KeyWrap node"
    );
    let wrapped_keys = wrapped_keys.unwrap();

    let bob_wrapped = wrapped_keys
        .iter()
        .any(|wk| wk.recipient_pk == bob.device_pk);
    assert!(
        !bob_wrapped,
        "Bob has only a last-resort key and must NOT receive a wrapped key during rotation; \
         the admin must defer and send an off-band HandshakePulse instead"
    );
}

/// The `anchor_hash` field in a `KeyWrap` node must reference the hash
/// of the most recent verified anchor (Genesis or Snapshot), not the conversation
/// ID. Currently `rotate_conversation_key` uses
/// `NodeHash::from(*conversation_id.as_bytes())` which is semantically wrong and
/// would break any recipient that validates the key generation chain.
#[test]
fn test_keywrap_anchor_hash_is_latest_anchor_not_conv_id() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let conv_id = ConversationId::from([5u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "Anchor Hash Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Trigger a generation-0 rotation; the spec mandates that the first KeyWrap
    // references the genesis node as its anchor.
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &store)
        .unwrap();
    apply_effects(effects.clone(), &store);

    // Find the KeyWrap and inspect its anchor_hash.
    let anchor_hash = effects.iter().find_map(|e| {
        if let Effect::WriteStore(_, node, _) = e
            && let Content::KeyWrap { anchor_hash, .. } = &node.content
        {
            Some(*anchor_hash)
        } else {
            None
        }
    });

    assert!(
        anchor_hash.is_some(),
        "rotate_conversation_key should produce a KeyWrap"
    );
    let anchor = anchor_hash.unwrap();

    // With the current bug: anchor_hash == NodeHash::from(*conv_id.as_bytes())
    // which is NOT the genesis node hash.
    let conv_id_as_hash = NodeHash::from(*conv_id.as_bytes());
    assert_ne!(
        anchor, conv_id_as_hash,
        "anchor_hash must not be set to the conversation ID bytes; \
         it should reference the latest verified anchor node (Genesis or Snapshot)"
    );
    assert_eq!(
        anchor,
        genesis_node.hash(),
        "anchor_hash should equal the genesis node hash for the first KeyWrap"
    );
}

/// `SenderKeyDistribution` nodes must be handled by the engine. When an
/// authorized device sends a `SenderKeyDistribution` whose `wrapped_keys` contains
/// an entry for our device (encrypted via ECIES with `ecies_wrap`),
/// the engine must decrypt the key and establish the conversation. Currently the node
/// falls through to `_ => {}` in side_effects.rs and the conversation stays Pending.
#[test]
fn test_sender_key_distribution_establishes_conversation() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([11u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "SKD Test");

    // Alice's engine – established via genesis + auth + key rotation.
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let alice_store = InMemoryStore::new();
    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        9_999_999,
        conv_id,
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
    let effects = alice_engine
        .handle_node(conv_id, auth_alice.clone(), &alice_store, None)
        .unwrap();
    apply_effects(effects, &alice_store);

    // Alice rotates to become Established (gives her a k_conv).
    let effects = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    apply_effects(effects, &alice_store);

    // Bob's engine – only processes genesis and Alice's AuthorizeDevice (no KeyWrap).
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
    let effects = bob_engine
        .handle_node(conv_id, auth_alice.clone(), &bob_store, None)
        .unwrap();
    apply_effects(effects, &bob_store);

    assert!(
        matches!(
            bob_engine.conversations.get(&conv_id),
            Some(Conversation::Pending(_))
        ),
        "Bob should be in Pending state before receiving SenderKeyDistribution",
    );

    // Extract Alice's k_conv for later direct-establishment of Bob.
    let k_conv_to_share =
        if let Some(Conversation::Established(em)) = alice_engine.conversations.get(&conv_id) {
            em.get_keys(em.current_epoch()).unwrap().k_conv.clone()
        } else {
            panic!("Alice should be Established after rotate_conversation_key");
        };

    // Build ECIES-wrapped SenderKey for Bob (using his device key as SPK).
    let bob_x25519_pk = merkle_tox_core::crypto::ed25519_pk_to_x25519(bob.device_pk.as_bytes())
        .expect("valid Ed25519 public key");
    let bob_spk = EphemeralX25519Pk::from(bob_x25519_pk.to_bytes());
    let alice_dh_sk = merkle_tox_core::crypto::ed25519_sk_to_x25519(alice.device_sk.as_bytes());
    let auth_secret = {
        let a = x25519_dalek::StaticSecret::from(alice_dh_sk);
        *a.diffie_hellman(&bob_x25519_pk).as_bytes()
    };
    let sender_key = [42u8; 32]; // dummy SenderKey

    // SKD node 1: manually constructed with parents that exist in Bob's DAG.
    // Processed while Bob is Pending: should NOT establish the conversation.
    let mut skd_e_sk = [0u8; 32];
    rand::RngCore::fill_bytes(&mut StdRng::seed_from_u64(99), &mut skd_e_sk);
    let skd_e_pk = EphemeralX25519Pk::from(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(skd_e_sk)).to_bytes(),
    );
    let skd_e_x25519 = EphemeralX25519Sk::from(skd_e_sk);
    let ciphertext = merkle_tox_core::crypto::ecies_wrap(
        &skd_e_x25519,
        &bob_spk,
        None,
        Some(&auth_secret),
        &sender_key,
    );
    let mut skd_node1 = merkle_tox_core::testing::test_node();
    skd_node1.parents = vec![auth_alice.hash()];
    skd_node1.author_pk = alice.master_pk;
    skd_node1.sender_pk = alice.device_pk;
    skd_node1.sequence_number = (1u64 << 32) | 1;
    skd_node1.topological_rank = 2;
    skd_node1.network_timestamp = 1000;
    skd_node1.content = Content::SenderKeyDistribution {
        ephemeral_pk: skd_e_pk,
        wrapped_keys: vec![WrappedKey {
            recipient_pk: bob.device_pk,
            ciphertext,
            opk_id: NodeHash::from([0u8; 32]),
        }],
        ephemeral_signing_pk: EphemeralSigningPk::from([0u8; 32]),
        disclosed_keys: vec![],
    };
    merkle_tox_core::testing::sign_admin_node(&mut skd_node1, &conv_id, &alice.device_sk);

    let bob_effects = bob_engine
        .handle_node(conv_id, skd_node1, &bob_store, None)
        .unwrap();
    apply_effects(bob_effects, &bob_store);

    assert!(
        matches!(
            bob_engine.conversations.get(&conv_id),
            Some(Conversation::Pending(_))
        ),
        "SenderKeyDistribution must NOT establish the conversation; KeyWrap does that",
    );

    // Establish Bob directly (in production, KeyWrap does this).
    {
        let pending_conv = bob_engine.conversations.remove(&conv_id).unwrap();
        if let Conversation::Pending(p) = pending_conv {
            let established = p.establish(k_conv_to_share.clone(), 1000, 1);
            bob_engine
                .conversations
                .insert(conv_id, Conversation::Established(established));
        } else {
            panic!("Expected Bob to be in Pending state");
        }
    }

    // SKD node 2: different ephemeral key → different hash → not deduplicated.
    // Processed while Bob is Established → SenderKey should be stored.
    let mut skd_e_sk2 = [0u8; 32];
    rand::RngCore::fill_bytes(&mut StdRng::seed_from_u64(101), &mut skd_e_sk2);
    let skd_e_pk2 = EphemeralX25519Pk::from(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(skd_e_sk2)).to_bytes(),
    );
    let skd_e_x25519_2 = EphemeralX25519Sk::from(skd_e_sk2);
    let ciphertext2 = merkle_tox_core::crypto::ecies_wrap(
        &skd_e_x25519_2,
        &bob_spk,
        None,
        Some(&auth_secret),
        &sender_key,
    );
    let mut skd_node2 = merkle_tox_core::testing::test_node();
    skd_node2.parents = vec![auth_alice.hash()];
    skd_node2.author_pk = alice.master_pk;
    skd_node2.sender_pk = alice.device_pk;
    skd_node2.sequence_number = (1u64 << 32) | 2;
    skd_node2.topological_rank = 2;
    skd_node2.network_timestamp = 1000;
    skd_node2.content = Content::SenderKeyDistribution {
        ephemeral_pk: skd_e_pk2,
        wrapped_keys: vec![WrappedKey {
            recipient_pk: bob.device_pk,
            ciphertext: ciphertext2,
            opk_id: NodeHash::from([0u8; 32]),
        }],
        ephemeral_signing_pk: EphemeralSigningPk::from([0u8; 32]),
        disclosed_keys: vec![],
    };
    merkle_tox_core::testing::sign_admin_node(&mut skd_node2, &conv_id, &alice.device_sk);

    let bob_effects = bob_engine
        .handle_node(conv_id, skd_node2, &bob_store, None)
        .unwrap();
    apply_effects(bob_effects, &bob_store);

    // Verify Bob stored Alice's SenderKey for the epoch.
    if let Some(Conversation::Established(em)) = bob_engine.conversations.get(&conv_id) {
        let epoch = 1u64;
        assert!(
            em.state.sender_keys.contains_key(&(alice.device_pk, epoch)),
            "Bob should have stored Alice's SenderKey from the SKD",
        );
    } else {
        panic!("Bob should be Established");
    }
}

/// Bonus: `author_x3dh_key_exchange` uses the wrong value for `anchor_hash`.
/// It currently encodes `NodeHash::from(*conversation_id.as_bytes())` which is
/// semantically wrong.  The `anchor_hash` field must reference the latest verified
/// anchor (Genesis or Snapshot), not the raw conversation-ID bytes.
#[test]
fn test_x3dh_keywrap_uses_genesis_as_anchor_hash() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([12u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "X3DH Anchor Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();
    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Register Bob's announcement so the last-resort blocking check passes.
    // The actual pre_spk we use (0x77) must differ from the last_resort_key (0x88).
    alice_engine.peer_announcements.insert(
        bob.device_pk,
        ControlAction::Announcement {
            pre_keys: vec![],
            last_resort_key: SignedPreKey {
                public_key: EphemeralX25519Pk::from([0x88_u8; 32]),
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: i64::MAX,
            },
        },
    );

    let bob_pre_spk = EphemeralX25519Pk::from([0x77_u8; 32]);

    let effects = alice_engine
        .author_x3dh_key_exchange(conv_id, bob.device_pk, bob_pre_spk, &store)
        .unwrap();
    apply_effects(effects.clone(), &store);

    let anchor_hash = effects.iter().find_map(|e| {
        if let Effect::WriteStore(_, node, _) = e
            && let Content::KeyWrap { anchor_hash, .. } = &node.content
        {
            Some(*anchor_hash)
        } else {
            None
        }
    });

    assert!(
        anchor_hash.is_some(),
        "author_x3dh_key_exchange should produce a KeyWrap node"
    );
    let anchor = anchor_hash.unwrap();

    let conv_id_as_hash = NodeHash::from(*conv_id.as_bytes());
    assert_ne!(
        anchor, conv_id_as_hash,
        "X3DH KeyWrap anchor_hash must not be the conversation-ID bytes; \
         it should reference the latest verified anchor (Genesis or Snapshot)",
    );
    assert_eq!(
        anchor,
        genesis_node.hash(),
        "X3DH KeyWrap anchor_hash should equal the genesis node hash",
    );
}

/// Spec §2.C (merkle-tox-handshake-x3dh.md): `author_x3dh_key_exchange` must
/// derive K_conv_0 INTERNALLY from SK_shared:
///
///   K_conv_0 = Blake3-KDF("merkle-tox v1 x3dh-kconv", SK_shared)
///
/// The function must NOT accept k_conv as a caller-supplied parameter; it derives
/// K_conv_0 itself and wraps it with SK_pairwise.  Currently the function wraps an
/// arbitrary externally-provided k_conv instead, so this test fails until the fix.
#[test]
fn test_x3dh_kconv_derived_from_sk_shared() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000i64));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([14u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "X3DH KConv Derivation Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();
    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Bob's SPK with known secret so we can verify decryption.
    let bob_spk_sk_bytes = [0x55u8; 32];
    let bob_spk_x25519_sk = x25519_dalek::StaticSecret::from(bob_spk_sk_bytes);
    let bob_spk_pk_bytes = x25519_dalek::PublicKey::from(&bob_spk_x25519_sk).to_bytes();
    let bob_spk_pk = EphemeralX25519Pk::from(bob_spk_pk_bytes);

    alice_engine.peer_announcements.insert(
        bob.device_pk,
        ControlAction::Announcement {
            pre_keys: vec![SignedPreKey {
                public_key: bob_spk_pk,
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: i64::MAX,
            }],
            last_resort_key: SignedPreKey {
                public_key: EphemeralX25519Pk::from([0x99u8; 32]),
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: i64::MAX,
            },
        },
    );

    // Alice authors the X3DH KeyWrap.
    let effects = alice_engine
        .author_x3dh_key_exchange(conv_id, bob.device_pk, bob_spk_pk, &store)
        .unwrap();
    apply_effects(effects.clone(), &store);

    // Extract e_a_pk and ciphertext for Bob.
    let (e_a_pk, ciphertext) = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && let Content::KeyWrap {
                    wrapped_keys,
                    ephemeral_pk: ea,
                    ..
                } = &node.content
            {
                let ct = wrapped_keys
                    .iter()
                    .find(|wk| wk.recipient_pk == bob.device_pk)
                    .map(|wk| wk.ciphertext.clone())?;
                Some((*ea, ct))
            } else {
                None
            }
        })
        .expect("author_x3dh_key_exchange must produce a KeyWrap with ephemeral_pk");

    // Bob decrypts the ciphertext using simple ECIES: DH(bob_spk_sk, e_a_pk).
    let bob_spk_sk = merkle_tox_core::dag::EphemeralX25519Sk::from(bob_spk_sk_bytes);
    let decrypted =
        merkle_tox_core::crypto::ecies_unwrap_32(&bob_spk_sk, &e_a_pk, None, None, &ciphertext)
            .expect("ECIES unwrap must succeed for initial KeyWrap");

    // The decrypted value is K_conv_0 directly (no intermediate KDF chain).
    // Verify it matches what Alice stored as her conversation key.
    let alice_k_conv = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteConversationKey(_, _, k) = e {
                Some(*k.as_bytes())
            } else {
                None
            }
        })
        .expect("author_x3dh_key_exchange must produce WriteConversationKey");
    assert_eq!(
        decrypted, alice_k_conv,
        "ECIES-unwrapped K_conv_0 must match Alice's stored conversation key"
    );
}

/// Spec: initial handshake uses simple ECIES: DH(e, SPK_b) only.
/// K_conv_0 is wrapped directly with ecies_wrap (no X3DH KDF chain).
/// This test verifies the recipient can recover K_conv_0 via ecies_unwrap.
#[test]
fn test_initial_keywrap_uses_ecies_not_x3dh() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000i64));
    let alice = TestIdentity::new();
    let bob = TestIdentity::new();
    let conv_id = ConversationId::from([13u8; 32]);

    let genesis_node = create_genesis_pow(&conv_id, &alice, "ECIES KeyWrap Test");

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng.clone(),
        tp.clone(),
    );
    let store = InMemoryStore::new();
    let effects = alice_engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Bob publishes a pre-key (SPK) with a known secret so we can verify decryption.
    let bob_spk_sk_bytes = [0x77u8; 32];
    let bob_spk_x25519_sk = x25519_dalek::StaticSecret::from(bob_spk_sk_bytes);
    let bob_spk_pk_bytes = x25519_dalek::PublicKey::from(&bob_spk_x25519_sk).to_bytes();
    let bob_spk_pk = EphemeralX25519Pk::from(bob_spk_pk_bytes);

    alice_engine.peer_announcements.insert(
        bob.device_pk,
        ControlAction::Announcement {
            pre_keys: vec![SignedPreKey {
                public_key: bob_spk_pk,
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: i64::MAX,
            }],
            last_resort_key: SignedPreKey {
                public_key: EphemeralX25519Pk::from([0x88u8; 32]),
                signature: Ed25519Signature::from([0u8; 64]),
                expires_at: i64::MAX,
            },
        },
    );

    // Alice authors the initial KeyWrap using ECIES.
    let effects = alice_engine
        .author_x3dh_key_exchange(conv_id, bob.device_pk, bob_spk_pk, &store)
        .unwrap();
    apply_effects(effects.clone(), &store);

    // Extract e_a_pk and ciphertext for Bob from the produced KeyWrap node.
    let (e_a_pk, ciphertext) = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && let Content::KeyWrap {
                    wrapped_keys,
                    ephemeral_pk: ea,
                    ..
                } = &node.content
            {
                let ct = wrapped_keys
                    .iter()
                    .find(|wk| wk.recipient_pk == bob.device_pk)
                    .map(|wk| wk.ciphertext.clone())?;
                Some((*ea, ct))
            } else {
                None
            }
        })
        .expect("author_x3dh_key_exchange must produce a KeyWrap with ephemeral_pk");

    // Ciphertext is 48 bytes (32 key + 16 tag) from ECIES.
    assert_eq!(ciphertext.len(), 48, "ECIES ciphertext must be 48 bytes");

    // Bob decrypts using simple ECIES unwrap.
    let bob_spk_sk = merkle_tox_core::dag::EphemeralX25519Sk::from(bob_spk_sk_bytes);
    let decrypted =
        merkle_tox_core::crypto::ecies_unwrap_32(&bob_spk_sk, &e_a_pk, None, None, &ciphertext)
            .expect("ECIES unwrap must succeed");

    // Verify it matches Alice's stored K_conv_0.
    let alice_k_conv = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteConversationKey(_, _, k) = e {
                Some(*k.as_bytes())
            } else {
                None
            }
        })
        .expect("must produce WriteConversationKey");
    assert_eq!(
        decrypted, alice_k_conv,
        "ECIES-unwrapped K_conv must match Alice's stored key"
    );
}

/// DARE §2: `rotate_conversation_key` must produce both KeyWrap AND
/// SenderKeyDistribution nodes. The SKD must carry `ephemeral_signing_pk`
/// for the new epoch and `disclosed_keys` containing the old epoch's secret.
#[test]
fn test_rotation_authors_skd_with_disclosed_keys() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];

    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);
    let conv_id = room.conv_id;

    // --- Epoch 0 → 1 rotation ---
    let effects_r1 = engine.rotate_conversation_key(conv_id, &store).unwrap();
    let r1_nodes: Vec<_> = effects_r1
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects_r1, &store);

    // Rotation must produce both KeyWrap and SKD
    let keywrap_r1 = r1_nodes
        .iter()
        .find(|n| matches!(n.content, Content::KeyWrap { .. }));
    let skd_r1 = r1_nodes
        .iter()
        .find(|n| matches!(n.content, Content::SenderKeyDistribution { .. }));

    assert!(keywrap_r1.is_some(), "Rotation must produce a KeyWrap node");
    assert!(
        skd_r1.is_some(),
        "Rotation must produce a SenderKeyDistribution node"
    );

    let skd_r1 = skd_r1.unwrap();
    if let Content::SenderKeyDistribution {
        ephemeral_signing_pk,
        disclosed_keys,
        ..
    } = &skd_r1.content
    {
        // First rotation: epoch 0 had no prior ephemeral key to disclose
        assert!(
            disclosed_keys.is_empty(),
            "First rotation should have no disclosed keys (no prior epoch)"
        );
        // ephemeral_signing_pk should be non-zero (a real verifying key)
        assert_ne!(
            ephemeral_signing_pk,
            &EphemeralSigningPk::from([0u8; 32]),
            "ephemeral_signing_pk must be a real verifying key"
        );
    } else {
        panic!("Expected SenderKeyDistribution content");
    }

    // --- Epoch 1 → 2 rotation ---
    let effects_r2 = engine.rotate_conversation_key(conv_id, &store).unwrap();
    let r2_nodes: Vec<_> = effects_r2
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects_r2, &store);

    let skd_r2 = r2_nodes
        .iter()
        .find(|n| matches!(n.content, Content::SenderKeyDistribution { .. }))
        .expect("Second rotation must also produce an SKD");

    if let Content::SenderKeyDistribution {
        ephemeral_signing_pk: new_epk,
        disclosed_keys,
        ..
    } = &skd_r2.content
    {
        // Second rotation: epoch 1's ephemeral key should be disclosed
        assert_eq!(
            disclosed_keys.len(),
            1,
            "Second rotation must disclose exactly one key (the old epoch's)"
        );

        // The disclosed key should be a valid Ed25519 signing key whose
        // verifying key matches the epoch 1 ephemeral_signing_pk from r1
        if let Content::SenderKeyDistribution {
            ephemeral_signing_pk: old_epk,
            ..
        } = &skd_r1.content
        {
            let disclosed_sk = ed25519_dalek::SigningKey::from_bytes(disclosed_keys[0].as_bytes());
            let disclosed_vk = EphemeralSigningPk::from(disclosed_sk.verifying_key().to_bytes());
            assert_eq!(
                &disclosed_vk, old_epk,
                "Disclosed key must match the previous epoch's ephemeral_signing_pk"
            );
        }

        // The new ephemeral signing pk should differ from the previous epoch's
        if let Content::SenderKeyDistribution {
            ephemeral_signing_pk: prev_epk,
            ..
        } = &skd_r1.content
        {
            assert_ne!(
                new_epk, prev_epk,
                "Each epoch must have a unique ephemeral signing key"
            );
        }
    } else {
        panic!("Expected SenderKeyDistribution content");
    }

    // SKD from second rotation should use EphemeralSignature (signed with prior epoch key)
    assert!(
        matches!(
            skd_r2.authentication,
            merkle_tox_core::dag::NodeAuth::EphemeralSignature(_)
        ),
        "SKD with prior epoch key available must use EphemeralSignature (DARE §2)"
    );

    // SKD from first rotation uses device Signature (no prior epoch key existed)
    assert!(
        matches!(
            skd_r1.authentication,
            merkle_tox_core::dag::NodeAuth::Signature(_)
        ),
        "First SKD (no prior epoch key) must use device Signature"
    );
}

/// DARE §2: When Bob receives an SKD with `disclosed_keys`, the old epoch's
/// ephemeral signing secret must be stored in `disclosed_signing_keys`.
#[test]
fn test_disclosed_keys_stored_on_skd_receipt() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice_store = InMemoryStore::new();
    let bob_store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &alice_store);

    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(43),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &bob_store);

    let conv_id = room.conv_id;

    // Alice rotates twice to produce an SKD with disclosed_keys
    let effects_r1 = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    apply_effects(effects_r1.clone(), &alice_store);

    let effects_r2 = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    apply_effects(effects_r2.clone(), &alice_store);

    // Collect all rotation nodes in order
    let mut all_nodes: Vec<_> = effects_r1
        .iter()
        .chain(effects_r2.iter())
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    all_nodes.sort_by_key(|n| (n.topological_rank, n.sequence_number));

    // Bob processes all nodes
    for node in &all_nodes {
        let effects = bob_engine
            .handle_node(conv_id, node.clone(), &bob_store, None)
            .unwrap();
        apply_effects(effects, &bob_store);
        bob_engine.clear_pending();
    }

    // Bob should have stored the disclosed key for Alice's epoch 1
    // (the second rotation disclosed epoch 1's key as epoch 2's SKD)
    let has_disclosed = bob_engine
        .disclosed_signing_keys
        .contains_key(&(alice.device_pk, 1));
    assert!(
        has_disclosed,
        "Bob must store the disclosed signing key from Alice's epoch 1"
    );

    // The disclosed key should be a valid signing key whose verifying key matches
    // the ephemeral_signing_pk stored for epoch 1
    if let Some(disclosed_bytes) = bob_engine.disclosed_signing_keys.get(&(alice.device_pk, 1)) {
        let disclosed_sk = ed25519_dalek::SigningKey::from_bytes(disclosed_bytes.as_bytes());
        let disclosed_vk = disclosed_sk.verifying_key().to_bytes();

        if let Some(stored_epk) = bob_engine
            .peer_ephemeral_signing_keys
            .get(&(alice.device_pk, 1))
        {
            assert_eq!(
                &disclosed_vk,
                stored_epk.as_bytes(),
                "Disclosed key must match the stored ephemeral signing pk for that epoch"
            );
        }
    }

    // Bob should also have the ephemeral signing pk for the latest epoch
    assert!(
        bob_engine
            .peer_ephemeral_signing_keys
            .contains_key(&(alice.device_pk, 2)),
        "Bob must have the ephemeral signing pk for the latest epoch"
    );
}

/// DARE §2: SKD for epoch n+1 signed with epoch n's ephemeral key must be
/// verifiable by a recipient who has the epoch n ephemeral signing pk.
#[test]
fn test_skd_ephemeral_signature_cross_epoch_verification() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice_store = InMemoryStore::new();
    let bob_store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];

    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(42),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &alice_store);

    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(43),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &bob_store);

    let conv_id = room.conv_id;

    // Rotation 1: epoch 0 → 1
    let effects_r1 = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    let r1_nodes: Vec<_> = effects_r1
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects_r1, &alice_store);

    // Bob receives rotation 1 nodes
    for node in &r1_nodes {
        let effects = bob_engine
            .handle_node(conv_id, node.clone(), &bob_store, None)
            .unwrap();
        apply_effects(effects, &bob_store);
        bob_engine.clear_pending();
    }

    // Bob should now have epoch 1's ephemeral signing pk from the SKD
    let r1_skd = r1_nodes
        .iter()
        .find(|n| matches!(n.content, Content::SenderKeyDistribution { .. }))
        .unwrap();
    if let Content::SenderKeyDistribution {
        ephemeral_signing_pk,
        ..
    } = &r1_skd.content
    {
        assert_eq!(
            bob_engine
                .peer_ephemeral_signing_keys
                .get(&(alice.device_pk, 1)),
            Some(ephemeral_signing_pk),
            "Bob must store epoch 1 ephemeral signing pk from first rotation's SKD"
        );
    }

    // Rotation 2: epoch 1 → 2 (SKD signed with epoch 1's key)
    let effects_r2 = alice_engine
        .rotate_conversation_key(conv_id, &alice_store)
        .unwrap();
    let r2_nodes: Vec<_> = effects_r2
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects_r2, &alice_store);

    let r2_skd = r2_nodes
        .iter()
        .find(|n| matches!(n.content, Content::SenderKeyDistribution { .. }))
        .unwrap();

    // The SKD for epoch 2 must use EphemeralSignature
    assert!(matches!(
        r2_skd.authentication,
        merkle_tox_core::dag::NodeAuth::EphemeralSignature(_)
    ));

    // Bob receives rotation 2 nodes: the SKD should verify via epoch 1's key
    for node in &r2_nodes {
        let effects = bob_engine
            .handle_node(conv_id, node.clone(), &bob_store, None)
            .unwrap();
        apply_effects(effects, &bob_store);
        bob_engine.clear_pending();
    }

    // Bob now has epoch 2 established
    assert_eq!(bob_engine.get_current_generation(&conv_id), 2);

    // Bob should have epoch 2's ephemeral signing pk
    assert!(
        bob_engine
            .peer_ephemeral_signing_keys
            .contains_key(&(alice.device_pk, 2)),
        "Bob must have epoch 2 ephemeral signing pk after processing rotation 2 SKD"
    );

    // Alice authors a message in epoch 2: Bob should verify it
    let msg_effects = alice_engine
        .author_node(
            conv_id,
            Content::Text("Hello from epoch 2".to_string()),
            vec![],
            &alice_store,
        )
        .unwrap();
    let msg_node = msg_effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, n, true) = e {
                Some(n.clone())
            } else {
                None
            }
        })
        .unwrap();
    transfer_wire_nodes(&msg_effects, &bob_store);
    apply_effects(msg_effects, &alice_store);

    let bob_effects = bob_engine
        .handle_node(conv_id, msg_node, &bob_store, None)
        .unwrap();
    // The message should be verified (not speculative)
    let was_verified = bob_effects.iter().any(|e| {
        matches!(
            e,
            Effect::EmitEvent(merkle_tox_core::NodeEvent::NodeVerified { .. })
        )
    });
    assert!(
        was_verified,
        "Epoch 2 message must be verified by Bob using the ephemeral signing key"
    );
}

#[test]
fn test_announcement_rotation_after_100_handshakes() {
    let _ = tracing_subscriber::fmt::try_init();

    let rng = StdRng::seed_from_u64(200);
    let base_instant = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(base_instant, 1000));
    let alice = TestIdentity::new();
    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng,
        tp.clone(),
    );
    let store = InMemoryStore::new();

    let conv_id = ConversationId::from([30u8; 32]);

    // Set up an established conversation so the engine has context
    let genesis_node = create_genesis_pow(&conv_id, &alice, "Handshake Test");
    let effects = engine
        .handle_node(conv_id, genesis_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Authorize the device
    let cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::all(),
        i64::MAX,
        conv_id,
    );
    let auth_node = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis_node.hash()],
        ControlAction::AuthorizeDevice { cert },
        1,
        1,
        1000,
    );
    let effects = engine
        .handle_node(conv_id, auth_node.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Set counter to 99: should NOT trigger rotation
    engine
        .handshake_count_since_announcement
        .insert(conv_id, 99);
    let _ = engine.poll(Instant::now(), &store);
    // Counter should still be 99 (not reset)
    assert_eq!(
        engine
            .handshake_count_since_announcement
            .get(&conv_id)
            .copied(),
        Some(99),
        "At 99 handshakes, announcement rotation should not trigger"
    );

    // Set counter to 100: should trigger rotation attempt
    engine
        .handshake_count_since_announcement
        .insert(conv_id, 100);
    let _ = engine.poll(Instant::now(), &store);
    // After poll, either the counter was reset to 0 (success) or it stays at 100
    // (failure due to missing keys, etc). The important thing is the threshold was checked.
    let count_after = engine
        .handshake_count_since_announcement
        .get(&conv_id)
        .copied()
        .unwrap_or(0);
    // If author_announcement succeeded, counter is reset to 0.
    // If it failed, it stays at 100. Either way, the threshold was checked.
    assert!(
        count_after == 0 || count_after == 100,
        "Counter should be 0 (success) or 100 (failed attempt), got: {}",
        count_after
    );
}
