//! Adversarial: `KeyWrap` `consumed_opk_ids` is recorded BEFORE
//! the ECIES decryption attempt — letting an authorized peer
//! pre-claim any OPK they observe in an Announcement.
//!
//! ## Attack
//!
//! At `engine/processor/verification.rs:502`, when a KeyWrap targets
//! the receiver's `self_pk` and carries a non-zero `opk_id`, the
//! engine inserts `(opk_id → (node_hash, sender_pk, rank))` into
//! `consumed_opk_ids` *before* the loop at `:507` that attempts to
//! decrypt the wrapped ciphertext. Consequence: a peer can ship a
//! KeyWrap whose `wrapped.ciphertext` is junk, "consume" any OPK
//! they like, and have that consumption persist in the receiver's
//! collision-tracker forever.
//!
//! When a legitimate sender later publishes a real KeyWrap for the
//! same `opk_id` (which, per the spec, can happen because pre-keys
//! are published in `Announcement` and may legitimately be picked
//! by multiple senders), the receiver's collision logic at
//! `:461-498` runs the seniority tiebreaker against the bogus
//! pre-claim. If the pre-claimer wins the tiebreaker, the
//! legitimate KeyWrap entry is `continue`d at `:490` and the real
//! K_conv is never delivered. K_conv distribution is denied.
//!
//! The fix is to move the `consumed_opk_ids.insert` into the
//! success-decryption branch, so a KeyWrap that fails to decrypt
//! never burns the OPK in the collision tracker.
//!
//! Found in audit round 7 (auditor's secondary finding 2a).

use merkle_tox_core::crypto::ecies_wrap;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EphemeralX25519Pk, EphemeralX25519Sk, KConv, NodeHash,
    Permissions, PhysicalDeviceSk, WrappedKey,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_genesis_pow, make_cert,
    sign_admin_node, test_node,
};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

/// §KW-PRE-1 — A KeyWrap with junk ciphertext (cannot decrypt) must
/// not pre-claim the OPK in `consumed_opk_ids`. Without the fix,
/// the bogus consumption persists and can later cause a legitimate
/// KeyWrap for the same OPK to lose the seniority tiebreaker.
#[test]
fn test_failed_keywrap_must_not_burn_opk_in_collision_tracker() {
    let _ = tracing_subscriber::fmt::try_init();

    let alice = TestIdentity::new(); // founder + legit sender
    let bob = TestIdentity::new(); // authorized; sends bogus KeyWrap
    let charlie = TestIdentity::new(); // recipient (publishes the OPK)
    let conv_id = ConversationId::from([0xCAu8; 32]);

    // ── Conversation setup: Alice founder, Alice + Bob authorized
    let genesis = create_genesis_pow(&conv_id, &alice, "§2a OPK pre-claim");
    let alice_cert = make_cert(
        &alice.master_sk,
        alice.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
    let auth_alice = create_admin_node(
        &conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis.hash()],
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1,
        1,
        1000,
    );
    let bob_cert = make_cert(
        &bob.master_sk,
        bob.device_pk,
        Permissions::ALL,
        9_999_999,
        conv_id,
    );
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

    // Charlie's OPK keypair (the target of pre-claim)
    let charlie_opk_sk_bytes = [0x42u8; 32];
    let charlie_opk_x_sk = x25519_dalek::StaticSecret::from(charlie_opk_sk_bytes);
    let charlie_opk_pk =
        EphemeralX25519Pk::from(x25519_dalek::PublicKey::from(&charlie_opk_x_sk).to_bytes());
    let charlie_opk_id = NodeHash::from(*blake3::hash(charlie_opk_pk.as_bytes()).as_bytes());

    // ── Charlie engine
    let tp = Arc::new(merkle_tox_core::clock::ManualTimeProvider::new(
        Instant::now(),
        3000,
    ));
    let mut charlie_engine = MerkleToxEngine::with_sk(
        charlie.device_pk,
        charlie.master_pk,
        PhysicalDeviceSk::from(charlie.device_sk.to_bytes()),
        rand::rngs::StdRng::seed_from_u64(0xCAFE),
        tp,
    );
    let store = InMemoryStore::new();
    for node in [&genesis, &auth_alice, &auth_bob] {
        let effects = charlie_engine
            .handle_node(conv_id, node.clone(), &store, None)
            .expect("admin chain node");
        apply_effects(effects, &store);
    }
    // Provision Charlie's OPK secret so legitimate KeyWraps can decrypt.
    charlie_engine
        .ephemeral_keys
        .insert(charlie_opk_pk, EphemeralX25519Sk::from(charlie_opk_sk_bytes));

    // ── Step 1: Bob ships a KeyWrap with junk ciphertext for Charlie's OPK.
    // The ciphertext is encrypted to a *different* X25519 key than Charlie's,
    // so Charlie's ECIES unwrap will fail (MAC mismatch).
    let k_conv_junk = KConv::from([0xBAu8; 32]);
    let bogus_recipient_x_sk = x25519_dalek::StaticSecret::from([0xCDu8; 32]);
    let bogus_recipient_pk = EphemeralX25519Pk::from(
        x25519_dalek::PublicKey::from(&bogus_recipient_x_sk).to_bytes(),
    );
    let bob_eph_x_sk = x25519_dalek::StaticSecret::from([0xB0u8; 32]);
    let bob_eph_pk = EphemeralX25519Pk::from(
        x25519_dalek::PublicKey::from(&bob_eph_x_sk).to_bytes(),
    );
    let bob_junk_ciphertext = ecies_wrap(
        &EphemeralX25519Sk::from([0xB0u8; 32]),
        &bogus_recipient_pk, // wrong recipient → Charlie's OPK won't unwrap it
        None,
        None,
        k_conv_junk.as_bytes(),
    );
    let bob_wrapped = WrappedKey {
        recipient_pk: charlie.device_pk, // claim Charlie as recipient
        ciphertext: bob_junk_ciphertext,
        opk_id: charlie_opk_id,
    };
    let mut bob_kw = test_node();
    bob_kw.author_pk = bob.master_pk;
    bob_kw.parents = tox_proto::BoundedVec::try_from_iter(vec![auth_bob.hash()])
        .expect("one parent");
    bob_kw.content = Content::KeyWrap {
        generation: 1,
        anchor_hash: NodeHash::from([0u8; 32]),
        ephemeral_pk: bob_eph_pk,
        wrapped_keys: tox_proto::bounded_vec![bob_wrapped],
    };
    bob_kw.topological_rank = 3;
    bob_kw.sequence_number = 2;
    bob_kw.network_timestamp = 2000;
    sign_admin_node(&mut bob_kw, &conv_id, &bob.device_sk);

    let effects = charlie_engine
        .handle_node(conv_id, bob_kw, &store, None)
        .expect("Bob's bogus KeyWrap is structurally valid; node verifies");
    apply_effects(effects, &store);

    // ── Post-fix assertion: Charlie's collision-tracker must not
    // record Bob's bogus KeyWrap as having consumed Charlie's OPK,
    // because the ECIES decryption failed. The OPK is still
    // available for legitimate KeyWraps.
    assert!(
        !charlie_engine.consumed_opk_ids.contains_key(&charlie_opk_id),
        "Pre-fix: consumed_opk_ids[charlie_opk_id] is set to Bob's KeyWrap \
         even though decryption failed. This burns Charlie's OPK in the \
         collision-tracker and can deny K_conv distribution from any later \
         legitimate sender that loses the seniority tiebreaker against Bob.",
    );

    // ── Step 2: Alice ships a legitimate KeyWrap for the same OPK.
    let k_conv_alice = KConv::from([0xA1u8; 32]);
    let alice_eph_x_sk = x25519_dalek::StaticSecret::from([0xA0u8; 32]);
    let alice_eph_pk = EphemeralX25519Pk::from(
        x25519_dalek::PublicKey::from(&alice_eph_x_sk).to_bytes(),
    );
    let alice_real_ciphertext = ecies_wrap(
        &EphemeralX25519Sk::from([0xA0u8; 32]),
        &charlie_opk_pk,       // SPK slot
        Some(&charlie_opk_pk), // OPK slot — wrap material must match
                               // unwrap material, and unwrap includes
                               // the OPK contribution because
                               // `find_opk_sk` returns Some for our
                               // non-zero opk_id.
        None,
        k_conv_alice.as_bytes(),
    );
    let alice_wrapped = WrappedKey {
        recipient_pk: charlie.device_pk,
        ciphertext: alice_real_ciphertext,
        opk_id: charlie_opk_id,
    };
    let mut alice_kw = test_node();
    alice_kw.author_pk = alice.master_pk;
    alice_kw.parents = tox_proto::BoundedVec::try_from_iter(vec![auth_bob.hash()])
        .expect("one parent");
    alice_kw.content = Content::KeyWrap {
        generation: 1,
        anchor_hash: NodeHash::from([0u8; 32]),
        ephemeral_pk: alice_eph_pk,
        wrapped_keys: tox_proto::bounded_vec![alice_wrapped],
    };
    alice_kw.topological_rank = 3;
    alice_kw.sequence_number = 2;
    alice_kw.network_timestamp = 2001;
    sign_admin_node(&mut alice_kw, &conv_id, &alice.device_sk);

    let effects = charlie_engine
        .handle_node(conv_id, alice_kw, &store, None)
        .expect("Alice's legitimate KeyWrap must verify");
    apply_effects(effects, &store);

    // After Alice's legit KeyWrap, consumed_opk_ids should be set
    // (this time legitimately) to Alice's entry.
    let entry = charlie_engine.consumed_opk_ids.get(&charlie_opk_id);
    assert!(
        entry.is_some(),
        "Alice's legitimate KeyWrap must register in consumed_opk_ids \
         (post-fix path: insert happens after successful decryption)",
    );
    let (_, recorded_sender, _) = entry.unwrap();
    assert_eq!(
        *recorded_sender, alice.device_pk,
        "Alice (the actual successful decrypter) must be the recorded \
         sender. Pre-fix without the seniority tiebreaker: Bob's pre-claim \
         could have stuck (depending on tiebreaker), denying Alice's K_conv \
         distribution to Charlie.",
    );
    let _ = charlie; // suppress warning
}
