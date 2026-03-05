//! Adversarial coverage for `Content::SenderKeyDistribution.disclosed_keys`.
//!
//! On SKD ingest, `apply_side_effects` (side_effects.rs) iterates the
//! peer-supplied `disclosed_keys` vector and stores each entry under
//! key `(sender_pk, epoch - 1 - i)`. The peer controls
//! `disclosed_keys.len()`; spec gives no upper bound. When
//! `disclosed_keys.len() > epoch`, the inner subtraction underflows.
//!
//! * **Debug build** (the default for `bazel test`): the subtraction
//!   panics on underflow → process crash → DoS reachable from any
//!   admin-authored SKD.
//! * **Release build**: wraps to `u64::MAX - k`, inserting a junk
//!   entry into `disclosed_signing_keys` that never matches any
//!   future signature lookup. The map grows unboundedly across
//!   repeated malicious SKDs.
//!
//! Round 10 fix: `(epoch - 1).checked_sub(i as u64)` with break-on-None
//! at side_effects.rs:302. Stops the loop the moment the chain would
//! underflow.

use ed25519_dalek::SigningKey;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, EphemeralSigningPk, EphemeralSigningSk,
    EphemeralX25519Pk, NodeHash, Permissions, PhysicalDeviceSk,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, apply_effects, create_admin_node, create_genesis_pow, make_cert,
    sign_admin_node, test_node,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// §SKD-1 — A `SenderKeyDistribution` carrying more `disclosed_keys`
/// than the SKD's own epoch must NOT panic on ingest, and must NOT
/// poison `engine.disclosed_signing_keys` with underflowed-epoch
/// junk entries (e.g. keys at `disclosed_epoch ≈ u64::MAX`).
///
/// Pre-fix behaviour: `epoch - 1 - i as u64` panics in debug builds
/// the moment `i >= epoch`; in release wraps to `u64::MAX - k` and
/// the loop continues, polluting the map. Either way is exploitable.
#[test]
fn test_skd_with_excess_disclosed_keys_does_not_panic_or_pollute() {
    let _ = tracing_subscriber::fmt::try_init();
    let rng = StdRng::seed_from_u64(42);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let conv_id = ConversationId::from([0xC1u8; 32]);

    let mut engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        rng,
        tp,
    );
    let store = InMemoryStore::new();

    // Stand up a minimal admin chain so the SKD has a verifiable parent
    // and Alice is recognized as an authorised admin.
    let genesis = create_genesis_pow(&conv_id, &alice, "SKD underflow test");
    let effects = engine
        .handle_node(conv_id, genesis.clone(), &store, None)
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
        vec![genesis.hash()],
        ControlAction::AuthorizeDevice { cert: alice_cert },
        1,
        1,
        1000,
    );
    let effects = engine
        .handle_node(conv_id, auth_alice.clone(), &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Construct a device-signed SKD at epoch=1 with five disclosed
    // keys. With epoch=1, the legitimate disclosure list length is 1
    // (the prior epoch's signing key). Five entries forces the loop
    // to walk past epoch and into underflow territory.
    let mut skd = test_node();
    skd.parents = tox_proto::bounded_vec![auth_alice.hash()];
    skd.author_pk = alice.master_pk;
    skd.sender_pk = alice.device_pk;
    // Sequence number = (epoch << 32) | seq_in_epoch. epoch=1, seq=1.
    skd.sequence_number = (1u64 << 32) | 1;
    skd.topological_rank = 2;
    skd.network_timestamp = 1000;
    skd.content = Content::SenderKeyDistribution {
        ephemeral_pk: EphemeralX25519Pk::from([0u8; 32]),
        wrapped_keys: tox_proto::BoundedVec::new(),
        ephemeral_signing_pk: EphemeralSigningPk::from(
            SigningKey::from_bytes(&[0xAAu8; 32])
                .verifying_key()
                .to_bytes(),
        ),
        // Five entries vs epoch=1 → loop indices 0..=4. Index 0 is the
        // only legitimate entry (epoch-1 = 0). Indices 1..=4 each
        // would require the map key `(sender, u64::MAX - k)` — the
        // pre-fix behaviour.
        disclosed_keys: tox_proto::bounded_vec![
            EphemeralSigningSk::from([0x11u8; 32]),
            EphemeralSigningSk::from([0x22u8; 32]),
            EphemeralSigningSk::from([0x33u8; 32]),
            EphemeralSigningSk::from([0x44u8; 32]),
            EphemeralSigningSk::from([0x55u8; 32]),
        ],
    };
    sign_admin_node(&mut skd, &conv_id, &alice.device_sk);

    // Pre-fix in debug: this call panics inside apply_side_effects.
    // Post-fix: returns Ok with the loop terminating at the first
    // underflow boundary.
    let _ = engine
        .handle_node(conv_id, skd, &store, None)
        .expect("malicious SKD must not produce an Err — silent drop is fine");

    // Cryptographic-impact check: no entry whose epoch is anywhere
    // near `u64::MAX`. The legitimate key is at epoch 0; everything
    // else (if anything) must also be a small value.
    let alice_dev = alice.device_pk;
    for (peer, ep) in engine.disclosed_signing_keys.keys() {
        if *peer == alice_dev {
            assert!(
                *ep < 1_000_000,
                "disclosed_signing_keys must not contain underflowed \
                 epoch values — found ({:?}, {}) which indicates the \
                 epoch arithmetic wrapped via u64 underflow",
                hex::encode(peer.as_bytes()),
                ep,
            );
        }
    }

    // Per-spec, only the index-0 entry is legitimate (epoch-1=0).
    // Indices 1..=4 must be silently dropped, leaving exactly one
    // (alice_dev, 0) entry from this SKD.
    let alice_entries = engine
        .disclosed_signing_keys
        .iter()
        .filter(|((peer, _), _)| *peer == alice_dev)
        .count();
    assert!(
        alice_entries <= 1,
        "expected at most 1 legitimate disclosed-key entry for the \
         SKD's sender, found {} — indicates the loop ran past the \
         underflow boundary and inserted wrap-around entries",
        alice_entries,
    );

    let _ = NodeHash::from([0u8; 32]); // suppress unused-import warning
}
