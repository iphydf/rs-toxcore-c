//! Adversarial: second-Genesis injection corrupts the founder anchor.
//!
//! ## Attack chain
//!
//! For a conversation `X`, only the original founder's Genesis node
//! should ever be accepted. The verifier currently treats Genesis as
//! `is_bootstrap = true`, so the parent-not-verified and unauthorized-
//! without-vouches quarantines (`verification.rs:138, :148`) are
//! bypassed. Combined with the self-bind shortcut in `is_authorized`
//! (`identity.rs:622`: returns `true` when `device_pk == logical_pk
//! .to_physical()`), any peer who knows `conv_id` can craft a Genesis
//! with their own keys and have it accepted as a SECOND founder.
//!
//! The state mutation in `apply_side_effects`
//! (`engine/processor/side_effects.rs:55-80`) then runs:
//! - `identity_manager.add_member(...)` — registers the attacker as
//!   a role-0 (Owner/Admin) member alongside the legitimate founder.
//! - `latest_anchor_hashes.insert(conv_id, attacker_genesis_hash)`
//!   — overwrites the trusted anchor.
//!
//! Downstream impact:
//! - `IdentityManager::get_founder` (`identity.rs:301-312`) returns
//!   the lex-smallest `LogicalIdentityPk` with role 0 from a
//!   `BTreeMap`, so if the attacker's `logical_pk` precedes the real
//!   founder's, all `verify_delegation` checks for AnchorSnapshots
//!   and admin certs (`verification.rs:803-832`,
//!   `engine/processor/snapshot.rs::verify_anchor_snapshot`) verify
//!   against the attacker's key — the attacker can mint admin certs
//!   that the codebase trusts as if from the real founder.
//! - `latest_anchor_hashes` overwrite affects KeyWrap chain anchoring.
//!
//! Found in audit round 6. The receiver-side fix is to refuse a
//! second Genesis at the verifier: drop the message if a founder
//! already exists for `conversation_id`.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, MerkleNode};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, TestIdentity, apply_effects, create_genesis_pow};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

/// Build a `MerkleNode` representing a forged Genesis: caller supplies
/// the identity and conversation. PoW + signature are real (the
/// attacker has full control of their own keys), so structurally
/// valid.
fn forge_genesis(conv_id: &ConversationId, attacker: &TestIdentity) -> MerkleNode {
    create_genesis_pow(conv_id, attacker, "Forged second Genesis")
}

/// §GI-1 — Founder anchor must not be overwritten by a second
/// Genesis. After a legitimate Genesis from Alice, an attacker
/// (Mallory) cannot mint a second Genesis for the same conversation
/// and have it register her as a co-founder.
#[test]
fn test_second_genesis_does_not_overwrite_founder_anchor() {
    let _ = tracing_subscriber::fmt::try_init();

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let mallory = TestIdentity::new();
    let conv_id = ConversationId::from([0xC1u8; 32]);
    let rng = StdRng::seed_from_u64(0x6E5151);

    // Bob is the receiver: starts with no conversation state, then
    // ingests Alice's legitimate Genesis. After this, Bob knows
    // Alice as the founder.
    let mut bob_engine = MerkleToxEngine::new(
        TestIdentity::new().device_pk,
        TestIdentity::new().master_pk,
        rng,
        tp,
    );
    let bob_store = InMemoryStore::new();

    let alice_genesis = create_genesis_pow(&conv_id, &alice, "Conv X");
    let alice_genesis_hash = alice_genesis.hash();
    let effects = bob_engine
        .handle_node(conv_id, alice_genesis.clone(), &bob_store, None)
        .expect("Alice's legitimate Genesis must verify");
    apply_effects(effects, &bob_store);

    let alice_logical = alice.master_pk;
    assert_eq!(
        bob_engine.identity_manager.get_founder(&conv_id),
        Some(alice_logical),
        "Bob must register Alice as the founder of conv_id after \
         processing her Genesis",
    );
    assert_eq!(
        bob_engine.latest_anchor_hashes.get(&conv_id),
        Some(&alice_genesis_hash),
        "latest_anchor_hashes must point to Alice's Genesis hash",
    );

    // Now Mallory ships her own forged Genesis for the same conv_id.
    // Mallory's Genesis is structurally valid: real PoW, real
    // signature with her own key. The verifier's self-bind shortcut
    // in is_authorized (identity.rs:622) and the is_bootstrap
    // quarantine bypass (verification.rs:148) admit it today.
    let mallory_genesis = forge_genesis(&conv_id, &mallory);
    let mallory_genesis_hash = mallory_genesis.hash();
    let effects = bob_engine
        .handle_node(conv_id, mallory_genesis.clone(), &bob_store, None)
        .expect("handle_node must not error on adversarial input");
    apply_effects(effects, &bob_store);

    // Post-fix assertions: Bob's view of the founder is unchanged,
    // anchor hash unchanged, no Mallory member added.
    assert_eq!(
        bob_engine.identity_manager.get_founder(&conv_id),
        Some(alice_logical),
        "After Mallory's forged Genesis, get_founder must still \
         return Alice. Without the fix, get_founder may return \
         Mallory (BTreeMap iteration yields lex-smallest \
         LogicalIdentityPk; if Mallory's pk precedes Alice's, the \
         attacker has supplanted the founder anchor — every \
         AnchorSnapshot and admin cert is verified against \
         Mallory's key thereafter).",
    );
    assert_eq!(
        bob_engine.latest_anchor_hashes.get(&conv_id),
        Some(&alice_genesis_hash),
        "latest_anchor_hashes must still point to Alice's Genesis \
         hash. Pre-fix the second Genesis insert (side_effects.rs:68) \
         overwrites it with Mallory's hash unconditionally — \
         corrupting any KeyWrap chain anchoring against the \
         legitimate Genesis.",
    );

    // Belt-and-braces: the forged Genesis must not appear in Bob's
    // verified DAG either. (Storing the wire node for re-distribution
    // is acceptable; promoting it to a verified MerkleNode is not.)
    assert!(
        !bob_store.is_verified(&mallory_genesis_hash),
        "Mallory's forged Genesis must not be marked verified — that \
         would let Bob accept downstream nodes claiming Mallory's \
         genesis as parent.",
    );
}

/// §GI-2 — Honest baseline: the legitimate Genesis arriving FIRST
/// must still register the founder normally. Without this guard the
/// fix could degenerate to "reject all Genesis" and pass §GI-1
/// trivially.
#[test]
fn test_first_genesis_still_registers_founder() {
    let _ = tracing_subscriber::fmt::try_init();

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let conv_id = ConversationId::from([0xC2u8; 32]);
    let rng = StdRng::seed_from_u64(0x6E5152);

    let mut bob_engine = MerkleToxEngine::new(
        TestIdentity::new().device_pk,
        TestIdentity::new().master_pk,
        rng,
        tp,
    );
    let bob_store = InMemoryStore::new();
    let alice_genesis = create_genesis_pow(&conv_id, &alice, "Conv Y");
    let effects = bob_engine
        .handle_node(conv_id, alice_genesis, &bob_store, None)
        .expect("Alice's legitimate Genesis must verify");
    apply_effects(effects, &bob_store);

    assert_eq!(
        bob_engine.identity_manager.get_founder(&conv_id),
        Some(alice.master_pk),
        "the FIRST Genesis (Alice's legitimate) must still register \
         her as the founder — the fix must not reject all Genesis",
    );
}

/// §GI-3 — Second-Genesis path through the wire-level
/// `ProtocolMessage::MerkleNode` handler. Same attack as §GI-1 but
/// driven through `engine.handle_message` rather than the direct
/// `handle_node` entry point, exercising the same path a malicious
/// peer would actually use over the network.
#[test]
fn test_second_genesis_via_handle_message_does_not_overwrite() {
    use merkle_tox_core::crypto::PackKeys;
    use merkle_tox_core::dag::{KConv, PhysicalDevicePk};
    use merkle_tox_core::engine::Conversation;
    use merkle_tox_core::engine::conversation::{ConversationData, Established};

    let _ = tracing_subscriber::fmt::try_init();

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let alice = TestIdentity::new();
    let mallory = TestIdentity::new();
    let conv_id = ConversationId::from([0xC3u8; 32]);
    let rng = StdRng::seed_from_u64(0x6E5153);

    let mut bob_engine = MerkleToxEngine::new(
        TestIdentity::new().device_pk,
        TestIdentity::new().master_pk,
        rng,
        tp,
    );
    let bob_store = InMemoryStore::new();

    // Bob has joined conv_id (as required by the recently-added
    // MerkleNode handler gate at handlers/mod.rs which drops messages
    // naming an unknown conversation).
    let established =
        ConversationData::<Established>::new(conv_id, KConv::from([0x11u8; 32]), 1000);
    bob_engine
        .conversations
        .insert(conv_id, Conversation::Established(established));

    // Bob has Alice's legitimate Genesis verified in his store.
    let alice_genesis = create_genesis_pow(&conv_id, &alice, "Conv Z");
    let alice_genesis_hash = alice_genesis.hash();
    let effects = bob_engine
        .handle_node(conv_id, alice_genesis, &bob_store, None)
        .expect("Alice's Genesis verifies");
    apply_effects(effects, &bob_store);

    // Mallory packs her forged Genesis as a wire node and ships it.
    let mallory_genesis = forge_genesis(&conv_id, &mallory);
    let mallory_wire = mallory_genesis
        .pack_wire(&PackKeys::Exception, false)
        .expect("Genesis should pack as Exception (cleartext)");
    let mallory_pk = PhysicalDevicePk::from(mallory.device_sk.verifying_key().to_bytes());

    let effects = bob_engine
        .handle_message(
            mallory_pk,
            ProtocolMessage::MerkleNode {
                conversation_id: conv_id,
                hash: mallory_genesis.hash(),
                node: mallory_wire,
            },
            &bob_store,
            None,
        )
        .expect("handle_message must not error");
    apply_effects(effects, &bob_store);

    assert_eq!(
        bob_engine.identity_manager.get_founder(&conv_id),
        Some(alice.master_pk),
        "Wire-level forged Genesis must not change the founder — \
         this is the actual exploitation path over the network",
    );
    assert_eq!(
        bob_engine.latest_anchor_hashes.get(&conv_id),
        Some(&alice_genesis_hash),
        "Wire-level forged Genesis must not overwrite the anchor hash",
    );
}
