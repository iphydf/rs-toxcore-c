//! Forged `KeywrapAck` adversarial coverage.
//!
//! `KeywrapAck` is an off-DAG transport message carrying only
//! `(keywrap_hash, recipient_pk)`. Both fields are publicly observable:
//! the `keywrap_hash` is the DAG node hash of a broadcast KeyWrap, and
//! `recipient_pk` is a cleartext field inside each `WrappedKey` entry.
//! If the handler accepts the ACK purely on content match, any passive
//! observer can forge an ACK as if they were the recipient. Two distinct
//! consequences follow:
//!
//!   1. `keywrap_pending` is released → the `§3.8` OPK-collision losing
//!      initiator can author content nodes before the real recipient
//!      has confirmed delivery. Those nodes are encrypted under a
//!      k_conv no one else possesses and become permanently unreadable
//!      DAG entries (history-erasure adjacent).
//!   2. The `keywrap_ack_counts` counter is incremented → at the 50 %
//!      threshold, `self_ephemeral_signing_keys` for prior epochs are
//!      wiped prematurely. Subsequent SKD nodes fall back to device
//!      signatures and lose the deniable authentication guarantee
//!      (§3.1 residual risk widens).
//!
//! The fix is cryptographically cheap: the Tox transport already
//! authenticates `sender_pk`, so the handler can enforce
//! `sender_pk == recipient_pk` before applying any side effect.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{KConv, NodeHash};
use merkle_tox_core::engine::{Conversation, KeyWrapPending, MerkleToxEngine};
use merkle_tox_core::engine::conversation::{ConversationData, Established};
use merkle_tox_core::testing::{InMemoryStore, TestRoom};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

/// Setup: three-identity room (founder, real recipient, attacker).
/// Engine is controlled by identity[0] (the KeyWrap initiator).
fn setup_three_party() -> (TestRoom, MerkleToxEngine, InMemoryStore) {
    let room = TestRoom::new(3);
    let store = InMemoryStore::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        StdRng::seed_from_u64(0x4E1),
        tp,
    );
    room.setup_engine(&mut engine, &store);
    (room, engine, store)
}

/// Arrange: a KeyWrap is pending delivery to identity[1]. Pre-seed the
/// ack counter at one short of the 50 % erasure threshold so a single
/// forged ACK would trip it if the handler were not authenticating
/// the sender.
fn seed_pending_and_counts(
    engine: &mut MerkleToxEngine,
    room: &TestRoom,
    kw_hash: NodeHash,
) {
    let established = ConversationData::<Established>::new(
        room.conv_id,
        KConv::from([0xCCu8; 32]),
        1000,
    );
    engine
        .conversations
        .insert(room.conv_id, Conversation::Established(established));
    if let Some(Conversation::Established(e)) = engine.conversations.get_mut(&room.conv_id) {
        e.state.current_epoch = 2;
    }
    engine
        .self_ephemeral_signing_keys
        .insert(0, ed25519_dalek::SigningKey::from_bytes(&[0x01u8; 32]));
    engine
        .self_ephemeral_signing_keys
        .insert(1, ed25519_dalek::SigningKey::from_bytes(&[0x02u8; 32]));
    engine
        .self_ephemeral_signing_keys
        .insert(2, ed25519_dalek::SigningKey::from_bytes(&[0x03u8; 32]));
    // total=4, acks=1 → one more valid ACK trips the 50 % threshold.
    engine.keywrap_ack_counts.insert(room.conv_id, (1, 4));
    engine.keywrap_pending.insert(
        kw_hash,
        KeyWrapPending {
            conversation_id: room.conv_id,
            recipient_pk: room.identities[1].device_pk,
            created_at: Instant::now(),
            attempts: 0,
        },
    );
}

/// §KW-ACK-1 — A `KeywrapAck` whose `sender_pk` is not the wrapped
/// recipient must be dropped: pending state is preserved, ack counter
/// is not advanced, and prior-epoch signing keys are NOT wiped.
#[test]
fn test_forged_keywrap_ack_from_non_recipient_is_rejected() {
    let (room, mut engine, store) = setup_three_party();
    let real_recipient = room.identities[1].device_pk;
    let attacker = room.identities[2].device_pk;
    let kw_hash = NodeHash::from([0xDDu8; 32]);

    seed_pending_and_counts(&mut engine, &room, kw_hash);

    engine
        .handle_message(
            attacker,
            ProtocolMessage::KeywrapAck {
                keywrap_hash: kw_hash,
                recipient_pk: tox_proto::Claimed::new(real_recipient),
            },
            &store,
            None,
        )
        .expect("handle_message");

    assert!(
        engine.keywrap_pending.contains_key(&kw_hash),
        "pending KeyWrap must NOT be released by a forged ACK — otherwise \
         an §3.8 OPK-collision loser could author unreadable content \
         before the real recipient confirms delivery",
    );
    let (acks, total) = engine
        .keywrap_ack_counts
        .get(&room.conv_id)
        .copied()
        .expect("ack counts");
    assert_eq!(
        (acks, total),
        (1, 4),
        "forged ACK must not advance the 50 % erasure counter",
    );
    assert!(
        engine.self_ephemeral_signing_keys.contains_key(&0)
            && engine.self_ephemeral_signing_keys.contains_key(&1),
        "prior-epoch signing keys must survive a forged ACK — premature \
         erasure forces SKD to fall back to device signatures and \
         undermines deniability",
    );
}

/// §KW-ACK-2 — Regression guard: a legitimate ACK (sender_pk == recipient_pk)
/// still releases the pending state and advances the counter. Pairs with
/// the adversarial case above so the fix can't be "reject everything".
#[test]
fn test_legitimate_keywrap_ack_still_releases_pending() {
    let (room, mut engine, store) = setup_three_party();
    let real_recipient = room.identities[1].device_pk;
    let kw_hash = NodeHash::from([0xEEu8; 32]);

    seed_pending_and_counts(&mut engine, &room, kw_hash);

    engine
        .handle_message(
            real_recipient,
            ProtocolMessage::KeywrapAck {
                keywrap_hash: kw_hash,
                recipient_pk: tox_proto::Claimed::new(real_recipient),
            },
            &store,
            None,
        )
        .expect("handle_message");

    assert!(
        !engine.keywrap_pending.contains_key(&kw_hash),
        "genuine ACK from the wrapped recipient must release pending state",
    );
}

/// §KW-ACK-3 — A forged ACK that also lies about `recipient_pk` (e.g.
/// attacker names themselves as the recipient) must be rejected by the
/// content check AND/OR the sender check. Guards against an attacker
/// simply claiming to be the recipient.
#[test]
fn test_forged_keywrap_ack_claiming_to_be_recipient_is_rejected() {
    let (room, mut engine, store) = setup_three_party();
    let attacker = room.identities[2].device_pk;
    let kw_hash = NodeHash::from([0xBAu8; 32]);

    seed_pending_and_counts(&mut engine, &room, kw_hash);

    engine
        .handle_message(
            attacker,
            ProtocolMessage::KeywrapAck {
                keywrap_hash: kw_hash,
                // Lie: attacker claims the wrap was for them.
                recipient_pk: tox_proto::Claimed::new(attacker),
            },
            &store,
            None,
        )
        .expect("handle_message");

    assert!(
        engine.keywrap_pending.contains_key(&kw_hash),
        "mismatched recipient_pk must leave pending state intact",
    );
}
