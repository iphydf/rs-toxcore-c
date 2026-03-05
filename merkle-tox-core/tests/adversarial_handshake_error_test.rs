//! §HSE adversarial coverage for `HandshakeError`.
//!
//! The handshake retry cap (`HANDSHAKE_RETRY_CAP = 3` per
//! `HANDSHAKE_RETRY_WINDOW_MS = 10 min`) is enforced in two places:
//! (a) the authoring path (`author_x3dh_key_exchange`), which resets
//!     the window when it has expired, and
//! (b) the `HandshakeError` handler, which — until this fix — only
//!     incremented `state.attempts` and never reset the window.
//!
//! Consequence: a peer can keep bumping `attempts` past the cap at
//! any cadence, and the stale `window_start_ms` keeps the counter
//! frozen. Real legitimate peers must not be able to accumulate
//! retry state beyond the cap, even under drip-fire of
//! `HandshakeError` packets across window boundaries.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, KConv, PhysicalDevicePk};
use merkle_tox_core::engine::conversation::{ConversationData, Established};
use merkle_tox_core::engine::{Conversation, HANDSHAKE_RETRY_WINDOW_MS, MerkleToxEngine};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn make_engine(
    now: Instant,
    conv_id: ConversationId,
) -> (MerkleToxEngine, Arc<ManualTimeProvider>, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp.clone(),
    );
    // The HandshakeError handler now drops messages naming a
    // conversation we have not joined locally (closes a
    // friend-authenticated `handshake_retry_state` growth attack —
    // see `tests/adversarial_unknown_conversation_test.rs`). Seed
    // the conversation so the rest of this file can exercise the
    // legitimate retry-state path.
    let established =
        ConversationData::<Established>::new(conv_id, KConv::from([0x11u8; 32]), 1000);
    engine
        .conversations
        .insert(conv_id, Conversation::Established(established));
    (engine, tp, self_pk)
}

/// §HSE-1: When a `HandshakeError` arrives *after* the previous
/// window has expired, the handler must reset `attempts` to 1 and
/// slide `window_start_ms` forward. Without this reset, a stale
/// window-start can freeze `attempts` at a high count even though
/// each event is separated by a full window.
#[test]
fn handshake_error_handler_resets_expired_window() {
    let now = Instant::now();
    let conv_id = ConversationId::from([1u8; 32]);
    let (mut engine, tp, _self_pk) = make_engine(now, conv_id);
    let store = InMemoryStore::new();
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    // First HandshakeError lands immediately.
    engine
        .handle_message(
            peer_pk,
            ProtocolMessage::HandshakeError {
                conversation_id: conv_id,
                reason: "first".to_string(),
            },
            &store,
            None,
        )
        .unwrap();

    // Advance past one full window.
    tp.advance(Duration::from_millis(
        (HANDSHAKE_RETRY_WINDOW_MS + 1_000) as u64,
    ));

    // Second HandshakeError arrives in a *new* window.
    engine
        .handle_message(
            peer_pk,
            ProtocolMessage::HandshakeError {
                conversation_id: conv_id,
                reason: "second".to_string(),
            },
            &store,
            None,
        )
        .unwrap();

    let state = engine
        .handshake_retry_state
        .get(&(conv_id, peer_pk))
        .expect("retry state recorded");

    assert_eq!(
        state.attempts, 1,
        "after a fresh-window `HandshakeError`, attempts must reset to 1 \
         (saw {})",
        state.attempts,
    );
}
