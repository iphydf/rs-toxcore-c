//! §SRL adversarial coverage for `SyncRateLimited`.
//!
//! A malicious peer can send `SyncRateLimited { retry_after_ms: u32::MAX }`
//! to force the local engine into a rate-limited state that lasts ~49.7 days.
//! The handler must clamp `retry_after_ms` at a self-chosen bound so a peer
//! cannot arbitrarily silence our sync loop for that conversation.
//!
//! The bound is `SYNC_RATE_LIMITED_MAX_MS` — the same order as the per-peer
//! CPU token-bucket refill window. A legitimate responder will never need
//! longer than one refill window.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, PhysicalDevicePk};
use merkle_tox_core::engine::session::PeerSession;
use merkle_tox_core::engine::{MerkleToxEngine, SYNC_RATE_LIMITED_MAX_MS};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn make_engine(now: Instant) -> (MerkleToxEngine, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp,
    );
    (engine, self_pk)
}

/// §SRL-1: A peer-supplied `retry_after_ms` of `u32::MAX` must be clamped
/// to `SYNC_RATE_LIMITED_MAX_MS`. Without the clamp, `rate_limited_until`
/// would land ~49.7 days in the future and the session would be silenced
/// for weeks.
#[test]
fn peer_cannot_silence_sync_indefinitely() {
    let now = Instant::now();
    let (mut engine, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    engine
        .handle_message(
            peer_pk,
            ProtocolMessage::SyncRateLimited {
                conversation_id: conv_id,
                retry_after_ms: tox_proto::Untrusted::new(u32::MAX),
            },
            &store,
            None,
        )
        .unwrap();

    let session = engine.sessions.get(&(peer_pk, conv_id)).unwrap();
    let until = session.common().rate_limited_until.unwrap();

    // The ceiling is set by SYNC_RATE_LIMITED_MAX_MS. Allow a small slack
    // for scheduling jitter (the handler also reads `now_instant` internally).
    let ceiling = now + Duration::from_millis(SYNC_RATE_LIMITED_MAX_MS as u64 + 100);
    assert!(
        until <= ceiling,
        "rate_limited_until must be bounded by SYNC_RATE_LIMITED_MAX_MS, \
         got offset {:?} past `now`",
        until.saturating_duration_since(now),
    );
}

/// §SRL-2: The clamp must not affect legitimate in-range values. A peer
/// sending a reasonable 1-second backoff must observe the full second,
/// not a clipped value.
#[test]
fn in_range_retry_after_is_honored() {
    let now = Instant::now();
    let (mut engine, _self_pk) = make_engine(now);
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([2u8; 32]);

    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }

    engine
        .handle_message(
            peer_pk,
            ProtocolMessage::SyncRateLimited {
                conversation_id: conv_id,
                retry_after_ms: tox_proto::Untrusted::new(1000),
            },
            &store,
            None,
        )
        .unwrap();

    let session = engine.sessions.get(&(peer_pk, conv_id)).unwrap();
    let until = session.common().rate_limited_until.unwrap();
    let delta = until.saturating_duration_since(now);
    assert!(
        delta >= Duration::from_millis(900) && delta <= Duration::from_millis(1100),
        "legitimate 1s backoff must be preserved, got {:?}",
        delta,
    );
}
