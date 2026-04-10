//! §SD coverage for the sketch-decode blacklist's "grace for joiners"
//! rule.
//!
//! Empirical tuning via ab_compare showed the sketch-decode blacklist
//! has contradictory requirements across scenarios:
//!
//! * **Late joiner (scenario 8, clean net)** — a peer catching up has
//!   an out-of-date DAG; their first few sketch-decodes against
//!   everyone fail. A threshold-gate protects them (they get a few
//!   tries to catch up). Without protection they're blacklisted
//!   immediately and can never catch up.
//!
//! * **Hostile network (scenario 10, 10% burst loss)** — 3 peers with
//!   mutually-divergent state. If everyone survives their failures,
//!   they loop forever. An immediate blacklist of one peer breaks the
//!   deadlock; the remaining two converge.
//!
//! The distinguishing signal is "has the peer ever decoded a sketch
//! against us successfully this session?" A peer with zero successes
//! is a joiner; their failures are expected. A peer who succeeded
//! once and is now failing is the "consistent failure" case that the
//! reconcile-spec blacklist targets.
//!
//! These tests pin that rule. A regression that re-adds threshold-
//! counting OR removes the grace period would fire one of these
//! asserts.

use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::PhysicalDevicePk;
use merkle_tox_core::engine::MerkleToxEngine;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

fn make_engine(now: Instant) -> MerkleToxEngine {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp,
    )
}

/// §SD-1: A peer who has NEVER decoded a sketch successfully gets a
/// grace period on decode failures — no matter how many times they
/// fail, they don't get blacklisted until at least one success has
/// been recorded. Protects late joiners mid-catch-up.
#[test]
fn joiner_is_not_blacklisted_on_decode_failures() {
    let mut engine = make_engine(Instant::now());
    let peer = PhysicalDevicePk::from([0xAAu8; 32]);

    for _ in 0..10 {
        engine.record_sketch_decode_failure(peer);
    }

    let now_ms = engine.clock.network_time_ms();
    assert!(
        !engine.is_blacklisted(&peer, now_ms),
        "peer with zero successful decodes is a joiner — no amount of \
         initial failures should blacklist them",
    );
}

/// §SD-2: After a single successful decode, the peer is "established".
/// Subsequent failures blacklist them immediately — this is the
/// spec's "consistently fail decoding" case (the success proved
/// decodability works in principle, so failure afterwards is real
/// evidence of misbehaviour or a deep divergence).
#[test]
fn established_peer_blacklisted_on_decode_failure() {
    let mut engine = make_engine(Instant::now());
    let peer = PhysicalDevicePk::from([0xAAu8; 32]);

    engine.record_sketch_decode_success(peer);
    engine.record_sketch_decode_failure(peer);

    let now_ms = engine.clock.network_time_ms();
    assert!(
        engine.is_blacklisted(&peer, now_ms),
        "peer with a successful decode is established — subsequent \
         failures must blacklist immediately to break mutual-failure \
         deadlocks (scenario 10)",
    );
}

/// §SD-3: Grace applies per-peer. Peer A's success doesn't extend the
/// grace period to peer B.
#[test]
fn grace_is_per_peer() {
    let mut engine = make_engine(Instant::now());
    let peer_a = PhysicalDevicePk::from([0xAAu8; 32]);
    let peer_b = PhysicalDevicePk::from([0xBBu8; 32]);

    engine.record_sketch_decode_success(peer_a);
    engine.record_sketch_decode_failure(peer_a);
    engine.record_sketch_decode_failure(peer_b);

    let now_ms = engine.clock.network_time_ms();
    assert!(engine.is_blacklisted(&peer_a, now_ms));
    assert!(
        !engine.is_blacklisted(&peer_b, now_ms),
        "peer_b has never succeeded — still in grace",
    );
}
