//! Adversarial coverage for `ProtocolMessage::SyncShardChecksums`.
//!
//! The handler at `engine/handlers/mod.rs` ingests a peer-supplied
//! `Vec<(SyncRange, ShardHash)>` and, for each entry not matching the
//! local shard map, builds and emits a `SyncSketch` packet. Two
//! amplification vectors live on this path:
//!
//! 1. **Unbounded shard count.** A single 1 MB inbound packet can
//!    carry ~21 000 shard entries (48 B each). Each forces one
//!    store-range scan + one outbound sketch — a 5× bandwidth
//!    amplification + O(N) CPU per request, repeatable per peer.
//!
//! 2. **Unbounded per-shard range size.** Each `SyncRange` is
//!    peer-controlled. A range with `min_rank=0, max_rank=u64::MAX`
//!    forces `store.get_node_hashes_in_range` to enumerate every
//!    node — O(N) memory and CPU per request.
//!
//! Round 10 fix: at the handler entry, drop the entire packet if
//! `shards.len() > MAX_SYNC_SHARDS` (4096) or if any per-shard range
//! spans more than `SHARD_SIZE` ranks. Dropping the whole packet on
//! a single malformed entry is the simpler invariant — partial
//! acceptance of a malformed packet invites mixed-trust state.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, PhysicalDevicePk, ShardHash};
use merkle_tox_core::engine::session::{PeerSession, SyncSession};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::SHARD_SIZE;
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;
use tox_reconcile::SyncRange;

fn make_engine() -> (
    MerkleToxEngine,
    InMemoryStore,
    ConversationId,
    PhysicalDevicePk,
) {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let self_pk = PhysicalDevicePk::from([0u8; 32]);
    let mut engine = MerkleToxEngine::new(
        self_pk,
        self_pk.to_logical(),
        rand::rngs::StdRng::seed_from_u64(42),
        tp,
    );
    let store = InMemoryStore::new();
    let conv_id = ConversationId::from([0xC1u8; 32]);
    let peer_pk = PhysicalDevicePk::from([0xAAu8; 32]);

    // Activate a sync session for the peer so the handler enters its
    // shard-checksum branch (rather than no-opping on a stranger).
    engine.start_sync(conv_id, Some(peer_pk), &store);
    let keys: Vec<_> = engine.sessions.keys().cloned().collect();
    for key in keys {
        if let Some(PeerSession::Handshake(s)) = engine.sessions.remove(&key) {
            engine
                .sessions
                .insert(key, PeerSession::Active(s.activate(0)));
        }
    }
    let _ = SyncSession::<merkle_tox_core::engine::session::Handshake>::new;

    (engine, store, conv_id, peer_pk)
}

fn count_sketches(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::SyncSketch(_))))
        .count()
}

// §SS-1 — A `SyncShardChecksums` packet with `shards.len()` above
// `MAX_SYNC_SHARDS` is rejected at the wire-deserialise boundary.
// This used to be enforced at the handler entry by an explicit
// `len() > MAX_SYNC_SHARDS` guard; with the migration to
// `BoundedVec<(SyncRange, ShardHash), MAX_SYNC_SHARDS>` on the field,
// the cap is now a structural property of the type and an oversize
// payload cannot deserialise at all. The wire-level pin lives in
// `tests/adversarial_oversized_wire_test.rs::
// sync_shard_checksums_with_oversize_shards_array_is_rejected_at_deserialize`;
// constructing a `ProtocolMessage::SyncShardChecksums` in safe Rust
// with `shards.len() > MAX_SYNC_SHARDS` is no longer possible, so the
// equivalent in-process test would have to abuse `unsafe` to reach
// the handler — which is no longer the right surface to test.

/// §SS-2 — One pathological per-shard range (span > `SHARD_SIZE`)
/// poisons the whole packet. Mixing valid + invalid entries is a
/// classic confused-packet attack: a permissive handler that
/// processes the valid entries and silently drops the bad ones still
/// expends store-scan work on the malformed input. Drop the whole
/// packet so the attacker cannot piggyback malicious ranges on
/// legitimate traffic.
#[test]
fn test_oversized_per_shard_range_rejects_whole_packet() {
    let (mut engine, store, conv_id, peer_pk) = make_engine();

    let shards = tox_proto::bounded_vec![
        // Three legitimate shards.
        (
            SyncRange {
                min_rank: 0,
                max_rank: SHARD_SIZE - 1,
            },
            ShardHash::from([0u8; 32]),
        ),
        (
            SyncRange {
                min_rank: SHARD_SIZE,
                max_rank: 2 * SHARD_SIZE - 1,
            },
            ShardHash::from([0u8; 32]),
        ),
        (
            SyncRange {
                min_rank: 2 * SHARD_SIZE,
                max_rank: 3 * SHARD_SIZE - 1,
            },
            ShardHash::from([0u8; 32]),
        ),
        // One malicious wide range — full u64 span. A permissive
        // handler would call `get_node_hashes_in_range` on this and
        // enumerate the entire store.
        (
            SyncRange {
                min_rank: 0,
                max_rank: u64::MAX,
            },
            ShardHash::from([0u8; 32]),
        ),
    ];

    let effects = engine
        .handle_message(
            peer_pk,
            ProtocolMessage::SyncShardChecksums {
                conversation_id: conv_id,
                shards,
            },
            &store,
            None,
        )
        .unwrap();

    assert_eq!(
        count_sketches(&effects),
        0,
        "any per-shard range > SHARD_SIZE must invalidate the whole \
         packet — partial acceptance lets an attacker piggyback a \
         u64::MAX-span range on legitimate-looking traffic",
    );
}

/// §SS-3 — Regression guard against blanket-rejection. A legitimate
/// 8-shard packet (well under `MAX_SYNC_SHARDS`, every range
/// `SHARD_SIZE`-wide) must still be processed, with at least one
/// sketch emitted per divergent shard (since the local store is
/// empty, every remote shard is "different").
#[test]
fn test_legitimate_packet_still_processed() {
    let (mut engine, store, conv_id, peer_pk) = make_engine();

    let shards = tox_proto::BoundedVec::try_from_iter((0..8u64).map(|i| {
        (
            SyncRange {
                min_rank: i * SHARD_SIZE,
                max_rank: i * SHARD_SIZE + SHARD_SIZE - 1,
            },
            // Non-zero hash so the receiver treats the shard as
            // diverging from the local empty-store state.
            ShardHash::from([(i + 1) as u8; 32]),
        )
    }))
    .expect("8 shards is well under MAX_SYNC_SHARDS");

    let effects = engine
        .handle_message(
            peer_pk,
            ProtocolMessage::SyncShardChecksums {
                conversation_id: conv_id,
                shards,
            },
            &store,
            None,
        )
        .unwrap();

    assert!(
        count_sketches(&effects) > 0,
        "legitimate SyncShardChecksums packet (8 SHARD_SIZE-wide \
         shards) must produce at least one outbound sketch — the \
         fix must not regress to blanket-rejection",
    );
}
