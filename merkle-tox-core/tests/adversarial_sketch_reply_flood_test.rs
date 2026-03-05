//! Adversarial coverage for the IBLT sketch reply path
//! (`handlers/mod.rs:1170-1217`).
//!
//! When `process_sketch` returns `DecodingResult::Success {
//! missing_remotely, ... }`, the handler walks the entire
//! `missing_remotely` set and emits one `ProtocolMessage::MerkleNode`
//! reply per hash. The set size is bounded only by the sketch's
//! tier capacity — `Tier::Small` decodes up to ~40 items, but the
//! peer can also solve the sketch PoW gate and send a Medium/Large
//! sketch decoding ~170 / ~680 items.
//!
//! Worst case: a peer-supplied SyncSketch with empty cells subtracts
//! to exactly `local_hashes`. One inbound packet causes the receiver
//! to emit up to `d_max(tier)` outbound `MerkleNode` packets, each
//! up to 1 MB. For a Small sketch with d_max=40, an attacker holding
//! a session in the conversation can pull up to 40 MB out of us per
//! ~3 KB inbound packet — a four-orders-of-magnitude bandwidth
//! amplification.
//!
//! Pre-fix: `for hash in missing_remotely` has no per-iteration cap.
//! Post-fix: clamp the iteration to a small constant
//! (`MAX_BATCH_SIZE`, e.g. 16). The remainder is naturally re-fetched
//! by the peer's next sketch round-trip — the existing reconcile
//! loop converges over multiple rounds rather than dumping in one
//! shot.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestRoom, apply_effects, create_signed_content_node,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;
use tox_reconcile::{IbltCell, SyncRange, SyncSketch, Tier};

/// §SF-1 — A peer-supplied empty IBLT sketch subtracts to exactly
/// `local_hashes`; the handler walks the resulting `missing_remotely`
/// set unbounded and emits one `MerkleNode` reply per element. The
/// reply count must be bounded by a small `MAX_BATCH_SIZE` constant,
/// not by the sketch's decode capacity.
#[test]
fn test_empty_sketch_triggers_unbounded_reply_flood() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let observer = &room.identities[1];

    let mut engine = MerkleToxEngine::new(
        observer.device_pk,
        observer.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Populate the observer's store with N verified content nodes from
    // alice. N is chosen below the Small-tier d_max (40) so the IBLT
    // decode succeeds; this ensures the handler reaches the
    // `missing_remotely` reply loop rather than the decode-fail path.
    let n: u64 = 30;
    let mut parents = store.get_admin_heads(&room.conv_id);
    for i in 0..n {
        let msg = create_signed_content_node(
            &room.conv_id,
            &room.keys,
            alice.master_pk,
            alice.device_pk,
            parents.clone(),
            Content::Text(format!("msg {}", i)),
            2 + i,
            2 + i,
            1_000 + i as i64,
        );
        parents = vec![msg.hash()];
        let effects = engine.handle_node(room.conv_id, msg, &store, None).unwrap();
        apply_effects(effects, &store);
    }

    // Construct an empty Small sketch (no PoW required, no CPU budget
    // pressure on first request). Range covers everything in the
    // conversation. Cells are all zero — the IBLT contains zero items.
    let attacker_pk = PhysicalDevicePk::from([0xCDu8; 32]);
    let sketch = SyncSketch {
        conversation_id: room.conv_id,
        cells: tox_proto::BoundedVec::try_from_iter(std::iter::repeat_n(
            IbltCell::default(),
            Tier::Small.cell_count(),
        ))
        .expect("under MAX_SKETCH_CELLS"),
        range: SyncRange {
            min_rank: 0,
            max_rank: u64::MAX,
        },
    };

    let effects = engine
        .handle_message(
            attacker_pk,
            ProtocolMessage::SyncSketch(sketch),
            &store,
            None,
        )
        .unwrap();

    let merkle_node_replies = effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::MerkleNode { .. })))
        .count();

    // Sanity check: the test must actually trigger replies — otherwise
    // we're just measuring "no decode", which would silently mask a
    // regression.
    assert!(
        merkle_node_replies > 0,
        "test wiring issue: no MerkleNode replies emitted at all. \
         Did the IBLT decode fail? Did the conversation key not load?",
    );

    // The amplification cap. 16 is the recommended MAX_BATCH_SIZE: it
    // matches the existing `next_fetch_batch()` batching pattern and
    // converges in ~log2 rounds for typical divergences.
    const MAX_REPLIES: usize = 16;
    assert!(
        merkle_node_replies <= MAX_REPLIES,
        "single empty IBLT sketch triggered {} MerkleNode replies — \
         the receiver should cap reply count at {} per sketch round-trip \
         to bound outbound bandwidth amplification. Excess defers to \
         the next sketch round-trip; convergence is unaffected.",
        merkle_node_replies,
        MAX_REPLIES,
    );
}
