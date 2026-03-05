//! Adversarial coverage for `ProtocolMessage::BlobData`.
//!
//! `BlobData.offset: u64` is peer-supplied and feeds straight into
//! unchecked u64 arithmetic in the receive handler:
//!
//! ```ignore
//! let chunk_idx   = data.offset / CHUNK_SIZE;
//! let chunk_start = chunk_idx * CHUNK_SIZE;
//! let chunk_end   = (chunk_start + CHUNK_SIZE).min(sync.info.size);
//! let full_chunk_size = (chunk_end - chunk_start) as usize;
//! let buf = sync.partial_chunks.entry(chunk_idx)
//!     .or_insert_with(|| vec![0u8; full_chunk_size]);
//! ```
//!
//! With `offset >= sync.info.size`:
//!   - `chunk_start >= sync.info.size`, so `.min(sync.info.size)` clamps
//!     `chunk_end` *below* `chunk_start`.
//!   - `chunk_end - chunk_start` underflows in release (panics in debug).
//!   - The wrapped `usize` then drives a giant `vec![0u8; …]` →
//!     OOM / abort.
//!
//! With `offset` near `u64::MAX`, `chunk_start + CHUNK_SIZE` overflows
//! independently — same family of vector.
//!
//! The fix retags `BlobData.offset` as `Untrusted<u64>` and clamps at
//! handler entry against `sync.info.size`. The same handler is reachable
//! by any authenticated peer — the unauthenticated `BlobAvail` join path
//! adds the sender to `sync.seeders` automatically — so this is a
//! single-packet kill, not a sustained-attack class.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobData, BlobInfo, BlobStatus, CHUNK_SIZE, MAX_PIECE_DATA, SwarmSync};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{LogicalIdentityPk, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::testing::InMemoryStore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;
use tox_proto::Untrusted;

struct Fixture {
    engine: MerkleToxEngine,
    store: InMemoryStore,
    blob_hash: NodeHash,
    sender_pk: PhysicalDevicePk,
}

fn fixture() -> Fixture {
    let _ = tracing_subscriber::fmt::try_init();
    let receiver_pk = PhysicalDevicePk::from([1u8; 32]);
    let sender_pk = PhysicalDevicePk::from([2u8; 32]);
    let blob_hash = NodeHash::from([0xBBu8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        receiver_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0xBD0F),
        tp,
    );
    let store = InMemoryStore::new();

    // Pre-register a SwarmSync so the BlobData handler has a state to
    // look up. Bypassing `BlobAvail` keeps the test focused on the
    // BlobData arithmetic alone.
    //
    // Use a deliberately *small* blob (one chunk) so any oversize
    // offset is unambiguously past `info.size` — and therefore the
    // discriminating signal between "handler clamps" and "handler
    // wraps".
    let info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE, // exactly one chunk
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync = SwarmSync::new_with_offset(info, &receiver_pk);
    // Register the sender as a known seeder. The BlobData handler now
    // gates on `sync.has_seeder(sender)` — only registered seeders
    // (peers who shipped a BlobAvail through the blob_conversations
    // gate) may push pieces. The §BD-{1,2,3} tests below exercise
    // *other* arithmetic / clamp guards on the legitimate seeder
    // path; the seeder-authorisation guard itself is exercised by
    // `test_blob_data_from_non_seeder_does_not_pin_partial_chunks`,
    // which keeps its own fixture without this seed.
    sync.add_seeder(sender_pk);
    engine.blob_syncs.insert(blob_hash, sync);

    Fixture {
        engine,
        store,
        blob_hash,
        sender_pk,
    }
}

/// §BD-1 — A `BlobData` whose `offset` lies past `sync.info.size` must
/// be dropped at the handler. Without the clamp, the underflow in
/// `chunk_end - chunk_start` produces a giant `usize` that is then
/// passed to `vec![0u8; ..]` — process abort under OOM, in a single
/// authenticated packet. The handler must produce zero effects and not
/// panic / abort.
#[test]
fn test_blob_data_offset_past_blob_size_is_rejected() {
    let mut f = fixture();

    // info.size = CHUNK_SIZE (one chunk); offset deliberately past
    // that. Pre-fix this would underflow `chunk_end - chunk_start` and
    // either panic in debug or drive a multi-GB allocation in release.
    let attacker_offset = CHUNK_SIZE * 8;

    let result = f.engine.handle_message(
        f.sender_pk,
        ProtocolMessage::BlobData(BlobData {
            hash: f.blob_hash,
            offset: Untrusted::new(attacker_offset),
            data: tox_proto::BoundedBytes::try_from_vec(vec![0xAAu8; 16]).expect("under cap"),
            proof: tox_proto::BoundedBytes::new(),
        }),
        &f.store,
        Some(&f.store),
    );

    let effects = result.expect("handler must not error on adversarial input");
    let write_chunks = effects
        .iter()
        .filter(|e| matches!(e, Effect::WriteChunk { .. }))
        .count();
    assert_eq!(
        write_chunks, 0,
        "BlobData with offset past blob size must not produce a \
         WriteChunk — without the handler-level clamp the receiver \
         either panics or allocates a multi-GB buffer driven by the \
         underflowed chunk_end - chunk_start",
    );
}

/// §BD-2 — `offset = u64::MAX` is the most extreme variant of §BD-1.
/// `chunk_start + CHUNK_SIZE` overflows independently of the
/// `info.size` comparison, so the clamp must reject this *before* any
/// arithmetic touches it.
#[test]
fn test_blob_data_u64_max_offset_is_rejected() {
    let mut f = fixture();

    let result = f.engine.handle_message(
        f.sender_pk,
        ProtocolMessage::BlobData(BlobData {
            hash: f.blob_hash,
            offset: Untrusted::new(u64::MAX),
            data: tox_proto::BoundedBytes::try_from_vec(vec![0xAAu8; 16]).expect("under cap"),
            proof: tox_proto::BoundedBytes::new(),
        }),
        &f.store,
        Some(&f.store),
    );

    let effects = result.expect("handler must not error on adversarial input");
    let write_chunks = effects
        .iter()
        .filter(|e| matches!(e, Effect::WriteChunk { .. }))
        .count();
    assert_eq!(
        write_chunks, 0,
        "BlobData with offset = u64::MAX must be dropped at the \
         handler — chunk_idx * CHUNK_SIZE and chunk_start + CHUNK_SIZE \
         both overflow without the clamp",
    );
}

/// §BD-3 — Honest baseline: a `BlobData` at a *valid* offset must
/// still be processed normally. Without this regression guard the fix
/// could degenerate to "reject everything" and pass §BD-1/2 trivially.
#[test]
fn test_blob_data_honest_offset_is_accepted() {
    let mut f = fixture();

    // Valid offset within the one-chunk blob. We don't assert the full
    // happy-path completion (chunk verification needs a matching
    // Merkle root, which is exercised in cas_push_test); we just
    // assert the handler doesn't *reject* the message — i.e.
    // `partial_chunks` gets touched.
    let result = f.engine.handle_message(
        f.sender_pk,
        ProtocolMessage::BlobData(BlobData {
            hash: f.blob_hash,
            offset: Untrusted::new(0),
            data: tox_proto::BoundedBytes::try_from_vec(vec![0xCDu8; MAX_PIECE_DATA])
                .expect("under cap"),
            proof: tox_proto::BoundedBytes::new(),
        }),
        &f.store,
        Some(&f.store),
    );
    assert!(result.is_ok(), "honest offset must not error");

    let sync = f
        .engine
        .blob_syncs
        .get(&f.blob_hash)
        .expect("sync still present");
    assert!(
        !sync.partial_chunks.is_empty() || !sync.tracker.completed_ranges.is_empty(),
        "honest BlobData must reach `partial_chunks` (or complete the \
         chunk outright) — if neither, the clamp is over-aggressive",
    );
}

/// §BD-4 — Sender authorisation. `BlobData` must be ignored when the
/// sender is not a registered seeder of the sync, mirroring the
/// `BlobAvail` / `BlobReq` / `BlobFetch` arms (handlers/mod.rs:769,
/// :833, :1055). Without this gate any friend who learns a blob hash
/// can pin receiver memory: each unique `chunk_idx` triggers
/// `partial_chunks.entry(chunk_idx).or_insert_with(|| vec![0u8;
/// 65 536])`, and one piece per chunk leaves `chunk_now_complete`
/// false so the buffer is retained. `remove_seeder` (cas.rs:750-764)
/// is the only path that drops `partial_chunks`, and it requires the
/// seeder set to empty — which is never reached for an attacker who
/// was never *in* `seeders`. Pre-fix this test panics with the
/// exploit measurement; post-fix it passes because the handler drops
/// non-seeder packets.
#[test]
fn test_blob_data_from_non_seeder_does_not_pin_partial_chunks() {
    let _ = tracing_subscriber::fmt::try_init();

    let receiver_pk = PhysicalDevicePk::from([1u8; 32]);
    let legit_seeder = PhysicalDevicePk::from([2u8; 32]);
    let attacker = PhysicalDevicePk::from([0xADu8; 32]);
    let blob_hash = NodeHash::from([0xBBu8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        receiver_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0xBADAD),
        tp,
    );
    let store = InMemoryStore::new();

    // The receiver is syncing a 256-chunk blob from a legitimate
    // seeder. With the recent BlobAvail clamp the maximum legitimate
    // `info.size` is `MAX_BLOB_SIZE` (100 GiB ≈ 1.6M chunks); we
    // pick 256 chunks here to keep the test fast while still being
    // discriminating between "gate works" and "gate absent".
    let info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 256,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync = SwarmSync::new_with_offset(info, &receiver_pk);
    sync.add_seeder(legit_seeder);
    engine.blob_syncs.insert(blob_hash, sync);

    // Attacker is a Tox friend (handle_message is reachable) but
    // *not* in the seeder set for this blob. Pieces from them are
    // adversarial input.
    const NUM_DISTINCT_CHUNKS: u64 = 256;
    let piece = vec![0xAAu8; MAX_PIECE_DATA];
    for chunk_idx in 0..NUM_DISTINCT_CHUNKS {
        let offset = chunk_idx * CHUNK_SIZE;
        engine
            .handle_message(
                attacker,
                ProtocolMessage::BlobData(BlobData {
                    hash: blob_hash,
                    offset: Untrusted::new(offset),
                    data: tox_proto::BoundedBytes::try_from_vec(piece.clone())
                        .expect("piece under cap"),
                    proof: tox_proto::BoundedBytes::new(),
                }),
                &store,
                Some(&store),
            )
            .unwrap();
    }

    let sync = engine
        .blob_syncs
        .get(&blob_hash)
        .expect("legitimate sync must remain — attacker must not destroy state either");
    let partial_chunks_count = sync.partial_chunks.len();
    let partial_bytes: usize = sync.partial_chunks.values().map(|v| v.len()).sum();
    assert_eq!(
        partial_chunks_count,
        0,
        "BlobData from a non-seeder must be dropped before allocating \
         `partial_chunks`. Observed {} buffered chunks ({} bytes resident) \
         from {} adversarial packets — sustained wire-to-RAM amplification \
         (~{}× per packet) limited only by `info.size / CHUNK_SIZE`. The \
         per-chunk buffers persist until the sync completes (which it \
         won't from non-seeder pieces) or the seeder set empties (which \
         the attacker can't trigger because they're not in it).",
        partial_chunks_count,
        partial_bytes,
        NUM_DISTINCT_CHUNKS,
        partial_bytes / NUM_DISTINCT_CHUNKS as usize,
    );
}
