//! Adversarial coverage for `PushStream::on_progress`.
//!
//! `BlobProgress` is a peer-supplied message dispatched directly to
//! `PushStream::on_progress` with no field validation. Two concrete
//! CPU/arithmetic-DoS attacks exist:
//!
//! 1. **Over-sized `completed_ranges`**: `(start_chunk, end_chunk)` pairs
//!    drive an inclusive loop. A `(0, u64::MAX)` pair spins the loop
//!    2^64 times — a one-packet CPU DoS against any peer we've
//!    agreed to push a blob to.
//!
//! 2. **Out-of-range `incomplete_chunks`**: `chunk_idx` feeds into
//!    `chunk_start_offset = chunk_idx * CHUNK_SIZE` followed by
//!    `chunk_end - chunk_start_offset`. A chunk_idx past the blob's
//!    real chunk count makes `chunk_end == blob_size`, and the
//!    subtraction underflows to a huge unsigned — either panicking
//!    in debug builds or driving another unbounded piece loop in
//!    release.
//!
//! Both attacks have the same root cause: trust of peer-supplied
//! indices without clamping against the blob's own bounds. The fix
//! clamps `end_chunk` to `num_chunks-1` and rejects any `chunk_idx`
//! that is out of range.

use merkle_tox_core::cas::{BlobProgress, CHUNK_SIZE, PushStream};
use merkle_tox_core::dag::NodeHash;
use tox_proto::Untrusted;

/// Guard 1 — `completed_ranges` with `end_chunk` far beyond the
/// blob's actual chunk count must not cause a CPU-bound loop. We
/// exercise the attack with a range large enough that the pre-fix
/// `(start..=end)` loop cannot complete in a reasonable test budget
/// but the clamped post-fix version finishes instantly.
#[test]
fn test_over_sized_completed_range_does_not_stall() {
    let blob_hash = NodeHash::from([0xA0u8; 32]);
    let blob_size = 4 * CHUNK_SIZE;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    // 10 million iterations would complete in <1s even pre-fix, so
    // a direct time probe isn't discriminating. Instead we use the
    // observable side-effect: post-fix, `max_credits` is bounded by
    // the genuine number of newly-confirmed pieces (≤ num_chunks ·
    // PIECES_PER_CHUNK). Pre-fix the loop counts every one of the
    // attacker's claimed chunks as newly confirmed, and
    // `max_credits` saturates at `MAX_CREDITS`.
    let attacker_range_end = 10_000_000u64;
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::bounded_vec![(
            Untrusted::new(0),
            Untrusted::new(attacker_range_end)
        )],
        incomplete_chunks: tox_proto::BoundedVec::new(),
    });

    // `all_done()` iterates `0..num_chunks` and returns true only if
    // every real chunk is in `receiver_completed`. Pre-fix the
    // range (0, 10_000_000) encompasses [0, 3] trivially so
    // `all_done()` returns true. Post-fix the range is clamped to
    // (0, 3) and `all_done()` still returns true. That's not
    // discriminating — we need a stronger signal.
    //
    // Use `retransmit_queue_len()`: it stays 0 in either
    // implementation, so that's not discriminating either. Fall
    // back to the credit window — post-fix `max_credits` grows by
    // at most `num_chunks · PIECES_PER_CHUNK`, not by the attacker's
    // absurd range.
    let max_creds = stream.max_credits;
    // 4 chunks × ~51 pieces per chunk = ~204. A well-behaved impl
    // caps well under 1_000. Pre-fix the `newly_confirmed` count
    // includes 10_000_001 spurious "chunks", driving `max_credits`
    // up to `MAX_CREDITS` (4096).
    assert!(
        max_creds < 1_000,
        "max_credits={} — a bounded completed_range was not clamped \
         against num_chunks, so every spurious chunk_idx was counted \
         as newly-confirmed and saturated the credit window.",
        max_creds,
    );
}

/// Guard 2 — `incomplete_chunks` with a `chunk_idx` past the blob's
/// `num_chunks` must not panic or populate garbage retransmit state.
/// The pre-fix code computes `chunk_start_offset = chunk_idx *
/// CHUNK_SIZE` and then `chunk_end - chunk_start_offset`, which
/// underflows when `chunk_start_offset > blob_size`.
#[test]
fn test_out_of_range_incomplete_chunk_does_not_panic() {
    let blob_hash = NodeHash::from([0xA1u8; 32]);
    let blob_size = 4 * CHUNK_SIZE;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    // First progress seeds `prev_incomplete[chunk_idx]` so the
    // second call takes the "missing across 2 cycles" branch with
    // the vulnerable subtraction.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![(Untrusted::new(1_000_000), vec![0x00u8; 2])],
    });

    // Second call: chunk_idx=1_000_000 is well past num_chunks=4.
    // Pre-fix: `chunk_start_offset = 65_536_000_000` > blob_size,
    // `chunk_end = blob_size = 262_144`, subtraction underflows —
    // panic in debug, huge garbage count in release.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![(Untrusted::new(1_000_000), vec![0x00u8; 2])],
    });

    // No retransmit entries can legitimately exist for offsets past
    // blob_size. Post-fix: the out-of-range `chunk_idx` is rejected
    // entirely so the queue stays empty.
    assert_eq!(
        stream.retransmit_queue_len(),
        0,
        "out-of-range chunk_idx must not produce retransmit entries",
    );
}
