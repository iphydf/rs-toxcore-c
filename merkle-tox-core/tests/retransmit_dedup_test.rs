//! Regression tests for `PushStream::on_progress` retransmit dedup.
//!
//! Before the fix: a piece that stayed missing across N BlobProgress
//! cycles produced N-1 duplicate retransmit entries, any of which
//! could itself be lost. Found during an ab_compare scenario 5
//! investigation that also turned up unrelated stalls — those
//! stalls are tracked separately; these tests guard only the dedup
//! invariant.

use merkle_tox_core::cas::{
    BlobProgress, PushStream, CHUNK_SIZE, MAX_PIECE_DATA, PIECES_PER_CHUNK,
};
use merkle_tox_core::dag::NodeHash;
use tox_proto::Untrusted;

/// Shorthand for constructing `Untrusted<u64>` wire values in test fixtures.
fn u(x: u64) -> Untrusted<u64> {
    Untrusted::new(x)
}

/// Helper: wrap a trusted `(start, end)` pair for wire use.
fn range(start: u64, end: u64) -> (Untrusted<u64>, Untrusted<u64>) {
    (u(start), u(end))
}

/// Helper: wrap a trusted `(chunk_idx, mask)` entry for wire use.
fn partial(chunk_idx: u64, mask: Vec<u8>) -> (Untrusted<u64>, Vec<u8>) {
    (u(chunk_idx), mask)
}

/// A single 64KB chunk with one piece persistently missing should
/// produce AT MOST one retransmit entry per missing piece, regardless
/// of how many BlobProgress messages we process.
#[test]
fn persistent_missing_piece_does_not_pile_up() {
    let blob_hash = NodeHash::from([0u8; 32]);
    let blob_size = CHUNK_SIZE;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    // Build a mask for chunk 0 where ALL pieces except piece 3 are
    // received. Piece 3 stays missing across many progress cycles.
    let num_pieces = PIECES_PER_CHUNK;
    let num_bytes = num_pieces.div_ceil(8);
    let mut mask = vec![0u8; num_bytes];
    for p in 0..num_pieces {
        if p == 3 {
            continue;
        }
        mask[p / 8] |= 1 << (p % 8);
    }

    // First progress — no prev_incomplete yet, nothing to retransmit.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![partial(0, mask.clone())],
    });
    assert_eq!(stream.retransmit_queue_len(), 0);

    // Fire 10 more identical progress messages. Piece 3 is still
    // missing; the retransmit_queue should not grow unboundedly.
    for _ in 0..10 {
        stream.on_progress(&BlobProgress {
            hash: blob_hash,
            completed_ranges: tox_proto::BoundedVec::new(),
            incomplete_chunks: tox_proto::bounded_vec![partial(0, mask.clone())],
        });
    }

    // Current (buggy) behaviour: queue grows by 1 per cycle → 10.
    // Desired: bounded at 1 (the single missing piece).
    assert!(
        stream.retransmit_queue_len() <= 1,
        "retransmit_queue grew to {} for a single persistently missing piece; \
         expected ≤ 1 (pile-up regression)",
        stream.retransmit_queue_len(),
    );
}

/// Ten pieces missing across ten progress cycles should produce at
/// most ten retransmit entries (one per piece), not one hundred.
#[test]
fn many_missing_pieces_do_not_multiply() {
    let blob_hash = NodeHash::from([1u8; 32]);
    let blob_size = CHUNK_SIZE;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    let num_pieces = PIECES_PER_CHUNK;
    let num_bytes = num_pieces.div_ceil(8);
    // Mark only pieces 0..10 as received — pieces 10..num_pieces are
    // missing.
    let mut mask = vec![0u8; num_bytes];
    for p in 0..10 {
        mask[p / 8] |= 1 << (p % 8);
    }
    let missing = num_pieces - 10;

    // Seed prev_incomplete.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![partial(0, mask.clone())],
    });

    for _ in 0..10 {
        stream.on_progress(&BlobProgress {
            hash: blob_hash,
            completed_ranges: tox_proto::BoundedVec::new(),
            incomplete_chunks: tox_proto::bounded_vec![partial(0, mask.clone())],
        });
    }

    let q = stream.retransmit_queue_len();
    assert!(
        q <= missing,
        "retransmit_queue = {} for {} persistently missing pieces after 10 \
         identical progress cycles; expected ≤ {} (pile-up regression)",
        q,
        missing,
        missing,
    );
}

/// Control: a piece that becomes missing and then arrives should only
/// be retransmitted at most once (between the two progress cycles it
/// was missing).
#[test]
fn piece_briefly_missing_retransmitted_once() {
    let blob_hash = NodeHash::from([2u8; 32]);
    let blob_size = CHUNK_SIZE;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    let num_pieces = PIECES_PER_CHUNK;
    let num_bytes = num_pieces.div_ceil(8);

    // All except piece 5.
    let mut missing_mask = vec![0u8; num_bytes];
    for p in 0..num_pieces {
        if p == 5 {
            continue;
        }
        missing_mask[p / 8] |= 1 << (p % 8);
    }

    // Seed.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![partial(0, missing_mask.clone())],
    });
    // Second with same mask → retransmit piece 5.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![partial(0, missing_mask.clone())],
    });

    assert_eq!(stream.retransmit_queue_len(), 1);

    // Piece arrives — chunk 0 is now fully received.
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::bounded_vec![range(0, 0)],
        incomplete_chunks: tox_proto::BoundedVec::new(),
    });

    // The retransmit_queue may still contain the stale entry (sender
    // will just waste one extra piece when it pops it). That's fine —
    // what matters is it doesn't KEEP growing.
    assert!(
        stream.retransmit_queue_len() <= 1,
        "retransmit_queue grew to {} after piece arrived",
        stream.retransmit_queue_len(),
    );
}

/// Sanity: the offsets in retransmit_queue should be valid piece
/// offsets within the blob, not garbage values.
#[test]
fn retransmit_offsets_are_piece_aligned() {
    let blob_hash = NodeHash::from([3u8; 32]);
    let blob_size = CHUNK_SIZE * 2;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    // Chunk 0 fully missing, chunk 1 fully missing.
    let num_pieces = PIECES_PER_CHUNK;
    let num_bytes = num_pieces.div_ceil(8);
    let empty = vec![0u8; num_bytes];

    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![partial(0, empty.clone()), partial(1, empty.clone())],
    });
    stream.on_progress(&BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::BoundedVec::new(),
        incomplete_chunks: tox_proto::bounded_vec![partial(0, empty.clone()), partial(1, empty.clone())],
    });

    // With dedup, at most (2 * num_pieces) entries.
    assert!(
        stream.retransmit_queue_len() <= 2 * num_pieces,
        "retransmit_queue = {} exceeds one entry per piece per chunk",
        stream.retransmit_queue_len(),
    );

    // Drain via next_piece() and check every popped offset is < blob_size
    // and aligned to MAX_PIECE_DATA within its chunk.
    while let Some(offset) = stream.next_piece() {
        assert!(offset < blob_size, "offset {} out of range", offset);
        let chunk_idx = offset / CHUNK_SIZE;
        let chunk_start = chunk_idx * CHUNK_SIZE;
        let piece_in_chunk = offset - chunk_start;
        assert_eq!(
            piece_in_chunk % MAX_PIECE_DATA as u64,
            0,
            "offset {} is not piece-aligned",
            offset
        );
        // Drain credits quickly — test only cares about shape.
        if stream.retransmit_queue_len() == 0 {
            break;
        }
    }
}
