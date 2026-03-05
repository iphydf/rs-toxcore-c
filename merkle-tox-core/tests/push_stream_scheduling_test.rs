//! Tests for push-stream scheduling fairness.
//!
//! The flush loop in `node.rs` drains pieces from PushStreams and sends
//! them via session.send_auto(). Two invariants tested here:
//!
//! 1. **Credit preservation**: if a PushStream produces N pieces but
//!    only M < N are successfully sent, the remaining N-M credits must
//!    not be wasted. The caller should drain one piece at a time and
//!    stop on send failure.
//!
//! 2. **Fan-out fairness**: when multiple PushStreams compete for send
//!    budget (e.g., same blob to 3 peers), round-robin scheduling
//!    ensures all streams make approximately equal progress.

use merkle_tox_core::cas::{CHUNK_SIZE, INITIAL_CREDITS, PushStream};
use merkle_tox_core::dag::NodeHash;

fn make_stream(seed: u8) -> PushStream {
    let blob_hash = NodeHash::from([seed; 32]);
    let blob_size = CHUNK_SIZE * 16; // 16 chunks = 1MB, ~880 pieces
    PushStream::new(blob_hash, blob_size, None, None)
}

/// Credits decrease by exactly the number of pieces consumed.
#[test]
fn credits_decrease_by_exact_pieces_consumed() {
    let mut stream = make_stream(1);
    assert_eq!(stream.credits, INITIAL_CREDITS);

    let consumed = 10;
    for _ in 0..consumed {
        assert!(stream.next_piece().is_some());
    }
    assert_eq!(
        stream.credits,
        INITIAL_CREDITS - consumed,
        "credits should decrease by exactly the number of pieces drained"
    );
}

/// Simulates the OLD flush pattern: drain 256 pieces into a Vec but
/// only "send" a fraction. The remaining credits are wasted.
///
/// This test documents the bug — the assertion on wasted credits shows
/// what the old code does wrong. When the fix lands (drain one at a
/// time, stop on failure), this pattern should never happen in
/// production, but the test remains as a regression guard on credit
/// accounting.
#[test]
fn pre_drain_wastes_credits_when_send_budget_is_small() {
    let mut stream = make_stream(2);

    // OLD pattern: drain 256 pieces up front (like the Vec pre-drain)
    let batch_size = INITIAL_CREDITS; // 256
    let mut drained_offsets = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        if let Some(offset) = stream.next_piece() {
            drained_offsets.push(offset);
        }
    }
    assert_eq!(drained_offsets.len(), batch_size);

    // Simulate: CC window only allows 10 sends — rest discarded
    let sent = 10;
    let _sent_offsets = &drained_offsets[..sent];
    // The remaining 246 pieces are gone — credits wasted
    let wasted = batch_size - sent;

    assert_eq!(stream.credits, 0, "all credits consumed by pre-drain");
    assert_eq!(wasted, 246, "246 credits wasted by the old pattern");
}

/// Simulates the CORRECT pattern: drain one piece at a time, stop
/// when the "send" fails. Credits consumed == pieces actually sent.
#[test]
fn drain_one_at_a_time_preserves_credits() {
    let mut stream = make_stream(3);

    let send_budget = 10;
    let mut sent = 0;
    for _ in 0..send_budget {
        if stream.next_piece().is_some() {
            sent += 1;
        }
    }

    assert_eq!(sent, send_budget);
    assert_eq!(
        stream.credits,
        INITIAL_CREDITS - send_budget,
        "only {send_budget} credits consumed — rest preserved for next poll"
    );
}

/// Three push streams drained round-robin (1 piece per stream per
/// cycle) all make equal progress, regardless of iteration order.
#[test]
fn fan_out_round_robin_distributes_equally() {
    let mut streams: Vec<PushStream> = (0..3).map(|i| make_stream(i + 10)).collect();
    let budget_per_stream = 50;

    // Round-robin: 1 piece from each stream, repeated budget times
    let mut pieces_per_stream = [0usize; 3];
    for _ in 0..budget_per_stream {
        for (i, stream) in streams.iter_mut().enumerate() {
            if stream.next_piece().is_some() {
                pieces_per_stream[i] += 1;
            }
        }
    }

    // All streams should have gotten exactly budget_per_stream pieces
    for (i, &count) in pieces_per_stream.iter().enumerate() {
        assert_eq!(
            count, budget_per_stream,
            "stream {i} got {count} pieces, expected {budget_per_stream}"
        );
    }

    // All streams should have equal remaining credits
    let remaining: Vec<usize> = streams.iter().map(|s| s.credits).collect();
    assert!(
        remaining.windows(2).all(|w| w[0] == w[1]),
        "streams have unequal remaining credits: {:?}",
        remaining
    );
}

/// Under the OLD sequential pattern with a global budget, only the
/// first stream gets served. This test documents the starvation.
#[test]
fn sequential_drain_starves_later_streams() {
    let mut streams: Vec<PushStream> = (0..3).map(|i| make_stream(i + 20)).collect();

    // Simulate: global budget of 50 pieces (e.g., CC window shared
    // across all outgoing traffic for a poll cycle).
    let global_budget = 50;
    let mut pieces_per_stream = [0usize; 3];
    let mut budget_remaining = global_budget;

    // OLD pattern: drain sequentially
    for (i, stream) in streams.iter_mut().enumerate() {
        let batch = budget_remaining.min(INITIAL_CREDITS);
        for _ in 0..batch {
            if stream.next_piece().is_some() {
                pieces_per_stream[i] += 1;
                budget_remaining -= 1;
                if budget_remaining == 0 {
                    break;
                }
            }
        }
        if budget_remaining == 0 {
            break;
        }
    }

    // Stream 0 ate the whole budget
    assert_eq!(pieces_per_stream[0], 50);
    assert_eq!(pieces_per_stream[1], 0, "stream 1 starved");
    assert_eq!(pieces_per_stream[2], 0, "stream 2 starved");
}

/// Round-robin with the same global budget distributes fairly.
#[test]
fn round_robin_with_global_budget_distributes_fairly() {
    let mut streams: Vec<PushStream> = (0..3).map(|i| make_stream(i + 30)).collect();
    let global_budget = 51; // divisible by 3

    let mut pieces_per_stream = [0usize; 3];
    let mut budget_remaining = global_budget;
    let mut active: Vec<usize> = (0..3).collect();

    while budget_remaining > 0 && !active.is_empty() {
        active.retain(|&i| {
            if budget_remaining == 0 {
                return false;
            }
            if let Some(_offset) = streams[i].next_piece() {
                pieces_per_stream[i] += 1;
                budget_remaining -= 1;
                true
            } else {
                false
            }
        });
    }

    // Each stream should get 17 pieces (51 / 3)
    for (i, &count) in pieces_per_stream.iter().enumerate() {
        assert_eq!(count, 17, "stream {i} got {count} pieces, expected 17");
    }
}
