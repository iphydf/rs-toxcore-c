//! Adversarial coverage for ACK packet poisoning.
//!
//! The sender processes peer-supplied `base_seq` and `recv_bytes`
//! fields in every incoming `Packet::Ack`. Both are authoritative
//! inputs to loss detection, delivery-rate sampling, and congestion
//! control, yet neither has any cryptographic binding at the
//! `tox-sequenced` layer — a compromised peer (authenticated at the
//! friend-connection layer) can supply any values they like.
//!
//! Without bounds, two concrete attacks exist:
//!
//! 1. **`base_seq` forward leap**: peer names a `base_seq` one
//!    ahead of the sender's next-outgoing seq. The wrapping_sub
//!    logic in `handle_ack` treats every in-flight seq as "before
//!    base_seq", implicitly marking every outstanding datagram
//!    `DatagramDelivered`. Genuine loss detection is lost and the
//!    sender's view of outstanding bytes collapses to zero,
//!    artificially reopening the congestion window.
//!
//! 2. **Inflated `recv_bytes`**: peer claims to have received far
//!    more bytes than the sender has sent. `delta_recv` feeds the
//!    BBR delivery sample (`bytes_delivered / duration`), so a
//!    fabricated jump inflates the perceived delivery rate and
//!    forces cwnd expansion.
//!
//! The defensive fix is two clamps: `recv_bytes <= bytes_sent`, and
//! `base_seq` must not be ahead of `next_seq`. Both are
//! self-consistency checks using values the sender already knows.

use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_proto::Untrusted;
use tox_sequenced::protocol::{MessageType, Packet};
use tox_sequenced::time::ManualTimeProvider;
use tox_sequenced::{SequenceSession, SessionEvent};

fn make_session(now: Instant) -> (SequenceSession, Arc<ManualTimeProvider>) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let session = SequenceSession::new_at(now, tp.clone(), &mut rng);
    (session, tp)
}

/// Flush all pacing-gated datagrams and return the sequence numbers
/// the session emitted. Advances `now` by 5ms between flush cycles so
/// the pacer releases the queue.
fn flush_seqs(session: &mut SequenceSession, start: Instant) -> Vec<u32> {
    let mut seqs = Vec::new();
    let mut now = start;
    for _ in 0..500 {
        session.flush(now, 0, &mut |p| {
            if let Packet::Data { seq, .. } = p {
                seqs.push(seq);
            }
            true
        });
        if session.outgoing_count() == 0 {
            break;
        }
        now += Duration::from_millis(5);
    }
    seqs
}

fn drain_events(session: &mut SequenceSession) -> Vec<SessionEvent> {
    let mut events = Vec::new();
    while let Some(e) = session.poll_event() {
        events.push(e);
    }
    events
}

/// Poisoning guard 1 — `base_seq` far ahead of `next_seq`. A single
/// forged ACK must NOT mark every in-flight datagram delivered.
#[test]
fn test_forged_ack_base_seq_ahead_of_next_seq_is_rejected() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    for i in 0..8 {
        let data = format!("msg{i}").into_bytes();
        alice.send(MessageType::MerkleNode, &data, now).unwrap();
    }
    let sent_seqs = flush_seqs(&mut alice, now);
    assert_eq!(sent_seqs.len(), 8);
    // Drain any early events (ReadyToSend etc) so the test only
    // observes events produced in response to the forged ACK.
    let _ = drain_events(&mut alice);

    // Forged ACK: peer claims base_seq strictly ahead of our
    // next-outgoing seq (base = highest_sent + 100). `base = next_seq`
    // is a legitimate "everything delivered" ACK (receiver has
    // consumed up through highest_sent and is waiting for
    // highest_sent+1 == next_seq), but values past next_seq reference
    // seqs we never transmitted and are unambiguously forged. Without
    // the clamp, every in-flight entry hits the wrap-boundary branch
    // and is marked DatagramDelivered.
    let highest = *sent_seqs.iter().max().unwrap();
    let future_base = highest.wrapping_add(100);
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(future_base),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
        },
        now + Duration::from_millis(1),
    );

    let events = drain_events(&mut alice);
    let spurious_deliveries: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::DatagramDelivered(seq) => Some(*seq),
            _ => None,
        })
        .collect();
    assert!(
        spurious_deliveries.is_empty(),
        "forged ACK with base_seq ahead of next_seq must not mark any \
         datagram delivered — got {:?}. A regression here lets a \
         compromised peer blind the sender's loss detector and \
         artificially reopen cwnd.",
        spurious_deliveries,
    );
}

/// Poisoning guard 2 — `recv_bytes` greater than `bytes_sent`. The
/// peer cannot have received more bytes than the sender transmitted.
/// An inflated `recv_bytes` is self-contradicting and must be ignored
/// (clamped) before feeding BBR's delivery-rate estimator.
#[test]
fn test_forged_ack_recv_bytes_exceeding_bytes_sent_is_clamped() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    let small = vec![0xAAu8; 64];
    alice.send(MessageType::MerkleNode, &small, now).unwrap();
    let _ = flush_seqs(&mut alice, now);
    let _ = drain_events(&mut alice);

    let cwnd_before = alice.cwnd();

    // Peer claims to have received an impossibly large cumulative
    // byte count. A faithful ACK-handler (no clamp) feeds this delta
    // straight into BBR: bytes_delivered in the sample jumps by
    // petabytes and pacing rate is driven to its ceiling.
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(0),
            recv_bytes: Untrusted::new(u64::MAX),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
        },
        now + Duration::from_millis(1),
    );

    let cwnd_after = alice.cwnd();

    // With clamp in place, cwnd cannot grow by more than one
    // reasonable multiplier from a single fake ACK. Without the
    // clamp, it jumps to MAX_WINDOW (1 MB / 64KB chunks).
    assert!(
        cwnd_after <= cwnd_before * 2,
        "forged ACK with recv_bytes=u64::MAX must not inflate cwnd \
         beyond ~2x — got before={}, after={}. BBR must see a delivery \
         sample bounded by what the sender actually transmitted.",
        cwnd_before,
        cwnd_after,
    );
}

// =============================================================================
// Plan B (SACK ranges) adversarial coverage.
//
// The ACK now carries a `sack_ranges: SmallVec<(u32, u32), 8>` field
// reporting non-contiguous above-base receipts. Each range is peer-
// supplied; the sender must clamp all of them before resolving any
// `sent_datagrams` entries. The defenses live in `handle_ack` (lines
// 660-696 ish): each range must have `start >= base_seq`, sorted &
// non-overlapping (`last_end` tracking), `length` in (0, MAX_SACK_RANGE_LENGTH],
// and `start + length <= next_seq`. The `entry.resolved` guard
// prevents double-decrement of `sum_unresolved_bytes` regardless of
// what ranges arrive.
//
// These tests pin those invariants against Byzantine peers.
// =============================================================================

/// Helper: send N packets and return their seqs.
fn send_n(session: &mut SequenceSession, n: u32, now: Instant) -> Vec<u32> {
    for i in 0..n {
        session
            .send(MessageType::MerkleNode, &[i as u8; 100], now)
            .unwrap();
    }
    flush_seqs(session, now)
}

/// SACK range with `start < base_seq` must be rejected. Below-base
/// seqs are already cumulatively acked; a range claiming them is
/// either redundant (resolved entries are skipped) or malicious
/// (trying to underflow sum_unresolved_bytes via double-decrement).
#[test]
fn test_sack_range_below_base_seq_rejected() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 6, now);
    let _ = drain_events(&mut alice);
    let in_flight_before = alice.in_flight();

    // Forged ACK: base_seq=seqs[3] (cumulative covers 0..=2), then a
    // SACK range claiming seqs[0]..=seqs[2] AGAIN (below base).
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[3]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[0], 3u32)]),
        },
        now + Duration::from_millis(1),
    );

    // After the ACK: cumulative resolution covers seqs[0..=2]. Below-
    // base SACK is rejected by the `start.wrapping_sub(base_seq) >
    // 0x7FFF_FFFF` clamp. seqs[3..=5] remain unresolved.
    let delivered: Vec<u32> = drain_events(&mut alice)
        .into_iter()
        .filter_map(|e| match e {
            SessionEvent::DatagramDelivered(s) => Some(s),
            _ => None,
        })
        .collect();
    let mut got = delivered;
    got.sort();
    let mut expected = vec![seqs[0], seqs[1], seqs[2]];
    expected.sort();
    assert_eq!(got, expected, "below-base SACK must not double-resolve");

    let in_flight_after = alice.in_flight();
    assert!(
        in_flight_after < in_flight_before,
        "in_flight must drop after cumulative resolution"
    );
    // The drop should equal exactly the size of seqs[0..=2], not 2x.
    // If the SACK had not been rejected, the same 3 entries would have
    // been "resolved" twice and sum_unresolved_bytes would have
    // saturated to 0 instead of dropping by ~3 packets' worth.
    let drop = in_flight_before - in_flight_after;
    let one_pkt_overhead = 100 + tox_sequenced::protocol::PACKET_OVERHEAD;
    assert!(
        drop <= 4 * one_pkt_overhead,
        "in_flight dropped by {}B; expected ~{}B (3 packets), \
         a larger drop suggests the below-base SACK was processed.",
        drop,
        3 * one_pkt_overhead,
    );
}

/// Boundary: a SACK range with `start + length == next_seq` is at the
/// edge of valid. The clamp uses `end != self.next_seq` as part of the
/// rejection condition — so end-equals-next-seq must be ACCEPTED.
#[test]
fn test_sack_range_end_equals_next_seq_accepted() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 5, now);
    let _ = drain_events(&mut alice);

    // Range spans seqs[2..=4] inclusive: start=seqs[2], length=3.
    // end = seqs[5] = next_seq (since we sent 5 packets).
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[1]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[2], 3u32)]),
        },
        now + Duration::from_millis(1),
    );

    let delivered: Vec<u32> = drain_events(&mut alice)
        .into_iter()
        .filter_map(|e| match e {
            SessionEvent::DatagramDelivered(s) => Some(s),
            _ => None,
        })
        .collect();
    let mut got = delivered;
    got.sort();
    // Cumulative covers seq 0; SACK covers seqs 2,3,4. Seq 1 stays
    // unresolved (the gap).
    let mut expected = vec![seqs[0], seqs[2], seqs[3], seqs[4]];
    expected.sort();
    assert_eq!(
        got, expected,
        "end-equals-next_seq SACK range must be accepted (boundary case)"
    );
}

/// Zero-length range is a no-op; must not affect any state.
#[test]
fn test_sack_range_zero_length_ignored() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 5, now);
    let _ = drain_events(&mut alice);
    let in_flight_before = alice.in_flight();

    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[0]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[2], 0u32)]),
        },
        now + Duration::from_millis(1),
    );

    assert!(
        drain_events(&mut alice)
            .iter()
            .all(|e| !matches!(e, SessionEvent::DatagramDelivered(_)))
    );
    assert_eq!(
        alice.in_flight(),
        in_flight_before,
        "zero-length range must not change in_flight"
    );
}

/// Range with length > MAX_SACK_RANGE_LENGTH is rejected.
#[test]
fn test_sack_range_over_max_length_rejected() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 5, now);
    let _ = drain_events(&mut alice);
    let in_flight_before = alice.in_flight();

    let oversized = tox_sequenced::protocol::MAX_SACK_RANGE_LENGTH + 1;
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[0]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[1], oversized)]),
        },
        now + Duration::from_millis(1),
    );

    // No DatagramDelivered should fire from the SACK path — the range
    // is rejected for length > MAX_SACK_RANGE_LENGTH.
    let delivered_count = drain_events(&mut alice)
        .iter()
        .filter(|e| matches!(e, SessionEvent::DatagramDelivered(_)))
        .count();
    assert_eq!(
        delivered_count, 0,
        "oversized SACK range must not deliver any seqs"
    );
    assert_eq!(alice.in_flight(), in_flight_before);
}

/// Out-of-order SACK ranges (second range starts before first ends)
/// must be rejected by the `last_end` monotonicity check. No double-
/// decrement, no corruption of sum_unresolved_bytes.
#[test]
fn test_sack_ranges_out_of_order_handled_safely() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 8, now);
    let _ = drain_events(&mut alice);

    // Ranges in non-monotonic order: [(seqs[5], 2), (seqs[1], 2)] —
    // the second range's start is before the first range's start, so
    // it should be rejected. Only the first range should resolve.
    // Use base_seq = seqs[1] so cumulative also resolves seqs[0],
    // exercising both paths in one ACK.
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[1]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[5], 2u32), (seqs[1], 2u32)]),
        },
        now + Duration::from_millis(1),
    );

    let delivered: Vec<u32> = drain_events(&mut alice)
        .into_iter()
        .filter_map(|e| match e {
            SessionEvent::DatagramDelivered(s) => Some(s),
            _ => None,
        })
        .collect();
    let mut got = delivered;
    got.sort();
    // Cumulative resolves seqs[0]; first SACK range resolves
    // seqs[5..=6]. Second range is rejected, so seqs[1..=2] stay
    // unresolved.
    let mut expected = vec![seqs[0], seqs[5], seqs[6]];
    expected.sort();
    assert_eq!(got, expected, "out-of-order second range must be rejected");
}

/// CPU amplification: the maximum permitted SACK shape (8 ranges ×
/// MAX_SACK_RANGE_LENGTH each) must complete in well under a second
/// even when the sender's `sent_datagrams` ring is near-full. Bounds
/// the worst-case per-ACK CPU cost.
#[test]
fn test_sack_cpu_amplification_with_maximal_ranges() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    // Fill sent_datagrams to a non-trivial size so the inner loop has
    // work to do.
    let seqs = send_n(&mut alice, 200, now);
    let _ = drain_events(&mut alice);

    let max_len = tox_sequenced::protocol::MAX_SACK_RANGE_LENGTH;
    // MAX_SACK_RANGES (8) ranges, each spaced and at max_len. They
    // will mostly exceed next_seq and be rejected, but the rejection
    // itself should be cheap.
    let mut ranges: tox_proto::BoundedVec<
        (u32, u32),
        { tox_sequenced::protocol::MAX_SACK_RANGES },
    > = tox_proto::BoundedVec::new();
    for i in 0..tox_sequenced::protocol::MAX_SACK_RANGES as u32 {
        let start = seqs[0].wrapping_add(i.wrapping_mul(max_len));
        ranges
            .try_push((start, max_len))
            .expect("filling within MAX_SACK_RANGES");
    }

    let t0 = Instant::now();
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[0]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(ranges),
        },
        now + Duration::from_millis(1),
    );
    let elapsed = t0.elapsed();

    // 100ms is generous; real should be sub-ms. If we exceed this the
    // amplification is real.
    assert!(
        elapsed < Duration::from_millis(100),
        "8 maximal SACK ranges should process in <100ms, took {:?}",
        elapsed
    );
}

/// Wraparound: SACK range whose `start + length` wraps past u32::MAX.
/// Wrapping arithmetic is consistent throughout `handle_ack` but
/// off-by-one is easy to miss. Verify a wrapping range constructed
/// against an attacker-chosen `next_seq` doesn't bypass clamping.
#[test]
fn test_sack_range_wraparound_at_u32_boundary() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    // Send a few packets to advance next_seq from its random initial value.
    let seqs = send_n(&mut alice, 4, now);
    let _ = drain_events(&mut alice);
    let in_flight_before = alice.in_flight();

    // Construct a range with start near u32::MAX and length pushing
    // it past 0. This claims seqs at the high end of the u32 space
    // PLUS seqs starting from 0. Whatever next_seq is, the range
    // covers at least one valid seq via wraparound.
    //
    // The clamping at `end.wrapping_sub(self.next_seq) <= 0x7FFF_FFFF
    // && end != self.next_seq` should reject this: end is "less than"
    // next_seq in wrapping sense (since we wrapped around).
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[0]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(u32::MAX - 100, 200u32)]),
        },
        now + Duration::from_millis(1),
    );

    // Cumulative resolution might have fired for seqs[0..0] (none if
    // base_seq=seqs[0], so just seq 0 is "before base"). Verify no
    // bogus deliveries from the wrapping range.
    let delivered_count = drain_events(&mut alice)
        .iter()
        .filter(|e| matches!(e, SessionEvent::DatagramDelivered(_)))
        .count();
    // Cumulative could resolve at most seqs whose seq < base_seq=seqs[0],
    // which is none of our sent seqs. So zero deliveries expected.
    assert_eq!(
        delivered_count, 0,
        "wrapping SACK range must not cause spurious deliveries"
    );
    assert_eq!(
        alice.in_flight(),
        in_flight_before,
        "in_flight must be unchanged by a rejected wrapping range"
    );
}

/// Repeated ACKs and duplicate ranges within a single ACK must be
/// idempotent — `sum_unresolved_bytes` is decremented at most once
/// per entry by virtue of the `entry.resolved` guard.
#[test]
fn test_sack_repeated_acks_and_ranges_idempotent() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 5, now);
    let _ = drain_events(&mut alice);

    let ack = Packet::Ack {
        base_seq: Untrusted::new(seqs[0]),
        recv_bytes: Untrusted::new(0),
        // Three identical ranges in the same ACK. Internal `last_end`
        // monotonicity check rejects duplicates 2 and 3, but even if
        // it didn't, `entry.resolved` would prevent double-decrement.
        sack_ranges: Untrusted::new(tox_proto::bounded_vec![
            (seqs[1], 3u32),
            (seqs[1], 3u32),
            (seqs[1], 3u32),
        ]),
    };

    let in_flight_after_first = {
        alice.handle_packet(ack.clone(), now + Duration::from_millis(1));
        alice.in_flight()
    };

    // Send the same ACK three more times. in_flight must NOT drop
    // further (no new resolutions) and must NOT underflow.
    for i in 2..=4 {
        alice.handle_packet(ack.clone(), now + Duration::from_millis(i));
    }
    let in_flight_after_repeats = alice.in_flight();

    assert_eq!(
        in_flight_after_first, in_flight_after_repeats,
        "repeated identical ACKs must be idempotent (got {} then {})",
        in_flight_after_first, in_flight_after_repeats,
    );
}

/// Invariant: `in_flight()` (which reads `sum_unresolved_bytes`) must
/// equal the actual sum of unresolved entry sizes after any sequence
/// of operations. Verified by sending, ACKing, and aging out, then
/// confirming the counter ends at zero when nothing is unresolved.
#[test]
fn test_sum_unresolved_bytes_never_underflows() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 10, now);
    let _ = drain_events(&mut alice);
    let initial = alice.in_flight();
    assert!(initial > 0);

    // Mix of operations: one ACK with cumulative + SACK, one
    // duplicate, one with overlapping ranges.
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[3]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[5], 2u32)]),
        },
        now + Duration::from_millis(1),
    );
    // Duplicate of the same ACK (idempotent).
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[3]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[5], 2u32)]),
        },
        now + Duration::from_millis(2),
    );
    // Overlapping SACK ranges in one ACK (second is rejected).
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[3]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[7], 2u32), (seqs[7], 3u32),]),
        },
        now + Duration::from_millis(3),
    );

    // After all this, the resolved set is: cumulative seqs[0..=2],
    // SACK seqs[5..=6], SACK seqs[7..=8]. Unresolved: seqs[3], seqs[4],
    // seqs[9]. The counter should equal exactly the sum of those
    // three packets' tracked sizes, NOT zero (no underflow) and NOT
    // the original initial value (some resolution happened).
    let after = alice.in_flight();
    assert!(
        after > 0,
        "in_flight should be non-zero (3 unresolved) after partial resolution"
    );
    assert!(
        after < initial,
        "in_flight should have decreased after resolutions"
    );
    // Now finally fully resolve: ACK with base_seq one past the highest sent.
    let last_seq = *seqs.last().unwrap();
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(last_seq.wrapping_add(1)),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
        },
        now + Duration::from_millis(10),
    );
    assert_eq!(
        alice.in_flight(),
        0,
        "in_flight must be exactly 0 after fully resolving every entry"
    );
}

/// PONG timestamp poisoning must not manipulate the RTO. The peer
/// can set `t2` and `t3` arbitrarily, but RTT samples come from the
/// local clock (`now - last_ping_sent`).
#[test]
fn test_rto_is_not_manipulated_by_pong_timestamps() {
    use tox_sequenced::protocol::TimestampMs;

    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    // Trigger alice to send a PING by waiting past PING_INTERVAL.
    // First flush to send any queued packets and emit the ping.
    let later = now + Duration::from_secs(11);
    let mut sent = Vec::new();
    alice.flush(later, 0, &mut |p| {
        sent.push(p);
        true
    });
    let ping_t1 = sent.iter().find_map(|p| match p {
        Packet::Ping { t1 } => Some(*t1),
        _ => None,
    });
    assert!(ping_t1.is_some(), "alice should have emitted a PING");

    let rto_before = alice.current_rto();

    // Forged PONG: t2 and t3 set to extreme values trying to inflate
    // the perceived clock-offset. The handler computes
    // `rtt_sample = now - sent_time` from the local clock — the
    // peer's t2/t3 only feed clock_offset, not RTT.
    let forged = Packet::Pong {
        t1: ping_t1.unwrap(),
        t2: TimestampMs(i64::MAX / 2),
        t3: TimestampMs(i64::MAX / 2),
    };
    alice.handle_packet(forged, later + Duration::from_millis(5));

    let rto_after = alice.current_rto();
    // RTO should be sensitive to the actual measured RTT (5 ms here),
    // not to the forged absolute timestamps. It should remain in a
    // sane range around the floor.
    assert!(
        rto_after >= Duration::from_millis(200),
        "RTO must respect MIN_RTO floor, got {:?}",
        rto_after
    );
    assert!(
        rto_after <= Duration::from_millis(5000),
        "RTO must respect MAX_RTO ceiling regardless of forged timestamps, got {:?}",
        rto_after
    );
    // Specifically, a few-ms actual RTT shouldn't push RTO anywhere
    // near MAX_RTO; if it does, the peer's timestamps polluted it.
    assert!(
        rto_after < Duration::from_secs(2),
        "RTO must be governed by local RTT samples, not peer timestamps; \
         before={:?} after={:?}",
        rto_before,
        rto_after
    );
}

/// Receiver bitmap window slide must not lose cumulative-ack
/// information. When a sender's seqs span far apart (forcing the
/// receiver's 1024-bit window to slide), `base` should still advance
/// correctly when the contiguous-received prefix grows.
#[test]
fn test_recv_window_slide_does_not_lose_cumulative_acks() {
    let now = Instant::now();
    let (mut bob, _tp) = make_session(now);

    // Bob receives seq 0. base advances to 1.
    bob.handle_packet(
        Packet::Data {
            seq: 0,
            msg_type: MessageType::MerkleNode,
            data: vec![0u8; 8],
        },
        now,
    );

    // Bob receives seq 2000 — far past the 1024-bit window. The
    // window slides to admit it; older bits drop. seq 0 was already
    // cumulatively absorbed (base=1), so its info isn't lost.
    bob.handle_packet(
        Packet::Data {
            seq: 2000,
            msg_type: MessageType::MerkleNode,
            data: vec![0u8; 8],
        },
        now + Duration::from_millis(1),
    );

    // Now bob receives seqs 1..=2 (filling the gap right after the
    // original base). base should advance through them.
    bob.handle_packet(
        Packet::Data {
            seq: 1,
            msg_type: MessageType::MerkleNode,
            data: vec![0u8; 8],
        },
        now + Duration::from_millis(2),
    );
    bob.handle_packet(
        Packet::Data {
            seq: 2,
            msg_type: MessageType::MerkleNode,
            data: vec![0u8; 8],
        },
        now + Duration::from_millis(3),
    );

    // Trigger ACK build by flushing.
    let mut acks = Vec::new();
    bob.flush(now + Duration::from_millis(100), 0, &mut |p| {
        if matches!(p, Packet::Ack { .. }) {
            acks.push(p.clone());
        }
        true
    });
    assert!(!acks.is_empty(), "bob should have emitted an ACK");

    // The reported base_seq should be > 0 (we know seq 0 is implicitly
    // delivered). After receiving 0, 1, 2, base should be at least 3.
    if let Packet::Ack { base_seq, .. } = &acks[0] {
        let base = *base_seq.expose_unchecked();
        assert!(
            base >= 3,
            "after receiving seqs 0,1,2 plus a far-future seq 2000, \
             base_seq must be >= 3 (cumulative info not lost), got {}",
            base
        );
    }
}

/// Combo attack: a sequence of forged + boundary inputs across
/// cumulative, SACK, and timer-loss paths must not corrupt
/// `sum_unresolved_bytes`. The `entry.resolved` guard is the central
/// invariant; this test exercises all three resolution paths against
/// the same set of entries.
#[test]
fn test_combined_cumulative_sack_timer_does_not_corrupt_state() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);
    let seqs = send_n(&mut alice, 6, now);
    let _ = drain_events(&mut alice);

    // Step 1: cumulative ACK resolves seqs[0..=1].
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[2]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
        },
        now + Duration::from_millis(1),
    );
    let in_flight_after_cumulative = alice.in_flight();

    // Step 2: SACK ACK that ALSO claims seqs[0..=1] (already resolved
    // via cumulative). Plus claims seqs[3..=4] (newly resolves).
    // The first range is no-op (entries are already resolved); the
    // second is real.
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs[2]),
            recv_bytes: Untrusted::new(0),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![(seqs[3], 2u32)]),
        },
        now + Duration::from_millis(2),
    );
    let in_flight_after_sack = alice.in_flight();

    // Step 3: advance time past RTO. check_losses fires; timer-loss
    // marks seqs[2] and seqs[5] (the still-unresolved ones).
    alice.flush(now + Duration::from_secs(2), 0, &mut |_| true);

    // After all three paths: every sent seq has resolved exactly once.
    // sum_unresolved_bytes must end at exactly 0 (no underflow, no
    // residual).
    assert!(
        in_flight_after_cumulative > in_flight_after_sack,
        "in_flight should drop after SACK resolves seqs[3..=4]"
    );
    assert_eq!(
        alice.in_flight(),
        0,
        "after cumulative + SACK + timer-loss across all entries, \
         sum_unresolved_bytes must be exactly 0 (no double-decrement, \
         no underflow, no leak)"
    );
}

// ---- Adversarial coverage for the BW-spike defences (RTT-from-ACK
// sampling + duration floor at min_rtt + MAX_BW_CEILING + pacing-rate
// output clamp). All four landed in `fix(transport): Sample RTT from
// regular ACKs` (ede1302) and `fix(cc): Defend BBR bandwidth estimator
// against sub-RTT delivery samples` (5f6e290) / `fix(cc): Tighten
// MAX_BW_CEILING` (516fca2). Each test below pins a specific peer-
// controllable manipulation — what a compromised friend, having been
// authenticated at the friend-connection layer, can do with the
// `Untrusted<T>`-tagged fields they supply.
//
// Attack surface:
//   * `Packet::Ack { base_seq, recv_bytes, sack_ranges }`: peer-
//     controlled. `recv_bytes` is clamped at `bytes_sent`; `base_seq`
//     is rejected ahead of `next_seq`; `sack_ranges` are validated
//     for ordering, length, and bounds (covered above).
//   * **ACK timing**: when ACKs arrive, and how they're spaced. Peer
//     can hold ACKs and burst them, batch them, or selectively
//     deliver them.
//   * **Per-ACK RTT sampling**: `now - sent_time` of the freshest
//     newly-resolved entry. Peer chooses *which* entry (via base_seq
//     + sack_ranges) becomes the freshest; the `sent_time` itself is
//     local state, not peer-controlled.
//
// What a peer can attempt:
//   1. Inflate pacing past physical link by reporting big
//      `recv_bytes` deltas in tightly-spaced ACKs. → `MAX_BW_CEILING`
//      ceiling clamps both `max_bw` (`update_bandwidth`) and
//      `pacing_rate` output.
//   2. Inflate `min_rtt` by selectively ACKing only the oldest
//      in-flight seq, making the freshest-acked-send-time stale. →
//      `update_min_rtt` only updates when `rtt < self.min_rtt`
//      (within the `PROBE_RTT_INTERVAL` window).
//   3. Inflate `srtt` (and therefore `rto`) by feeding stale
//      timestamps. → SRTT is smoothed (alpha=0.125); per-sample
//      influence bounded; RTO clamped at `MAX_RTO = 5 s`.
//   4. Stall the connection by sending no ACKs. → Sender's cwnd
//      gate stops sending; RTO eventually fires; existing loss
//      machinery handles it. Pacing stays at `STARTUP_MIN_PACING_
//      RATE` floor — no path to runaway.

/// BW-spike guard 1 — burst-of-ACKs cannot drive pacing past
/// `MAX_BW_CEILING`. A peer that holds ACKs and then releases them in
/// tight succession produces a sequence of (small `delta_time`, large
/// `delta_recv`) samples, which a naive estimator would multiply into
/// multi-Gbps. The combination of duration-floor-at-min_rtt and the
/// hard ceiling must keep pacing bounded.
#[test]
fn test_burst_acks_cannot_inflate_pacing_past_ceiling() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    // Send a healthy burst of payload data so the sender has bytes
    // outstanding for the peer's ACKs to claim against.
    let payload = vec![0xCDu8; 256];
    for _ in 0..200 {
        alice.send(MessageType::MerkleNode, &payload, now).unwrap();
    }
    let seqs = flush_seqs(&mut alice, now);
    let bytes_sent = alice.bytes_sent();
    assert!(seqs.len() >= 100, "warmup must produce many in-flight seqs");

    // Peer holds ACKs for 100 ms, then releases them in 10 tight
    // ACKs spaced 100 µs apart. Each ACK advances `recv_bytes` by
    // `bytes_sent / 10`. Naive bw on the second-and-later ACKs would
    // be `(bytes_sent / 10) / 100 µs` ≈ tens of Gbps each.
    let mut t = now + Duration::from_millis(100);
    let chunk = bytes_sent / 10;
    for i in 1..=10 {
        let cumulative = (chunk * i).min(bytes_sent);
        let base_seq_for_chunk = seqs
            .get((seqs.len() * (i as usize) / 10).saturating_sub(1))
            .copied()
            .unwrap_or(seqs[seqs.len() - 1])
            .wrapping_add(1);
        alice.handle_packet(
            Packet::Ack {
                base_seq: Untrusted::new(base_seq_for_chunk),
                recv_bytes: Untrusted::new(cumulative),
                sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
            },
            t,
        );
        t += Duration::from_micros(100);
    }

    // After the burst, pacing must be bounded by MAX_BW_CEILING.
    // We assert at the symbolic constant rather than the numeric
    // value so future tightening of the ceiling tightens the test
    // automatically.
    let pacing = alice.pacing_rate();
    assert!(
        pacing <= tox_sequenced::congestion::MAX_BW_CEILING,
        "burst-ACK attack pushed pacing to {:.1} Mbps; MAX_BW_CEILING \
         is {:.1} Mbps. The duration floor + ceiling clamps in \
         update_bandwidth must keep pacing bounded under any peer-\
         induced ACK timing pattern.",
        pacing * 8.0 / 1_000_000.0,
        tox_sequenced::congestion::MAX_BW_CEILING * 8.0 / 1_000_000.0,
    );
}

/// BW-spike guard 2 — a peer ACKing only the oldest unresolved seq
/// (and never the newer ones) inflates `rtt_sample` because the
/// freshest-newly-acked entry IS the only-acked entry. Per-ACK
/// sampling feeds a large `now - oldest_sent_time` into the RTT
/// estimator. The smoothing factor (`RTT_ALPHA = 0.125`) bounds
/// per-sample influence on `srtt`; `update_min_rtt` only takes the
/// minimum within `PROBE_RTT_INTERVAL`, so a single high sample
/// CANNOT replace `min_rtt` once it has converged to a lower value.
#[test]
fn test_selective_oldest_ack_does_not_inflate_min_rtt_within_probe_window() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    // Establish a low min_rtt with a normal early exchange.
    alice
        .send(MessageType::MerkleNode, &[0u8; 64], now)
        .unwrap();
    let seqs_warmup = flush_seqs(&mut alice, now);
    let warmup_t = now + Duration::from_millis(5);
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(seqs_warmup[0].wrapping_add(1)),
            recv_bytes: Untrusted::new(64),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
        },
        warmup_t,
    );
    // SRTT estimator should now have at least one sample of ~5 ms.
    // The CC's min_rtt should also reflect it on the next ack-driven
    // path.

    // Send several more packets at known times within a short window,
    // so the *send_time* of the oldest is far behind "now" once the
    // adversarial ACK arrives.
    let mut t = warmup_t + Duration::from_millis(1);
    let mut adversarial_seqs = Vec::new();
    for _ in 0..5 {
        alice.send(MessageType::MerkleNode, &[0u8; 64], t).unwrap();
        let s = flush_seqs(&mut alice, t);
        adversarial_seqs.extend(s);
        t += Duration::from_millis(2);
    }

    // Adversarial ACK at t = warmup_t + 8 s, naming `base_seq =
    // adversarial_seqs[0] + 1` — only the *oldest* of the new burst
    // is acked. `now - sent_time` ≈ 8 s, which would be the
    // rtt_sample fed to the estimator.
    let adversarial_t = warmup_t + Duration::from_secs(8);
    let cumulative = alice.bytes_sent();
    alice.handle_packet(
        Packet::Ack {
            base_seq: Untrusted::new(adversarial_seqs[0].wrapping_add(1)),
            recv_bytes: Untrusted::new(cumulative),
            sack_ranges: Untrusted::new(tox_proto::bounded_vec![]),
        },
        adversarial_t,
    );

    // 8 s elapsed since warmup ACK is well below `PROBE_RTT_INTERVAL =
    // 10 s`, so `update_min_rtt`'s expiry path does NOT fire. The
    // 8 s sample is therefore dropped at the `rtt < self.min_rtt`
    // gate. min_rtt must remain at the warmup-driven low value, and
    // pacing must still be bounded by MAX_BW_CEILING. SRTT will
    // shift, but the CC-facing `min_rtt` is what drives BDP / cwnd.
    let pacing_after = alice.pacing_rate();
    assert!(
        pacing_after <= tox_sequenced::congestion::MAX_BW_CEILING,
        "adversarial 8 s rtt_sample drove pacing past ceiling: \
         {:.1} Mbps. update_min_rtt must reject high samples within \
         PROBE_RTT_INTERVAL, and the ceiling must clamp regardless.",
        pacing_after * 8.0 / 1_000_000.0,
    );
    assert!(
        alice.current_rto() <= tox_sequenced::rtt::MAX_RTO,
        "RTO escaped MAX_RTO clamp: got {:?}, max {:?}",
        alice.current_rto(),
        tox_sequenced::rtt::MAX_RTO,
    );
}

/// BW-spike guard 3 — a peer that batches every ACK to land at the
/// PROBE_RTT_INTERVAL boundary CAN replace the converged `min_rtt`
/// with a higher value (the expiry path admits any sample), but a
/// single normal-RTT sample afterwards must restore it. This pins
/// the recovery path so a long-lived session can't be permanently
/// throttled by a one-off adversarial sample at the refresh window.
#[test]
fn test_min_rtt_refresh_admits_recovery_via_normal_sample() {
    use tox_sequenced::congestion::{Algorithm, AlgorithmType, CongestionControl, DeliverySample};
    let now = Instant::now();
    let mut cc = Algorithm::new(AlgorithmType::Bbrv1, rand::rngs::StdRng::seed_from_u64(99));

    // Establish a low min_rtt.
    cc.on_ack(
        Duration::from_millis(2),
        Some(DeliverySample {
            bytes_delivered: 1500,
            duration: Duration::from_millis(2),
            now,
            app_limited: false,
        }),
        1500,
        1500,
        now,
    );
    let min_rtt_low = cc.min_rtt();
    assert!(
        min_rtt_low <= Duration::from_millis(5),
        "warmup must establish a low min_rtt; got {:?}",
        min_rtt_low,
    );

    // 11 s later — past PROBE_RTT_INTERVAL = 10 s — feed a high
    // adversarial RTT.
    let later = now + Duration::from_secs(11);
    cc.on_ack(
        Duration::from_millis(900),
        Some(DeliverySample {
            bytes_delivered: 1500,
            duration: Duration::from_millis(900),
            now: later,
            app_limited: false,
        }),
        1500,
        1500,
        later,
    );
    // The expiry path lets this sample replace min_rtt.
    let min_rtt_inflated = cc.min_rtt();
    assert!(
        min_rtt_inflated >= Duration::from_millis(800),
        "post-expiry adversarial sample should have replaced min_rtt; \
         got {:?}",
        min_rtt_inflated,
    );

    // Recovery: a single normal sample brings min_rtt back to the
    // floor via the `rtt < min_rtt` path. This is what protects a
    // long-lived session from one-shot adversarial inflation.
    let recover = later + Duration::from_millis(100);
    cc.on_ack(
        Duration::from_millis(2),
        Some(DeliverySample {
            bytes_delivered: 1500,
            duration: Duration::from_millis(2),
            now: recover,
            app_limited: false,
        }),
        1500,
        1500,
        recover,
    );
    assert!(
        cc.min_rtt() <= Duration::from_millis(5),
        "min_rtt should recover after one normal sample; got {:?}. \
         Without the recovery path, a peer that times one bad ACK at \
         the 10 s refresh boundary could permanently inflate the \
         BDP / cwnd estimate for the session.",
        cc.min_rtt(),
    );
}

/// BW-spike guard 4 — a silent peer (no ACKs) cannot trigger any
/// runaway state. The sender's pacing stays at `STARTUP_MIN_PACING_
/// RATE` and cwnd stays at the initial gate; with no `recv_bytes`
/// advance, the BBR delivery sample is `None`, so `update_bandwidth`
/// is never called and `max_bw` cannot grow.
#[test]
fn test_silent_peer_does_not_runaway_pacing() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    let pacing_initial = alice.pacing_rate();

    // Send a steady trickle for 30 s of simulated time. No ACKs
    // arrive at all.
    let mut t = now;
    for _ in 0..30 {
        alice.send(MessageType::MerkleNode, &[0u8; 256], t).unwrap();
        let _ = flush_seqs(&mut alice, t);
        t += Duration::from_secs(1);
    }
    // Drain any RTO-based loss events.
    let _ = drain_events(&mut alice);

    let pacing_silent = alice.pacing_rate();
    assert!(
        pacing_silent <= tox_sequenced::congestion::MAX_BW_CEILING,
        "pacing escaped ceiling under silent-peer condition: {:.1} Mbps",
        pacing_silent * 8.0 / 1_000_000.0,
    );
    // The sender should not have grown pacing dramatically without
    // any peer signal.  We don't pin "==initial" because the
    // controller may transition through internal states based on
    // local timers, but the order of magnitude must not move.
    assert!(
        pacing_silent < pacing_initial * 100.0,
        "pacing grew by >100× without any peer ACK signal: initial \
         {:.1} Mbps, after silence {:.1} Mbps. Without peer signal \
         there is no information that could justify pacing growth.",
        pacing_initial * 8.0 / 1_000_000.0,
        pacing_silent * 8.0 / 1_000_000.0,
    );
}
