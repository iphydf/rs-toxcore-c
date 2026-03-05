//! TDD anchors for the cumulative-only ACK redesign (Plan C).
//!
//! Today's transport sends a per-packet ACK bitmap that grows unbounded
//! under sustained loss, eventually exceeding `MAX_DATAGRAM_SIZE` and
//! wedging the connection. The redesign replaces the bitmap with a
//! cumulative-only ACK `{base_seq, recv_bytes}` and shifts loss detection
//! to a sender-side timer using the existing RFC 6298 RTO estimator.
//!
//! These tests encode the invariants that the redesign must preserve.
//! Tests 1 and 3 currently fail (or hit the bug) and will pass after the
//! redesign; tests 2 and 4 should pass both before and after, as
//! regression guards.
//!
//! See `doc/merkle-tox-design-rationale.md` §17 for the full rationale.

use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{MAX_DATAGRAM_SIZE, MessageType, Packet};
use tox_sequenced::time::ManualTimeProvider;
use tox_sequenced::{SequenceSession, SessionEvent};

fn make_session(now: Instant) -> (SequenceSession, Arc<ManualTimeProvider>) {
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let session = SequenceSession::new_at(now, tp.clone(), &mut rng);
    (session, tp)
}

fn collect_events(session: &mut SequenceSession) -> Vec<SessionEvent> {
    let mut events = Vec::new();
    while let Some(e) = session.poll_event() {
        events.push(e);
    }
    events
}

fn flush_all(session: &mut SequenceSession, start: Instant) -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut now = start;
    for _ in 0..1000 {
        session.flush(now, 0, &mut |packet| {
            packets.push(packet);
            true
        });
        if session.outgoing_count() == 0 {
            break;
        }
        now += Duration::from_millis(5);
    }
    packets
}

fn capture_acks(session: &mut SequenceSession, now: Instant) -> Vec<Packet> {
    let mut acks = Vec::new();
    session.flush(now, 0, &mut |packet| {
        if matches!(packet, Packet::Ack { .. }) {
            acks.push(packet.clone());
        }
        true
    });
    acks
}

/// Test 1: an ACK packet must always serialize to ≤ `MAX_DATAGRAM_SIZE`,
/// regardless of how many non-contiguous seqs the receiver has tracked.
///
/// This is the invariant that fails today: the bitmap grows without
/// bound when the receiver sees sustained loss with a non-advancing
/// base, and the resulting `Packet::Ack` exceeds `MAX_DATAGRAM_SIZE`,
/// causing every ACK send to fail with `TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG`.
///
/// After the redesign the ACK is fixed-size and this is true by
/// construction.
#[test]
fn ack_packet_size_is_bounded_under_sustained_loss() {
    let now = Instant::now();
    let (mut bob, _tp) = make_session(now);

    // Mark 50,000 non-contiguous seqs received: every other seq, leaving
    // the gap at seq 1 unrecoverable. With the bitmap design this grows
    // the on-wire bitmap to ~6 KB, well past MAX_DATAGRAM_SIZE.
    for i in (0..50_000u32).step_by(2) {
        bob.handle_packet(
            Packet::Data {
                seq: i,
                msg_type: MessageType::MerkleNode,
                data: vec![0u8; 8],
            },
            now,
        );
    }

    let acks = capture_acks(&mut bob, now + Duration::from_millis(50));
    assert!(!acks.is_empty(), "receiver must emit at least one ACK");

    for ack in &acks {
        let bytes = tox_proto::serialize(ack).expect("serialize ACK");
        assert!(
            bytes.len() <= MAX_DATAGRAM_SIZE,
            "ACK serialized to {} bytes, exceeds MAX_DATAGRAM_SIZE={}. \
             Bitmap is unbounded — this is the wedge bug.",
            bytes.len(),
            MAX_DATAGRAM_SIZE,
        );
    }
}

/// Test 2: cumulative ACK semantics. `base_seq` reports the
/// next-expected seq; it advances past every contiguously-received seq
/// when a gap is filled.
///
/// Passes today (the bitmap path computes this correctly via
/// `advance_base`) and must continue to pass after the redesign.
#[test]
fn cumulative_ack_advances_base_correctly() {
    let now = Instant::now();
    let (mut bob, _tp) = make_session(now);

    // Receive 0,1,2 contiguously, then 4,5,6,7,8,9 with a gap at 3.
    let received = [0u32, 1, 2, 4, 5, 6, 7, 8, 9];
    for seq in received {
        bob.handle_packet(
            Packet::Data {
                seq,
                msg_type: MessageType::MerkleNode,
                data: vec![0u8; 8],
            },
            now,
        );
    }

    let acks = capture_acks(&mut bob, now + Duration::from_millis(50));
    assert!(!acks.is_empty(), "receiver must emit at least one ACK");
    let base = match &acks[0] {
        Packet::Ack { base_seq, .. } => *base_seq.expose_unchecked(),
        _ => unreachable!(),
    };
    assert_eq!(
        base, 3,
        "before gap is filled, base_seq must be 3 (oldest gap)"
    );

    // Now fill the gap. base_seq should jump to 10 in the next ACK.
    bob.handle_packet(
        Packet::Data {
            seq: 3,
            msg_type: MessageType::MerkleNode,
            data: vec![0u8; 8],
        },
        now + Duration::from_millis(60),
    );

    let acks = capture_acks(&mut bob, now + Duration::from_millis(100));
    assert!(!acks.is_empty(), "receiver must emit a second ACK");
    let base = match &acks[0] {
        Packet::Ack { base_seq, .. } => *base_seq.expose_unchecked(),
        _ => unreachable!(),
    };
    assert_eq!(
        base, 10,
        "after gap fill, base_seq must jump past all contiguous seqs"
    );
}

/// Test 3: after a sender's send time exceeds RTO without an ack
/// covering the seq, a `DatagramLost` event fires.
///
/// Today this never fires from a pure timeout (loss detection is gated
/// inside `handle_ack`, which never runs if no ACK arrives). The 30 s
/// hard-expiry exists but is too coarse to call "loss detection."
/// After the redesign, the sender scans `sent_datagrams` on each flush
/// (or equivalent driving function) and emits losses for entries whose
/// `now - sent_time >= rto()`.
#[test]
fn timer_based_loss_fires_after_rto() {
    let now = Instant::now();
    let (mut alice, _tp) = make_session(now);

    alice
        .send(MessageType::MerkleNode, &[1u8; 100], now)
        .expect("send");
    let _packets = flush_all(&mut alice, now);

    // Initial RTO (per RFC 6298 with srtt=200ms, rttvar=100ms) is
    // 200 + 4*100 = 600 ms, capped to [200ms, 5000ms]. Two seconds is
    // comfortably past it.
    let later = now + Duration::from_secs(2);

    // Drive the session forward — implementation chooses where the
    // timer scan lives, but flush is the natural choice and is
    // already called by hosts on a regular cadence.
    alice.flush(later, 0, &mut |_p| true);

    let events = collect_events(&mut alice);
    let lost_count = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::DatagramLost(_)))
        .count();
    assert_eq!(
        lost_count, 1,
        "expected exactly one DatagramLost event after RTO expired \
         (events: {:?})",
        events
    );
}

/// Test 4: out-of-order delivery with each ack arriving well within RTO
/// must NOT trigger spurious `DatagramLost` events.
///
/// This is the reordering tolerance check — losing it would mean Plan C
/// over-fires loss on jittery connections. Today's bitmap path passes
/// this trivially (bitmap resolves exact delivery). After the redesign,
/// the RFC 6298 RTO multiplier (`srtt + 4*rttvar`, floor 200ms) must be
/// loose enough that 50 ms reordering delays do not trigger loss.
#[test]
fn reordering_within_rto_does_not_fire_loss() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);
    let (mut bob, _tp_b) = make_session(now);

    // Alice sends three packets back-to-back.
    for i in 0..3u8 {
        alice
            .send(MessageType::MerkleNode, &[i; 100], now)
            .expect("send");
    }
    let packets = flush_all(&mut alice, now);
    let data_packets: Vec<Packet> = packets
        .into_iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();
    assert_eq!(data_packets.len(), 3, "expected 3 DATA packets");

    // Bob receives them OUT OF ORDER: middle, first, last.
    // Each is followed by an ACK arriving back at alice within ~50 ms,
    // well under any plausible RTO floor (200 ms).
    let order = [1usize, 0, 2];
    let mut clock = now;
    for idx in order {
        clock += Duration::from_millis(50);
        bob.handle_packet(data_packets[idx].clone(), clock);
        let acks = capture_acks(&mut bob, clock + Duration::from_millis(15));
        clock += Duration::from_millis(20);
        for ack in acks {
            alice.handle_packet(ack, clock);
        }
        // Drive alice's flush in case loss detection runs there.
        alice.flush(clock, 0, &mut |_p| true);
    }

    let events = collect_events(&mut alice);
    let lost: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::DatagramLost(_)))
        .collect();
    assert!(
        lost.is_empty(),
        "no DatagramLost events expected for in-RTO reordering, got {:?}",
        lost
    );
}

// ===========================================================================
// Plan B: SACK-style range ACKs.
//
// After Plan C, the e2e bench showed massive false-positive loss (~92%) under
// real-loss conditions because cumulative-only ACKs can't tell the sender
// which specific seqs above an unfilled gap actually arrived. Plan B adds a
// bounded `sack_ranges` field to the ACK so receivers can selectively
// acknowledge above-base seqs. Cap is 8 ranges; total wire size ≤ ~80 bytes.
//
// SACK-specific tests.

/// SACK ranges in an ACK should resolve covered `sent_datagrams` entries
/// (mark delivered + decrement `sum_unresolved_bytes`) without needing the
/// cumulative `base_seq` to advance.
#[test]
fn sack_resolves_above_base() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);

    // Alice sends 5 packets. Capture the seqs.
    for i in 0..5u8 {
        alice
            .send(MessageType::MerkleNode, &[i; 100], now)
            .expect("send");
    }
    let packets = flush_all(&mut alice, now);
    let seqs: Vec<u32> = packets
        .iter()
        .filter_map(|p| match p {
            Packet::Data { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(seqs.len(), 5);

    let in_flight_before = alice.in_flight();
    assert!(
        in_flight_before > 0,
        "in_flight must be non-zero after sending"
    );

    // Construct an ACK that:
    //   - Cumulatively acks seq 0 only (base_seq = seqs[1])
    //   - SACKs seqs 2..=4 via a single range (start=seqs[2], length=3)
    //   Seq 1 is NOT covered (the "gap").
    let ack = Packet::Ack {
        base_seq: tox_proto::Untrusted::new(seqs[1]),
        recv_bytes: tox_proto::Untrusted::new(0), // zero is fine for this test
        sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![(seqs[2], 3u32)]),
    };

    alice.handle_packet(ack, now + Duration::from_millis(20));

    let events = collect_events(&mut alice);
    let delivered: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::DatagramDelivered(s) => Some(*s),
            _ => None,
        })
        .collect();

    // Expect: seq 0 (cumulative) + seqs 2,3,4 (SACK) = 4 deliveries; seq 1 unresolved.
    let mut expected = vec![seqs[0], seqs[2], seqs[3], seqs[4]];
    let mut got = delivered.clone();
    expected.sort();
    got.sort();
    assert_eq!(got, expected, "SACK should resolve above-base seqs");

    let in_flight_after = alice.in_flight();
    assert!(
        in_flight_after < in_flight_before,
        "in_flight must decrease after SACK resolution ({} -> {})",
        in_flight_before,
        in_flight_after
    );
}

/// The exact e2e failure mode in unit-test form: receiver loses one early
/// packet but receives 98 more. With Plan C alone, all 98 time out as loss.
/// With Plan B, SACK reports them as received and zero spurious losses fire
/// before RTO expires.
#[test]
fn sack_prevents_spurious_loss_with_persistent_gap() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);

    for i in 0..100u32 {
        alice
            .send(MessageType::MerkleNode, &[(i & 0xFF) as u8; 100], now)
            .expect("send");
    }
    let packets = flush_all(&mut alice, now);
    let seqs: Vec<u32> = packets
        .iter()
        .filter_map(|p| match p {
            Packet::Data { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(seqs.len(), 100);

    // Bob acks: lost seq 0 (the early gap). Received seqs 1..=99 — reported
    // via a single SACK range.
    let ack = Packet::Ack {
        base_seq: tox_proto::Untrusted::new(seqs[0]),
        recv_bytes: tox_proto::Untrusted::new(0),
        sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![(seqs[1], 99u32)]),
    };
    alice.handle_packet(ack, now + Duration::from_millis(50));

    // Advance virtual time past RTO (~600 ms initial). With SACK, the 99
    // packets are already resolved; the timer scan should find only seq 0
    // (the genuinely lost one) — that's at most 1 loss.
    alice.flush(now + Duration::from_secs(1), 0, &mut |_p| true);

    let events = collect_events(&mut alice);
    let lost_count = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::DatagramLost(_)))
        .count();

    assert!(
        lost_count <= 1,
        "expected at most 1 DatagramLost (the actually-lost seq 0), got {}",
        lost_count
    );
}

/// Forged SACK ranges claiming receipt of seqs the sender never transmitted
/// must not cause spurious resolution. Sender clamps `start + length` to
/// `next_seq` (or rejects the range entirely).
#[test]
fn sack_clamped_against_unsent_seqs() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);

    // Alice sends 5 packets.
    for i in 0..5u8 {
        alice
            .send(MessageType::MerkleNode, &[i; 100], now)
            .expect("send");
    }
    let packets = flush_all(&mut alice, now);
    let seqs: Vec<u32> = packets
        .iter()
        .filter_map(|p| match p {
            Packet::Data { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    let in_flight_before = alice.in_flight();

    // Forged ACK: cumulative covers only seq 0 (base_seq = seqs[1]),
    // SACK range claims 1000 seqs past the last sent seq (impossibly far).
    let ack = Packet::Ack {
        base_seq: tox_proto::Untrusted::new(seqs[1]),
        recv_bytes: tox_proto::Untrusted::new(0),
        sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![(
            seqs[4].wrapping_add(1000),
            100u32
        )]),
    };
    alice.handle_packet(ack, now + Duration::from_millis(20));

    let events = collect_events(&mut alice);
    let delivered: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::DatagramDelivered(s) => Some(*s),
            _ => None,
        })
        .collect();

    // Only seq 0 should be delivered (cumulative). Forged range produces nothing.
    assert_eq!(
        delivered,
        vec![seqs[0]],
        "forged out-of-range SACK must not cause spurious DatagramDelivered events"
    );

    // in_flight must reflect only the cumulative resolution (seq 0).
    let in_flight_after = alice.in_flight();
    let expected_drop = packets
        .iter()
        .find_map(|p| match p {
            Packet::Data { seq, data, .. } if *seq == seqs[0] => {
                Some(data.len() + tox_sequenced::protocol::PACKET_OVERHEAD)
            }
            _ => None,
        })
        .unwrap();
    assert!(
        in_flight_before.saturating_sub(in_flight_after) <= expected_drop * 2,
        "in_flight dropped by more than the cumulative resolution justifies \
         (before={}, after={}, expected drop ~{})",
        in_flight_before,
        in_flight_after,
        expected_drop,
    );
}

/// Overlapping or repeated SACK ranges must not cause an entry to be
/// resolved twice (which would double-decrement `sum_unresolved_bytes`).
/// Either the ranges are rejected/normalized, or the resolution loop
/// guards on `entry.resolved` and skips already-resolved entries.
#[test]
fn sack_overlapping_does_not_double_decrement() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);

    for i in 0..5u8 {
        alice
            .send(MessageType::MerkleNode, &[i; 100], now)
            .expect("send");
    }
    let packets = flush_all(&mut alice, now);
    let seqs: Vec<u32> = packets
        .iter()
        .filter_map(|p| match p {
            Packet::Data { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();

    let in_flight_before = alice.in_flight();

    // Two ranges that overlap on seqs[2..=3]:
    //   range A: seqs[1..=3]   (start=seqs[1], length=3)
    //   range B: seqs[2..=4]   (start=seqs[2], length=3)
    let ack = Packet::Ack {
        base_seq: tox_proto::Untrusted::new(seqs[0]),
        recv_bytes: tox_proto::Untrusted::new(0),
        sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![
            (seqs[1], 3u32),
            (seqs[2], 3u32)
        ]),
    };
    alice.handle_packet(ack, now + Duration::from_millis(20));

    // Whether the second range is rejected or just deduped, the net effect
    // must be: each of seqs[1..=4] resolved at most once. in_flight drops by
    // approximately the size of seqs[0..=4] (cumulative + range), no more.
    let in_flight_after = alice.in_flight();
    let drop = in_flight_before.saturating_sub(in_flight_after);
    let one_packet = 100 + tox_sequenced::protocol::PACKET_OVERHEAD;
    let max_legitimate_drop = 5 * one_packet + one_packet; // 5 packets + slack
    assert!(
        drop <= max_legitimate_drop,
        "overlapping SACK ranges caused {}-byte drop; expected ≤ {} (5 packets). \
         Likely double-decrement bug.",
        drop,
        max_legitimate_drop,
    );
}
