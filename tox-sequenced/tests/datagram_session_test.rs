use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{MessageType, Packet};
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

/// Flush all queued packets by advancing time past pacing intervals.
fn flush_all(session: &mut SequenceSession, start: Instant) -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut now = start;
    for _ in 0..500 {
        session.flush(now, 0, &mut |packet| {
            packets.push(packet);
            true
        });
        if session.outgoing_count() == 0 {
            break;
        }
        // Advance past pacing interval
        now += Duration::from_millis(5);
    }
    packets
}

#[test]
fn test_send_data_and_receive() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);
    let (mut bob, _tp_b) = make_session(now);

    let data = b"hello world".to_vec();
    alice
        .send(MessageType::MerkleNode, &data, now)
        .expect("send failed");

    let packets = flush_all(&mut alice, now);
    let data_packets: Vec<_> = packets
        .iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();
    assert_eq!(data_packets.len(), 1);

    for p in packets {
        bob.handle_packet(p, now);
    }

    let events = collect_events(&mut bob);
    let received = events
        .iter()
        .find(|e| matches!(e, SessionEvent::DataReceived(_, _, _)));
    assert!(received.is_some(), "Expected DataReceived event");

    if let SessionEvent::DataReceived(_, msg_type, recv_data) = received.unwrap() {
        assert_eq!(*msg_type, MessageType::MerkleNode);
        assert_eq!(recv_data, &data);
    }
}

#[test]
fn test_ack_bitmap_and_delivery() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);
    let (mut bob, _tp_b) = make_session(now);

    for i in 0..5 {
        alice
            .send(MessageType::MerkleNode, &[i as u8; 100], now)
            .unwrap();
    }

    let packets = flush_all(&mut alice, now);
    let data_count = packets
        .iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .count();
    assert!(
        data_count >= 5,
        "Expected at least 5 DATA packets, got {}",
        data_count
    );

    for p in packets {
        bob.handle_packet(p, now);
    }

    // Bob flushes → should produce ACK
    let later = now + Duration::from_millis(100);
    let ack_packets = flush_all(&mut bob, later);
    let ack = ack_packets.iter().find(|p| matches!(p, Packet::Ack { .. }));
    assert!(ack.is_some(), "Expected ACK packet from bob");

    for p in &ack_packets {
        if let Packet::Ack {
            base_seq,
            recv_bytes,
            sack_ranges,
        } = p
        {
            eprintln!(
                "ACK: base_seq={:?}, recv_bytes={:?}, sack_ranges={:?}",
                base_seq, recv_bytes, sack_ranges,
            );
        }
    }
    for p in ack_packets {
        alice.handle_packet(p, later);
    }

    let events = collect_events(&mut alice);
    let delivered_count = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::DatagramDelivered(_)))
        .count();
    assert!(
        delivered_count >= 1,
        "Expected DatagramDelivered events, got: {:?}",
        events
    );
}

#[test]
fn test_fragment_send_and_reassemble() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);
    let (mut bob, _tp_b) = make_session(now);

    let data = vec![0xAB; 10_000];
    alice
        .send_fragmented(MessageType::MerkleNode, &data, now)
        .expect("send_fragmented failed");

    // Exchange fragments and ACKs in rounds to open the congestion window
    let mut all_frag_packets = Vec::new();
    let mut now = now;
    for _ in 0..50 {
        let packets = flush_all(&mut alice, now);
        let frags: Vec<_> = packets
            .iter()
            .filter(|p| matches!(p, Packet::Fragment { .. }))
            .cloned()
            .collect();
        all_frag_packets.extend(frags);

        // Feed to bob
        for p in &packets {
            bob.handle_packet(p.clone(), now);
        }

        // Bob sends ACKs back
        now += Duration::from_millis(50);
        let acks = flush_all(&mut bob, now);
        for a in acks {
            alice.handle_packet(a, now);
        }

        if alice.outgoing_count() == 0 {
            break;
        }
        now += Duration::from_millis(50);
    }

    assert!(
        all_frag_packets.len() >= 7,
        "Expected at least 7 fragment packets, got {}",
        all_frag_packets.len()
    );

    // Bob should have MessageCompleted
    let events = collect_events(&mut bob);
    let completed = events
        .iter()
        .find(|e| matches!(e, SessionEvent::MessageCompleted(_, _, _)));
    assert!(
        completed.is_some(),
        "Expected MessageCompleted event, got {:?}",
        events
    );

    if let SessionEvent::MessageCompleted(_, msg_type, recv_data) = completed.unwrap() {
        assert_eq!(*msg_type, MessageType::MerkleNode);
        assert_eq!(recv_data.len(), data.len());
        assert_eq!(recv_data, &data);
    }
}

#[test]
fn test_send_auto_small_uses_data() {
    let now = Instant::now();
    let (mut alice, _) = make_session(now);

    alice
        .send_auto(MessageType::BlobData, &[0; 100], now)
        .unwrap();

    let packets = flush_all(&mut alice, now);
    let data_packets: Vec<_> = packets
        .iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();
    assert_eq!(data_packets.len(), 1);
}

#[test]
fn test_send_auto_large_uses_fragment() {
    let now = Instant::now();
    let (mut alice, _) = make_session(now);

    alice
        .send_auto(MessageType::MerkleNode, &[0; 5000], now)
        .unwrap();

    let packets = flush_all(&mut alice, now);
    let frag_packets: Vec<_> = packets
        .iter()
        .filter(|p| matches!(p, Packet::Fragment { .. }))
        .collect();
    assert!(frag_packets.len() > 1, "Expected multiple Fragment packets");
}

#[test]
fn test_ping_pong() {
    let now = Instant::now();
    let (mut alice, tp_a) = make_session(now);
    let (mut bob, tp_b) = make_session(now);

    let later = now + Duration::from_secs(61);
    tp_a.set_time(later, 61000);
    tp_b.set_time(later, 61000);

    let mut packets = Vec::new();
    alice.flush(later, 61000, &mut |packet| {
        packets.push(packet);
        true
    });
    let ping = packets.iter().find(|p| matches!(p, Packet::Ping { .. }));
    assert!(ping.is_some(), "Expected PING packet");

    for p in packets {
        let replies = bob.handle_packet(p, later);
        for r in replies {
            if matches!(r, Packet::Pong { .. }) {
                alice.handle_packet(r, later);
            }
        }
    }
}

#[test]
fn test_fragment_timeout_drops_message() {
    let now = Instant::now();
    let (mut bob, _tp_b) = make_session(now);

    bob.handle_packet(
        Packet::Fragment {
            frag_id: 99,
            frag_index: 0,
            frag_total: 5,
            msg_type: MessageType::MerkleNode,
            data: vec![0; 1300],
        },
        now,
    );
    bob.handle_packet(
        Packet::Fragment {
            frag_id: 99,
            frag_index: 2,
            frag_total: 5,
            msg_type: MessageType::MerkleNode,
            data: vec![0; 1300],
        },
        now,
    );

    let later = now + Duration::from_secs(6);
    bob.cleanup(later);

    let events = collect_events(&mut bob);
    let dropped = events
        .iter()
        .find(|e| matches!(e, SessionEvent::MessageDropped(99)));
    assert!(
        dropped.is_some(),
        "Expected MessageDropped event for frag_id=99"
    );
}

#[test]
fn test_queue_full_error() {
    let now = Instant::now();
    let (mut alice, _) = make_session(now);

    // Fill the send queue without flushing
    let mut count = 0;
    loop {
        match alice.send(MessageType::BlobData, &[0; 100], now) {
            Ok(_) => count += 1,
            Err(tox_sequenced::SequencedError::WindowFull) => break,
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
        if count > 10000 {
            panic!("Queue never filled");
        }
    }
    assert!(count > 0, "Should have queued at least one packet");
    assert!(
        count <= 4096,
        "Queue limit should be 4096, queued {}",
        count
    );
}

#[test]
fn test_is_dead_after_timeout() {
    let now = Instant::now();
    let (alice, _) = make_session(now);

    assert!(!alice.is_dead(now));
    assert!(!alice.is_dead(now + Duration::from_secs(299)));
    assert!(alice.is_dead(now + Duration::from_secs(301)));
}

#[test]
fn test_outgoing_count_and_bytes() {
    let now = Instant::now();
    let (mut alice, _) = make_session(now);

    assert_eq!(alice.outgoing_count(), 0);
    assert_eq!(alice.outgoing_bytes(), 0);

    alice.send(MessageType::MerkleNode, &[0; 500], now).unwrap();
    assert_eq!(alice.outgoing_count(), 1);
    assert!(alice.outgoing_bytes() > 0);

    alice.send(MessageType::MerkleNode, &[0; 500], now).unwrap();
    assert_eq!(alice.outgoing_count(), 2);
}

#[test]
fn test_data_packet_serialization_roundtrip() {
    let packet = Packet::Data {
        seq: 42,
        msg_type: MessageType::BlobData,
        data: vec![1, 2, 3, 4, 5],
    };

    let serialized = tox_proto::serialize(&packet).unwrap();
    let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

#[test]
fn test_ack_packet_serialization_roundtrip() {
    let packet = Packet::Ack {
        base_seq: tox_proto::Untrusted::new(100),
        recv_bytes: tox_proto::Untrusted::new(123456),
        sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![
            (105u32, 3u32),
            (200u32, 7u32)
        ]),
    };

    let serialized = tox_proto::serialize(&packet).unwrap();
    let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

#[test]
fn test_fragment_packet_serialization_roundtrip() {
    let packet = Packet::Fragment {
        frag_id: 7,
        frag_index: 3,
        frag_total: 10,
        msg_type: MessageType::SyncSketch,
        data: vec![0xAB; 1000],
    };

    let serialized = tox_proto::serialize(&packet).unwrap();
    let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

/// When the transport rejects a packet (sender returns false), the packet
/// MUST stay in the queue so the next flush retries it. Without this, a
/// rate-limited or temporarily-full transport (e.g. real toxcore custom
/// packet send queue) silently loses application data.
///
/// Regression test for the bug where flush() popped the packet from the
/// queue before calling sender(), and dropped it on the floor when the
/// sender returned false.
#[test]
fn test_rejected_packet_stays_in_queue() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);

    let data = vec![0xAB; 500];
    alice.send(MessageType::MerkleNode, &data, now).unwrap();
    assert_eq!(alice.outgoing_count(), 1);

    // Flush with a sender that always rejects. Filter to data packets so we
    // don't count the PING that flush() sends on its first call.
    let mut data_attempts = 0;
    alice.flush(now, 0, &mut |packet| {
        if matches!(packet, Packet::Data { .. }) {
            data_attempts += 1;
        }
        false
    });

    assert_eq!(data_attempts, 1, "data packet should be attempted once");
    assert_eq!(
        alice.outgoing_count(),
        1,
        "packet must remain queued after sender rejection",
    );
    assert_eq!(
        alice.in_flight(),
        0,
        "rejected packet must not count as in-flight (bytes_sent unchanged)",
    );

    // Flush again with a successful sender — same packet should be presented
    // and actually delivered.
    let mut delivered_data: Vec<Packet> = Vec::new();
    let later = now + Duration::from_millis(10);
    alice.flush(later, 0, &mut |packet| {
        if matches!(packet, Packet::Data { .. }) {
            delivered_data.push(packet);
        }
        true
    });

    assert_eq!(
        delivered_data.len(),
        1,
        "data packet should be delivered on retry"
    );
    if let Packet::Data { data: d, .. } = &delivered_data[0] {
        assert_eq!(d, &data, "delivered packet must contain the original data");
    } else {
        unreachable!();
    }
    assert_eq!(
        alice.outgoing_count(),
        0,
        "queue should be empty after successful send"
    );
    assert!(
        alice.in_flight() > 0,
        "successful send should count as in-flight"
    );
}

/// Measures how many DATA packets a single `flush()` call emits at steady
/// state with a fixed iteration cadence (mirroring the tox host loop, which
/// calls flush every ~20ms). The host loop is the only thing that drives
/// `now` forward, so within a single flush call `now` is constant — and the
/// scheduler / pacing logic must not cap the call to one DRR quantum, or
/// the iteration cadence becomes a hard rate cap (e.g. 50 calls/sec × 53
/// pkts/quantum ≈ 7.5 Mbps observed in real-Tox e2e blob transfers before
/// the single-active-level scheduler fix).
///
/// The test queues a fixed number of packets, refills between flushes so
/// the queue stays close to its target depth, and measures pkts/call. With
/// only one active priority level (P4 / BlobData) and a healthy cwnd, a
/// single flush should be able to emit FAR more than one quantum (~50)
/// per call — ideally close to the cwnd limit.
#[test]
fn test_flush_pkts_per_call_at_iteration_cadence() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);
    let (mut bob, _tp_b) = make_session(now);

    // Helper: top up alice's queue back to the target depth.
    fn refill(alice: &mut SequenceSession, target: usize, now: Instant) {
        while alice.outgoing_count() < target {
            if alice
                .send(MessageType::BlobData, &[0xCD; 1200], now)
                .is_err()
            {
                break;
            }
        }
    }

    // Keep the queue small enough that the test stays fast (with the
    // single-active-level fast path, each flush can emit thousands of
    // packets when cwnd is large; processing those on bob is real work).
    // 1024 is comfortably above one quantum (~50) so a regression to the
    // quantum cap is still detectable.
    let target_queue_depth = 1024usize;
    refill(&mut alice, target_queue_depth, now);

    // Warm up: alternate flush + ACK round-trip so BBR exits startup
    // and settles on a non-trivial cwnd. Refill the queue between
    // flushes so it doesn't drain.
    let mut now = now;
    for _ in 0..10 {
        refill(&mut alice, target_queue_depth, now);
        let mut sent = Vec::new();
        alice.flush(now, 0, &mut |p| {
            sent.push(p);
            true
        });
        for p in sent {
            bob.handle_packet(p, now);
        }
        now += Duration::from_millis(20);
        let mut acks = Vec::new();
        bob.flush(now, 0, &mut |p| {
            acks.push(p);
            true
        });
        for p in acks {
            alice.handle_packet(p, now);
        }
        now += Duration::from_millis(20);
    }

    // Steady-state measurement: 20 host iterations at 20 ms each, with
    // the queue refilled before each flush so the test never measures
    // an artificially-empty queue.
    let mut pkts_per_call: Vec<usize> = Vec::with_capacity(20);
    for _ in 0..20 {
        refill(&mut alice, target_queue_depth, now);
        let mut sent_data = 0usize;
        let mut sent = Vec::new();
        alice.flush(now, 0, &mut |p| {
            if matches!(p, Packet::Data { .. }) {
                sent_data += 1;
            }
            sent.push(p);
            true
        });
        pkts_per_call.push(sent_data);
        for p in sent {
            bob.handle_packet(p, now);
        }
        now += Duration::from_millis(20);
        let mut acks = Vec::new();
        bob.flush(now, 0, &mut |p| {
            acks.push(p);
            true
        });
        for p in acks {
            alice.handle_packet(p, now);
        }
    }

    let total: usize = pkts_per_call.iter().sum();
    let avg = total as f64 / pkts_per_call.len() as f64;
    let max = *pkts_per_call.iter().max().unwrap();
    let min = *pkts_per_call.iter().min().unwrap();
    let cwnd = alice.cwnd();
    let in_flight = alice.in_flight();
    let pacing = alice.pacing_rate();
    eprintln!(
        "flush_pkts_per_call: total={} avg={:.1} min={} max={} \
         cwnd={} in_flight={} pacing_bps={:.0} \
         iters_at_<=10={} iters_at_>=100={}",
        total,
        avg,
        min,
        max,
        cwnd,
        in_flight,
        pacing,
        pkts_per_call.iter().filter(|&&n| n <= 10).count(),
        pkts_per_call.iter().filter(|&&n| n >= 100).count(),
    );
    eprintln!(
        "pkts_per_call sample: {:?}",
        &pkts_per_call[..pkts_per_call.len().min(10)]
    );

    // Hard floor: with a single active priority level, a healthy cwnd,
    // and a queue that's never empty, flush() must emit substantially
    // more than one DRR quantum (~50 packets) per call. Anything less
    // than 100 means the single-active-level scheduler fast path has
    // regressed and we are back to one-quantum-per-call throughput
    // (which combined with the host iteration cadence caps real-Tox
    // blob transfers at ~7.5 Mbps).
    assert!(
        avg >= 100.0,
        "flush emits only {:.1} pkts per call on average — single-active-level \
         scheduler fast path is broken; throughput is quantum-capped. \
         cwnd={} in_flight={} pacing_bps={:.0}",
        avg,
        cwnd,
        in_flight,
        pacing,
    );
}

/// When the sender rejects a packet mid-flush, that packet must be
/// preserved in the queue without losing it (the bug we're guarding
/// against caused complete data loss when toxcore's custom-packet send
/// queue filled up).
#[test]
fn test_rejected_packet_eventually_delivered() {
    let now = Instant::now();
    let (mut alice, _tp_a) = make_session(now);

    // Queue a few packets.
    for i in 0..3 {
        alice
            .send(MessageType::MerkleNode, &[i as u8; 100], now)
            .unwrap();
    }
    assert_eq!(alice.outgoing_count(), 3);

    // Sender rejects everything. Nothing should be lost.
    alice.flush(now, 0, &mut |_| false);
    assert_eq!(alice.outgoing_count(), 3, "no packets should be lost");

    // Drain with a fully-accepting sender. Filter to data packets to
    // ignore the PING that flush() sends.
    let mut delivered_data: Vec<Packet> = Vec::new();
    let mut now = now;
    for _ in 0..50 {
        now += Duration::from_millis(5);
        alice.flush(now, 0, &mut |packet| {
            if matches!(packet, Packet::Data { .. }) {
                delivered_data.push(packet);
            }
            true
        });
        if alice.outgoing_count() == 0 {
            break;
        }
    }
    assert_eq!(
        delivered_data.len(),
        3,
        "all 3 data packets should eventually be delivered"
    );
    assert_eq!(alice.outgoing_count(), 0, "queue should be empty");
}
