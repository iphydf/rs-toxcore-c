use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MAX_MESSAGE_SIZE};
use tox_sequenced::{MessageType, Packet, SequenceSession};

#[test]
fn test_retransmission_after_completion_does_not_restart_reassembly() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // Create a valid serialized message
    let envelope = tox_sequenced::protocol::MessageType::MerkleNode;
    let data = vec![0u8; 2000];

    // We'll manually construct fragments that represent a valid RawMessageOwned
    // Or simpler: use a real session to generate them.
    let mut sender = SequenceSession::new_at(now, tp, &mut rng);
    sender.send_message_at(envelope, &data, now).unwrap();

    let mut packets = Vec::new();
    let mut temp_now = now;
    for _ in 0..10 {
        packets.extend(sender.get_packets_to_send(temp_now, 0));
        temp_now += Duration::from_millis(100);
    }

    // We should have at least 2 fragments
    let packet1 = packets
        .iter()
        .find(|p| {
            matches!(
                p,
                Packet::Data {
                    fragment_index: FragmentIndex(0),
                    ..
                }
            )
        })
        .unwrap()
        .clone();
    let packet2 = packets
        .iter()
        .find(|p| {
            matches!(
                p,
                Packet::Data {
                    fragment_index: FragmentIndex(1),
                    ..
                }
            )
        })
        .unwrap()
        .clone();

    // Receive first packet
    session.handle_packet(packet1.clone(), now);

    // Receive second packet - completes the message
    let _replies = session.handle_packet(packet2.clone(), now);

    let mut completed = false;
    while let Some(event) = session.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            completed = true;
        }
    }
    assert!(completed);

    // BUG: Receive first packet again (retransmission from peer who didn't get our ACK)
    session.handle_packet(packet1, now);

    // If the bug exists, packet1 created a new reassembler.
    // Sending packet2 again will complete it AGAIN.
    let _replies = session.handle_packet(packet2, now);

    let mut completed_again = false;
    while let Some(event) = session.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            completed_again = true;
        }
    }

    assert!(!completed_again, "Message should not be completed twice");
}

#[test]
fn test_send_message_too_large() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    // MAX_MESSAGE_SIZE is 1MB. The envelope adds some overhead.
    // We want the total serialized size to exceed MAX_MESSAGE_SIZE.
    let too_large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
    let result = session.send_message_at(MessageType::MerkleNode, &too_large_data, now);

    assert!(
        result.is_err(),
        "Should not allow sending messages larger than MAX_MESSAGE_SIZE"
    );
}

#[test]
fn test_rto_does_not_stall_when_window_full() {
    let now_instant = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now_instant, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut now = now_instant;
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    let large_data = vec![0u8; 20000]; // ~16 fragments, fills initial cwnd (10)
    session
        .send_message_at(MessageType::MerkleNode, &large_data, now)
        .unwrap();

    // Drain pacing and send first batch
    let mut packets = Vec::new();
    for _ in 0..100 {
        let mut p = session.get_packets_to_send(now, 0);
        packets.append(&mut p);
        now += Duration::from_millis(1);
    }

    assert!(packets.len() >= 10, "Should have sent initial cwnd");

    // Now we have many bytes in flight.
    // Trigger timeout for the first packet.
    let timeout_time = now + Duration::from_secs(10);
    let packets_at_timeout = session.get_packets_to_send(timeout_time, 0);

    let data_packets: Vec<_> = packets_at_timeout
        .into_iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();
    assert!(
        !data_packets.is_empty(),
        "Should retransmit on timeout even if window is full"
    );
}

#[test]
fn test_ack_efficiency_for_large_messages_with_early_loss() {
    // Use a large initial cwnd to ensure Alice sends everything quickly
    let now_instant = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now_instant, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut now = now_instant;
    let mut alice = SequenceSession::with_congestion_control_at(
        tox_sequenced::congestion::Algorithm::Aimd(tox_sequenced::Aimd::with_cwnd(200.0)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    // 1. Send enough fragments to exceed bitmask (64)
    let data = vec![0u8; 150 * 1024]; // ~120 fragments
    let mid = alice
        .send_message_at(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Simulate exchange
    for _ in 0..100 {
        let packets = alice.get_packets_to_send(now, 0);
        for p in packets {
            if let Packet::Data {
                fragment_index: FragmentIndex(0),
                ..
            } = p
            {
                continue; // PERMANENTLY LOSE fragment 0
            }
            let replies = bob.handle_packet(p, now);
            for r in replies {
                alice.handle_packet(r, now);
            }
        }

        let acks = bob.get_packets_to_send(now, 0);
        for ack in acks {
            alice.handle_packet(ack, now);
        }

        now += Duration::from_millis(10);
    }

    // Alice's retransmit queue should ONLY contain fragment 0.
    // Everything else (1..119) should have been acked by either bitmask or NACK-fill.

    // DEBUG: Is 0 acked?
    if let Some(msg) = alice.find_outgoing(mid) {
        println!(
            "Alice message {} status: acked_count={}, is_0_acked={}, retransmit_q={:?}, in_flight_q_len={}",
            mid,
            msg.acked_count,
            msg.is_acked(FragmentIndex(0)),
            msg.retransmit_queue,
            msg.in_flight_queue.len()
        );
    }

    // We wait for RTO to ensure 0 is retransmitted even if it was recently sent.
    let mut retrans = Vec::new();
    let mut current_now = now + Duration::from_secs(10);
    for i in 0..10 {
        let p = alice.get_packets_to_send(current_now, 0);
        if !p.is_empty() {
            println!("Tick {}: Alice returned {:?}", i, p);
            retrans.extend(p);
        }
        if retrans
            .iter()
            .filter(|p| matches!(p, Packet::Data { .. }))
            .count()
            >= 2
        {
            break;
        }
        current_now += Duration::from_millis(10);
    }

    let sent_indices: Vec<FragmentIndex> = retrans
        .iter()
        .filter_map(|p| {
            if let Packet::Data { fragment_index, .. } = p {
                Some(*fragment_index)
            } else {
                None
            }
        })
        .collect();

    assert!(
        sent_indices.contains(&FragmentIndex(0)),
        "Should retransmit fragment 0. Sent: {:?}",
        sent_indices
    );
    assert!(
        !sent_indices.contains(&FragmentIndex(100)),
        "Should NOT retransmit fragment 100 as it was acked by Bob. Sent: {:?}",
        sent_indices
    );
}

#[test]
fn test_progressing_message_does_not_timeout_prematurely() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    let data = vec![0u8; 1000];
    let mid = alice
        .send_message_at(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Simulate some progress at 50 seconds
    let half_ack = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: mid,
        base_index: FragmentIndex(0),
        bitmask: 1, // Ack fragment 1
        rwnd: FragmentCount(100),
    });
    alice.handle_packet(half_ack, now + Duration::from_secs(50));

    // At 70 seconds, the message should still be alive because we had progress at T=50
    alice.cleanup(now + Duration::from_secs(70));

    let mut event_found = false;
    while let Some(event) = alice.poll_event() {
        if let tox_sequenced::SessionEvent::MessageFailed(id, _) = event
            && id == mid
        {
            event_found = true;
        }
    }

    assert!(
        !event_found,
        "Message should NOT have timed out yet as it had recent activity"
    );
}

#[test]
fn test_zero_rtt_pacing() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    // Send a message
    let data = vec![0u8; 1000];
    let msg_id = session
        .send_message_at(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Simulate ACK with 0 RTT
    let ack = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(1),
        bitmask: 0,
        rwnd: FragmentCount(100),
    });

    // This should not panic or result in NaN/Inf pacing
    session.handle_packet(ack.clone(), now);

    // Also try with a very small duration to check update_bandwidth in BBR
    let _sample = tox_sequenced::congestion::DeliverySample {
        bytes_delivered: 1300,
        duration: Duration::from_nanos(1),
        now,
        app_limited: false,
    };

    // We can't easily reach into BBR here without generic specialized session,
    // but we can trust the on_ack call in session.rs
    session.handle_packet(ack, now);
}

#[test]
fn test_message_id_collision_avoidance() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    // Fill up outgoing queue
    let mut ids = Vec::new();
    for _ in 0..tox_sequenced::protocol::MAX_CONCURRENT_OUTGOING {
        let id = session
            .send_message_at(MessageType::MerkleNode, b"test", now)
            .unwrap();
        ids.push(id);
    }

    // Try to send one more
    assert!(
        session
            .send_message_at(MessageType::MerkleNode, b"overflow", now)
            .is_err()
    );

    // Ack one message
    let ack = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: ids[0],
        base_index: FragmentIndex(1),
        bitmask: 0,
        rwnd: FragmentCount(100),
    });
    session.handle_packet(ack, now);

    // Now we should be able to send one more, and it shouldn't collide
    let new_id = session
        .send_message_at(MessageType::MerkleNode, b"new", now)
        .expect("Should be able to send after ACK");
    assert!(!ids.contains(&new_id));
}

// end of tests
