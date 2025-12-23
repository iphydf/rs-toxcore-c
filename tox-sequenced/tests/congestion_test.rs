use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{
    ESTIMATED_PAYLOAD_SIZE, FragmentCount, FragmentIndex, MessageType, SelectiveAck,
};
use tox_sequenced::{Algorithm, AlgorithmType, Packet, SequenceSession};

fn bbr_delivery(algo: AlgorithmType) {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    let data = vec![0u8; 10000];
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .expect("Failed to send message");

    let packets = alice.get_packets_to_send(now, 0);
    assert!(!packets.is_empty());

    for packet in packets {
        let _replies = bob.handle_packet(packet, now);
        while let Some(event) = bob.poll_event() {
            if let tox_sequenced::SessionEvent::MessageCompleted(_id, _type, received_data) = event
            {
                assert_eq!(received_data, data);
            }
        }
    }

    let acks = bob.get_packets_to_send(now, 0);
    assert!(!acks.is_empty());

    for ack in acks {
        alice.handle_packet(ack, now);
    }
}

#[test]
fn test_bbrv1_delivery() {
    bbr_delivery(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_delivery() {
    bbr_delivery(AlgorithmType::Bbrv2);
}

#[test]
fn test_aimd_delivery() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(AlgorithmType::Aimd, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    alice
        .send_message(MessageType::MerkleNode, &[0u8; 5000], now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);

    for p in packets {
        bob.handle_packet(p, now);
    }

    let acks = bob.get_packets_to_send(now, 0);
    for ack in acks {
        alice.handle_packet(ack, now);
    }
}

#[test]
fn test_cubic_delivery() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(AlgorithmType::Cubic, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    alice
        .send_message(MessageType::MerkleNode, &[0u8; 5000], now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);

    for p in packets {
        bob.handle_packet(p, now);
    }

    let acks = bob.get_packets_to_send(now, 0);
    for ack in acks {
        alice.handle_packet(ack, now);
    }
}

fn cwnd_reduction_only_once_per_burst_loss(algo: AlgorithmType) {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp,
        &mut rng,
    );

    let data = vec![0u8; 20 * ESTIMATED_PAYLOAD_SIZE];
    alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    let mut current_time = now;
    for _ in 0..100 {
        let p = alice.get_packets_to_send(current_time, 0);
        if p.is_empty() {
            current_time += Duration::from_millis(10);
            continue;
        }
        if alice.in_flight() >= 10 * ESTIMATED_PAYLOAD_SIZE {
            break;
        }
    }

    let initial_cwnd = alice.cwnd();

    let timeout_time = current_time + Duration::from_secs(12);
    alice.get_packets_to_send(timeout_time, 0);

    let final_cwnd = alice.cwnd();

    assert!(
        final_cwnd >= initial_cwnd / 2,
        "{:?} CWND dropped too aggressively on a single burst timeout event. Initial: {}, Final: {}",
        algo,
        initial_cwnd,
        final_cwnd
    );
}

#[test]
fn test_bbrv1_cwnd_reduction_only_once_per_burst_loss() {
    cwnd_reduction_only_once_per_burst_loss(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_cwnd_reduction_only_once_per_burst_loss() {
    cwnd_reduction_only_once_per_burst_loss(AlgorithmType::Bbrv2);
}

#[test]
fn test_congestion_control_notified_on_duplicate_acks() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(AlgorithmType::Cubic, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp,
        &mut rng,
    );

    let data = vec![0u8; 10000];
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();
    let _ = alice.get_packets_to_send(now, 0);

    // Duplicate ACKs for base_index 0, bitmask 0.
    let ack = Packet::Ack(SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(0),
        bitmask: 0,
        rwnd: FragmentCount(100),
    });

    alice.handle_packet(ack.clone(), now + Duration::from_millis(200));
    let cwnd_after_epoch_start = alice.cwnd();

    alice.handle_packet(ack, now + Duration::from_secs(30));
    let cwnd_after_dup_ack = alice.cwnd();

    assert!(
        cwnd_after_dup_ack >= cwnd_after_epoch_start,
        "CWND should not shrink on duplicate ACKs in Cubic if notified. Initial: {}, Final: {}",
        cwnd_after_epoch_start,
        cwnd_after_dup_ack
    );
}
