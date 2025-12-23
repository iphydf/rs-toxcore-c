use rand::SeedableRng;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tox_sequenced::{Algorithm, AlgorithmType, MessageType, Packet, SequenceSession};

fn bbr_fairness_two_flows(algo: AlgorithmType) {
    let now_instant = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now_instant, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut now = now_instant;
    let start = now;

    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(1)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let mut charlie = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(2)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut dave = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let link_bw_bps = 2_000_000.0;
    let latency = Duration::from_millis(30);
    let max_buffer_bytes = 40_000;
    let mut buffer_bytes = 0;

    let mut wire: VecDeque<(Instant, Packet, usize, u8)> = VecDeque::new();
    let mut last_tx = now;

    while now.duration_since(start) < Duration::from_secs(20) {
        if alice.in_flight() < 500_000 {
            let data = vec![0u8; 1000];
            let _ = alice.send_message_at(MessageType::MerkleNode, &data, now);
        }

        if now.duration_since(start) > Duration::from_secs(5) && charlie.in_flight() < 500_000 {
            let data = vec![0u8; 1000];
            let _ = charlie.send_message_at(MessageType::MerkleNode, &data, now);
        }

        for p in alice.get_packets_to_send(now, 0) {
            let size = 1300;
            if buffer_bytes + size <= max_buffer_bytes {
                let tx_delay = Duration::from_secs_f32((size as f32 * 8.0) / link_bw_bps);
                last_tx = last_tx.max(now) + tx_delay;
                buffer_bytes += size;
                wire.push_back((last_tx + latency, p, size, 1));
            }
        }

        for p in charlie.get_packets_to_send(now, 0) {
            let size = 1300;
            if buffer_bytes + size <= max_buffer_bytes {
                let tx_delay = Duration::from_secs_f32((size as f32 * 8.0) / link_bw_bps);
                last_tx = last_tx.max(now) + tx_delay;
                buffer_bytes += size;
                wire.push_back((last_tx + latency, p, size, 2));
            }
        }

        while let Some((at, _, _, _)) = wire.front() {
            if *at <= now {
                let (_, p, size, flow) = wire.pop_front().unwrap();
                buffer_bytes -= size;
                if flow == 1 {
                    for r in bob.handle_packet(p, now) {
                        alice.handle_packet(r, now);
                    }
                } else {
                    for r in dave.handle_packet(p, now) {
                        charlie.handle_packet(r, now);
                    }
                }
            } else {
                break;
            }
        }

        for p in bob.get_packets_to_send(now, 0) {
            alice.handle_packet(p, now);
        }
        for p in dave.get_packets_to_send(now, 0) {
            charlie.handle_packet(p, now);
        }

        now += Duration::from_millis(2);
    }

    let rate1 = alice.pacing_rate();
    let rate2 = charlie.pacing_rate();

    println!(
        "{:?} Flow 1 rate: {} bps, Flow 2 rate: {} bps",
        algo,
        rate1 * 8.0,
        rate2 * 8.0
    );

    assert!(rate1 * 8.0 > 500_000.0, "{:?} Flow 1 starved", algo);
    assert!(rate2 * 8.0 > 500_000.0, "{:?} Flow 2 starved", algo);

    let ratio = if rate1 > rate2 {
        rate1 / rate2
    } else {
        rate2 / rate1
    };
    assert!(ratio < 4.0, "{:?} Fairness ratio too high: {}", algo, ratio);
}

#[test]
fn test_bbrv1_fairness_two_flows() {
    bbr_fairness_two_flows(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_fairness_two_flows() {
    bbr_fairness_two_flows(AlgorithmType::Bbrv2);
}

fn bbr_rtt_fairness(algo: AlgorithmType) {
    let now_instant = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now_instant, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(123);
    let mut now = now_instant;
    let start = now;

    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(1)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let mut charlie = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(2)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut dave = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let link_bw_bps = 4_000_000.0;
    let mut wire: VecDeque<(Instant, Packet, usize, u8)> = VecDeque::new();
    let mut last_tx = now;

    while now.duration_since(start) < Duration::from_secs(30) {
        if alice.in_flight() < 1_000_000 {
            let _ = alice.send_message_at(MessageType::MerkleNode, &[0; 1000], now);
        }
        if charlie.in_flight() < 1_000_000 {
            let _ = charlie.send_message_at(MessageType::MerkleNode, &[0; 1000], now);
        }

        for p in alice.get_packets_to_send(now, 0) {
            let tx_delay = Duration::from_secs_f32((1300.0 * 8.0) / link_bw_bps);
            last_tx = last_tx.max(now) + tx_delay;
            wire.push_back((last_tx + Duration::from_millis(10), p, 1300, 1));
        }
        for p in charlie.get_packets_to_send(now, 0) {
            let tx_delay = Duration::from_secs_f32((1300.0 * 8.0) / link_bw_bps);
            last_tx = last_tx.max(now) + tx_delay;
            wire.push_back((last_tx + Duration::from_millis(50), p, 1300, 2));
        }

        while let Some((at, _, _, _)) = wire.front() {
            if *at <= now {
                let (_, p, _, flow) = wire.pop_front().unwrap();
                if flow == 1 {
                    for r in bob.handle_packet(p, now) {
                        alice.handle_packet(r, now);
                    }
                } else {
                    for r in dave.handle_packet(p, now) {
                        charlie.handle_packet(r, now);
                    }
                }
            } else {
                break;
            }
        }

        for p in bob.get_packets_to_send(now, 0) {
            alice.handle_packet(p, now);
        }
        for p in dave.get_packets_to_send(now, 0) {
            charlie.handle_packet(p, now);
        }

        now += Duration::from_millis(2);
    }

    let rate1 = alice.pacing_rate();
    let rate2 = charlie.pacing_rate();
    println!(
        "{:?} Short RTT rate: {} bps, Long RTT rate: {} bps",
        algo,
        rate1 * 8.0,
        rate2 * 8.0
    );

    assert!(
        rate2 * 8.0 > 400_000.0,
        "{:?} Long RTT flow starved: {} bps",
        algo,
        rate2 * 8.0
    );
}

#[test]
fn test_bbrv1_rtt_fairness() {
    bbr_rtt_fairness(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_rtt_fairness() {
    bbr_rtt_fairness(AlgorithmType::Bbrv2);
}
