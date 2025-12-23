use rand::SeedableRng;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tox_sequenced::{Algorithm, AlgorithmType, MessageType, Packet, SequenceSession};

fn bbr_convergence(algo: AlgorithmType) {
    let now_instant = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now_instant, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut now = now_instant;
    let start = now;

    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    let data = vec![0u8; 1_000_000];
    alice
        .send_message_at(MessageType::MerkleNode, &data, now)
        .unwrap();

    let mut link_bw_bps = 5_000_000.0;
    let latency = Duration::from_millis(50);
    let max_buffer_bytes = 50_000;
    let mut buffer_bytes = 0;

    let mut wire: VecDeque<(Instant, Packet, usize)> = VecDeque::new();
    let mut last_tx = now;

    while now.duration_since(start) < Duration::from_secs(15) {
        let packets = alice.get_packets_to_send(now, 0);
        for p in packets {
            let size = if let Packet::Data { data, .. } = &p {
                data.len() + 30
            } else {
                60
            };

            if buffer_bytes + size > max_buffer_bytes {
                continue;
            }

            let tx_delay = Duration::from_secs_f32((size as f32 * 8.0) / link_bw_bps);
            last_tx = last_tx.max(now) + tx_delay;
            buffer_bytes += size;
            wire.push_back((last_tx + latency, p, size));
        }

        while let Some((at, _, _)) = wire.front() {
            if *at <= now {
                let (_, p, size) = wire.pop_front().unwrap();
                buffer_bytes -= size;
                let replies = bob.handle_packet(p, now);
                for r in replies {
                    alice.handle_packet(r, now);
                }
            } else {
                break;
            }
        }

        for p in bob.get_packets_to_send(now, 0) {
            alice.handle_packet(p, now);
        }

        if now.duration_since(start) > Duration::from_secs(2) {
            link_bw_bps = 50_000.0;
        }

        now += Duration::from_millis(1);
    }

    let final_rate = alice.cwnd() * 1300 * 8;
    let pacing_rate_bps = alice.pacing_rate() * 8.0;

    println!("{:?} Final pacing rate: {} bps", algo, pacing_rate_bps);
    println!("{:?} Final CWND-based rate: {} bps", algo, final_rate);

    assert!(
        pacing_rate_bps < 150_000.0,
        "{:?} failed to react to bandwidth drop. Pacing rate: {} bps",
        algo,
        pacing_rate_bps
    );
    assert!(
        final_rate < 150_000,
        "{:?} CWND too high after drop. Rate: {} bps",
        algo,
        final_rate
    );
    assert!(
        pacing_rate_bps > 10_000.0,
        "{:?} choked too much. Pacing rate: {} bps",
        algo,
        pacing_rate_bps
    );
}

#[test]
fn test_bbrv1_convergence() {
    bbr_convergence(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_convergence() {
    bbr_convergence(AlgorithmType::Bbrv2);
}
