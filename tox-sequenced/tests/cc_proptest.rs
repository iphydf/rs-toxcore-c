use proptest::prelude::*;
use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::congestion::{Algorithm, AlgorithmType, CongestionControl, DeliverySample};

fn arb_algo_type() -> impl Strategy<Value = AlgorithmType> {
    prop_oneof![
        Just(AlgorithmType::Aimd),
        Just(AlgorithmType::Bbrv1),
        Just(AlgorithmType::Bbrv2),
        Just(AlgorithmType::Cubic),
    ]
}

#[test]
fn test_cc_loss_decreases_cwnd() {
    proptest!(|(algo_type in arb_algo_type(), seed in any::<u64>(), is_nack in any::<bool>())| {
        let mut cc = Algorithm::new(algo_type, rand::rngs::StdRng::seed_from_u64(seed));
        let now = Instant::now();

        for i in 0..10 {
            cc.on_ack(
                Duration::from_millis(100),
                Some(DeliverySample {
                    bytes_delivered: 1300,
                    duration: Duration::from_millis(10),
                    now: now + Duration::from_millis(i * 10),
                    app_limited: false,
                }),
                1300,
                1300 * 10,
                now + Duration::from_millis(i * 10),
            );
        }

        let initial_cwnd = cc.cwnd();
        let initial_pacing = cc.pacing_rate();

        if is_nack {
            cc.on_nack(now + Duration::from_secs(1));
        } else {
            cc.on_timeout(now + Duration::from_secs(1));
        }

        prop_assert!(cc.cwnd() <= initial_cwnd || cc.cwnd() == 4);
        prop_assert!(cc.pacing_rate() <= initial_pacing || initial_pacing == 0.0);
    });
}

#[test]
fn test_cc_pacing_sanity() {
    proptest!(|(algo_type in arb_algo_type(), seed in any::<u64>())| {
        let cc = Algorithm::new(algo_type, rand::rngs::StdRng::seed_from_u64(seed));
        let pacing = cc.pacing_rate();
        prop_assert!(pacing >= 0.0);
        prop_assert!(pacing.is_finite());
    });
}

#[test]
fn test_bbr_monotonic_max_bw() {
    proptest!(|(is_v2 in any::<bool>(), seed in any::<u64>(), samples in prop::collection::vec(10_000..1_000_000usize, 1..50))| {
        let algo_type = if is_v2 { AlgorithmType::Bbrv2 } else { AlgorithmType::Bbrv1 };
        let mut cc = Algorithm::new(algo_type, rand::rngs::StdRng::seed_from_u64(seed));
        let start = Instant::now();

        let mut max_observed_bw = 0.0;

        for (i, &bytes) in samples.iter().enumerate() {
            let now = start + Duration::from_millis(i as u64 * 10);
            let sample = DeliverySample {
                bytes_delivered: bytes,
                duration: Duration::from_millis(10),
                now,
                app_limited: false,
            };

            let bw = bytes as f32 / 0.01;
            if bw > max_observed_bw {
                max_observed_bw = bw;
            }

            cc.on_ack(Duration::from_millis(50), Some(sample), bytes, 0, now);
        }

        prop_assert!(cc.pacing_rate() <= max_observed_bw * 4.0 + 200_000.0);
    });
}

#[test]
fn test_cc_large_rtt_stability() {
    proptest!(|(algo_type in arb_algo_type(), rtt_ms in 1..5000u64)| {
        let mut cc = Algorithm::new(algo_type, rand::rngs::StdRng::seed_from_u64(0));
        let now = Instant::now();
        let rtt = Duration::from_millis(rtt_ms);

        for i in 0..10 {
            cc.on_ack(
                rtt,
                Some(DeliverySample {
                    bytes_delivered: 1300,
                    duration: rtt,
                    now: now + Duration::from_secs(i),
                    app_limited: false,
                }),
                1300,
                1300,
                now + Duration::from_secs(i),
            );
        }

        prop_assert!(cc.cwnd() >= 4);
        prop_assert!(cc.pacing_rate() >= 0.0);
    });
}

#[test]
fn test_cc_cwnd_lower_bound() {
    proptest!(|(algo_type in arb_algo_type(), seed in any::<u64>())| {
        let mut cc = Algorithm::new(algo_type, rand::rngs::StdRng::seed_from_u64(seed));
        let now = Instant::now();

        for i in 0..100 {
            cc.on_nack(now + Duration::from_millis(i));
        }

        prop_assert!(cc.cwnd() >= 1);
    });
}
#[test]
fn test_bbr_min_rtt_update() {
    proptest!(|(is_v2 in any::<bool>(), seed in any::<u64>(), rtt_samples in prop::collection::vec(10..1000u64, 1..50))| {
        let algo_type = if is_v2 { AlgorithmType::Bbrv2 } else { AlgorithmType::Bbrv1 };
        let mut cc = Algorithm::new(algo_type, rand::rngs::StdRng::seed_from_u64(seed));
        let now = Instant::now();

        let mut expected_min = Duration::from_secs(100);

        for (i, &rtt_ms) in rtt_samples.iter().enumerate() {
            let rtt = Duration::from_millis(rtt_ms);
            if rtt < expected_min {
                expected_min = rtt;
            }

            cc.on_ack(rtt, None, 0, 0, now + Duration::from_millis(i as u64));
        }

        prop_assert_eq!(cc.min_rtt(), expected_min);
    });
}
