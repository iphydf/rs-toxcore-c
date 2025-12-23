use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::congestion::{Algorithm, AlgorithmType, CongestionControl, DeliverySample};

fn bbr_startup_should_not_exit_early(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let mut now = Instant::now();

    let rtt = Duration::from_millis(100);
    let sample = DeliverySample {
        bytes_delivered: 100_000,
        duration: rtt,
        now,
        app_limited: false,
    };
    cc.on_ack(rtt, Some(sample), sample.bytes_delivered, 0, now);

    let startup_pacing = cc.pacing_rate();
    assert!(startup_pacing > 2_000_000.0);

    for _ in 0..3 {
        now += Duration::from_millis(10);
        let s = DeliverySample {
            bytes_delivered: 100_000,
            duration: rtt,
            now,
            app_limited: false,
        };
        cc.on_ack(rtt, Some(s), s.bytes_delivered, 0, now);
    }

    let current_pacing = cc.pacing_rate();
    assert!(
        current_pacing >= startup_pacing,
        "{:?} exited Startup prematurely! Current pacing: {}, Startup pacing: {}",
        algo,
        current_pacing,
        startup_pacing
    );
}

#[test]
fn test_bbrv1_startup_should_not_exit_early() {
    bbr_startup_should_not_exit_early(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_startup_should_not_exit_early() {
    bbr_startup_should_not_exit_early(AlgorithmType::Bbrv2);
}

fn bbr_startup_app_limited(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let mut now = Instant::now();
    let rtt = Duration::from_millis(100);

    let sample = DeliverySample {
        bytes_delivered: 100_000,
        duration: rtt,
        now,
        app_limited: false,
    };
    cc.on_ack(rtt, Some(sample), 100_000, 100_000, now);

    let startup_pacing = cc.pacing_rate();

    for _ in 0..5 {
        now += rtt + Duration::from_millis(1);
        let s = DeliverySample {
            bytes_delivered: 1000,
            duration: rtt,
            now,
            app_limited: true,
        };
        cc.on_ack(rtt, Some(s), 1000, 1000, now);
    }

    assert!(
        cc.pacing_rate() >= startup_pacing,
        "{:?} exited Startup while app-limited!",
        algo
    );
}

#[test]
fn test_bbrv1_startup_app_limited() {
    bbr_startup_app_limited(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_startup_app_limited() {
    bbr_startup_app_limited(AlgorithmType::Bbrv2);
}

fn bbr_startup_with_ping_ack(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let mut now = Instant::now();
    let rtt = Duration::from_millis(100);

    let sample = DeliverySample {
        bytes_delivered: 100_000,
        duration: rtt,
        now,
        app_limited: false,
    };
    cc.on_ack(rtt, Some(sample), 100_000, 100_000, now);
    let startup_pacing = cc.pacing_rate();

    for i in 1..=5 {
        now += rtt + Duration::from_millis(1);

        let s = DeliverySample {
            bytes_delivered: 100_000 * (i + 1),
            duration: rtt,
            now,
            app_limited: false,
        };
        cc.on_ack(rtt, Some(s), 100_000 * (i + 1), 100_000, now);

        cc.on_ack(rtt, None, 0, 100_000, now + Duration::from_millis(1));
    }

    assert!(
        cc.pacing_rate() >= startup_pacing,
        "{:?} exited Startup prematurely due to app-limited ACKs (Pings)!",
        algo
    );
}

#[test]
fn test_bbrv1_startup_with_ping_ack() {
    bbr_startup_with_ping_ack(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_startup_with_ping_ack() {
    bbr_startup_with_ping_ack(AlgorithmType::Bbrv2);
}
