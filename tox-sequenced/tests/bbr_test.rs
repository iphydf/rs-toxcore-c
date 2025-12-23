use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::congestion::{Algorithm, AlgorithmType, CongestionControl, DeliverySample};

fn bbr_loss_resilience(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let rtt = Duration::from_millis(100);

    for i in 0..100 {
        cc.on_ack(
            rtt,
            Some(DeliverySample {
                bytes_delivered: 125000,
                duration: rtt,
                now: now + rtt * i,
                app_limited: false,
            }),
            125000,
            125000,
            now + rtt * i,
        );
    }

    for i in 100..110 {
        cc.on_ack(
            rtt,
            Some(DeliverySample {
                bytes_delivered: 125000,
                duration: rtt,
                now: now + rtt * i,
                app_limited: false,
            }),
            125000,
            125000,
            now + rtt * i,
        );
    }

    let stable_cwnd = cc.cwnd();
    assert!(stable_cwnd >= 100);

    let later = now + Duration::from_secs(20);
    for i in 0..3 {
        cc.on_nack(later + Duration::from_millis(i * 10));
    }

    let post_loss_cwnd = cc.cwnd();
    assert!(
        post_loss_cwnd > stable_cwnd * 3 / 4,
        "{:?} CWND collapsed! Stable: {}, Post-Loss: {}",
        algo,
        stable_cwnd,
        post_loss_cwnd
    );
}

#[test]
fn test_bbrv1_loss_resilience() {
    bbr_loss_resilience(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_loss_resilience() {
    bbr_loss_resilience(AlgorithmType::Bbrv2);
}

fn bbr_behavioral_bandwidth_growth(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let initial_pacing = cc.pacing_rate();
    assert!(initial_pacing >= 100_000.0);

    let sample = DeliverySample {
        bytes_delivered: 100_000,
        duration: Duration::from_millis(100),
        now,
        app_limited: false,
    };
    cc.on_ack(
        Duration::from_millis(50),
        Some(sample),
        sample.bytes_delivered,
        0,
        now,
    );

    let grew_pacing = cc.pacing_rate();
    assert!(grew_pacing > 2_000_000.0);
}

#[test]
fn test_bbrv1_behavioral_bandwidth_growth() {
    bbr_behavioral_bandwidth_growth(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_behavioral_bandwidth_growth() {
    bbr_behavioral_bandwidth_growth(AlgorithmType::Bbrv2);
}

fn bbr_behavioral_loss_response(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let sample = DeliverySample {
        bytes_delivered: 10_000,
        duration: Duration::from_millis(100),
        now,
        app_limited: false,
    };
    cc.on_ack(
        Duration::from_millis(50),
        Some(sample),
        sample.bytes_delivered,
        0,
        now,
    );

    let initial_cwnd = cc.cwnd();

    for _ in 0..10 {
        cc.on_nack(now);
    }

    assert!(cc.cwnd() < initial_cwnd || cc.cwnd() == 4);
}

#[test]
fn test_bbrv1_behavioral_loss_response() {
    bbr_behavioral_loss_response(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_behavioral_loss_response() {
    bbr_behavioral_loss_response(AlgorithmType::Bbrv2);
}

fn bbr_behavioral_idle_restart(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let sample = DeliverySample {
        bytes_delivered: 100_000,
        duration: Duration::from_millis(100),
        now,
        app_limited: false,
    };
    cc.on_ack(
        Duration::from_millis(50),
        Some(sample),
        sample.bytes_delivered,
        0,
        now,
    );

    let pacing_startup = cc.pacing_rate();

    for i in 1..=4 {
        let s = DeliverySample {
            bytes_delivered: 100_000,
            duration: Duration::from_millis(100),
            now: now + Duration::from_millis(100 * i),
            app_limited: false,
        };
        cc.on_ack(
            Duration::from_millis(50),
            Some(s),
            s.bytes_delivered,
            0,
            now + Duration::from_millis(100 * i),
        );
    }

    let pacing_steady = cc.pacing_rate();
    assert!(pacing_steady < pacing_startup);

    let idle_now = now + Duration::from_millis(2000);
    cc.on_ack(Duration::from_millis(50), None, 0, 0, idle_now);

    let pacing_restarted = cc.pacing_rate();
    assert!(pacing_restarted > pacing_steady * 2.0);
}

#[test]
fn test_bbrv1_behavioral_idle_restart() {
    bbr_behavioral_idle_restart(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_behavioral_idle_restart() {
    bbr_behavioral_idle_restart(AlgorithmType::Bbrv2);
}

fn bbr_probertt_entry(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let sample = DeliverySample {
        bytes_delivered: 100_000,
        duration: Duration::from_millis(100),
        now,
        app_limited: false,
    };
    cc.on_ack(
        Duration::from_millis(50),
        Some(sample),
        sample.bytes_delivered,
        0,
        now,
    );
    let initial_cwnd = cc.cwnd();
    assert!(initial_cwnd > 4);

    let much_later = now + Duration::from_secs(11);
    cc.on_ack(Duration::from_millis(60), None, 0, 0, much_later);

    assert_eq!(cc.cwnd(), 4);
}

#[test]
fn test_bbrv1_probertt_entry() {
    bbr_probertt_entry(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_probertt_entry() {
    bbr_probertt_entry(AlgorithmType::Bbrv2);
}

fn bbr_bandwidth_spike_protection(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let sample = DeliverySample {
        bytes_delivered: 1300,
        duration: Duration::from_nanos(1),
        now,
        app_limited: false,
    };

    cc.on_ack(Duration::from_millis(100), Some(sample), 1300, 0, now);

    let rate = cc.pacing_rate();

    assert!(
        rate < 10_000_000.0,
        "Pacing rate is too high: {}. Bandwidth spike protection failed.",
        rate
    );
}

#[test]
fn test_bbrv1_bandwidth_spike_protection() {
    bbr_bandwidth_spike_protection(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_bandwidth_spike_protection() {
    bbr_bandwidth_spike_protection(AlgorithmType::Bbrv2);
}

fn bbr_cwnd_gain_recovery(algo: AlgorithmType) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    let mut current_now = now;
    let sample = DeliverySample {
        bytes_delivered: 200_000,
        duration: Duration::from_millis(100),
        now: current_now,
        app_limited: false,
    };
    cc.on_ack(
        Duration::from_millis(50),
        Some(sample),
        200_000,
        100_000,
        current_now,
    );

    for _ in 0..10 {
        current_now += Duration::from_millis(100);
        let s = DeliverySample {
            bytes_delivered: 100_000,
            duration: Duration::from_millis(100),
            now: current_now,
            app_limited: false,
        };
        cc.on_ack(Duration::from_millis(50), Some(s), 100_000, 0, current_now);
    }

    for _ in 0..10 {
        cc.on_nack(current_now);
    }

    let reduced_cwnd = cc.cwnd();

    for _ in 0..10 {
        current_now += Duration::from_millis(100);
        let s = DeliverySample {
            bytes_delivered: 100_000,
            duration: Duration::from_millis(100),
            now: current_now,
            app_limited: false,
        };
        cc.on_ack(Duration::from_millis(50), Some(s), 100_000, 0, current_now);
    }

    assert!(
        cc.cwnd() > reduced_cwnd,
        "BBR cwnd_gain failed to recover after loss while staying in ProbeBw (stays at {})",
        reduced_cwnd
    );
}

#[test]
fn test_bbrv1_cwnd_gain_recovery() {
    bbr_cwnd_gain_recovery(AlgorithmType::Bbrv1);
}
#[test]
fn test_bbrv2_cwnd_gain_recovery() {
    bbr_cwnd_gain_recovery(AlgorithmType::Bbrv2);
}
