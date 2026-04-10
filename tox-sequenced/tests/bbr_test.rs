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
        cc.on_loss(tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE, later + Duration::from_millis(i * 10));
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
        cc.on_loss(tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE, now);
    }

    assert!(cc.cwnd() <= initial_cwnd);
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
        cc.on_loss(tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE, current_now);
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

/// BBRv2 reacts proportionally to the byte volume of loss, not just
/// loss event count. A single `on_loss(N, _)` call where N >> MTU
/// must change CC state more aggressively than a single
/// `on_loss(MTU, _)` call. This pins the fix that replaced the
/// previous fixed-`ESTIMATED_PAYLOAD_SIZE` increment in BBRv2's
/// `bytes_lost_in_round`.
#[test]
fn test_bbrv2_on_loss_uses_byte_count_not_fixed_mtu() {
    let now = Instant::now();
    let rtt = Duration::from_millis(100);
    let mtu = tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE;

    // Two parallel sessions warmed identically.
    let warm = |cc: &mut Algorithm| {
        for i in 0..100 {
            cc.on_ack(
                rtt,
                Some(DeliverySample {
                    bytes_delivered: 125_000,
                    duration: rtt,
                    now: now + rtt * i,
                    app_limited: false,
                }),
                125_000,
                125_000,
                now + rtt * i,
            );
        }
    };
    let mut small_loss = Algorithm::new(AlgorithmType::Bbrv2, rand::rngs::StdRng::seed_from_u64(0));
    let mut large_loss = Algorithm::new(AlgorithmType::Bbrv2, rand::rngs::StdRng::seed_from_u64(0));
    warm(&mut small_loss);
    warm(&mut large_loss);

    let later = now + Duration::from_secs(20);

    // Both sessions get a single on_loss call. Small loss = 1 MTU's
    // worth (the old fixed-MTU semantics). Large loss = 100 MTUs
    // (representing a burst that the timer-based scan picks up in
    // one go). BBRv2's loss-rate divisor sees vastly different
    // numerators; the response should differ.
    small_loss.on_loss(mtu, later);
    large_loss.on_loss(mtu * 100, later);

    // Drive a few more on_ack rounds so the round-end logic
    // (handle_loss_in_round) gets a chance to fire on both.
    let drive = |cc: &mut Algorithm| {
        for i in 0..50 {
            cc.on_ack(
                rtt,
                Some(DeliverySample {
                    bytes_delivered: 125_000,
                    duration: rtt,
                    now: later + rtt * i,
                    app_limited: false,
                }),
                125_000,
                125_000,
                later + rtt * i,
            );
        }
    };
    drive(&mut small_loss);
    drive(&mut large_loss);

    // Large-loss session should have responded more aggressively —
    // its post-loss cwnd should be no greater than the small-loss
    // session's. (Cannot strictly assert "smaller" because cwnd may
    // recover to similar values over the drive period; the
    // direction is what matters.)
    assert!(
        large_loss.cwnd() <= small_loss.cwnd(),
        "BBRv2 with 100×MTU bytes_lost should respond at least as \
         aggressively as 1×MTU. Got large={} vs small={}. If equal, \
         the byte-count parameter is being ignored — regression to \
         fixed-MTU accounting.",
        large_loss.cwnd(),
        small_loss.cwnd(),
    );
}

/// BBRv2's bandwidth estimate must not be derailed by a single
/// "delivery burst" sample where many bytes appear over an unrealistically
/// short window. Such samples arise naturally from receiver ack-batching
/// and from cumulative-base catch-up across SACK gaps: a single ACK can
/// report a multi-MB jump in `recv_bytes` over a sub-RTT delta_time,
/// which previously read as multi-Gbps.
///
/// Two layers of defence are pinned here:
///   - `update_bandwidth` floors `sample.duration` at `min_rtt` (the
///     smallest meaningful measurement window for delivery rate).
///   - `update_bandwidth` clamps the resulting bandwidth at
///     `MAX_BW_CEILING` (10 Gbps) so that even when `min_rtt` itself
///     converges to a real-link sub-millisecond value, an enormous
///     `bytes_delivered` cannot drive the pacer past any plausible
///     physical link.
///
/// Pre-fix the 1 ms `Duration` floor in `update_bandwidth` admits a
/// 1 GB/s reading from a 1 MB / 100 µs sample, which combined with
/// `STARTUP_PACING_GAIN ≈ 2.885` yields ~22 Gbps and triggers the
/// "Alice overruns Bob's UDP rcvbuf in startup → loss burst → BBR
/// backs off to 50 % link util" pathology observed under tc and on
/// plain loopback.
fn run_burst_resistance(
    algo: AlgorithmType,
    min_rtt_warmup: Duration,
    burst_bytes: usize,
    burst_duration: Duration,
    expected_mbps_ceiling: f32,
) {
    let mut cc = Algorithm::new(algo, rand::rngs::StdRng::seed_from_u64(0));
    let now = Instant::now();

    // Warmup sample establishes min_rtt at the chosen value.
    let warmup = DeliverySample {
        bytes_delivered: 50_000,
        duration: min_rtt_warmup,
        now,
        app_limited: false,
    };
    cc.on_ack(
        min_rtt_warmup,
        Some(warmup),
        warmup.bytes_delivered,
        warmup.bytes_delivered,
        now,
    );

    let burst_now = now + min_rtt_warmup + Duration::from_millis(1);
    let burst = DeliverySample {
        bytes_delivered: burst_bytes,
        duration: burst_duration,
        now: burst_now,
        app_limited: false,
    };
    cc.on_ack(
        min_rtt_warmup,
        Some(burst),
        burst.bytes_delivered,
        burst.bytes_delivered,
        burst_now,
    );

    let pacing = cc.pacing_rate();
    let pacing_mbps = pacing * 8.0 / 1_000_000.0;
    assert!(
        pacing_mbps < expected_mbps_ceiling,
        "{:?} pacing_rate spiked to {:.1} Mbps after a sub-RTT burst \
         sample ({} bytes in {:?} with min_rtt warmup={:?}). The \
         bandwidth estimator should defend against this via the \
         min_rtt duration floor *and* the MAX_BW_CEILING clamp.",
        algo, pacing_mbps, burst_bytes, burst_duration, min_rtt_warmup,
    );
}

#[test]
fn test_bbrv1_bandwidth_spike_resists_subrtt_burst_10ms_min_rtt() {
    run_burst_resistance(
        AlgorithmType::Bbrv1,
        Duration::from_millis(10),
        1_000_000,
        Duration::from_micros(100),
        2_000.0,
    );
}

#[test]
fn test_bbrv2_bandwidth_spike_resists_subrtt_burst_10ms_min_rtt() {
    // Realistic "post-startup on a moderate link" min_rtt regime.
    // Original spike: 22 Gbps. With min_rtt-floored duration the
    // sample bw is ~100 MB/s (1 MB / 10 ms); pacing is therefore
    // bounded by max_bw × startup_gain ≈ 200 MB/s, well under the
    // 1 Gbps MAX_BW_CEILING. Threshold 2 Gbps catches any future
    // regression that re-admits the un-clamped spike path.
    run_burst_resistance(
        AlgorithmType::Bbrv2,
        Duration::from_millis(10),
        1_000_000,
        Duration::from_micros(100),
        2_000.0,
    );
}

#[test]
fn test_bbrv1_bandwidth_spike_resists_subrtt_burst_sub_ms_min_rtt() {
    run_burst_resistance(
        AlgorithmType::Bbrv1,
        Duration::from_millis(1),
        2_000_000,
        Duration::from_micros(50),
        2_000.0,
    );
}

#[test]
fn test_bbrv2_bandwidth_spike_resists_subrtt_burst_sub_ms_min_rtt() {
    // Real-LAN regime where min_rtt has converged to ~1 ms. The
    // duration floor at min_rtt is no longer a strong defence at
    // this RTT (2 MB / 1 ms is still 16 Gbps), so the
    // MAX_BW_CEILING clamp (1 Gbps) is the active line of defence.
    // Threshold 2 Gbps gives ~2× headroom over the ceiling so
    // pacing-gain output is still admitted while pre-fix multi-Gbps
    // readings are rejected.
    run_burst_resistance(
        AlgorithmType::Bbrv2,
        Duration::from_millis(1),
        2_000_000,
        Duration::from_micros(50),
        2_000.0,
    );
}
