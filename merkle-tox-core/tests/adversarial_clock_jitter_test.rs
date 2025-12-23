use merkle_tox_core::clock::{ManualTimeProvider, NetworkClock};
use merkle_tox_core::dag::PhysicalDevicePk;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_clock_stability_under_adversarial_jitter() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000000));
    let mut clock = NetworkClock::new(tp.clone());

    // 3 Honest peers reporting perfect time (0 offset)
    let honest_peers = [
        PhysicalDevicePk::from([1u8; 32]),
        PhysicalDevicePk::from([2u8; 32]),
        PhysicalDevicePk::from([3u8; 32]),
    ];
    for p in honest_peers {
        clock.update_peer_offset(p, 0);
    }

    // 2 Malicious peers attempting to nudge the clock up (+9 minutes)
    // just below the 10-minute quarantine threshold.
    let malicious_peers = [
        PhysicalDevicePk::from([6u8; 32]),
        PhysicalDevicePk::from([7u8; 32]),
    ];
    let nudge_offset = 9 * 60 * 1000;

    // Simulate 1,000 updates over time
    let mut last_net_time = clock.network_time_ms();

    for _ in 0..1000 {
        // Honest peers update
        for p in honest_peers {
            clock.update_peer_offset(p, 0);
        }
        // Attackers update
        for p in malicious_peers {
            clock.update_peer_offset(p, nudge_offset);
        }

        // Advance physical time by 1 second
        tp.advance(Duration::from_secs(1));

        let current_net_time = clock.network_time_ms();

        // 1. Monotonicity check
        assert!(
            current_net_time >= last_net_time,
            "Clock moved backward during jitter attack!"
        );

        // 2. Slewing rate check (max 1%)
        // Elapsed real time is 1000ms. Max net time jump should be 1010ms.
        let elapsed_net = current_net_time - last_net_time;
        assert!(
            elapsed_net <= 1010,
            "Clock slewed too fast ({}ms net for 1000ms real)",
            elapsed_net
        );

        last_net_time = current_net_time;
    }

    // 3. Byzantine Resistance Check
    // With 3 honest (0) and 2 malicious (+9m), median should be index 2 (0).
    // The network clock should have stayed perfectly aligned with honest time.
    assert_eq!(
        clock.consensus_offset(),
        0,
        "Malicious minority successfully shifted the median!"
    );
}

#[test]
fn test_clock_stability_with_majority_jitter() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000000));
    let mut clock = NetworkClock::new(tp.clone());

    // 2 Honest peers (0 offset)
    let honest_peers = [
        PhysicalDevicePk::from([1u8; 32]),
        PhysicalDevicePk::from([2u8; 32]),
    ];
    // 3 Malicious peers (+9m offset)
    let malicious_peers = [
        PhysicalDevicePk::from([6u8; 32]),
        PhysicalDevicePk::from([7u8; 32]),
        PhysicalDevicePk::from([8u8; 32]),
    ];
    let nudge_offset = 9 * 60 * 1000;

    let mut last_net_time = clock.network_time_ms();

    // The majority SHOULD be able to shift the clock, but only at the SLEWING rate (1%).
    for _ in 0..60 {
        // 1 minute of simulation
        for p in honest_peers {
            clock.update_peer_offset(p, 0);
        }
        for p in malicious_peers {
            clock.update_peer_offset(p, nudge_offset);
        }

        tp.advance(Duration::from_secs(1));
        let current_net_time = clock.network_time_ms();

        assert!(current_net_time >= last_net_time);
        last_net_time = current_net_time;
    }

    // After 60 seconds of 1% slewing, the offset should be exactly 600ms.
    assert_eq!(clock.consensus_offset(), 600);
}
