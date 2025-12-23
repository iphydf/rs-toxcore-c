use std::time::Duration;
use tox_sequenced::rtt::{MAX_RTO, MIN_RTO, RttEstimator};

#[test]
fn test_rtt_update() {
    let mut rtt = RttEstimator::new();
    let initial_rto = rtt.rto();

    // One sample smaller than initial
    rtt.update(Duration::from_millis(100));
    assert!(rtt.rto() < initial_rto);

    // Multiple samples should converge
    for _ in 0..50 {
        rtt.update(Duration::from_millis(50));
    }
    assert!(rtt.srtt() < Duration::from_millis(60));
    assert!(rtt.srtt() > Duration::from_millis(40));
}

#[test]
fn test_rto_clamping() {
    let mut rtt = RttEstimator::new();

    // Very large sample
    rtt.update(Duration::from_secs(10));
    assert!(rtt.rto() <= MAX_RTO);

    // Very small sample
    for _ in 0..100 {
        rtt.update(Duration::from_millis(1));
    }
    assert!(rtt.rto() >= MIN_RTO);
}

#[test]
fn test_backoff() {
    let rtt = RttEstimator::new();
    let base_rto = rtt.rto();
    assert_eq!(rtt.rto_with_backoff(1), base_rto * 2);
    assert_eq!(rtt.rto_with_backoff(2), base_rto * 4);
    // Max backoff exponent is 6
    assert_eq!(rtt.rto_with_backoff(10), base_rto * 64);
}

// end of tests
