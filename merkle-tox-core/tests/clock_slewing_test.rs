use merkle_tox_core::clock::{NetworkClock, TimeProvider};
use merkle_tox_core::dag::PhysicalDevicePk;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct MockTimeProvider {
    base_instant: Instant,
    base_system_ms: AtomicI64,
    elapsed_ms: AtomicU64,
}

impl MockTimeProvider {
    fn new(base_system_ms: i64) -> Self {
        Self {
            base_instant: Instant::now(),
            base_system_ms: AtomicI64::new(base_system_ms),
            elapsed_ms: AtomicU64::new(0),
        }
    }

    fn advance(&self, ms: u64) {
        self.elapsed_ms.fetch_add(ms, Ordering::SeqCst);
    }

    fn jump_system_time(&self, ms: i64) {
        self.base_system_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl TimeProvider for MockTimeProvider {
    fn now_instant(&self) -> Instant {
        self.base_instant + Duration::from_millis(self.elapsed_ms.load(Ordering::SeqCst))
    }

    fn now_system_ms(&self) -> i64 {
        self.base_system_ms.load(Ordering::SeqCst) + self.elapsed_ms.load(Ordering::SeqCst) as i64
    }
}

#[test]
fn test_clock_slewing_up() {
    let mock = Arc::new(MockTimeProvider::new(1000000));
    // We need to pass a Box<dyn TimeProvider>. Since Arc<T> doesn't easily convert to Box<dyn Trait>
    // while keeping shared access, we can use a wrapper or just a simple struct that clones the Arc.
    let mut clock = NetworkClock::new(mock.clone());
    let peer = PhysicalDevicePk::from([1u8; 32]);

    // Initial state
    assert_eq!(clock.consensus_offset(), 0);

    // Set a target offset of +1000ms.
    // The first sample is expected to cause an immediate jump to the target offset
    // to allow for quick initial synchronization.
    clock.update_peer_offset(peer, 1000);

    // Get the offset after the first update (should have jumped)
    let start_offset = clock.consensus_offset();
    assert_eq!(
        start_offset, 1000,
        "Clock should have jumped to the first sample offset"
    );

    // Now set target to start_offset + 1000. Subsequent updates should slew.
    clock.update_peer_offset(peer, start_offset + 1000);
    assert_eq!(clock.consensus_offset(), start_offset);

    // Advance mock time by 1 second (1000ms).
    // Slewing is 1%, so it should advance by 10ms.
    mock.advance(1000);
    clock.network_time_ms();

    assert_eq!(clock.consensus_offset(), start_offset + 10);

    // Advance by another 10 seconds. Should advance by 100ms.
    mock.advance(10000);
    clock.network_time_ms();
    assert_eq!(clock.consensus_offset(), start_offset + 110);
}

#[test]
fn test_clock_slewing_down() {
    let mock = Arc::new(MockTimeProvider::new(1000000));
    let mut clock = NetworkClock::new(mock.clone());
    let peer = PhysicalDevicePk::from([1u8; 32]);

    // Initial jump to +1000ms
    clock.update_peer_offset(peer, 1000);
    let start_offset = clock.consensus_offset();
    assert_eq!(start_offset, 1000);

    // Target offset is now 0 (should slew DOWN from 1000ms to 0ms)
    clock.update_peer_offset(peer, 0);
    assert_eq!(clock.consensus_offset(), 1000);

    // Advance by 1 second. Slew is -1%, so should decrease by 10ms.
    mock.advance(1000);
    clock.network_time_ms();
    assert_eq!(clock.consensus_offset(), 990);

    // Advance by another 10 seconds. Should decrease by 100ms.
    mock.advance(10000);
    clock.network_time_ms();
    assert_eq!(clock.consensus_offset(), 890);
}

#[test]
fn test_clock_monotonicity_system_jump() {
    let mock = Arc::new(MockTimeProvider::new(1000000));
    let mut clock = NetworkClock::new(mock.clone());
    let t1 = clock.network_time_ms();

    // Verification that repeated calls are monotonic.
    mock.advance(10);
    let t2 = clock.network_time_ms();
    assert!(t2 >= t1);

    // Even if we don't advance time, it should be monotonic.
    let t3 = clock.network_time_ms();
    assert!(t3 >= t2);
}

#[test]
fn test_clock_monotonicity_backward_jump() {
    let mock = Arc::new(MockTimeProvider::new(1000000));
    let mut clock = NetworkClock::new(mock.clone());
    let t1 = clock.network_time_ms();

    // System clock jumps back by 500ms
    mock.jump_system_time(-500);
    let t2 = clock.network_time_ms();
    assert!(
        t2 >= t1,
        "Network time must not move backward even if system clock does"
    );
}

#[test]
fn test_clock_hard_jump() {
    let mock = Arc::new(MockTimeProvider::new(1000000));
    let mut clock = NetworkClock::new(mock.clone());
    let peer = PhysicalDevicePk::from([1u8; 32]);

    // Initialize with 0 offset first to bypass initial sample jump logic
    clock.update_peer_offset(peer, 0);
    assert_eq!(clock.consensus_offset(), 0);

    // 11 minutes offset (exceeds 10 min threshold)
    let large_offset = 11 * 60 * 1000;
    clock.update_peer_offset(peer, large_offset);

    // Should jump immediately because it exceeds threshold
    assert_eq!(clock.consensus_offset(), large_offset);

    let t1 = clock.network_time_ms();
    assert!(t1 >= 1000000 + large_offset);
}

// end of file
