use rand::SeedableRng;
use std::time::Instant;
use tox_sequenced::SequenceSession;
use tox_sequenced::protocol::{
    ESTIMATED_PAYLOAD_SIZE, FragmentCount, FragmentIndex, MessageId, Packet,
};
use tox_sequenced::quota::{Priority, ReassemblyQuota};

#[test]
fn test_quota_basic() {
    let quota = ReassemblyQuota::new(1000);
    assert_eq!(quota.available(), 1000);
    assert_eq!(quota.used(), 0);

    // Using reserve_guaranteed for 100% capacity tests
    assert!(quota.reserve_guaranteed(400));
    assert_eq!(quota.available(), 600);
    assert_eq!(quota.used(), 400);

    assert!(quota.reserve_guaranteed(600));
    assert_eq!(quota.available(), 0);
    assert_eq!(quota.used(), 1000);

    assert!(!quota.reserve_guaranteed(1));

    quota.release(500);
    assert_eq!(quota.available(), 500);
    assert_eq!(quota.used(), 500);

    assert!(quota.reserve_guaranteed(1));
}

#[test]
fn test_quota_priority_thresholds() {
    let quota = ReassemblyQuota::new(1000);

    // Bulk threshold: 70% (700 bytes)
    assert!(quota.reserve(600, Priority::Bulk));
    assert!(quota.reserve(100, Priority::Bulk)); // Exactly 700
    assert!(!quota.reserve(1, Priority::Bulk)); // Exceeds 70%

    // Standard threshold: 90% (900 bytes)
    assert!(quota.reserve(200, Priority::Standard)); // Exactly 900
    assert!(!quota.reserve(1, Priority::Standard)); // Exceeds 90%

    // Critical threshold: 99% (990 bytes)
    assert!(quota.reserve(90, Priority::Critical)); // Exactly 990
    assert!(!quota.reserve(1, Priority::Critical)); // Exceeds 99%
}

#[test]
fn test_quota_clone_sharing() {
    let quota1 = ReassemblyQuota::new(1000);
    let quota2 = quota1.clone();

    assert!(quota1.reserve_guaranteed(600));
    assert_eq!(quota2.available(), 400);
    assert_eq!(quota2.used(), 600);

    assert!(quota2.reserve_guaranteed(400));
    assert_eq!(quota1.available(), 0);

    quota2.release(1000);
    assert_eq!(quota1.available(), 1000);
}

#[test]
fn test_quota_reserve_exact() {
    let quota = ReassemblyQuota::new(100);
    assert!(quota.reserve_guaranteed(100));
    assert!(!quota.reserve_guaranteed(1));
    quota.release(100);
    assert!(quota.reserve_guaranteed(100));
}

#[test]
fn test_quota_multithreaded() {
    use std::sync::Arc;
    use std::thread;

    let quota = Arc::new(ReassemblyQuota::new(10000));
    let mut handles = vec![];

    for _ in 0..10 {
        let q = Arc::clone(&quota);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                if q.reserve_guaranteed(10) {
                    // simulate work
                    q.release(10);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(quota.used(), 0);
    assert_eq!(quota.available(), 10000);
}

#[test]
fn test_rwnd_accounting_for_potential_allocation() {
    let quota = ReassemblyQuota::new(100_000);
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::with_quota_at(quota.clone(), now, tp, &mut rng);

    // Explicitly set a small max_per_session for this test.
    session.max_per_session = 20000;

    let now = Instant::now();

    // 2. Bob receives Alice's message.
    let packet = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(10),
        data: vec![0u8; ESTIMATED_PAYLOAD_SIZE],
    };
    session.handle_packet(packet, now);

    assert!(
        session.find_incoming(MessageId(1)).is_some(),
        "Message should be accepted within quota"
    );

    // 2. Check the current rwnd.
    // Session limit: 20,000. Planned: 10,000.
    // rwnd SHOULD be 10,000.
    // If bug exists, it will be 19,000 (only subtracting actually used 1000).
    let rwnd = session.current_rwnd();

    assert!(
        rwnd.0 <= 10000,
        "Misleading RWND! Reported {}, but we have a 10-fragment message pending (total 10,000)",
        rwnd
    );
}

#[test]
fn test_priority_escalation_by_fragment_count() {
    // Quota with 1MB limit.
    // Bulk threshold: 700KB.
    // Critical threshold: 990KB.
    let quota = ReassemblyQuota::new(1024 * 1024);
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp, &mut rng);

    // Fill up to 80% (819.2 KB) with critical data.
    // Now, any Bulk request (>70% used) should be rejected.
    // But a Critical request (<99% used) would be accepted.
    quota.reserve(819_200, Priority::Critical);

    // Try to send a "CapsAnnounce" (normally Critical) but with many fragments.
    // total_fragments: 100 -> ~130KB.
    // 819.2 + 130 = 949.2 KB.
    // This is > 700KB (Bulk limit) but < 990KB (Critical limit).
    let responses = bob.handle_packet(
        Packet::Data {
            message_id: MessageId(1),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(100),
            data: vec![0; 1000],
        },
        now,
    );

    // If it was correctly downgraded to Bulk, it should be rejected.
    let is_rejected = responses.iter().any(|p| {
        if let Packet::Ack(ack) = p {
            ack.message_id == MessageId(1) && ack.base_index == FragmentIndex(0) && ack.bitmask == 0
        } else {
            false
        }
    });

    assert!(
        is_rejected,
        "Message with many fragments should have been downgraded to Bulk and rejected due to quota pressure"
    );
}

// end of tests
