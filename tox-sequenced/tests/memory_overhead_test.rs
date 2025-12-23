use rand::SeedableRng;
use std::time::Instant;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId, Packet};
use tox_sequenced::quota::ReassemblyQuota;
use tox_sequenced::session::SequenceSession;

#[test]
fn test_memory_overhead_accounting() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let global_limit = 1024 * 1024; // 1MB Quota
    let quota = ReassemblyQuota::new(global_limit);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp, &mut rng);

    // 1. Send a message with 1000 fragments.
    // 2. Each fragment is 1 byte.
    // 3. This should technically use ~1000 bytes of "payload" memory.
    // 4. But the overhead of storing 1000 fragments (Vec<Option<Vec<u8>>>) plus allocator overhead is high.
    // 5. We want to ensure the quota system accounts for this overhead to prevent DoS.

    // Use 500 fragments.
    // Initial reservation logic assumes 1300 bytes per fragment.
    // 500 * 1300 = 650,000 bytes. This fits in the 1MB (1,048,576) global limit.
    // If we used 1000, 1000 * 1300 = 1.3MB > 1MB, so it would be rejected immediately.
    let total_fragments = 500;

    // Send all but the last fragment to keep it in buffer
    for i in 0..(total_fragments - 1) {
        let p = Packet::Data {
            message_id: MessageId(1),
            fragment_index: FragmentIndex(i),
            total_fragments: FragmentCount(total_fragments),
            data: vec![0u8; 1], // 1 byte
        };
        bob.handle_packet(p, now);
    }

    let used = quota.used();
    println!("Quota Used: {}", used);

    // Real memory usage estimation:
    // 500 * (24 bytes for Vec<u8> struct + 1 byte payload + allocator metadata ~16 bytes) = 41 bytes per frag.
    // 500 * 41 = 20,500 bytes.
    //
    // If the system is vulnerable, 'used' will be ~500 bytes (payload only).
    // We assert that 'used' should reflect the overhead (e.g., > 10,000 bytes).

    assert!(
        used > 10000,
        "Quota usage {} is suspiciously low. It likely ignores fragment memory overhead.",
        used
    );
}
