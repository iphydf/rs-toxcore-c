use rand::SeedableRng;
use std::time::Instant;
use tox_sequenced::{
    MessageReassembler, SequenceSession,
    protocol::{FragmentCount, FragmentIndex, MAX_FRAGMENTS_PER_MESSAGE, MessageId, Packet},
    quota::{Priority, ReassemblyQuota},
};

#[test]
fn test_max_fragments_enforcement() {
    let now = Instant::now();
    // Try to create a reassembler with too many fragments
    let res = MessageReassembler::new(
        MessageId(1),
        FragmentCount(MAX_FRAGMENTS_PER_MESSAGE + 1),
        Priority::Standard,
        0,
        now,
    );
    assert!(
        res.is_err(),
        "Should reject messages exceeding MAX_FRAGMENTS_PER_MESSAGE"
    );
}

#[test]
fn test_amplification_attack_via_fragment_count() {
    // Attack: Send a packet with small data but huge total_fragments.
    // If the system reserves memory based on total_fragments * MTU,
    // a small packet causes huge reservation.
    // The cap MAX_FRAGMENTS_PER_MESSAGE (1024) limits this to ~1.3MB per message.

    let quota_limit = 10 * 1024 * 1024; // 10MB
    let quota = ReassemblyQuota::new(quota_limit);
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp, &mut rng);

    // Max fragments = 1024.
    // Est payload = 1300.
    // Total reservation ≈ 1.33 MB.

    let p_small = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(MAX_FRAGMENTS_PER_MESSAGE),
        data: vec![0u8; 10], // Small payload
    };

    bob.handle_packet(p_small, now);

    let used_after_small = quota.used();
    // Optimistic allocation: should shrink to ~10KB (10 * 1024)
    // BUT we now account for overhead (1024 * 56 = 57KB).
    // So usage should be ~67KB.
    // The previous vulnerability was that it ignored overhead.
    assert!(
        used_after_small > 50_000,
        "Should reserve overhead for all fragments: {}",
        used_after_small
    );

    // "Bait and Switch" Attack: Now send a full-sized fragment.
    // The system MUST increase reservation.
    let p_large = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(1),
        total_fragments: FragmentCount(MAX_FRAGMENTS_PER_MESSAGE),
        data: vec![0u8; 1300], // Full payload
    };

    bob.handle_packet(p_large, now);

    let used_after_large = quota.used();
    // Should now be based on 1300 bytes: ~1.33 MB.
    assert!(
        used_after_large > 1_000_000,
        "Should expand reservation on large fragment: {}",
        used_after_large
    );
}

#[test]
fn test_single_session_quota_exhaustion() {
    // Demonstration of "Noisy Neighbor" vulnerability if session limit == global limit.
    let global_limit = 500_000; // 500KB
    let quota = ReassemblyQuota::new(global_limit);
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    // Bob uses the shared quota.
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // Alice is another user sharing the quota
    let mut alice = SequenceSession::with_quota_at(quota.clone(), now, tp, &mut rng);

    // 1. Bob Fills 70% with Bulk (350KB)
    // Use ~50KB messages.
    // With overhead (56 bytes/frag), 38 frags * 1300 = 49,400.
    // Overhead = 38 * 56 = 2,128. Total = 51,528.
    // 6 * 51,528 = 309,168.
    for i in 0..6 {
        let p = Packet::Data {
            message_id: MessageId(i),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(38),
            data: vec![0u8; 1300],
        };
        bob.handle_packet(p, now);
        assert!(
            bob.find_incoming(MessageId(i)).is_some(),
            "Bulk message {} rejected early",
            i
        );
    }

    // 7th Bulk -> 309,168 + 51,528 = 360,696 > 350,000. Rejected.
    let p_bulk_fail = Packet::Data {
        message_id: MessageId(6),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(38),
        data: vec![0u8; 1300],
    };
    bob.handle_packet(p_bulk_fail, now);
    assert!(
        bob.find_incoming(MessageId(6)).is_none(),
        "Bulk limit should be enforced"
    );

    // 2. Bob Fills next 20% with Standard (up to 90% = 450KB)
    // Use ~30KB messages.
    // 22 frags * 1300 = 28,600.
    // Overhead = 22 * 56 = 1,232. Total = 29,832.
    // 4 * 29,832 = 119,328.
    // Total = 309,168 + 119,328 = 428,496.
    for i in 100..104 {
        let p = Packet::Data {
            message_id: MessageId(i),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(22),
            data: vec![0u8; 1300],
        };
        bob.handle_packet(p, now);
        assert!(
            bob.find_incoming(MessageId(i)).is_some(),
            "Standard message {} rejected early",
            i
        );
    }

    // 5th Standard -> 458,328 > 450,000. Rejected.
    let p_std_fail = Packet::Data {
        message_id: MessageId(104),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(22),
        data: vec![0u8; 1300],
    };
    bob.handle_packet(p_std_fail, now);
    assert!(
        bob.find_incoming(MessageId(104)).is_none(),
        "Standard limit should be enforced"
    );

    use tox_sequenced::protocol::{MessageType, OutboundEnvelope, serialize};
    let crit_env = OutboundEnvelope {
        message_type: MessageType::CapsAnnounce,
        payload: &[0u8; 1200],
    };
    let crit_data = serialize(&crit_env).unwrap();

    // 3. Bob Fills next ~9% with Critical (up to 99% = 495KB)
    // Total = 428,496 + 2 * 29,832 = 488,160.
    for i in 200..202 {
        let p = Packet::Data {
            message_id: MessageId(i),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(22),
            data: crit_data.clone(),
        };
        bob.handle_packet(p, now);
        assert!(
            bob.find_incoming(MessageId(i)).is_some(),
            "Critical message {} rejected early",
            i
        );
    }

    // 3rd Critical -> 517,992 > 495,000. Rejected.
    let p_crit_fail = Packet::Data {
        message_id: MessageId(202),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(22),
        data: vec![0u8; 1300],
    };
    bob.handle_packet(p_crit_fail, now);
    assert!(
        bob.find_incoming(MessageId(202)).is_none(),
        "Critical limit should be enforced"
    );

    // 4. Bob tries to fill the last bit
    // Current used: 488,160.

    // Send 7.8KB message (6 fragments * 1300).
    // Overhead = 6 * 56 = 336. Total = 8,136.
    // 488,160 + 8,136 = 496,296 > 495,000.
    // Should be REJECTED.
    let p_fill_1 = Packet::Data {
        message_id: MessageId(300),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(6),
        data: vec![0u8; 1300],
    };
    bob.handle_packet(p_fill_1, now);
    assert!(
        bob.find_incoming(MessageId(300)).is_none(),
        "Bob should be capped at 99% (Critical threshold)"
    );

    assert!(
        quota.used() <= 495_000,
        "Quota used {} too high before Alice",
        quota.used()
    );
    assert!(
        quota.available() >= 1000,
        "Quota available {} too low before Alice",
        quota.available()
    );

    // 5. Alice tries to send a Critical handshake (1 fragment, small data).
    // Alice's buffer is 0. 1300 + 56 = 1356 <= 16KB (Fair Share Guarantee).
    // Fair Share uses reserve_guaranteed (checks against 100% = 500KB).
    // 488,160 + 1356 = 489,516 < 500,000.
    // Should be ACCEPTED.

    let env = OutboundEnvelope {
        message_type: MessageType::CapsAnnounce,
        payload: &[0u8; 50],
    };
    let valid_data = serialize(&env).unwrap();

    let p_alice = Packet::Data {
        message_id: MessageId(999),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: valid_data,
    };

    // Alice generates replies (likely an ACK)
    let _replies = alice.handle_packet(p_alice, now);

    // Message should complete immediately.
    let mut accepted = false;
    while let Some(event) = alice.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, _, _) = event
            && id == MessageId(999)
        {
            accepted = true;
        }
    }

    assert!(
        accepted,
        "Alice should be admitted via Fair Share and complete immediately"
    );

    // 6. Verify Alice cannot send a HUGE message (exceeding Fair Share)
    // Send 52KB Bulk message.
    let p_alice_huge = Packet::Data {
        message_id: MessageId(1000),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(38), // ~51KB
        data: vec![0u8; 1300],
    };
    alice.handle_packet(p_alice_huge, now);
    assert!(
        alice.find_incoming(MessageId(1000)).is_none(),
        "Alice huge message should be rejected (not in incoming)"
    );

    // Also verify no event
    let mut huge_accepted = false;
    while let Some(event) = alice.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, _, _) = event
            && id == MessageId(1000)
        {
            huge_accepted = true;
        }
    }
    assert!(!huge_accepted, "Alice huge message should NOT complete");
}
