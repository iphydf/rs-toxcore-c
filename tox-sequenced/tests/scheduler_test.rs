use std::collections::HashMap;
use tox_sequenced::scheduler::PriorityScheduler;

#[test]
fn test_scheduler_prioritization_behavior() {
    let mut scheduler = PriorityScheduler::new();

    // Message 0 is Critical (P0)
    // Message 4 is Bulk (P4)
    scheduler.update_message(0, 0);
    scheduler.update_message(4, 4);

    let mut counts = HashMap::new();

    // Simulate sending 100 packets of equal size (1000 bytes)
    for _ in 0..100 {
        if let Some(id) = scheduler.next_message(|_| Some(1000)) {
            *counts.entry(id).or_insert(0) += 1;
        }
    }

    let p0_count = counts.get(&0).copied().unwrap_or(0);
    let p4_count = counts.get(&4).copied().unwrap_or(0);
    println!("P0 count: {}, P4 count: {}", p0_count, p4_count);

    // Behavior: P0 should have significantly more packets than P4
    // Default weights are 4096 vs 512 (8:1 ratio)
    assert!(
        p0_count > p4_count * 5,
        "P0 should be served much more than P4"
    );
    assert!(p4_count > 0, "P4 should not be completely starved");
}

#[test]
fn test_scheduler_fairness_within_level() {
    let mut scheduler = PriorityScheduler::new();

    // Three messages at the same priority level
    scheduler.update_message(1, 2);
    scheduler.update_message(2, 2);
    scheduler.update_message(3, 2);

    let mut sequence = Vec::new();
    for _ in 0..6 {
        if let Some(id) = scheduler.next_message(|_| Some(100)) {
            sequence.push(id);
        }
    }

    // Should be round-robin: 1, 2, 3, 1, 2, 3
    assert_eq!(sequence, vec![1, 2, 3, 1, 2, 3]);
}

#[test]
fn test_scheduler_ready_logic() {
    let mut scheduler = PriorityScheduler::new();

    scheduler.update_message(1, 0);
    scheduler.update_message(2, 0);

    // Message 1 is NOT ready, Message 2 IS ready
    let first = scheduler.next_message(|id| if id == 2 { Some(100) } else { None });
    assert_eq!(first, Some(2));

    // Now Message 1 becomes ready
    let second = scheduler.next_message(|id| if id == 1 { Some(100) } else { None });
    assert_eq!(second, Some(1));
}

#[test]
fn test_scheduler_removal() {
    let mut scheduler = PriorityScheduler::new();

    scheduler.update_message(1, 0);
    assert_eq!(scheduler.next_message(|_| Some(100)), Some(1));

    scheduler.remove_message(1);
    assert_eq!(scheduler.next_message(|_| Some(100)), None);
}

#[test]
fn test_scheduler_empty_behavior() {
    let mut scheduler = PriorityScheduler::new();
    assert_eq!(scheduler.next_message(|_| Some(100)), None);
}

#[test]
fn test_scheduler_large_packet_deficit() {
    let mut scheduler = PriorityScheduler::new();

    // P4 has quantum 512
    scheduler.update_message(4, 4);

    // Try to send a 1000 byte packet.
    // First call: deficit 512, packet 1000 -> too big.
    // But DRR should eventually accumulate enough deficit.
    // In our implementation, we add quantum if deficit <= 0.

    // Try multiple rounds
    let mut found = false;
    for _ in 0..10 {
        if scheduler.next_message(|_| Some(1000)).is_some() {
            found = true;
            break;
        }
    }

    assert!(
        found,
        "Should eventually accumulate enough deficit for large packets"
    );
}
