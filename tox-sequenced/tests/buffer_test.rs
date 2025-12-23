use tox_sequenced::protocol::{FragmentCount, FragmentIndex};
use tox_sequenced::reassembly::buffer::FragmentBuffer;

#[test]
fn test_fragment_buffer_single() {
    let mut fb = FragmentBuffer::new(FragmentCount(1));
    assert!(!fb.is_complete());
    assert!(
        fb.add_fragment(FragmentIndex(0), b"hello".to_vec())
            .unwrap()
    );
    assert!(fb.is_complete());
    assert_eq!(fb.assemble().unwrap(), b"hello");
}

#[test]
fn test_fragment_buffer_multi_ordered() {
    let mut fb = FragmentBuffer::new(FragmentCount(3));
    assert!(!fb.add_fragment(FragmentIndex(0), b"AAA".to_vec()).unwrap());
    assert!(!fb.add_fragment(FragmentIndex(1), b"BBB".to_vec()).unwrap());
    assert!(fb.add_fragment(FragmentIndex(2), b"C".to_vec()).unwrap());
    assert!(fb.is_complete());
    assert_eq!(fb.assemble().unwrap(), b"AAABBBC");
}

#[test]
fn test_fragment_buffer_multi_unordered() {
    let mut fb = FragmentBuffer::new(FragmentCount(3));
    assert!(!fb.add_fragment(FragmentIndex(2), b"C".to_vec()).unwrap());
    assert!(!fb.add_fragment(FragmentIndex(0), b"AAA".to_vec()).unwrap());
    assert!(fb.add_fragment(FragmentIndex(1), b"BBB".to_vec()).unwrap());
    assert!(fb.is_complete());
    assert_eq!(fb.assemble().unwrap(), b"AAABBBC");
}

#[test]
fn test_fragment_buffer_inconsistent_size_allowed() {
    let mut fb = FragmentBuffer::new(FragmentCount(3));
    fb.add_fragment(FragmentIndex(0), b"AAA".to_vec()).unwrap();
    // Inconsistent size is now allowed!
    let res = fb.add_fragment(FragmentIndex(1), b"BB".to_vec());
    assert!(res.is_ok());
    assert!(!fb.is_complete());
    fb.add_fragment(FragmentIndex(2), b"C".to_vec()).unwrap();
    assert_eq!(fb.assemble().unwrap(), b"AAABBC");
}

#[test]
fn test_fragment_buffer_out_of_bounds() {
    let mut fb = FragmentBuffer::new(FragmentCount(2));
    let res = fb.add_fragment(FragmentIndex(2), b"C".to_vec());
    assert!(res.is_err());
}

#[test]
fn test_fragment_buffer_duplicate() {
    let mut fb = FragmentBuffer::new(FragmentCount(2));
    assert!(!fb.add_fragment(FragmentIndex(0), b"AAA".to_vec()).unwrap());
    assert!(!fb.add_fragment(FragmentIndex(0), b"AAA".to_vec()).unwrap());
    assert_eq!(fb.received_count(), FragmentCount(1));
}

#[test]
fn test_fragment_buffer_variable_size_fragments() {
    let mut fb = FragmentBuffer::new(FragmentCount(3));
    fb.add_fragment(FragmentIndex(0), b"AAAAA".to_vec())
        .expect("First fragment should set the size");
    fb.add_fragment(FragmentIndex(1), b"BBB".to_vec())
        .expect("Should accept smaller fragment");
    fb.add_fragment(FragmentIndex(2), b"C".to_vec())
        .expect("Should accept last fragment");
    assert!(fb.is_complete());
    assert_eq!(fb.assemble().unwrap(), b"AAAAABBBC");
}

#[test]
fn test_fragment_buffer_out_of_order_accounting() {
    let mut fb = FragmentBuffer::new(FragmentCount(10));
    // Receive fragment 9 (last) first. Size 100.
    fb.add_fragment(FragmentIndex(9), vec![0u8; 100]).unwrap();

    // current_size should be 100.
    // With overhead (56 bytes), total is 156.
    assert_eq!(fb.total_allocated_size(), 156);

    // Receive fragment 0. Size 1000.
    fb.add_fragment(FragmentIndex(0), vec![0u8; 1000]).unwrap();

    // current_size should be 1100 + 56 (overhead) = 1156.
    // Wait, total_allocated_size includes overhead for RECEIVED fragments.
    // 2 fragments received. Overhead = 2 * 56 = 112.
    // 1100 + 112 = 1212.
    assert_eq!(fb.total_allocated_size(), 1212);

    // planned_total_size should estimate the remaining 8 fragments.
    // Last size = 100, Full size = 1000.
    // Total Payload = (10 - 1) * 1000 + 100 = 9100.
    // Total Overhead = 10 * 56 = 560.
    // Total Planned = 9660.
    assert_eq!(fb.planned_total_size(), 9660);
}

#[test]
fn test_fragment_buffer_serialization_cycle() {
    let mut fb = FragmentBuffer::new(FragmentCount(5));
    fb.add_fragment(FragmentIndex(0), b"start".to_vec())
        .unwrap();
    fb.add_fragment(FragmentIndex(4), b"end".to_vec()).unwrap();

    // Serialize using ToxProto
    let serialized = tox_proto::serialize(&fb).unwrap();

    // Deserialize back
    let mut reloaded: FragmentBuffer = tox_proto::deserialize(&serialized).unwrap();

    assert_eq!(reloaded.received_count(), FragmentCount(2));
    assert!(reloaded.received_mask().get(0));
    assert!(reloaded.received_mask().get(4));

    // Add remaining fragments to reloaded buffer
    reloaded
        .add_fragment(FragmentIndex(1), b"-".to_vec())
        .unwrap();
    reloaded
        .add_fragment(FragmentIndex(2), b"mid".to_vec())
        .unwrap();
    reloaded
        .add_fragment(FragmentIndex(3), b"-".to_vec())
        .unwrap();

    assert!(reloaded.is_complete());
    assert_eq!(reloaded.assemble().unwrap(), b"start-mid-end");
}

#[test]
fn test_fragment_buffer_empty_fragments() {
    let mut fb = FragmentBuffer::new(FragmentCount(3));
    fb.add_fragment(FragmentIndex(0), b"A".to_vec()).unwrap();
    fb.add_fragment(FragmentIndex(1), b"".to_vec()).unwrap(); // Empty middle
    fb.add_fragment(FragmentIndex(2), b"C".to_vec()).unwrap();

    assert!(fb.is_complete());
    assert_eq!(fb.assemble().unwrap(), b"AC");
}

#[test]
fn test_fragment_buffer_max_fragments() {
    let max = 1024;
    let mut fb = FragmentBuffer::new(FragmentCount(max));

    for i in 0..max {
        fb.add_fragment(FragmentIndex(i), b".".to_vec()).unwrap();
    }

    assert!(fb.is_complete());
    assert_eq!(fb.assemble().unwrap().len(), max as usize);
}

// end of tests
