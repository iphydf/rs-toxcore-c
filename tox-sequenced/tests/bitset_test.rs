use tox_sequenced::bitset::BitSet;

#[test]
fn test_basic_set_get_unset() {
    let mut bs = BitSet::<2>::new(); // 128 bits
    assert!(!bs.get(10));
    assert!(bs.set(10));
    assert!(bs.get(10));
    assert!(!bs.set(10)); // Already set
    assert!(bs.unset(10));
    assert!(!bs.get(10));
    assert!(!bs.unset(10)); // Already unset
}

#[test]
fn test_sack_mask() {
    let mut bs = BitSet::<2>::new(); // 128 bits

    // Set some bits
    bs.set(1); // bit 1
    bs.set(2); // bit 2
    bs.set(63); // bit 63
    bs.set(64); // bit 64 (bit 0 of word 1)
    bs.set(65); // bit 65 (bit 1 of word 1)

    // sack_mask(base_index). base_index+1 is start.

    // Case 1: Start at 0. base_index = -1? No usize.
    // base_index 0 -> start 1.
    // Expected: bits 1..65 (64 bits).
    // bit 1 -> mask bit 0.
    // bit 2 -> mask bit 1.
    // ...
    // bit 63 -> mask bit 62.
    // bit 64 -> mask bit 63.
    let mask = bs.sack_mask(0);
    assert_eq!(mask & 1, 1, "Bit 1 should map to mask bit 0");
    assert_eq!(mask & 2, 2, "Bit 2 should map to mask bit 1");
    assert_eq!(
        mask & (1 << 62),
        1 << 62,
        "Bit 63 should map to mask bit 62"
    );
    assert_eq!(
        mask & (1 << 63),
        1 << 63,
        "Bit 64 should map to mask bit 63"
    );

    // Check value explicitly
    // word 0: ...1...110 (bit 63, 2, 1 set)
    // shifted right by 1: ...1...11
    // word 1: ...11 (bit 1, 0 set (indices 65, 64))
    // shifted left by 63: 1000...
    // bit 64 (0 of word 1) moves to 63.
    // bit 65 (1 of word 1) moves to 64 (overflow).

    // So mask bit 63 corresponds to global bit 64.

    // Test aligned read
    // base_index = 63. start = 64.
    // Should get word 1 exactly.
    // word 1 has bits 0 and 1 set (global 64, 65).
    let mask2 = bs.sack_mask(63);
    assert_eq!(mask2, 3);

    // Test cross boundary
    // base_index = 62. start = 63.
    // bit 63 -> mask bit 0.
    // bit 64 -> mask bit 1.
    // bit 65 -> mask bit 2.
    let mask3 = bs.sack_mask(62);
    assert_eq!(mask3 & 1, 1);
    assert_eq!(mask3 & 2, 2);
    assert_eq!(mask3 & 4, 4);
}

#[test]
fn test_last_one() {
    let mut bs = BitSet::<2>::new();
    assert_eq!(bs.last_one(100), None);

    bs.set(10);
    assert_eq!(bs.last_one(100), Some(10));
    assert_eq!(bs.last_one(11), Some(10));
    assert_eq!(bs.last_one(10), None);

    bs.set(70);
    assert_eq!(bs.last_one(100), Some(70));
    assert_eq!(bs.last_one(71), Some(70));
    assert_eq!(bs.last_one(70), Some(10));
}

#[test]
fn test_next_zero() {
    let mut bs = BitSet::<2>::new();
    bs.fill(); // All ones

    assert_eq!(bs.next_zero(0, 128), None);

    bs.unset(10);
    assert_eq!(bs.next_zero(0, 128), Some(10));
    assert_eq!(bs.next_zero(10, 128), Some(10));
    assert_eq!(bs.next_zero(11, 128), None);

    bs.unset(70);
    assert_eq!(bs.next_zero(11, 128), Some(70));

    // Range limit
    assert_eq!(bs.next_zero(0, 5), None); // 10 is > 5

    // Boundary cases
    bs.clear();
    bs.fill();
    bs.unset(63);
    assert_eq!(bs.next_zero(0, 128), Some(63));
    assert_eq!(bs.next_zero(63, 128), Some(63));
    assert_eq!(bs.next_zero(64, 128), None);

    bs.unset(64);
    assert_eq!(bs.next_zero(63, 128), Some(63));
    assert_eq!(bs.next_zero(64, 128), Some(64));
}

#[test]
fn test_first_zero() {
    let mut bs = BitSet::<2>::new();
    assert_eq!(bs.first_zero(128), 0);

    bs.set(0);
    assert_eq!(bs.first_zero(128), 1);

    bs.set(1);
    assert_eq!(bs.first_zero(128), 2);

    bs.fill();
    assert_eq!(bs.first_zero(128), 128);

    bs.unset(63);
    assert_eq!(bs.first_zero(128), 63);

    bs.unset(64);
    assert_eq!(bs.first_zero(128), 63); // 63 is still zero

    bs.set(63);
    assert_eq!(bs.first_zero(128), 64);
}

#[test]
fn test_boundary_conditions() {
    let mut bs = BitSet::<1>::new(); // 64 bits

    assert!(!bs.set(64)); // Out of bounds
    assert!(!bs.get(64));

    bs.set(63);
    assert!(bs.get(63));
    assert_eq!(bs.last_one(64), Some(63));
    assert_eq!(bs.last_one(63), None);

    // next_zero across word boundary
    let mut bs2 = BitSet::<2>::new();
    bs2.fill();
    bs2.unset(63);
    bs2.unset(64);

    assert_eq!(bs2.next_zero(0, 128), Some(63));
    assert_eq!(bs2.next_zero(64, 128), Some(64));
}

#[test]
fn test_sack_mask_bridge() {
    let mut bs = BitSet::<2>::new();
    // Set bits around the 64-bit boundary
    bs.set(63);
    bs.set(64);

    // If base_index is 62, start is 63.
    // mask bit 0 should be bit 63.
    // mask bit 1 should be bit 64.
    let mask = bs.sack_mask(62);
    assert_eq!(mask & 1, 1, "Bit 63 should be at mask bit 0");
    assert_eq!(mask & 2, 2, "Bit 64 should be at mask bit 1");
}

#[test]
fn test_next_zero_boundary() {
    let mut bs = BitSet::<2>::new();
    bs.fill();
    bs.unset(63);
    assert_eq!(bs.next_zero(0, 128), Some(63));
    assert_eq!(bs.next_zero(63, 128), Some(63));
    assert_eq!(bs.next_zero(64, 128), None);

    bs.set(63);
    bs.unset(64);
    assert_eq!(bs.next_zero(0, 128), Some(64));
    assert_eq!(bs.next_zero(64, 128), Some(64));
}

#[test]
fn test_clear_fill() {
    let mut bs = BitSet::<2>::new();
    bs.set(10);
    bs.set(70);

    bs.clear();
    assert!(!bs.get(10));
    assert!(!bs.get(70));
    assert_eq!(bs.first_zero(128), 0);

    bs.fill();
    assert!(bs.get(0));
    assert!(bs.get(127));
    assert_eq!(bs.first_zero(128), 128);
}

#[test]
fn test_last_one_overflow() {
    let mut bs = BitSet::<2>::new();
    bs.set(63);
    // This should not panic. limit=64 means last_idx=63, bit_limit=64.
    assert_eq!(bs.last_one(64), Some(63));
}

// end of tests
