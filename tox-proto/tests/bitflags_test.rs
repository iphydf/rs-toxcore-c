use bitflags::bitflags;
use tox_proto::{ToxProto, deserialize, serialize};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ToxProto)]
    #[tox(bits = "u32")]
    pub struct TestFlags: u32 {
        const A = 0x01;
        const B = 0x02;
        const C = 0x04;
    }
}

#[test]
fn test_bitflags_serialization() {
    let flags = TestFlags::A | TestFlags::C;
    let serialized = serialize(&flags).expect("Failed to serialize");
    let deserialized: TestFlags = deserialize(&serialized).expect("Failed to deserialize");
    assert_eq!(flags, deserialized);
    assert_eq!(deserialized.bits(), 0x05);
}

#[test]
fn test_bitflags_unknown_bits() {
    let raw_bits: u32 = 0x08 | 0x01; // 0x01 (A) + 0x08 (unknown)
    let serialized = serialize(&raw_bits).expect("Failed to serialize raw bits");
    let deserialized: TestFlags = deserialize(&serialized).expect("Failed to deserialize");
    assert_eq!(deserialized.bits(), 0x09);
    assert!(deserialized.contains(TestFlags::A));
}
