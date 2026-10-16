use tox_proto::{ToxProto, serialize};

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum EnumWithArrays {
    Small([u8; 4]),
    Large([u8; 32]),
    Mixed { id: u32, data: [u8; 64] },
}

#[test]
fn test_enum_with_arrays_serialization() {
    let small = EnumWithArrays::Small([1, 2, 3, 4]);
    let encoded_small = serialize(&small).expect("Failed to serialize Small");
    assert!(!encoded_small.is_empty());

    let large = EnumWithArrays::Large([0xFF; 32]);
    let encoded_large = serialize(&large).expect("Failed to serialize Large");
    assert!(!encoded_large.is_empty());

    let mixed = EnumWithArrays::Mixed {
        id: 42,
        data: [0xAA; 64],
    };
    let encoded_mixed = serialize(&mixed).expect("Failed to serialize Mixed");
    assert!(!encoded_mixed.is_empty());
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct StructWithArrays {
    pub a: [u8; 32],
    pub b: [u8; 64],
}

#[test]
fn test_struct_with_arrays_serialization() {
    let s = StructWithArrays {
        a: [0x11; 32],
        b: [0x22; 64],
    };
    let encoded = serialize(&s).expect("Failed to serialize struct");
    assert!(!encoded.is_empty());
}
