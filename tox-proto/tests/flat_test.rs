use tox_proto::{ToxProto, deserialize, serialize};

#[test]
fn test_transparent_u32_wrapper() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct MyInt(u32);

    let val = MyInt(0x12345678);
    let encoded = serialize(&val).expect("Serialization failed");

    // Rule 1: Transparent Wrapping
    // Expected: [u32 marker] [bytes]
    assert_eq!(encoded.len(), 5);
    assert_eq!(encoded[0], 0xce);
    assert_eq!(&encoded[1..], &[0x12, 0x34, 0x56, 0x78]);

    let decoded: MyInt = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_all_bytes_flat_struct() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct AllBytes {
        a: [u8; 2],
        b: u8,
        c: [u8; 3],
    }

    let val = AllBytes {
        a: [0x11, 0x22],
        b: 0xAA,
        c: [1, 2, 3],
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // Rule 2: Binary Concatenation
    // Expected format: [bin8] [len=6] [0x11, 0x22, 0xAA, 0x01, 0x02, 0x03]
    assert_eq!(encoded.len(), 1 + 1 + 6);
    assert_eq!(encoded[0], 0xc4); // bin8
    assert_eq!(encoded[1], 6); // length
    assert_eq!(&encoded[2..], &[0x11, 0x22, 0xAA, 1, 2, 3]);

    let decoded: AllBytes = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_flat_fallback_to_array() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct Mixed {
        a: u32,
        b: u32,
    }

    let val = Mixed { a: 1, b: 2 };
    let encoded = serialize(&val).expect("Serialization failed");

    // Rule 4: Default Fallback (not all byte-like)
    // Expected: [fixarray(2)] [1] [2]
    assert_eq!(encoded.len(), 3);
    assert_eq!(encoded[0], 0x92);
    assert_eq!(encoded[1], 0x01);
    assert_eq!(encoded[2], 0x02);

    let decoded: Mixed = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_nested_flat_byte_struct() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct Inner([u8; 2]);

    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct Outer {
        inner: Inner,
        b: u8,
    }

    let val = Outer {
        inner: Inner([0x11, 0x22]),
        b: 0x33,
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // Inner is byte-like, Outer is byte-like.
    // Expected: [bin8] [len=3] [0x11, 0x22, 0x33]
    assert_eq!(encoded.len(), 1 + 1 + 3);
    assert_eq!(encoded[0], 0xc4);
    assert_eq!(encoded[1], 3);
    assert_eq!(&encoded[2..], &[0x11, 0x22, 0x33]);

    let decoded: Outer = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_flat_struct_with_trailing_vec() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct TrailingVec {
        id: [u8; 2],
        data: Vec<u8>,
    }

    let val = TrailingVec {
        id: [0xAB, 0xCD],
        data: vec![1, 2, 3, 4, 5],
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // Rule 3: Trailing Dynamic Data
    // Expected: [bin8] [len=7] [0xAB, 0xCD, 1, 2, 3, 4, 5]
    assert_eq!(encoded.len(), 1 + 1 + 7);
    assert_eq!(encoded[0], 0xc4);
    assert_eq!(encoded[1], 7);
    assert_eq!(&encoded[2..], &[0xAB, 0xCD, 1, 2, 3, 4, 5]);

    let decoded: TrailingVec = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_flat_struct_inside_normal_struct() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct FlatPart {
        a: [u8; 2],
        b: [u8; 2],
    }

    #[derive(Debug, PartialEq, ToxProto)]
    struct NormalStruct {
        header: u8,
        flat: FlatPart,
        footer: u8,
    }

    let val = NormalStruct {
        header: 1,
        flat: FlatPart {
            a: [0x11, 0x11],
            b: [0x22, 0x22],
        },
        footer: 2,
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // NormalStruct: [fixarray(3)] [header] [bin8(4) + payload] [footer]
    assert_eq!(encoded.len(), 1 + 1 + (1 + 1 + 4) + 1);
    assert_eq!(encoded[0], 0x93); // fixarray(3)
    assert_eq!(encoded[1], 0x01); // header
    assert_eq!(encoded[2], 0xc4); // bin8
    assert_eq!(encoded[3], 4); // flat len
    assert_eq!(&encoded[4..8], &[0x11, 0x11, 0x22, 0x22]);
    assert_eq!(encoded[8], 0x02); // footer

    let decoded: NormalStruct = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_flat_struct_with_trailing_string() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct StringMsg {
        id: u8,
        name: String,
    }

    let val = StringMsg {
        id: 42,
        name: "Tox".to_string(),
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // Rule 3: Trailing Dynamic Data
    // [bin8] [len=1+3=4] [42, 'T', 'o', 'x']
    assert_eq!(encoded.len(), 1 + 1 + 4);
    assert_eq!(encoded[0], 0xc4);
    assert_eq!(encoded[1], 4);
    assert_eq!(encoded[2], 42);
    assert_eq!(&encoded[3..], b"Tox");

    let decoded: StringMsg = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(val, decoded);
}

#[test]
fn test_skip_attribute() {
    #[derive(Debug, PartialEq, ToxProto)]
    struct SkippedFields {
        a: u32,
        #[tox(skip)]
        b: String,
        c: u8,
    }

    let val = SkippedFields {
        a: 100,
        b: "this will be skipped".to_string(),
        c: 200,
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // Encoded as array of 2 elements: [a, c]
    // 0x92 0x64 0xcc 0xc8
    assert_eq!(encoded.len(), 1 + 1 + 2);
    assert_eq!(encoded[0], 0x92); // fixarray(2)
    assert_eq!(encoded[1], 100); // a
    assert_eq!(encoded[2], 0xcc); // u8 marker
    assert_eq!(encoded[3], 200); // c

    let decoded: SkippedFields = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(decoded.a, 100);
    assert_eq!(decoded.b, ""); // Default::default()
    assert_eq!(decoded.c, 200);
}

#[test]
fn test_skip_in_flat_struct() {
    #[derive(Debug, PartialEq, ToxProto)]
    #[tox(flat)]
    struct FlatSkipped {
        a: u8,
        #[tox(skip)]
        b: [u8; 32],
        c: u8,
    }

    let val = FlatSkipped {
        a: 1,
        b: [2; 32],
        c: 3,
    };

    let encoded = serialize(&val).expect("Serialization failed");

    // Encoded as bin(2): [1, 3]
    // 0xc4 0x02 0x01 0x03
    assert_eq!(encoded.len(), 4);
    assert_eq!(encoded[0], 0xc4);
    assert_eq!(encoded[1], 2);
    assert_eq!(encoded[2], 1);
    assert_eq!(encoded[3], 3);

    let decoded: FlatSkipped = deserialize(&encoded).expect("Deserialization failed");
    assert_eq!(decoded.a, 1);
    assert_eq!(decoded.b, [0; 32]);
    assert_eq!(decoded.c, 3);
}

// end of file
