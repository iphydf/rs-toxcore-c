use tox_proto::{ToxProto, deserialize, serialize};

#[derive(Debug, PartialEq, ToxProto)]
struct V1 {
    a: u32,
    b: String,
}

#[derive(Debug, PartialEq, ToxProto)]
struct V2 {
    a: u32,
    b: String,
    c: u64, // New field
}

#[derive(Debug, PartialEq, ToxProto)]
struct V3 {
    a: u32,
    b: String,
    c: u64,
    d: Vec<u8>, // Another new field
}

#[test]
fn test_forward_compatibility() {
    // V2 is newer than V1. V1 should be able to read V2 and ignore field 'c'.
    let v2 = V2 {
        a: 42,
        b: "hello".to_string(),
        c: 1337,
    };
    let encoded = serialize(&v2).expect("Failed to serialize V2");

    let v1: V1 = deserialize(&encoded).expect("V1 failed to deserialize V2");
    assert_eq!(v1.a, 42);
    assert_eq!(v1.b, "hello");

    // V3 is even newer. V1 should ignore 'c' and 'd'.
    let v3 = V3 {
        a: 100,
        b: "compat".to_string(),
        c: 999,
        d: vec![1, 2, 3, 4],
    };
    let encoded_v3 = serialize(&v3).expect("Failed to serialize V3");
    let v1_from_v3: V1 = deserialize(&encoded_v3).expect("V1 failed to deserialize V3");
    assert_eq!(v1_from_v3.a, 100);
    assert_eq!(v1_from_v3.b, "compat");
}

#[test]
fn test_size_efficiency_primitives() {
    // Small integers should be 1 byte in MessagePack (fixnum)
    let val: u8 = 42;
    let encoded = serialize(&val).unwrap();
    assert_eq!(encoded.len(), 1, "Small u8 should be 1 byte");

    let val: u64 = 42;
    let encoded = serialize(&val).unwrap();
    assert_eq!(encoded.len(), 1, "Small u64 should be 1 byte (fixnum)");

    // Larger integers
    let val: u32 = 1000;
    let encoded = serialize(&val).unwrap();
    assert_eq!(
        encoded.len(),
        3,
        "u32(1000) should be 3 bytes (marker + 2 bytes)"
    );

    // Boolean
    let val = true;
    let encoded = serialize(&val).unwrap();
    assert_eq!(encoded.len(), 1, "bool should be 1 byte");
}

#[test]
fn test_size_efficiency_byte_specialization() {
    // [u8; 32] should be 1 (marker) + 1 (len) + 32 = 34 bytes
    // If it were an array, it would be 1 (marker) + 32 * (1 byte per u8) = 33+ bytes,
    // but u8 is often 1 byte, so it might be similar, but bin is more robust.
    // For values > 127, array would be 2 bytes per element.

    let data = [255u8; 32];
    let encoded = serialize(&data).unwrap();
    // MessagePack bin8: 0xc4, len, data...
    assert_eq!(
        encoded.len(),
        34,
        "Fixed array [u8; 32] should use bin8 encoding (34 bytes)"
    );

    let vec_data = vec![255u8; 100];
    let encoded_vec = serialize(&vec_data).unwrap();
    assert_eq!(
        encoded_vec.len(),
        102,
        "Vec<u8> of 100 should be 102 bytes (bin8)"
    );
}

#[test]
fn test_struct_overhead() {
    #[derive(ToxProto)]
    struct Empty;

    let encoded = serialize(&Empty).unwrap();
    assert_eq!(
        encoded.len(),
        1,
        "Empty struct should be 1 byte (fixarray of 0)"
    );

    #[derive(ToxProto)]
    struct OneField {
        a: u8,
    }
    let encoded = serialize(&OneField { a: 42 }).unwrap();
    assert_eq!(
        encoded.len(),
        2,
        "One field struct should be 2 bytes (fixarray of 1 + fixnum)"
    );
}

#[test]
fn test_deep_nesting_efficiency() {
    #[derive(Debug, PartialEq, ToxProto)]
    enum Linked {
        Node(u32, Box<Linked>),
        Nil,
    }

    let mut list = Linked::Nil;
    for i in 0..50 {
        list = Linked::Node(i, Box::new(list));
    }

    let encoded = serialize(&list).expect("Failed to serialize deep list");
    // Each node: fixarray(2) [tag, fixarray(2) [u32, next]]
    // u32 (0..49) are 1 byte.
    // Outer fixarray(2) is 1 byte.
    // Inner fixarray(2) is 1 byte.
    // tag is 1 byte.
    // Total per node: 4 bytes.
    // 50 nodes * 4 = 200. Plus Nil (1 byte).
    assert_eq!(
        encoded.len(),
        201,
        "Deeply nested list should be exactly 201 bytes"
    );

    let decoded: Linked = deserialize(&encoded).expect("Failed to deserialize deep list");
    assert_eq!(list, decoded);
}

#[test]
fn test_enum_variant_efficiency() {
    #[derive(ToxProto)]
    enum ManyVariants {
        V0,
        V1,
        V2,
        V3,
        V4,
        V5,
        V6,
        V7,
        V8,
        V9,
    }

    let encoded = serialize(&ManyVariants::V9).unwrap();
    // Naked discriminator (fixnum)
    assert_eq!(
        encoded.len(),
        1,
        "Unit enum variant should be 1 byte (optimized)"
    );
}

#[test]
fn test_complex_skipping() {
    #[derive(ToxProto)]
    struct Large {
        a: u32,
        ignored_map: std::collections::HashMap<String, Vec<u32>>,
        ignored_nested: V3,
        b: String,
    }

    #[derive(ToxProto)]
    struct Small {
        a: u32,
    }

    let mut map = std::collections::HashMap::new();
    map.insert("key".to_string(), vec![1, 2, 3, 4, 5]);

    let large = Large {
        a: 42,
        ignored_map: map,
        ignored_nested: V3 {
            a: 1,
            b: "inner".to_string(),
            c: 2,
            d: vec![0; 100],
        },
        b: "end".to_string(),
    };

    let encoded = serialize(&large).unwrap();

    // Small should be able to read Large because it just sees an array and takes the first element.
    let small: Small = deserialize(&encoded).expect("Small failed to deserialize Large");
    assert_eq!(small.a, 42);
}

#[test]
fn test_very_deep_nesting() {
    #[derive(Debug, PartialEq, ToxProto)]
    enum Tree {
        Branch(Vec<Tree>),
        Leaf(u32),
    }

    fn make_deep(depth: u32) -> Tree {
        if depth == 0 {
            Tree::Leaf(42)
        } else {
            Tree::Branch(vec![make_deep(depth - 1)])
        }
    }

    let deep = make_deep(100);
    let encoded = serialize(&deep).unwrap();
    let decoded: Tree = deserialize(&encoded).unwrap();
    assert_eq!(deep, decoded);

    #[derive(ToxProto)]
    struct Skipper {
        // Just skip it
    }
    // Struct with 0 fields will read array len and skip everything.
    let _: Skipper = deserialize(&encoded).unwrap();
}

#[test]
fn test_collection_efficiency() {
    let mut map = std::collections::HashMap::new();
    for i in 0..10 {
        map.insert(i, i * 10);
    }
    let encoded = serialize(&map).unwrap();
    // Map marker (1) + 10 * (key(1) + val(1)) = 21 bytes.
    assert!(encoded.len() <= 21);

    let mut set = std::collections::HashSet::new();
    for i in 0..10 {
        set.insert(i);
    }
    let encoded_set = serialize(&set).unwrap();
    // Array marker (1) + 10 * (val(1)) = 11 bytes.
    assert!(encoded_set.len() <= 11);
}

#[test]
fn test_ext_type_skipping() {
    // FixExt1 (0xd4), type 0x01, data 0x42
    let mut data1 = Vec::new();
    tox_proto::rmp::encode::write_array_len(&mut data1, 2).unwrap();
    tox_proto::rmp::encode::write_uint(&mut data1, 123).unwrap();
    data1.extend_from_slice(&[0xd4, 0x01, 0x42]);

    #[derive(ToxProto)]
    struct OnlyOne {
        a: u32,
    }
    let decoded: OnlyOne = deserialize(&data1).expect("Failed to skip FixExt1");
    assert_eq!(decoded.a, 123);

    // Ext8 (0xc7), len 10, type 0x02, data [0; 10]
    let mut data2 = Vec::new();
    tox_proto::rmp::encode::write_array_len(&mut data2, 2).unwrap();
    tox_proto::rmp::encode::write_uint(&mut data2, 456).unwrap();
    data2.extend_from_slice(&[0xc7, 10, 0x02]);
    data2.extend_from_slice(&[0; 10]);
    let decoded2: OnlyOne = deserialize(&data2).expect("Failed to skip Ext8");
    assert_eq!(decoded2.a, 456);

    // Ext16 (0xc8), len 300, type 0x03, data [0; 300]
    let mut data3 = Vec::new();
    tox_proto::rmp::encode::write_array_len(&mut data3, 2).unwrap();
    tox_proto::rmp::encode::write_uint(&mut data3, 789).unwrap();
    data3.push(0xc8);
    data3.extend_from_slice(&(300u16).to_be_bytes());
    data3.push(0x03);
    data3.extend_from_slice(&[0; 300]);
    let decoded3: OnlyOne = deserialize(&data3).expect("Failed to skip Ext16");
    assert_eq!(decoded3.a, 789);
}
