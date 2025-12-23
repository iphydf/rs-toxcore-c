use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tox_proto::{ToxProto, ToxSerialize, deserialize, serialize};

#[derive(Debug, PartialEq, ToxProto)]
struct TestStruct {
    a: u32,
    b: String,
}

#[derive(Debug, PartialEq, ToxProto)]
enum TestEnum {
    Unit,
    Newtype(u32),
    Tuple(u32, String),
    Struct { x: u32, y: u32 },
}

#[derive(Debug, PartialEq, ToxSerialize)]
struct BorrowedStruct<'a> {
    data: &'a [u8],
}

#[derive(Debug, PartialEq, ToxProto)]
struct BorrowedStructOwned {
    data: Vec<u8>,
}

#[derive(Debug, PartialEq, ToxProto)]
struct AllPrimitives {
    u8_: u8,
    u16_: u16,
    u32_: u32,
    u64_: u64,
    i8_: i8,
    i16_: i16,
    i32_: i32,
    i64_: i64,
    f32_: f32,
    f64_: f64,
    bool_: bool,
    char_: char,
    string_: String,
}

#[derive(Debug, PartialEq, ToxProto)]
struct Nested {
    inner: AllPrimitives,
    opt: Option<u32>,
    res: Result<u32, String>,
}

#[derive(Debug, PartialEq, ToxProto)]
struct Collections {
    vec_: Vec<u32>,
    hash_map: HashMap<String, u32>,
    btree_map: BTreeMap<u32, String>,
    hash_set: HashSet<u32>,
    btree_set: BTreeSet<u32>,
}

#[derive(Debug, PartialEq, ToxProto)]
struct Unit;

#[derive(Debug, PartialEq, ToxProto)]
struct TupleStruct(u32, String);

#[derive(Debug, PartialEq, ToxProto)]
enum GenericEnum<T, E> {
    Success(T),
    Failure(E),
}

#[test]
fn test_struct_serialization() {
    let s = TestStruct {
        a: 42,
        b: "hello".to_string(),
    };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: TestStruct = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(s, decoded);
}

#[test]
fn test_enum_serialization() {
    let e = TestEnum::Unit;
    let encoded = serialize(&e).expect("Failed to serialize unit");
    assert_eq!(deserialize::<TestEnum>(&encoded).unwrap(), e);

    let e = TestEnum::Newtype(42);
    let encoded = serialize(&e).expect("Failed to serialize newtype");
    let decoded: TestEnum = deserialize(&encoded).expect("Failed to deserialize newtype");
    assert_eq!(e, decoded);

    let e = TestEnum::Tuple(42, "hello".to_string());
    let encoded = serialize(&e).expect("Failed to serialize tuple");
    let decoded: TestEnum = deserialize(&encoded).expect("Failed to deserialize tuple");
    assert_eq!(e, decoded);

    let e = TestEnum::Struct { x: 1, y: 2 };
    let encoded = serialize(&e).expect("Failed to serialize struct variant");
    let decoded: TestEnum = deserialize(&encoded).expect("Failed to deserialize struct variant");
    assert_eq!(e, decoded);
}

#[test]
fn test_borrowed_serialization() {
    let data = vec![1, 2, 3];
    let s = BorrowedStruct { data: &data };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: BorrowedStructOwned = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(decoded.data, data);
}

#[test]
fn test_all_primitives() {
    let s = AllPrimitives {
        u8_: u8::MAX,
        u16_: u16::MAX,
        u32_: u32::MAX,
        u64_: u64::MAX,
        i8_: i8::MIN,
        i16_: i16::MIN,
        i32_: i32::MIN,
        i64_: i64::MIN,
        f32_: std::f32::consts::PI,
        f64_: std::f64::consts::E,
        bool_: true,
        char_: 'z',
        string_: "exhaustive".to_string(),
    };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: AllPrimitives = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(s.u8_, decoded.u8_);
    assert_eq!(s.u16_, decoded.u16_);
    assert_eq!(s.u32_, decoded.u32_);
    assert_eq!(s.u64_, decoded.u64_);
    assert_eq!(s.i8_, decoded.i8_);
    assert_eq!(s.i16_, decoded.i16_);
    assert_eq!(s.i32_, decoded.i32_);
    assert_eq!(s.i64_, decoded.i64_);
    assert_eq!(s.bool_, decoded.bool_);
    assert_eq!(s.char_, decoded.char_);
    assert_eq!(s.string_, decoded.string_);
}

#[test]
fn test_nested() {
    let s = Nested {
        inner: AllPrimitives {
            u8_: 1,
            u16_: 2,
            u32_: 3,
            u64_: 4,
            i8_: -1,
            i16_: -2,
            i32_: -3,
            i64_: -4,
            f32_: 1.0,
            f64_: 2.0,
            bool_: false,
            char_: 'a',
            string_: "inner".to_string(),
        },
        opt: Some(42),
        res: Err("error".to_string()),
    };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: Nested = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(s, decoded);
}

#[test]
fn test_collections() {
    let mut hash_map = HashMap::new();
    hash_map.insert("one".to_string(), 1);
    let mut btree_map = BTreeMap::new();
    btree_map.insert(2, "two".to_string());
    let mut hash_set = HashSet::new();
    hash_set.insert(3);
    let mut btree_set = BTreeSet::new();
    btree_set.insert(4);

    let s = Collections {
        vec_: vec![1, 2, 3],
        hash_map,
        btree_map,
        hash_set,
        btree_set,
    };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: Collections = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(s, decoded);
}

#[test]
fn test_special_structs() {
    let s = Unit;
    let encoded = serialize(&s).expect("Failed to serialize unit");
    let _: Unit = deserialize(&encoded).expect("Failed to deserialize unit");

    let s = TupleStruct(42, "tuple".to_string());
    let encoded = serialize(&s).expect("Failed to serialize tuple struct");
    let decoded: TupleStruct = deserialize(&encoded).expect("Failed to deserialize tuple struct");
    assert_eq!(s, decoded);
}

#[test]
fn test_generic_enum() {
    let e: GenericEnum<u32, String> = GenericEnum::Success(42);
    let encoded = serialize(&e).expect("Failed to serialize");
    let decoded: GenericEnum<u32, String> = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(e, decoded);

    let e: GenericEnum<u32, String> = GenericEnum::Failure("oops".to_string());
    let encoded = serialize(&e).expect("Failed to serialize");
    let decoded: GenericEnum<u32, String> = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(e, decoded);
}

#[test]
fn test_large_data() {
    let s = AllPrimitives {
        u8_: 0,
        u16_: 0,
        u32_: 0,
        u64_: 0,
        i8_: 0,
        i16_: 0,
        i32_: 0,
        i64_: 0,
        f32_: 0.0,
        f64_: 0.0,
        bool_: false,
        char_: ' ',
        string_: "a".repeat(10000),
    };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: AllPrimitives = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(s.string_, decoded.string_);
}

#[test]
fn test_array() {
    #[derive(Debug, PartialEq, ToxProto)]
    struct ArrayStruct {
        data: [u8; 32],
    }

    let s = ArrayStruct { data: [42; 32] };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: ArrayStruct = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(s, decoded);
}

#[test]
fn test_option_array() {
    #[derive(Debug, PartialEq, ToxProto)]
    struct OptionArrayStruct {
        data: Option<[u8; 32]>,
    }

    let s = OptionArrayStruct {
        data: Some([255; 32]),
    };
    let encoded = serialize(&s).expect("Failed to serialize Some");
    let decoded: OptionArrayStruct = deserialize(&encoded).expect("Failed to deserialize Some");
    assert_eq!(s, decoded);

    let s2 = OptionArrayStruct { data: None };
    let encoded2 = serialize(&s2).expect("Failed to serialize None");
    let decoded2: OptionArrayStruct = deserialize(&encoded2).expect("Failed to deserialize None");
    assert_eq!(s2, decoded2);
}

#[test]
fn test_reference_serialization() {
    #[derive(ToxSerialize)]
    struct RefStruct<'a> {
        s: &'a str,
        opt_s: Option<&'a str>,
        b: &'a [u8],
        opt_b: Option<&'a [u8]>,
    }

    #[derive(Debug, PartialEq, ToxProto)]
    struct OwnedStruct {
        s: String,
        opt_s: Option<String>,
        b: Vec<u8>,
        opt_b: Option<Vec<u8>>,
    }

    let s = RefStruct {
        s: "hello",
        opt_s: Some("world"),
        b: b"bytes",
        opt_b: Some(b"more bytes"),
    };
    let encoded = serialize(&s).expect("Failed to serialize");
    let decoded: OwnedStruct = deserialize(&encoded).expect("Failed to deserialize");
    assert_eq!(decoded.s, "hello");
    assert_eq!(decoded.opt_s, Some("world".to_string()));
    assert_eq!(decoded.b, b"bytes".to_vec());
    assert_eq!(decoded.opt_b, Some(b"more bytes".to_vec()));
}
