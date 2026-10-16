use std::collections::HashMap;
use tox_proto::{ToxProto, ToxSerialize, deserialize, serialize};

#[derive(Debug, PartialEq, ToxSerialize)]
struct AuthData<'a> {
    parents: &'a Vec<[u8; 32]>,
    author_pk: &'a [u8; 32],
    sender_pk: &'a [u8; 32],
    sequence_number: u64,
    content: &'a TestContent,
    metadata: &'a [u8],
}

#[derive(Debug, PartialEq, ToxProto)]
enum TestContent {
    Text(String),
    Data(Vec<u8>),
    Nested { id: u32, payload: Vec<u8> },
}

#[test]
fn test_complex_references() {
    let parents = vec![[1u8; 32], [2u8; 32]];
    let author_pk = [3u8; 32];
    let sender_pk = [4u8; 32];
    let content = TestContent::Nested {
        id: 42,
        payload: vec![0xAA, 0xBB],
    };
    let metadata = [0xCC, 0xDD];

    let auth = AuthData {
        parents: &parents,
        author_pk: &author_pk,
        sender_pk: &sender_pk,
        sequence_number: 100,
        content: &content,
        metadata: &metadata,
    };

    let encoded = serialize(&auth).expect("Failed to serialize");

    // We deserialize into an owned version because AuthData has references that cannot be borrowed
    // from a Read stream (like &Vec).
    let decoded: AuthDataOwned = deserialize(&encoded).expect("Failed to deserialize");

    assert_eq!(decoded.parents, parents);
    assert_eq!(decoded.author_pk, author_pk);
    assert_eq!(decoded.sender_pk, sender_pk);
    assert_eq!(decoded.sequence_number, 100);
    assert_eq!(decoded.metadata, metadata.to_vec());
}

#[derive(Debug, PartialEq, ToxProto)]
struct AuthDataOwned {
    parents: Vec<[u8; 32]>,
    author_pk: [u8; 32],
    sender_pk: [u8; 32],
    sequence_number: u64,
    content: TestContent,
    metadata: Vec<u8>,
}

#[derive(Debug, PartialEq, ToxProto)]
struct DeeplyNested {
    map: HashMap<u32, Vec<String>>,
    opt_nested: Option<Box<DeeplyNested>>,
}

#[test]
fn test_recursion_and_collections() {
    let mut map = HashMap::new();
    map.insert(1, vec!["hello".to_string(), "world".to_string()]);

    let nested = DeeplyNested {
        map,
        opt_nested: Some(Box::new(DeeplyNested {
            map: HashMap::new(),
            opt_nested: None,
        })),
    };

    let encoded = serialize(&nested).unwrap();
    let decoded: DeeplyNested = deserialize(&encoded).unwrap();
    assert_eq!(nested, decoded);
}

#[derive(Debug, PartialEq, ToxSerialize)]
enum ComplexEnum<'a> {
    A(&'a [u8]),
    B { name: &'a str, age: u8 },
    C(Option<&'a [u8]>),
}

#[derive(Debug, PartialEq, ToxProto)]
enum ComplexEnumOwned {
    A(Vec<u8>),
    B { name: String, age: u8 },
    C(Option<Vec<u8>>),
}

#[test]
fn test_enum_references_serialization() {
    let data = [1u8, 2, 3];
    let e = ComplexEnum::A(&data);
    let encoded = serialize(&e).unwrap();
    let decoded: ComplexEnumOwned = deserialize(&encoded).unwrap();
    if let ComplexEnumOwned::A(v) = decoded {
        assert_eq!(v, data);
    } else {
        panic!("Wrong variant");
    }

    let e = ComplexEnum::B {
        name: "Alice",
        age: 30,
    };
    let encoded = serialize(&e).unwrap();
    let decoded: ComplexEnumOwned = deserialize(&encoded).unwrap();
    if let ComplexEnumOwned::B { name, age } = decoded {
        assert_eq!(name, "Alice");
        assert_eq!(age, 30);
    } else {
        panic!("Wrong variant");
    }

    let pk = [0xFFu8; 32];
    let e = ComplexEnum::C(Some(&pk));
    let encoded = serialize(&e).unwrap();
    let decoded: ComplexEnumOwned = deserialize(&encoded).unwrap();
    if let ComplexEnumOwned::C(v) = decoded {
        assert_eq!(v.unwrap(), pk);
    } else {
        panic!("Wrong variant");
    }
}
