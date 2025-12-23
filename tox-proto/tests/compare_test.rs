use tox_proto::ToxProto;

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum TestEnum {
    A(u32),
    B { x: u64, y: Vec<u8> },
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct TestStruct {
    pub parents: Vec<[u8; 32]>,
    pub author_pk: [u8; 32],
    pub sequence_number: u64,
    pub content: TestEnum,
    pub metadata: Vec<u8>,
}

#[test]
fn test_serialization_compatibility() {
    let parents = vec![[1u8; 32], [2u8; 32]];
    let author_pk = [3u8; 32];
    let sequence_number = 42;
    let content = TestEnum::B {
        x: 7,
        y: vec![8, 9],
    };
    let metadata = vec![5, 6, 7];

    let s = TestStruct {
        parents: parents.clone(),
        author_pk,
        sequence_number,
        content: content.clone(),
        metadata: metadata.clone(),
    };

    let serialized_macro = tox_proto::serialize(&s).unwrap();

    // Manual tuple-based serialization
    let manual_data = (
        parents.clone(),
        author_pk,
        sequence_number,
        content.clone(),
        metadata.clone(),
    );
    let serialized_manual = tox_proto::serialize(&manual_data).unwrap();

    assert_eq!(serialized_macro, serialized_manual);

    // Test deserialization
    let deserialized: TestStruct = tox_proto::deserialize(&serialized_macro).unwrap();
    assert_eq!(deserialized, s);
}
