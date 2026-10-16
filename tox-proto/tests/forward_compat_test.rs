use tox_proto::{ToxProto, deserialize, serialize};

/// "Old" enum that doesn't know about variant C.
#[derive(Debug, PartialEq, ToxProto)]
enum EnumV1 {
    A,
    B(u32),
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// "New" enum with an additional variant C at discriminant 2.
#[derive(Debug, PartialEq, ToxProto)]
enum EnumV2 {
    A,
    B(u32),
    C(String),
}

#[test]
fn test_unknown_discriminant_captured() {
    // V2::C has discriminant 2, which V1 doesn't know about (catch_all skips its own idx).
    let v2 = EnumV2::C("hello from the future".to_string());
    let encoded = serialize(&v2).expect("serialize V2::C");

    let v1: EnumV1 = deserialize(&encoded).expect("V1 should capture unknown discriminant");
    match &v1 {
        EnumV1::Unknown { discriminant, data } => {
            assert_eq!(*discriminant, 2, "should capture discriminant 2");
            assert!(!data.is_empty(), "should have payload data");
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }
}

#[test]
fn test_unknown_unit_variant() {
    // Simulate a unit variant from a newer version at discriminant 4.
    #[derive(ToxProto)]
    enum Newer {
        A,
        B,
        _C,
        _D,
        E,
    }

    let encoded = serialize(&Newer::E).expect("serialize unit variant");
    let v1: EnumV1 = deserialize(&encoded).expect("V1 should capture unknown unit variant");
    match &v1 {
        EnumV1::Unknown { discriminant, data } => {
            assert_eq!(*discriminant, 4);
            assert!(data.is_empty(), "unit variant should have empty data");
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }
}

#[test]
fn test_unknown_roundtrip() {
    // Serialize V2::C, deserialize as V1, re-serialize, deserialize as V2 → recover original.
    let original = EnumV2::C("roundtrip payload".to_string());
    let encoded_v2 = serialize(&original).expect("serialize V2::C");

    // Deserialize as V1 (captures into Unknown)
    let v1: EnumV1 = deserialize(&encoded_v2).expect("V1 capture");

    // Re-serialize from V1
    let re_encoded = serialize(&v1).expect("re-serialize V1 Unknown");

    // Byte-level fidelity: the re-encoded bytes must be identical, not just
    // semantically equivalent. This is critical for hash stability.
    assert_eq!(
        re_encoded, encoded_v2,
        "re-serialized bytes must be identical to original"
    );

    // Deserialize back as V2. Should recover the original.
    let recovered: EnumV2 = deserialize(&re_encoded).expect("V2 recovery");
    assert_eq!(recovered, original, "round-trip should preserve the value");
}

#[test]
fn test_known_variants_unaffected() {
    // Unit variant
    let a = EnumV1::A;
    let encoded = serialize(&a).unwrap();
    let decoded: EnumV1 = deserialize(&encoded).unwrap();
    assert_eq!(decoded, EnumV1::A);

    // Payload variant
    let b = EnumV1::B(42);
    let encoded = serialize(&b).unwrap();
    let decoded: EnumV1 = deserialize(&encoded).unwrap();
    assert_eq!(decoded, EnumV1::B(42));
}

#[test]
fn test_multi_field_unknown_variant_roundtrip() {
    // Multi-field variants use an inner array: [disc, [f1, f2, ...]]
    // Verify the catch_all captures the inner array as a single msgpack value.
    #[derive(Debug, PartialEq, ToxProto)]
    enum NewMulti {
        A,
        B(u32),
        C(String, Vec<u8>),
    }

    let original = NewMulti::C("multi".to_string(), vec![1, 2, 3, 4, 5]);
    let encoded = serialize(&original).expect("serialize multi-field");

    let v1: EnumV1 = deserialize(&encoded).expect("V1 should capture multi-field variant");
    match &v1 {
        EnumV1::Unknown { discriminant, data } => {
            assert_eq!(*discriminant, 2);
            assert!(!data.is_empty(), "multi-field payload should be non-empty");
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }

    // Re-serialize and verify byte-level fidelity
    let re_encoded = serialize(&v1).expect("re-serialize");
    assert_eq!(re_encoded, encoded, "multi-field round-trip byte fidelity");

    // Recover as NewMulti
    let recovered: NewMulti = deserialize(&re_encoded).expect("recover multi-field");
    assert_eq!(recovered, original);
}

#[test]
fn test_enum_without_catch_all_rejects_unknown() {
    // Enums without #[tox(catch_all)] must still reject unknown discriminants.
    #[derive(Debug, PartialEq, ToxProto)]
    enum Strict {
        A,
        B(u32),
    }

    let v2 = EnumV2::C("should fail".to_string());
    let encoded = serialize(&v2).expect("serialize V2::C");

    let result = deserialize::<Strict>(&encoded);
    assert!(result.is_err(), "Strict enum should reject unknown variant");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Unknown variant"),
        "Error should mention unknown variant, got: {}",
        err
    );
}

#[test]
fn test_high_discriminant_roundtrip() {
    // Discriminant 127: max fixpos value in msgpack (single byte 0x7f).
    let wire_127 = vec![0x7f];
    let v1: EnumV1 = deserialize(&wire_127).expect("should capture disc 127");
    assert!(matches!(&v1, EnumV1::Unknown { discriminant: 127, data } if data.is_empty()));
    assert_eq!(serialize(&v1).unwrap(), wire_127, "disc 127 byte fidelity");

    // Discriminant 255: requires msgpack u8 marker (0xcc, 0xff).
    // This exercises the Marker::U8 branch of read_enum_header, which
    // previously called rmp::decode::read_u8 (reads marker+data) after
    // the marker was already consumed, causing a double-read bug.
    let wire_255 = vec![0xcc, 0xff];
    let v1: EnumV1 = deserialize(&wire_255).expect("should capture disc 255");
    assert!(matches!(&v1, EnumV1::Unknown { discriminant: 255, data } if data.is_empty()));
    assert_eq!(serialize(&v1).unwrap(), wire_255, "disc 255 byte fidelity");

    // Discriminant 128: smallest value that crosses from fixpos to u8 encoding.
    let wire_128 = vec![0xcc, 0x80];
    let v1: EnumV1 = deserialize(&wire_128).expect("should capture disc 128");
    assert!(matches!(&v1, EnumV1::Unknown { discriminant: 128, data } if data.is_empty()));
    assert_eq!(serialize(&v1).unwrap(), wire_128, "disc 128 byte fidelity");
}

/// An older version of `Newer`, from before `added` was appended.
#[derive(Debug, PartialEq, ToxProto)]
struct Older {
    kept: u32,
}

#[derive(Debug, PartialEq, ToxProto)]
struct Newer {
    kept: u32,
    #[tox(default)]
    added: Option<String>,
}

#[derive(Debug, PartialEq, ToxProto)]
enum NewerEnum {
    Variant {
        kept: u32,
        other: u32,
        #[tox(default)]
        added: Option<String>,
    },
}

#[derive(Debug, PartialEq, ToxProto)]
enum OlderEnum {
    Variant { kept: u32, other: u32 },
}

#[test]
fn test_appended_fields_default_when_missing() {
    let older = serialize(&Older { kept: 7 }).unwrap();
    assert_eq!(
        deserialize::<Newer>(&older).unwrap(),
        Newer {
            kept: 7,
            added: None
        }
    );
    let older = serialize(&OlderEnum::Variant { kept: 1, other: 2 }).unwrap();
    assert_eq!(
        deserialize::<NewerEnum>(&older).unwrap(),
        NewerEnum::Variant {
            kept: 1,
            other: 2,
            added: None
        }
    );

    // Required fields still are.
    assert!(deserialize::<Newer>(&serialize(&Vec::<u32>::new()).unwrap()).is_err());
}

#[test]
fn test_older_readers_skip_appended_fields() {
    let newer = Newer {
        kept: 7,
        added: Some("new".to_owned()),
    };
    assert_eq!(
        deserialize::<Older>(&serialize(&newer).unwrap()).unwrap(),
        Older { kept: 7 }
    );
    let newer = NewerEnum::Variant {
        kept: 1,
        other: 2,
        added: Some("new".to_owned()),
    };
    assert_eq!(
        deserialize::<OlderEnum>(&serialize(&newer).unwrap()).unwrap(),
        OlderEnum::Variant { kept: 1, other: 2 }
    );
}

#[derive(Debug, PartialEq, ToxProto)]
#[repr(u8)]
enum Sparse {
    Low(u32) = 1,
    Next(u32),
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    } = 255,
}

#[test]
fn test_discriminants_up_to_255() {
    assert_eq!(serialize(&Sparse::Next(5)).unwrap(), [0x92, 0x02, 0x05]);
    let unknown: Sparse = deserialize(&[0x92, 0x07, 0x05]).unwrap();
    assert!(matches!(
        unknown,
        Sparse::Unknown {
            discriminant: 7,
            ..
        }
    ));
}
