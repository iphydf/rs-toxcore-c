use tox_proto::{ToxProto, Variant, deserialize, serialize};

#[derive(Debug, Clone, PartialEq, ToxProto)]
struct Mute {
    until: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, ToxProto)]
struct Format {
    format: u8,
}

#[derive(Debug, Clone, PartialEq, ToxProto)]
#[tox(lenient)]
#[repr(u8)]
enum Setting {
    Mute(Mute) = 0,
    Format(Format) = 1,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    } = 255,
}

#[test]
fn test_a_variant_is_its_struct_in_an_array() {
    assert_eq!(
        serialize(&Setting::from(Format { format: 3 })).unwrap(),
        [0x92, 0x01, 0x91, 0x03]
    );
}

#[test]
fn test_a_variant_that_doesnt_decode_is_kept_as_unknown() {
    for bytes in [
        // A string where `Format` has a number.
        [0x92, 0x01, 0x91, 0xa1, b'x'],
        // A kind this version doesn't know.
        [0x92, 0x07, 0x91, 0xa1, b'x'],
    ] {
        let setting: Setting = deserialize(&bytes).unwrap();
        assert!(matches!(&setting, Setting::Unknown { data, .. } if data[..] == bytes[2..]));
        assert_eq!(setting.kind(), u32::from(bytes[1]));
        assert_eq!(serialize(&setting).unwrap(), bytes);
    }
}

#[test]
fn test_a_variant_is_found_by_its_type() {
    let mute = Mute { until: Some(5) };
    let setting = Setting::from(mute.clone());
    assert_eq!((Mute::KIND, Format::KIND), (0, 1));
    assert_eq!(setting.kind(), Mute::KIND);
    assert_eq!(Mute::of(&setting), Some(&mute));
    assert_eq!(Format::of(&setting), None);
    let unknown = Setting::Unknown {
        discriminant: Mute::KIND,
        data: vec![0x90],
    };
    assert_eq!(Mute::of(&unknown), None);
}
