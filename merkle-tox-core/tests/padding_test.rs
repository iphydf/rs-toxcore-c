use merkle_tox_core::dag::{apply_padding, remove_padding};

#[test]
fn test_padding_roundtrip() {
    let mut data = vec![1, 2, 3];
    apply_padding(&mut data);
    assert!(data.len().is_power_of_two());
    assert!(data.len() >= tox_proto::constants::MIN_PADDING_BIN);
    remove_padding(&mut data).unwrap();
    assert_eq!(data, vec![1, 2, 3]);
}

#[test]
fn test_padding_exact_power_of_two() {
    let mut data = vec![0u8; 127];
    apply_padding(&mut data);
    assert_eq!(data.len(), 128);
    assert_eq!(data[127], 0x80);
    remove_padding(&mut data).unwrap();
    assert_eq!(data.len(), 127);
}

#[test]
fn test_padding_malformed() {
    let mut data = vec![0u8; 128];
    // No 0x80 marker
    assert!(remove_padding(&mut data).is_err());

    // Non-zero after marker
    let mut data2 = vec![1, 2, 3];
    apply_padding(&mut data2);
    let last = data2.len() - 1;
    data2[last] = 0x01;
    assert!(remove_padding(&mut data2).is_err());
}
