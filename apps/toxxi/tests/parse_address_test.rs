use toxxi::utils::parse_address;

/// A valid Tox ID.
const ID: &str = "ed8a3ff5c756546a912eaabd0ee9381aba9c47f18af24c4725073441a84f3a276b8a74d7eb88";

#[test]
fn reads_a_tox_id_in_either_case() {
    assert!(parse_address(ID).is_ok());
    assert_eq!(parse_address(&ID.to_uppercase()), parse_address(ID));
}

#[test]
fn says_how_long_a_tox_id_is() {
    assert_eq!(
        parse_address(&format!("{ID}de")).unwrap_err(),
        "it has 78 characters, a Tox ID has 76"
    );
}

#[test]
fn tells_a_public_key_from_a_tox_id() {
    assert_eq!(
        parse_address(&ID[..64]).unwrap_err(),
        "it's a public key (64 characters): ask for the whole Tox ID (76)"
    );
}

#[test]
fn says_where_a_character_isnt_hex() {
    assert_eq!(
        parse_address(&format!("é{}", &ID[1..])).unwrap_err(),
        "'é' (character 1) isn't a hex digit"
    );
}

#[test]
fn checks_the_checksum() {
    let typo = format!("0{}", &ID[1..]);
    assert_eq!(
        parse_address(&typo).unwrap_err(),
        "its checksum doesn't match: a character is wrong somewhere"
    );
}

#[test]
fn says_how_long_other_ids_are() {
    assert_eq!(
        toxxi::utils::parse_id::<32>("56a1", "a group's chat ID").unwrap_err(),
        "it has 4 characters, a group's chat ID has 64"
    );
}
