use toxcore::tox::encryptsave::*;

pub fn subtest_encryptsave() {
    println!("Running subtest_encryptsave...");

    let passphrase = b"SuperSecretKey";
    let plaintext = b"This is a secret message.";

    // 1. Test PassKey Derivation and Encryption
    let key = PassKey::derive(passphrase).expect("Failed to derive key");
    let ciphertext = key.encrypt(plaintext).expect("Failed to encrypt with key");
    assert_ne!(plaintext, ciphertext.as_slice());
    assert!(is_data_encrypted(&ciphertext));

    let decrypted = key
        .decrypt(&ciphertext)
        .expect("Failed to decrypt with key");
    assert_eq!(plaintext, decrypted.as_slice());

    // 2. Test Convenience Functions
    let ciphertext_conv = encrypt(plaintext, passphrase).expect("Failed to encrypt convenience");
    assert_ne!(plaintext, ciphertext_conv.as_slice());
    assert!(is_data_encrypted(&ciphertext_conv));

    let decrypted_conv =
        decrypt(&ciphertext_conv, passphrase).expect("Failed to decrypt convenience");
    assert_eq!(plaintext, decrypted_conv.as_slice());

    // 3. Test Salt extraction and manual derivation
    let salt = get_salt(&ciphertext).expect("Failed to get salt");
    let key_manual =
        PassKey::derive_with_salt(passphrase, &salt).expect("Failed to derive with salt");
    let decrypted_manual = key_manual
        .decrypt(&ciphertext)
        .expect("Failed to decrypt with manual key");
    assert_eq!(plaintext, decrypted_manual.as_slice());
}
