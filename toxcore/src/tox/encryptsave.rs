use crate::core;
use crate::types::{PASS_SALT_LENGTH, ToxError};

pub struct PassKey(core::PassKey);

impl PassKey {
    pub fn derive(passphrase: &[u8]) -> Result<Self, ToxError> {
        let ptr = core::PassKey::derive(passphrase).map_err(ToxError::KeyDerivation)?;
        Ok(PassKey(ptr))
    }

    pub fn derive_with_salt(
        passphrase: &[u8],
        salt: &[u8; PASS_SALT_LENGTH],
    ) -> Result<Self, ToxError> {
        let ptr =
            core::PassKey::derive_with_salt(passphrase, salt).map_err(ToxError::KeyDerivation)?;
        Ok(PassKey(ptr))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ToxError> {
        self.0.encrypt(plaintext).map_err(ToxError::Encryption)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ToxError> {
        self.0.decrypt(ciphertext).map_err(ToxError::Decryption)
    }
}

pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, ToxError> {
    core::PassKey::pass_encrypt(plaintext, passphrase).map_err(ToxError::Encryption)
}

pub fn decrypt(ciphertext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, ToxError> {
    core::PassKey::pass_decrypt(ciphertext, passphrase).map_err(ToxError::Decryption)
}

pub fn get_salt(ciphertext: &[u8]) -> Result<[u8; PASS_SALT_LENGTH], ToxError> {
    core::PassKey::get_salt(ciphertext).map_err(ToxError::GetSalt)
}

pub fn is_data_encrypted(data: &[u8]) -> bool {
    core::PassKey::is_data_encrypted(data)
}
