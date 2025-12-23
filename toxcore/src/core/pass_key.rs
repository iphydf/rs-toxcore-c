use crate::ffi;
use crate::types::{
    PASS_ENCRYPTION_EXTRA_LENGTH, PASS_SALT_LENGTH, Tox_Err_Decryption, Tox_Err_Encryption,
    Tox_Err_Get_Salt, Tox_Err_Key_Derivation,
};

pub struct PassKey {
    pub(crate) ptr: *mut ffi::Tox_Pass_Key,
}

impl Drop for PassKey {
    fn drop(&mut self) {
        unsafe { ffi::tox_pass_key_free(self.ptr) };
    }
}

impl PassKey {
    pub fn derive(passphrase: &[u8]) -> Result<Self, Tox_Err_Key_Derivation> {
        let ptr = ffi_call!(
            tox_pass_key_derive,
            ffi::Tox_Err_Key_Derivation::TOX_ERR_KEY_DERIVATION_OK,
            passphrase.as_ptr(),
            passphrase.len()
        )
        .map_err(Tox_Err_Key_Derivation::from)?;
        Ok(Self { ptr })
    }

    pub fn derive_with_salt(
        passphrase: &[u8],
        salt: &[u8; PASS_SALT_LENGTH],
    ) -> Result<Self, Tox_Err_Key_Derivation> {
        let ptr = ffi_call!(
            tox_pass_key_derive_with_salt,
            ffi::Tox_Err_Key_Derivation::TOX_ERR_KEY_DERIVATION_OK,
            passphrase.as_ptr(),
            passphrase.len(),
            salt.as_ptr()
        )
        .map_err(Tox_Err_Key_Derivation::from)?;
        Ok(Self { ptr })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Tox_Err_Encryption> {
        let mut err = ffi::Tox_Err_Encryption::TOX_ERR_ENCRYPTION_OK;
        let ciphertext_len = plaintext.len() + PASS_ENCRYPTION_EXTRA_LENGTH;
        let mut ciphertext = vec![0u8; ciphertext_len];
        if unsafe {
            ffi::tox_pass_key_encrypt(
                self.ptr,
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                &mut err,
            )
        } {
            Ok(ciphertext)
        } else {
            Err(Tox_Err_Encryption::from(err))
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Tox_Err_Decryption> {
        if ciphertext.len() < PASS_ENCRYPTION_EXTRA_LENGTH {
            return Err(Tox_Err_Decryption::TOX_ERR_DECRYPTION_INVALID_LENGTH);
        }
        let mut err = ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_OK;
        let plaintext_len = ciphertext.len() - PASS_ENCRYPTION_EXTRA_LENGTH;
        let mut plaintext = vec![0u8; plaintext_len];
        if unsafe {
            ffi::tox_pass_key_decrypt(
                self.ptr,
                ciphertext.as_ptr(),
                ciphertext.len(),
                plaintext.as_mut_ptr(),
                &mut err,
            )
        } {
            Ok(plaintext)
        } else {
            Err(Tox_Err_Decryption::from(err))
        }
    }

    pub fn pass_encrypt(
        plaintext: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, Tox_Err_Encryption> {
        let mut err = ffi::Tox_Err_Encryption::TOX_ERR_ENCRYPTION_OK;
        let ciphertext_len = plaintext.len() + PASS_ENCRYPTION_EXTRA_LENGTH;
        let mut ciphertext = vec![0u8; ciphertext_len];
        if unsafe {
            ffi::tox_pass_encrypt(
                plaintext.as_ptr(),
                plaintext.len(),
                passphrase.as_ptr(),
                passphrase.len(),
                ciphertext.as_mut_ptr(),
                &mut err,
            )
        } {
            Ok(ciphertext)
        } else {
            Err(Tox_Err_Encryption::from(err))
        }
    }

    pub fn pass_decrypt(
        ciphertext: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, Tox_Err_Decryption> {
        if ciphertext.len() < PASS_ENCRYPTION_EXTRA_LENGTH {
            return Err(Tox_Err_Decryption::TOX_ERR_DECRYPTION_INVALID_LENGTH);
        }
        let mut err = ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_OK;
        let plaintext_len = ciphertext.len() - PASS_ENCRYPTION_EXTRA_LENGTH;
        let mut plaintext = vec![0u8; plaintext_len];
        if unsafe {
            ffi::tox_pass_decrypt(
                ciphertext.as_ptr(),
                ciphertext.len(),
                passphrase.as_ptr(),
                passphrase.len(),
                plaintext.as_mut_ptr(),
                &mut err,
            )
        } {
            Ok(plaintext)
        } else {
            Err(Tox_Err_Decryption::from(err))
        }
    }

    pub fn get_salt(ciphertext: &[u8]) -> Result<[u8; PASS_SALT_LENGTH], Tox_Err_Get_Salt> {
        ffi_get_array!(
            tox_get_salt,
            ffi::Tox_Err_Get_Salt::TOX_ERR_GET_SALT_OK,
            PASS_SALT_LENGTH,
            ciphertext.as_ptr()
        )
        .map_err(Tox_Err_Get_Salt::from)
    }

    pub fn is_data_encrypted(data: &[u8]) -> bool {
        if data.len() < PASS_ENCRYPTION_EXTRA_LENGTH {
            return false;
        }
        ffi_bool!(tox_is_data_encrypted, data.as_ptr())
    }
}
