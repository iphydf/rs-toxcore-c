#![allow(unused_imports)]
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
use super::tox::Tox;
pub struct PassKey {
    pub(crate) ptr: *mut ffi::Tox_Pass_Key

}
impl Drop for PassKey {
    fn drop(&mut self) {
        unsafe {
            ffi::tox_pass_key_free(self.ptr)
        }
    }
}
impl PassKey {
    pub fn derive(passphrase: &[u8]) -> std::result::Result<Self, Tox_Err_Key_Derivation> {
        ffi_call!(tox_pass_key_derive, ffi::Tox_Err_Key_Derivation::TOX_ERR_KEY_DERIVATION_OK, passphrase.as_ptr(), passphrase.len()).map(|val| Self { ptr: val })
    }

    pub fn derive_with_salt(passphrase: &[u8], salt: &PassSalt) -> std::result::Result<Self, Tox_Err_Key_Derivation> {
        ffi_call!(tox_pass_key_derive_with_salt, ffi::Tox_Err_Key_Derivation::TOX_ERR_KEY_DERIVATION_OK, passphrase.as_ptr(), passphrase.len(), salt.0.as_ptr()).map(|val| Self { ptr: val })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, Tox_Err_Encryption> {
        unsafe {
            let len = std::ops::Add::add(plaintext.len(), ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize);
            let mut buf = vec![0u8; len];
            let mut err = ffi::Tox_Err_Encryption::TOX_ERR_ENCRYPTION_OK;
            ffi::tox_pass_key_encrypt(self.ptr, plaintext.as_ptr(), plaintext.len(), buf.as_mut_ptr(), &mut err);
            if err != ffi::Tox_Err_Encryption::TOX_ERR_ENCRYPTION_OK {
                return Err(err.into());
            };
            Ok(buf)
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> std::result::Result<Vec<u8>, Tox_Err_Decryption> {
        unsafe {
            if ciphertext.len() < ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize {
                return Err(ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_INVALID_LENGTH.into());
            };
            let len = std::ops::Sub::sub(ciphertext.len(), ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize);
            let mut buf = vec![0u8; len];
            let mut err = ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_OK;
            ffi::tox_pass_key_decrypt(self.ptr, ciphertext.as_ptr(), ciphertext.len(), buf.as_mut_ptr(), &mut err);
            if err != ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_OK {
                return Err(err.into());
            };
            Ok(buf)
        }
    }

    pub fn pass_salt_length() -> u32 {
        unsafe {
            ffi::tox_pass_salt_length()
        }
    }

    pub fn length() -> u32 {
        unsafe {
            ffi::tox_pass_key_length()
        }
    }

    pub fn pass_encryption_extra_length() -> u32 {
        unsafe {
            ffi::tox_pass_encryption_extra_length()
        }
    }

    pub fn err_key_derivation_to_string(error: ffi::Tox_Err_Key_Derivation) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_key_derivation_to_string(error) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_encryption_to_string(error: ffi::Tox_Err_Encryption) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_encryption_to_string(error) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn err_decryption_to_string(error: ffi::Tox_Err_Decryption) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_decryption_to_string(error) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn pass_encrypt(plaintext: &[u8], passphrase: &[u8]) -> std::result::Result<Vec<u8>, Tox_Err_Encryption> {
        unsafe {
            let len = std::ops::Add::add(plaintext.len(), ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize);
            let mut buf = vec![0u8; len];
            let mut err = ffi::Tox_Err_Encryption::TOX_ERR_ENCRYPTION_OK;
            ffi::tox_pass_encrypt(plaintext.as_ptr(), plaintext.len(), passphrase.as_ptr(), passphrase.len(), buf.as_mut_ptr(), &mut err);
            if err != ffi::Tox_Err_Encryption::TOX_ERR_ENCRYPTION_OK {
                return Err(err.into());
            };
            Ok(buf)
        }
    }

    pub fn pass_decrypt(ciphertext: &[u8], passphrase: &[u8]) -> std::result::Result<Vec<u8>, Tox_Err_Decryption> {
        unsafe {
            if ciphertext.len() < ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize {
                return Err(ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_INVALID_LENGTH.into());
            };
            let len = std::ops::Sub::sub(ciphertext.len(), ffi::TOX_PASS_ENCRYPTION_EXTRA_LENGTH as usize);
            let mut buf = vec![0u8; len];
            let mut err = ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_OK;
            ffi::tox_pass_decrypt(ciphertext.as_ptr(), ciphertext.len(), passphrase.as_ptr(), passphrase.len(), buf.as_mut_ptr(), &mut err);
            if err != ffi::Tox_Err_Decryption::TOX_ERR_DECRYPTION_OK {
                return Err(err.into());
            };
            Ok(buf)
        }
    }

    pub fn err_get_salt_to_string(error: ffi::Tox_Err_Get_Salt) -> &'static str {
        unsafe {
            let ptr = ffi::tox_err_get_salt_to_string(error) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn get_salt(ciphertext: &[u8]) -> std::result::Result<PassSalt, Tox_Err_Get_Salt> {
        assert!(ciphertext.len() >= PASS_ENCRYPTION_EXTRA_LENGTH);
        ffi_get_array!(tox_get_salt, ffi::Tox_Err_Get_Salt::TOX_ERR_GET_SALT_OK, PASS_SALT_LENGTH, ciphertext.as_ptr()).map(PassSalt)
    }

    pub fn is_data_encrypted(data: &[u8]) -> bool {
        assert!(data.len() >= PASS_ENCRYPTION_EXTRA_LENGTH);
        ffi_bool!(tox_is_data_encrypted, data.as_ptr())
    }
}
