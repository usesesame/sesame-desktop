//! Windows Hello unlock via the CNG Passport KSP; the private key never leaves the device.
//! `NCryptDecrypt` requires a fresh Hello gesture; Sesame only ever sees success or failure.

use crate::VaultResult;

/// Neither field is secret alone: the name and ciphertext only work with a fresh gesture.
pub struct HelloWrapMaterial {
    pub key_name: String,
    pub ciphertext: Vec<u8>,
}

/// Domain separation, the same role the `*_AAD` constants play for the other wraps.
#[cfg(windows)]
const HELLO_OAEP_LABEL: &[u8] = b"sesame:hello-wrapped-vault-key:v1";

#[cfg(windows)]
mod win {
    use super::{HelloWrapMaterial, VaultResult, HELLO_OAEP_LABEL};
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, NCRYPT_KEY_HANDLE,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM,
        NCRYPT_USE_CONTEXT_PROPERTY,
    };
    use zeroize::Zeroize;

    const KEY_BITS: u32 = 2048;
    const PROVIDER_NAME: &str = "Microsoft Passport Key Storage Provider";
    const USE_CONTEXT: &str = "Sesame vault unlock";

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    struct ProviderHandle(NCRYPT_PROV_HANDLE);
    impl Drop for ProviderHandle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    NCryptFreeObject(self.0);
                }
            }
        }
    }

    struct KeyHandle(NCRYPT_KEY_HANDLE);
    impl Drop for KeyHandle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    NCryptFreeObject(self.0);
                }
            }
        }
    }

    fn open_provider() -> VaultResult<ProviderHandle> {
        let name = wide(PROVIDER_NAME);
        let mut handle: NCRYPT_PROV_HANDLE = 0;
        let status = unsafe { NCryptOpenStorageProvider(&mut handle, name.as_ptr(), 0) };
        if status != 0 || handle == 0 {
            return Err(
                "Windows Hello is not available on this device. Set it up in Windows Settings, then try again."
                    .into(),
            );
        }
        Ok(ProviderHandle(handle))
    }

    fn oaep_padding_info(label: &mut Vec<u8>) -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: label.as_mut_ptr(),
            cbLabel: label.len() as u32,
        }
    }

    pub fn create_and_wrap(key_name: &str, vault_key: &[u8; 32]) -> VaultResult<HelloWrapMaterial> {
        let provider = open_provider()?;
        let name_wide = wide(key_name);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                NCRYPT_RSA_ALGORITHM,
                name_wide.as_ptr(),
                0,
                0,
            )
        };
        if status != 0 || key == 0 {
            return Err(
                "Windows Hello is not available on this device. Set it up in Windows Settings, then try again."
                    .into(),
            );
        }
        let key = KeyHandle(key);

        let length_bytes = KEY_BITS.to_le_bytes();
        let length_status = unsafe {
            NCryptSetProperty(
                key.0,
                NCRYPT_LENGTH_PROPERTY,
                length_bytes.as_ptr(),
                length_bytes.len() as u32,
                0,
            )
        };
        if length_status != 0 {
            return Err("Sesame could not configure Windows Hello unlock.".into());
        }

        let context_wide = wide(USE_CONTEXT);
        let context_bytes = context_wide.as_ptr() as *const u8;
        let context_len = (context_wide.len() * 2) as u32;
        unsafe {
            // Best-effort: a missing display context still leaves a usable key.
            NCryptSetProperty(
                key.0,
                NCRYPT_USE_CONTEXT_PROPERTY,
                context_bytes,
                context_len,
                0,
            );
        }

        let finalize_status = unsafe { NCryptFinalizeKey(key.0, 0) };
        if finalize_status != 0 {
            let _ = unsafe { NCryptDeleteKey(key.0, 0) };
            return Err(
                "Windows Hello is not available on this device. Set it up in Windows Settings, then try again."
                    .into(),
            );
        }

        let mut label = HELLO_OAEP_LABEL.to_vec();
        let padding = oaep_padding_info(&mut label);
        let padding_ptr = &padding as *const BCRYPT_OAEP_PADDING_INFO as *const c_void;

        let mut needed: u32 = 0;
        let size_status = unsafe {
            NCryptEncrypt(
                key.0,
                vault_key.as_ptr(),
                vault_key.len() as u32,
                padding_ptr,
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_PAD_OAEP_FLAG,
            )
        };
        if size_status != 0 || needed == 0 {
            let _ = unsafe { NCryptDeleteKey(key.0, 0) };
            return Err("Sesame could not protect the vault key with Windows Hello.".into());
        }

        let mut ciphertext = vec![0_u8; needed as usize];
        let mut written: u32 = 0;
        let encrypt_status = unsafe {
            NCryptEncrypt(
                key.0,
                vault_key.as_ptr(),
                vault_key.len() as u32,
                padding_ptr,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        };
        if encrypt_status != 0 {
            let _ = unsafe { NCryptDeleteKey(key.0, 0) };
            return Err("Sesame could not protect the vault key with Windows Hello.".into());
        }
        ciphertext.truncate(written as usize);

        // The key is persisted by name, so it is closed rather than deleted here.
        drop(key);
        Ok(HelloWrapMaterial {
            key_name: key_name.to_string(),
            ciphertext,
        })
    }

    /// The one call gated on a fresh gesture; every failure mode reads as a plain decrypt failure.
    pub fn open_and_unwrap(key_name: &str, ciphertext: &[u8]) -> VaultResult<[u8; 32]> {
        let provider = open_provider()?;
        let name_wide = wide(key_name);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        let open_status = unsafe { NCryptOpenKey(provider.0, &mut key, name_wide.as_ptr(), 0, 0) };
        if open_status != 0 || key == 0 {
            return Err(
                "Windows Hello is no longer set up for this vault. Use your master password or recovery kit."
                    .into(),
            );
        }
        let key = KeyHandle(key);

        let mut label = HELLO_OAEP_LABEL.to_vec();
        let padding = oaep_padding_info(&mut label);
        let padding_ptr = &padding as *const BCRYPT_OAEP_PADDING_INFO as *const c_void;

        // One decrypt, not a size probe: a second Hello prompt trains people to approve blind.
        let mut plain = vec![0_u8; (KEY_BITS / 8) as usize];
        let mut written: u32 = 0;
        let decrypt_status = unsafe {
            NCryptDecrypt(
                key.0,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                padding_ptr,
                plain.as_mut_ptr(),
                plain.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        };
        if decrypt_status != 0 {
            plain.zeroize();
            return Err(
                "Windows Hello unlock was cancelled or did not succeed. Use your master password or recovery kit."
                    .into(),
            );
        }
        plain.truncate(written as usize);
        let result: VaultResult<[u8; 32]> = plain
            .as_slice()
            .try_into()
            .map_err(|_| "The Windows Hello unlock data for this vault is invalid.".to_string());
        plain.zeroize();
        result
    }

    /// Best-effort: an already-gone key is not an error worth surfacing.
    pub fn delete_key(key_name: &str) {
        let Ok(provider) = open_provider() else {
            return;
        };
        let name_wide = wide(key_name);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        let open_status = unsafe { NCryptOpenKey(provider.0, &mut key, name_wide.as_ptr(), 0, 0) };
        if open_status != 0 || key == 0 {
            return;
        }
        // `NCryptDeleteKey` frees the handle on success; only a failed delete needs manual free.
        if unsafe { NCryptDeleteKey(key, 0) } != 0 {
            unsafe {
                NCryptFreeObject(key);
            }
        }
    }

    /// Opening requires no gesture, so this is a safe existence probe.
    pub fn key_exists(key_name: &str) -> bool {
        let Ok(provider) = open_provider() else {
            return false;
        };
        let name_wide = wide(key_name);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        let open_status = unsafe { NCryptOpenKey(provider.0, &mut key, name_wide.as_ptr(), 0, 0) };
        if open_status != 0 || key == 0 {
            return false;
        }
        unsafe {
            NCryptFreeObject(key);
        }
        true
    }
}

#[cfg(windows)]
pub fn create_and_wrap(key_name: &str, vault_key: &[u8; 32]) -> VaultResult<HelloWrapMaterial> {
    win::create_and_wrap(key_name, vault_key)
}

#[cfg(windows)]
pub fn open_and_unwrap(key_name: &str, ciphertext: &[u8]) -> VaultResult<[u8; 32]> {
    win::open_and_unwrap(key_name, ciphertext)
}

#[cfg(windows)]
pub fn delete_key(key_name: &str) {
    win::delete_key(key_name)
}

#[cfg(windows)]
pub fn key_exists(key_name: &str) -> bool {
    win::key_exists(key_name)
}

#[cfg(not(windows))]
pub fn create_and_wrap(_key_name: &str, _vault_key: &[u8; 32]) -> VaultResult<HelloWrapMaterial> {
    Err("Windows Hello unlock is available on Windows only.".into())
}

#[cfg(not(windows))]
pub fn open_and_unwrap(_key_name: &str, _ciphertext: &[u8]) -> VaultResult<[u8; 32]> {
    Err("Windows Hello unlock is available on Windows only.".into())
}

#[cfg(not(windows))]
pub fn delete_key(_key_name: &str) {}

#[cfg(not(windows))]
pub fn key_exists(_key_name: &str) -> bool {
    false
}
