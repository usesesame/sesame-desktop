use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde_json;
use std::io::{self, Write};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{
    types::*, util::fill_random, VaultResult, MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB,
    MAX_KDF_PARALLELISM, MAX_KDF_TOTAL_WORK, MAX_VAULT_FILE_BYTES, MIN_KDF_ITERATIONS,
    MIN_KDF_MEMORY_KIB, VAULT_SIZE_LIMIT_MESSAGE,
};

pub fn default_kdf_params() -> KdfParams {
    let mut salt = [0_u8; 32];
    fill_random(&mut salt);
    KdfParams {
        algorithm: "argon2id".into(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        memory_kib: MIN_KDF_MEMORY_KIB,
        iterations: MIN_KDF_ITERATIONS,
        parallelism: 4,
    }
}

pub fn derive_key(password: &str, params: &KdfParams) -> VaultResult<[u8; 32]> {
    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    derive_key_from_exact(&normalized, params)
}

pub fn password_forms(password: &str) -> Vec<Zeroizing<String>> {
    let mut forms: Vec<Zeroizing<String>> = Vec::with_capacity(3);
    for form in [
        Zeroizing::new(password.nfc().collect::<String>()),
        Zeroizing::new(password.nfd().collect::<String>()),
        Zeroizing::new(password.to_string()),
    ] {
        if !forms.iter().any(|seen| seen.as_str() == form.as_str()) {
            forms.push(form);
        }
    }
    forms
}

pub fn unwrap_with_password(
    password: &str,
    params: &KdfParams,
    blob: &CipherBlob,
    aad: &[u8],
) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
    for form in password_forms(password) {
        let wrapping_key = Zeroizing::new(derive_key_from_exact(&form, params)?);
        if let Ok(bytes) = decrypt_bytes(&wrapping_key, blob, aad) {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn derive_key_from_exact(password: &str, params: &KdfParams) -> VaultResult<[u8; 32]> {
    validate_kdf_params(params)?;
    let salt = URL_SAFE_NO_PAD
        .decode(&params.salt)
        .map_err(|_| "The vault KDF settings are invalid.".to_string())?;
    let config = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| "The vault KDF settings are invalid.".to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, config);
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|_| "Sesame could not derive a local vault key.".to_string())?;
    Ok(output)
}

pub fn validate_kdf_params(params: &KdfParams) -> VaultResult<()> {
    if params.algorithm != "argon2id"
        || params.memory_kib < MIN_KDF_MEMORY_KIB
        || params.memory_kib > MAX_KDF_MEMORY_KIB
        || params.iterations < MIN_KDF_ITERATIONS
        || params.iterations > MAX_KDF_ITERATIONS
        || params.parallelism == 0
        || params.parallelism > MAX_KDF_PARALLELISM
    {
        return Err("The vault KDF settings are outside Sesame's safe limits.".into());
    }
    if u64::from(params.memory_kib) * u64::from(params.iterations) > MAX_KDF_TOTAL_WORK {
        return Err("The vault KDF settings are outside Sesame's safe limits.".into());
    }
    let salt = URL_SAFE_NO_PAD
        .decode(&params.salt)
        .map_err(|_| "The vault KDF settings are invalid.".to_string())?;
    if !(16..=64).contains(&salt.len()) {
        return Err("The vault KDF settings are invalid.".into());
    }
    Ok(())
}

pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> VaultResult<CipherBlob> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Sesame could not initialise local encryption.".to_string())?;
    let mut nonce = [0_u8; 24];
    fill_random(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Sesame could not encrypt the local vault.".to_string())?;
    Ok(CipherBlob {
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_bytes(
    key: &[u8; 32],
    blob: &CipherBlob,
    aad: &[u8],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Sesame could not initialise local encryption.".to_string())?;
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&blob.nonce)
        .map_err(|_| "The encrypted vault nonce is invalid.".to_string())?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| "The encrypted vault nonce is invalid.".to_string())?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&blob.ciphertext)
        .map_err(|_| "The encrypted vault data is invalid.".to_string())?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "The encrypted vault could not be authenticated.".to_string())
}

struct CappedBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: u64,
}

impl Write for CappedBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.bytes.len() as u64 + data.len() as u64 > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the encoded vault would exceed its size limit",
            ));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn serialize_payload(payload: &VaultPayload) -> VaultResult<Zeroizing<Vec<u8>>> {
    serialize_payload_capped(payload, MAX_VAULT_FILE_BYTES)
}

fn serialize_payload_capped(payload: &VaultPayload, limit: u64) -> VaultResult<Zeroizing<Vec<u8>>> {
    let mut buffer = CappedBuffer {
        bytes: Zeroizing::new(Vec::new()),
        limit,
    };
    serde_json::to_writer(&mut buffer, payload).map_err(|error| {
        if error.is_io() {
            VAULT_SIZE_LIMIT_MESSAGE.to_string()
        } else {
            "Sesame could not prepare the local vault.".to_string()
        }
    })?;
    Ok(buffer.bytes)
}

pub fn bytes_match(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (index, byte) in left.iter().enumerate() {
        difference |= byte ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Attachment, DocumentMetadata};
    use crate::WRAP_AAD;

    const COMPOSED: &str = "fictional caf\u{e9} na\u{ef}ve password";
    const DECOMPOSED: &str = "fictional cafe\u{301} nai\u{308}ve password";

    fn wrap_with_exact(password: &str, params: &KdfParams, secret: &[u8]) -> CipherBlob {
        let key = derive_key_from_exact(password, params).expect("legacy key");
        encrypt_bytes(&key, secret, WRAP_AAD).expect("legacy wrap")
    }

    #[test]
    fn an_ascii_password_derives_the_same_key_as_before_normalization() {
        let params = default_kdf_params();
        let password = "fictional ascii password 42";
        assert_eq!(
            derive_key(password, &params).expect("normalized"),
            derive_key_from_exact(password, &params).expect("exact")
        );
        assert_eq!(password_forms(password).len(), 1);
    }

    #[test]
    fn composed_and_decomposed_forms_derive_one_key() {
        assert_ne!(COMPOSED, DECOMPOSED);
        let params = default_kdf_params();
        assert_eq!(
            derive_key(COMPOSED, &params).expect("composed"),
            derive_key(DECOMPOSED, &params).expect("decomposed")
        );
    }

    #[test]
    fn a_wrap_written_from_the_decomposed_form_opens_with_the_composed_form() {
        let params = default_kdf_params();
        let wrap = wrap_with_exact(DECOMPOSED, &params, &[5_u8; 32]);
        let opened = unwrap_with_password(COMPOSED, &params, &wrap, WRAP_AAD)
            .expect("derivation")
            .expect("opened");
        assert_eq!(opened.as_slice(), &[5_u8; 32]);
    }

    #[test]
    fn a_wrap_written_from_the_composed_form_opens_with_the_decomposed_form() {
        let params = default_kdf_params();
        let wrap = wrap_with_exact(COMPOSED, &params, &[6_u8; 32]);
        let opened = unwrap_with_password(DECOMPOSED, &params, &wrap, WRAP_AAD)
            .expect("derivation")
            .expect("opened");
        assert_eq!(opened.as_slice(), &[6_u8; 32]);
    }

    #[test]
    fn a_wrong_password_opens_nothing_in_any_form() {
        let params = default_kdf_params();
        let wrap = wrap_with_exact(COMPOSED, &params, &[7_u8; 32]);
        assert!(unwrap_with_password(
            "fictional caf\u{e9} other password",
            &params,
            &wrap,
            WRAP_AAD
        )
        .expect("derivation")
        .is_none());
    }

    #[test]
    fn invalid_kdf_settings_are_an_error_not_a_wrong_password() {
        let mut params = default_kdf_params();
        let wrap = wrap_with_exact(COMPOSED, &params, &[8_u8; 32]);
        params.memory_kib = 0;
        assert!(unwrap_with_password(COMPOSED, &params, &wrap, WRAP_AAD).is_err());
    }

    #[test]
    fn capped_buffer_keeps_only_bytes_under_the_limit() {
        let mut buffer = CappedBuffer {
            bytes: Zeroizing::new(Vec::new()),
            limit: 4,
        };
        buffer.write_all(b"abc").expect("under the limit");
        assert!(buffer.write_all(b"de").is_err());
        assert_eq!(&*buffer.bytes, b"abc");
    }

    #[test]
    fn payload_serialization_rejects_an_oversized_change_early() {
        let mut document = DocumentMetadata::default();
        document.id = "fictional-document".into();
        document.title = "Fictional document".into();
        document.attachments = vec![Attachment {
            id: "fictional-attachment".into(),
            filename: "fictional.bin".into(),
            content_type: "application/octet-stream".into(),
            size: 4096,
            data: vec![7; 4096],
        }];
        let mut payload = VaultPayload::default();
        payload.vault_name = "fictional oversized vault".into();
        payload.documents = vec![document];
        let encoded = serialize_payload_capped(&payload, 256);
        assert_eq!(encoded.err().as_deref(), Some(VAULT_SIZE_LIMIT_MESSAGE));
        let accepted = serialize_payload_capped(&payload, 64 * 1024).expect("small limit passes");
        assert!(serde_json::from_slice::<serde_json::Value>(&accepted).is_ok());
    }
}
