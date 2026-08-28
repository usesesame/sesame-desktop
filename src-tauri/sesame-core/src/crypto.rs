use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde_json;
use zeroize::Zeroizing;

use crate::{
    types::*, util::fill_random, VaultResult, MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB,
    MAX_KDF_PARALLELISM,
};

pub fn default_kdf_params() -> KdfParams {
    let mut salt = [0_u8; 32];
    fill_random(&mut salt);
    KdfParams {
        algorithm: "argon2id".into(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
    }
}

pub fn derive_key(password: &str, params: &KdfParams) -> VaultResult<[u8; 32]> {
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
        || params.memory_kib == 0
        || params.memory_kib > MAX_KDF_MEMORY_KIB
        || params.iterations == 0
        || params.iterations > MAX_KDF_ITERATIONS
        || params.parallelism == 0
        || params.parallelism > MAX_KDF_PARALLELISM
    {
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
            XNonce::from_slice(&nonce),
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

pub fn decrypt_bytes(key: &[u8; 32], blob: &CipherBlob, aad: &[u8]) -> VaultResult<Vec<u8>> {
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
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| "The encrypted vault could not be authenticated.".to_string())
}

pub fn serialize_payload(payload: &VaultPayload) -> VaultResult<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(payload)
        .map(Zeroizing::new)
        .map_err(|_| "Sesame could not prepare the local vault.".to_string())
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
