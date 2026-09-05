//! Wrapping the vault key to another device: a sealed box with an explicit sender.
//! Ephemeral X25519 + HKDF bound to protocol, keys, and vault id; the service can do nothing with the package.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::vault::VaultResult;

/// Domain separation: one purpose, one info string, one protocol version.
const KEY_PACKAGE_INFO: &[u8] = b"sesame-sync-key-package-v1";

pub const X25519_KEY_BYTES: usize = 32;
pub const KEY_PACKAGE_NONCE_BYTES: usize = 24;
/// Ephemeral public key + nonce + at least the AEAD tag.
const MIN_PACKAGE_BYTES: usize = X25519_KEY_BYTES + KEY_PACKAGE_NONCE_BYTES + 16;
/// Matches `syncproto.MaxEncryptedKeyPackageBytes`.
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;

/// Secret half never leaves the device; zeroized on drop.
pub struct EncryptionKeypair {
    secret: StaticSecret,
}

impl EncryptionKeypair {
    pub fn generate() -> VaultResult<Self> {
        let mut seed = [0u8; X25519_KEY_BYTES];
        SysRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| "Sesame could not generate device keys.".to_string())?;
        let secret = StaticSecret::from(seed);
        seed.zeroize();
        Ok(Self { secret })
    }

    pub fn from_secret_bytes(bytes: [u8; X25519_KEY_BYTES]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn public_key(&self) -> [u8; X25519_KEY_BYTES] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// For DPAPI persistence only; never across IPC, and the copy must be zeroized.
    pub fn secret_bytes(&self) -> [u8; X25519_KEY_BYTES] {
        self.secret.to_bytes()
    }
}

/// Refuses low-order recipient keys that drive the shared secret to zero (RFC 7748 6.1).
///
/// The check must happen before the secret is turned into bytes, which is why
/// this returns the bytes rather than letting a caller call `to_bytes()` itself.
fn contributory_shared_secret(secret: &StaticSecret, public: &PublicKey) -> VaultResult<[u8; 32]> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err("This device key is not usable for Sesame Sync.".to_string());
    }
    Ok(shared.to_bytes())
}

/// Both sides must build `info` identically or the AEAD fails: that is the binding.
fn derive(
    shared: &mut [u8; 32],
    ephemeral_public: &[u8; X25519_KEY_BYTES],
    recipient_public: &[u8; X25519_KEY_BYTES],
    vault_id: &str,
    nonce: &[u8],
) -> VaultResult<([u8; 32], Vec<u8>)> {
    let mut info = Vec::with_capacity(KEY_PACKAGE_INFO.len() + 64 + vault_id.len());
    info.extend_from_slice(KEY_PACKAGE_INFO);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);
    info.extend_from_slice(vault_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared.as_slice());
    let mut key = [0u8; 32];
    let derived = hkdf.expand(&info, &mut key);
    shared.zeroize();
    derived.map_err(|_| "Sesame could not prepare the device key package.".to_string())?;
    Ok((key, info))
}

/// The caller signs the package so the recipient knows which approved device made it.
pub fn seal_vault_key(
    vault_key: &[u8],
    recipient_public_key: &[u8; X25519_KEY_BYTES],
    vault_id: &str,
) -> VaultResult<Vec<u8>> {
    if vault_key.is_empty() {
        return Err("Sesame could not prepare the device key package.".to_string());
    }
    let ephemeral = EncryptionKeypair::generate()?;
    let ephemeral_public = ephemeral.public_key();

    let mut nonce_bytes = [0u8; KEY_PACKAGE_NONCE_BYTES];
    SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| "Sesame could not prepare the device key package.".to_string())?;

    let mut shared =
        contributory_shared_secret(&ephemeral.secret, &PublicKey::from(*recipient_public_key))?;
    let (mut key, info) = derive(
        &mut shared,
        &ephemeral_public,
        recipient_public_key,
        vault_id,
        &nonce_bytes,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Sesame could not prepare the device key package.".to_string())?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: vault_key,
                aad: &info,
            },
        )
        .map_err(|_| "Sesame could not prepare the device key package.".to_string());
    key.zeroize();
    let ciphertext = ciphertext?;

    let mut package =
        Vec::with_capacity(X25519_KEY_BYTES + KEY_PACKAGE_NONCE_BYTES + ciphertext.len());
    package.extend_from_slice(&ephemeral_public);
    package.extend_from_slice(&nonce_bytes);
    package.extend_from_slice(&ciphertext);
    if package.len() > MAX_KEY_PACKAGE_BYTES {
        package.zeroize();
        return Err("Sesame could not prepare the device key package.".to_string());
    }
    Ok(package)
}

/// The returned vault key is secret; the caller must zeroize it.
pub fn open_vault_key(
    package: &[u8],
    recipient: &EncryptionKeypair,
    vault_id: &str,
) -> VaultResult<Vec<u8>> {
    if package.len() < MIN_PACKAGE_BYTES || package.len() > MAX_KEY_PACKAGE_BYTES {
        return Err("This device key package could not be read.".to_string());
    }
    let (ephemeral_public, rest) = package.split_at(X25519_KEY_BYTES);
    let (nonce_bytes, ciphertext) = rest.split_at(KEY_PACKAGE_NONCE_BYTES);
    let nonce: [u8; KEY_PACKAGE_NONCE_BYTES] = nonce_bytes
        .try_into()
        .map_err(|_| "This device key package could not be read.".to_string())?;

    let ephemeral_array: [u8; X25519_KEY_BYTES] = ephemeral_public
        .try_into()
        .map_err(|_| "This device key package could not be read.".to_string())?;
    let recipient_public = recipient.public_key();

    let mut shared =
        contributory_shared_secret(&recipient.secret, &PublicKey::from(ephemeral_array))?;
    let (mut key, info) = derive(
        &mut shared,
        &ephemeral_array,
        &recipient_public,
        vault_id,
        nonce_bytes,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "This device key package could not be read.".to_string())?;
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &info,
            },
        )
        .map_err(|_| "This device key package could not be read.".to_string());
    key.zeroize();
    plaintext
}

pub fn encode_package(package: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(package)
}

pub fn decode_package(value: &str) -> VaultResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "This device key package could not be read.".to_string())
}
