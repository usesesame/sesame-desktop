//! Wrapping the vault key to another device: a sealed box with an explicit sender.
//! Ephemeral X25519 + HKDF bound to protocol, keys, and vault id; the service can do nothing with the package.

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

const HYBRID_KEY_PACKAGE_INFO: &[u8] = b"sesame-sync-key-package-hybrid-xwing-v1";
pub const HYBRID_PACKAGE_VERSION: u8 = 1;
const MIN_HYBRID_PACKAGE_BYTES: usize =
    1 + super::xwing::CIPHERTEXT_BYTES + KEY_PACKAGE_NONCE_BYTES + 16;

fn hybrid_context(vault_id: &str, epoch: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(HYBRID_KEY_PACKAGE_INFO.len() + vault_id.len() + 8);
    info.extend_from_slice(HYBRID_KEY_PACKAGE_INFO);
    info.extend_from_slice(vault_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

fn hybrid_wrapping_key(
    shared: &[u8; super::xwing::SHARED_SECRET_BYTES],
    nonce: &[u8],
    info: &[u8],
) -> VaultResult<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared.as_slice());
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|_| "Sesame could not prepare the device key package.".to_string())?;
    Ok(key)
}

pub fn seal_vault_key_hybrid(
    vault_key: &[u8],
    recipient_public_key: &[u8],
    vault_id: &str,
    epoch: u64,
) -> VaultResult<Vec<u8>> {
    if vault_key.is_empty() {
        return Err("Sesame could not prepare the device key package.".to_string());
    }
    let (kem_ciphertext, shared) = super::xwing::encapsulate(recipient_public_key)?;
    let mut nonce_bytes = [0u8; KEY_PACKAGE_NONCE_BYTES];
    SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| "Sesame could not prepare the device key package.".to_string())?;
    let info = hybrid_context(vault_id, epoch);
    let mut key = hybrid_wrapping_key(&shared, &nonce_bytes, &info)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Sesame could not prepare the device key package.".to_string());
    key.zeroize();
    let ciphertext = cipher?
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: vault_key,
                aad: &info,
            },
        )
        .map_err(|_| "Sesame could not prepare the device key package.".to_string())?;
    let mut package =
        Vec::with_capacity(1 + kem_ciphertext.len() + nonce_bytes.len() + ciphertext.len());
    package.push(HYBRID_PACKAGE_VERSION);
    package.extend_from_slice(&kem_ciphertext);
    package.extend_from_slice(&nonce_bytes);
    package.extend_from_slice(&ciphertext);
    if package.len() > MAX_KEY_PACKAGE_BYTES {
        package.zeroize();
        return Err("Sesame could not prepare the device key package.".to_string());
    }
    Ok(package)
}

pub fn open_vault_key_hybrid(
    package: &[u8],
    recipient: &super::xwing::SecretKey,
    vault_id: &str,
    epoch: u64,
) -> VaultResult<Vec<u8>> {
    const UNREADABLE: &str = "This device key package could not be read.";
    if package.len() < MIN_HYBRID_PACKAGE_BYTES
        || package.len() > MAX_KEY_PACKAGE_BYTES
        || package[0] != HYBRID_PACKAGE_VERSION
    {
        return Err(UNREADABLE.to_string());
    }
    let rest = &package[1..];
    let (kem_ciphertext, rest) = rest.split_at(super::xwing::CIPHERTEXT_BYTES);
    let (nonce_bytes, ciphertext) = rest.split_at(KEY_PACKAGE_NONCE_BYTES);
    let nonce: [u8; KEY_PACKAGE_NONCE_BYTES] =
        nonce_bytes.try_into().map_err(|_| UNREADABLE.to_string())?;
    let shared = recipient
        .decapsulate(kem_ciphertext)
        .map_err(|_| UNREADABLE.to_string())?;
    let info = hybrid_context(vault_id, epoch);
    let mut key = hybrid_wrapping_key(&shared, &nonce, &info)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| UNREADABLE.to_string());
    key.zeroize();
    cipher?
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &info,
            },
        )
        .map_err(|_| UNREADABLE.to_string())
}

#[cfg(test)]
mod hybrid_tests {
    use super::super::xwing::{SecretKey, CIPHERTEXT_BYTES};
    use super::*;

    const VAULT: &str = "vault0000000000000001";

    fn pair() -> (SecretKey, [u8; super::super::xwing::PUBLIC_KEY_BYTES]) {
        let secret = SecretKey::generate().expect("key");
        let public = secret.public_key();
        (secret, public)
    }

    #[test]
    fn a_hybrid_package_opens_only_for_its_recipient_vault_and_epoch() {
        let (recipient, public) = pair();
        let (other, _) = pair();
        let key = [7u8; 32];
        let package = seal_vault_key_hybrid(&key, &public, VAULT, 4).expect("seal");
        assert_eq!(
            open_vault_key_hybrid(&package, &recipient, VAULT, 4).expect("open"),
            key
        );
        assert!(open_vault_key_hybrid(&package, &other, VAULT, 4).is_err());
        assert!(open_vault_key_hybrid(&package, &recipient, "vault0000000000000002", 4).is_err());
        assert!(open_vault_key_hybrid(&package, &recipient, VAULT, 5).is_err());
    }

    #[test]
    fn a_hybrid_package_has_the_documented_framing() {
        let (_, public) = pair();
        let package = seal_vault_key_hybrid(&[7u8; 32], &public, VAULT, 1).expect("seal");
        assert_eq!(package[0], HYBRID_PACKAGE_VERSION);
        assert_eq!(
            package.len(),
            1 + CIPHERTEXT_BYTES + KEY_PACKAGE_NONCE_BYTES + 32 + 16
        );
        assert_eq!(package.len(), 1193);
        assert!(package.len() <= MAX_KEY_PACKAGE_BYTES);
    }

    #[test]
    fn two_hybrid_packages_of_the_same_key_differ() {
        let (_, public) = pair();
        let first = seal_vault_key_hybrid(&[7u8; 32], &public, VAULT, 1).expect("first");
        let second = seal_vault_key_hybrid(&[7u8; 32], &public, VAULT, 1).expect("second");
        assert_ne!(first, second);
    }

    #[test]
    fn a_changed_byte_anywhere_in_a_hybrid_package_never_opens() {
        let (recipient, public) = pair();
        let package = seal_vault_key_hybrid(&[7u8; 32], &public, VAULT, 1).expect("seal");
        for position in [
            0,
            1,
            CIPHERTEXT_BYTES,
            CIPHERTEXT_BYTES + 1,
            1 + CIPHERTEXT_BYTES + 5,
            package.len() - 1,
        ] {
            let mut changed = package.clone();
            changed[position] ^= 1;
            assert!(
                open_vault_key_hybrid(&changed, &recipient, VAULT, 1).is_err(),
                "position {position}"
            );
        }
    }

    #[test]
    fn a_hybrid_package_of_the_wrong_size_or_version_is_refused() {
        let (recipient, public) = pair();
        let package = seal_vault_key_hybrid(&[7u8; 32], &public, VAULT, 1).expect("seal");
        for length in [0, 1, 32, MIN_HYBRID_PACKAGE_BYTES - 1] {
            assert!(open_vault_key_hybrid(&package[..length], &recipient, VAULT, 1).is_err());
        }
        let mut longer = package.clone();
        longer.push(0);
        assert!(open_vault_key_hybrid(&longer, &recipient, VAULT, 1).is_err());
        let oversized = vec![HYBRID_PACKAGE_VERSION; MAX_KEY_PACKAGE_BYTES + 1];
        assert!(open_vault_key_hybrid(&oversized, &recipient, VAULT, 1).is_err());
        let mut wrong_version = package;
        wrong_version[0] = 2;
        assert!(open_vault_key_hybrid(&wrong_version, &recipient, VAULT, 1).is_err());
    }

    #[test]
    fn an_empty_vault_key_and_a_classical_sized_recipient_key_are_refused() {
        let (_, public) = pair();
        assert!(seal_vault_key_hybrid(&[], &public, VAULT, 1).is_err());
        assert!(seal_vault_key_hybrid(&[7u8; 32], &[7u8; 32], VAULT, 1).is_err());
    }

    #[test]
    fn a_classical_package_is_never_read_as_a_hybrid_one() {
        let (recipient, _) = pair();
        let classical_recipient = EncryptionKeypair::generate().expect("keypair");
        let classical =
            seal_vault_key(&[7u8; 32], &classical_recipient.public_key(), VAULT).expect("seal");
        assert!(open_vault_key_hybrid(&classical, &recipient, VAULT, 1).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "vault0000000000000001";

    #[test]
    fn a_sealed_vault_key_opens_only_for_its_recipient_and_vault() {
        let recipient = EncryptionKeypair::generate().expect("keypair");
        let other = EncryptionKeypair::generate().expect("keypair");
        let key = [7u8; 32];
        let package = seal_vault_key(&key, &recipient.public_key(), VAULT).expect("seal");
        assert_eq!(
            open_vault_key(&package, &recipient, VAULT).expect("open"),
            key
        );
        assert!(open_vault_key(&package, &other, VAULT).is_err());
        assert!(open_vault_key(&package, &recipient, "vault0000000000000002").is_err());
    }

    #[test]
    fn a_changed_or_short_package_is_refused() {
        let recipient = EncryptionKeypair::generate().expect("keypair");
        let package = seal_vault_key(&[7u8; 32], &recipient.public_key(), VAULT).expect("seal");
        for position in [0, X25519_KEY_BYTES, package.len() - 1] {
            let mut damaged = package.clone();
            damaged[position] ^= 1;
            assert!(
                open_vault_key(&damaged, &recipient, VAULT).is_err(),
                "byte {position}"
            );
        }
        assert!(open_vault_key(&package[..MIN_PACKAGE_BYTES - 1], &recipient, VAULT).is_err());
        assert!(open_vault_key(&vec![0u8; MAX_KEY_PACKAGE_BYTES + 1], &recipient, VAULT).is_err());
        assert!(open_vault_key(&[], &recipient, VAULT).is_err());
    }

    #[test]
    fn a_low_order_recipient_key_is_refused_on_both_sides() {
        assert!(seal_vault_key(&[7u8; 32], &[0u8; 32], VAULT).is_err());
        let recipient = EncryptionKeypair::generate().expect("keypair");
        let mut package = seal_vault_key(&[7u8; 32], &recipient.public_key(), VAULT).expect("seal");
        package[..X25519_KEY_BYTES].fill(0);
        assert!(open_vault_key(&package, &recipient, VAULT).is_err());
        assert!(seal_vault_key(&[], &recipient.public_key(), VAULT).is_err());
    }

    #[test]
    fn two_packages_of_one_key_differ() {
        let recipient = EncryptionKeypair::generate().expect("keypair");
        let first = seal_vault_key(&[7u8; 32], &recipient.public_key(), VAULT).expect("seal");
        let second = seal_vault_key(&[7u8; 32], &recipient.public_key(), VAULT).expect("seal");
        assert_ne!(first, second);
    }
}
