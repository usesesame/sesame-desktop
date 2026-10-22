use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
use ml_kem::{FromSeed, MlKem768};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::util::fill_secret;
use crate::vault::VaultResult;

pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 1216;
pub const CIPHERTEXT_BYTES: usize = 1120;
pub const SHARED_SECRET_BYTES: usize = 32;
const ML_KEM_PUBLIC_KEY_BYTES: usize = 1184;
const ML_KEM_CIPHERTEXT_BYTES: usize = 1088;
const ENCAPSULATION_RANDOMNESS_BYTES: usize = 64;
const LABEL: &[u8; 6] = b"\\.//^\\";

const INVALID_KEY: &str = "This device key is not valid.";
const INVALID_PACKAGE: &str = "This key package is not valid.";

pub struct SecretKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
}

struct Expanded {
    decapsulation: DecapsulationKey,
    x25519: StaticSecret,
    public_key: [u8; PUBLIC_KEY_BYTES],
}

fn expand(seed: &[u8; SEED_BYTES]) -> Expanded {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut ml_kem_seed = Zeroizing::new([0_u8; 64]);
    reader.read(ml_kem_seed.as_mut_slice());
    let mut x25519_bytes = Zeroizing::new([0_u8; 32]);
    reader.read(x25519_bytes.as_mut_slice());
    let (decapsulation, encapsulation) = MlKem768::from_seed(&(*ml_kem_seed).into());
    let x25519 = StaticSecret::from(*x25519_bytes);
    let x25519_public = PublicKey::from(&x25519);
    let mut public_key = [0_u8; PUBLIC_KEY_BYTES];
    public_key[..ML_KEM_PUBLIC_KEY_BYTES].copy_from_slice(encapsulation.to_bytes().as_ref());
    public_key[ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(x25519_public.as_bytes());
    Expanded {
        decapsulation,
        x25519,
        public_key,
    }
}

fn combine(
    ml_kem_secret: &[u8],
    x25519_secret: &[u8; 32],
    x25519_ciphertext: &[u8; 32],
    x25519_public: &[u8; 32],
) -> Zeroizing<[u8; SHARED_SECRET_BYTES]> {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, ml_kem_secret);
    Digest::update(&mut hasher, x25519_secret);
    Digest::update(&mut hasher, x25519_ciphertext);
    Digest::update(&mut hasher, x25519_public);
    Digest::update(&mut hasher, LABEL);
    Zeroizing::new(hasher.finalize().into())
}

impl SecretKey {
    pub fn generate() -> VaultResult<Self> {
        let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
        fill_secret(seed.as_mut_slice())?;
        Ok(Self { seed })
    }

    pub fn from_seed(seed: [u8; SEED_BYTES]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    pub fn seed_bytes(&self) -> [u8; SEED_BYTES] {
        *self.seed
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        expand(&self.seed).public_key
    }

    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> VaultResult<Zeroizing<[u8; SHARED_SECRET_BYTES]>> {
        let ciphertext: &[u8; CIPHERTEXT_BYTES] = ciphertext
            .try_into()
            .map_err(|_| INVALID_PACKAGE.to_string())?;
        let expanded = expand(&self.seed);
        let ml_kem_ciphertext: [u8; ML_KEM_CIPHERTEXT_BYTES] = ciphertext
            [..ML_KEM_CIPHERTEXT_BYTES]
            .try_into()
            .map_err(|_| INVALID_PACKAGE.to_string())?;
        let x25519_ciphertext: [u8; 32] = ciphertext[ML_KEM_CIPHERTEXT_BYTES..]
            .try_into()
            .map_err(|_| INVALID_PACKAGE.to_string())?;
        let ml_kem_secret = expanded
            .decapsulation
            .decapsulate(&ml_kem_ciphertext.into());
        let x25519_secret = expanded
            .x25519
            .diffie_hellman(&PublicKey::from(x25519_ciphertext));
        if !x25519_secret.was_contributory() {
            return Err(INVALID_PACKAGE.to_string());
        }
        let x25519_public: [u8; 32] = expanded.public_key[ML_KEM_PUBLIC_KEY_BYTES..]
            .try_into()
            .map_err(|_| INVALID_KEY.to_string())?;
        Ok(combine(
            ml_kem_secret.as_ref(),
            x25519_secret.as_bytes(),
            &x25519_ciphertext,
            &x25519_public,
        ))
    }
}

pub fn encapsulate(
    public_key: &[u8],
) -> VaultResult<([u8; CIPHERTEXT_BYTES], Zeroizing<[u8; SHARED_SECRET_BYTES]>)> {
    let mut randomness = Zeroizing::new([0_u8; ENCAPSULATION_RANDOMNESS_BYTES]);
    fill_secret(randomness.as_mut_slice())?;
    encapsulate_with(public_key, &randomness)
}

fn encapsulate_with(
    public_key: &[u8],
    randomness: &[u8; ENCAPSULATION_RANDOMNESS_BYTES],
) -> VaultResult<([u8; CIPHERTEXT_BYTES], Zeroizing<[u8; SHARED_SECRET_BYTES]>)> {
    let public_key: &[u8; PUBLIC_KEY_BYTES] =
        public_key.try_into().map_err(|_| INVALID_KEY.to_string())?;
    let ml_kem_public: [u8; ML_KEM_PUBLIC_KEY_BYTES] = public_key[..ML_KEM_PUBLIC_KEY_BYTES]
        .try_into()
        .map_err(|_| INVALID_KEY.to_string())?;
    let x25519_public: [u8; 32] = public_key[ML_KEM_PUBLIC_KEY_BYTES..]
        .try_into()
        .map_err(|_| INVALID_KEY.to_string())?;
    let encapsulation =
        EncapsulationKey::new(&ml_kem_public.into()).map_err(|_| INVALID_KEY.to_string())?;
    let mut ml_kem_randomness = Zeroizing::new([0_u8; 32]);
    ml_kem_randomness.copy_from_slice(&randomness[..32]);
    let mut ephemeral_bytes = Zeroizing::new([0_u8; 32]);
    ephemeral_bytes.copy_from_slice(&randomness[32..]);
    let (ml_kem_ciphertext, ml_kem_secret) =
        encapsulation.encapsulate_deterministic(&(*ml_kem_randomness).into());
    let ephemeral = StaticSecret::from(*ephemeral_bytes);
    let x25519_ciphertext = PublicKey::from(&ephemeral);
    let x25519_secret = ephemeral.diffie_hellman(&PublicKey::from(x25519_public));
    if !x25519_secret.was_contributory() {
        return Err(INVALID_KEY.to_string());
    }
    let mut ciphertext = [0_u8; CIPHERTEXT_BYTES];
    ciphertext[..ML_KEM_CIPHERTEXT_BYTES].copy_from_slice(ml_kem_ciphertext.as_ref());
    ciphertext[ML_KEM_CIPHERTEXT_BYTES..].copy_from_slice(x25519_ciphertext.as_bytes());
    let shared = combine(
        ml_kem_secret.as_ref(),
        x25519_secret.as_bytes(),
        x25519_ciphertext.as_bytes(),
        &x25519_public,
    );
    let mut ml_kem_secret_bytes: [u8; 32] = ml_kem_secret.into();
    ml_kem_secret_bytes.zeroize();
    Ok((ciphertext, shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex"))
            .collect()
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("xwing-vectors.json")).expect("vector file")
    }

    fn field(record: &serde_json::Value, name: &str) -> Vec<u8> {
        decode(record[name].as_str().expect("hex field"))
    }

    #[test]
    fn the_draft_vectors_match_for_key_generation_encapsulation_and_decapsulation() {
        let data = vectors();
        let records = data["records"].as_array().expect("records");
        assert_eq!(records.len(), 3);
        for record in records {
            let seed: [u8; SEED_BYTES] = field(record, "sk").try_into().expect("seed");
            let randomness: [u8; ENCAPSULATION_RANDOMNESS_BYTES] =
                field(record, "eseed").try_into().expect("eseed");
            let secret = SecretKey::from_seed(seed);
            assert_eq!(secret.public_key().to_vec(), field(record, "pk"));
            let (ciphertext, shared) =
                encapsulate_with(&secret.public_key(), &randomness).expect("encapsulated");
            assert_eq!(ciphertext.to_vec(), field(record, "ct"));
            assert_eq!(shared.to_vec(), field(record, "ss"));
            let opened = secret.decapsulate(&ciphertext).expect("decapsulated");
            assert_eq!(opened.to_vec(), field(record, "ss"));
        }
    }

    #[test]
    fn a_fresh_key_round_trips_and_every_encapsulation_differs() {
        let secret = SecretKey::generate().expect("key");
        let public_key = secret.public_key();
        let (first, shared_first) = encapsulate(&public_key).expect("first");
        let (second, shared_second) = encapsulate(&public_key).expect("second");
        assert_ne!(first.to_vec(), second.to_vec());
        assert_ne!(shared_first.to_vec(), shared_second.to_vec());
        assert_eq!(
            secret.decapsulate(&first).expect("open").to_vec(),
            shared_first.to_vec()
        );
        assert_eq!(
            secret.decapsulate(&second).expect("open").to_vec(),
            shared_second.to_vec()
        );
    }

    #[test]
    fn a_changed_ciphertext_never_opens_to_the_sender_secret() {
        let secret = SecretKey::generate().expect("key");
        let (ciphertext, shared) = encapsulate(&secret.public_key()).expect("sealed");
        for position in [
            0,
            ML_KEM_CIPHERTEXT_BYTES - 1,
            ML_KEM_CIPHERTEXT_BYTES,
            CIPHERTEXT_BYTES - 1,
        ] {
            let mut changed = ciphertext;
            changed[position] ^= 1;
            match secret.decapsulate(&changed) {
                Ok(opened) => assert_ne!(opened.to_vec(), shared.to_vec(), "position {position}"),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn another_key_never_opens_the_ciphertext() {
        let secret = SecretKey::generate().expect("key");
        let other = SecretKey::generate().expect("other key");
        let (ciphertext, shared) = encapsulate(&secret.public_key()).expect("sealed");
        let opened = other.decapsulate(&ciphertext).expect("implicit rejection");
        assert_ne!(opened.to_vec(), shared.to_vec());
    }

    #[test]
    fn lengths_other_than_the_exact_ones_are_refused() {
        let secret = SecretKey::generate().expect("key");
        let public_key = secret.public_key();
        for length in [0, 32, PUBLIC_KEY_BYTES - 1] {
            assert!(encapsulate(&public_key[..length]).is_err());
        }
        let mut long = public_key.to_vec();
        long.push(0);
        assert!(encapsulate(&long).is_err());
        let (ciphertext, _) = encapsulate(&public_key).expect("sealed");
        for length in [0, 32, CIPHERTEXT_BYTES - 1] {
            assert!(secret.decapsulate(&ciphertext[..length]).is_err());
        }
        let mut long = ciphertext.to_vec();
        long.push(0);
        assert!(secret.decapsulate(&long).is_err());
    }

    #[test]
    fn a_public_key_whose_x25519_half_has_a_low_order_point_is_refused() {
        let secret = SecretKey::generate().expect("key");
        let mut public_key = secret.public_key();
        public_key[ML_KEM_PUBLIC_KEY_BYTES..].fill(0);
        assert!(encapsulate(&public_key).is_err());
    }

    #[test]
    fn a_ciphertext_whose_x25519_half_is_a_low_order_point_is_refused() {
        let secret = SecretKey::generate().expect("key");
        let (mut ciphertext, _) = encapsulate(&secret.public_key()).expect("sealed");
        ciphertext[ML_KEM_CIPHERTEXT_BYTES..].fill(0);
        assert!(secret.decapsulate(&ciphertext).is_err());
    }

    #[test]
    fn a_public_key_with_an_invalid_ml_kem_half_is_refused() {
        let secret = SecretKey::generate().expect("key");
        let mut public_key = secret.public_key();
        public_key[..ML_KEM_PUBLIC_KEY_BYTES].fill(0xff);
        assert!(encapsulate(&public_key).is_err());
    }

    #[test]
    fn the_seed_reproduces_the_same_public_key() {
        let secret = SecretKey::generate().expect("key");
        let again = SecretKey::from_seed(secret.seed_bytes());
        assert_eq!(secret.public_key().to_vec(), again.public_key().to_vec());
    }
}
