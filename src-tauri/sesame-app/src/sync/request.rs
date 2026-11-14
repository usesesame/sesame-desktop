use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::canonical::{Canonical, LABEL_RECEIPT, LABEL_REQUEST};
use super::canonical::{ProofError, ProofResult};
use super::devicelist::verify_with_key;

pub struct RequestSignature<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub body: &'a [u8],
    pub token: &'a str,
    pub timestamp: u64,
    pub nonce: &'a str,
}

impl RequestSignature<'_> {
    pub fn signing_payload(&self) -> Vec<u8> {
        let body = Sha256::digest(self.body);
        let token = Sha256::digest(self.token.as_bytes());
        let mut canonical = Canonical::new(LABEL_REQUEST);
        canonical
            .text(self.method)
            .text(self.target)
            .add(&body)
            .add(&token)
            .number(self.timestamp)
            .text(self.nonce);
        canonical.bytes()
    }

    pub fn sign(&self, key: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(key.sign(&self.signing_payload()).to_bytes())
    }
}

pub struct Receipt<'a> {
    pub vault_id: &'a str,
    pub revision: u64,
    pub header_digest: &'a str,
    pub vault_epoch: u64,
    pub accepted_at: u64,
}

impl Receipt<'_> {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut canonical = Canonical::new(LABEL_RECEIPT);
        canonical
            .text(self.vault_id)
            .number(self.revision)
            .text(self.header_digest)
            .number(self.vault_epoch)
            .number(self.accepted_at);
        canonical.bytes()
    }

    pub fn verify(&self, instance_key: &str, signature: &str) -> ProofResult<()> {
        verify_with_key(
            instance_key,
            signature,
            &self.signing_payload(),
            ProofError::history("receipt signature"),
        )
    }
}

pub const LABEL_KEY_PACKAGE: &str = "sesame-sync-v3-keypackage";
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyPackageV3 {
    pub vault_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub vault_epoch: u64,
    pub entry_digest: String,
    pub ciphertext: String,
    pub signature: String,
}

impl KeyPackageV3 {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut canonical = Canonical::new(LABEL_KEY_PACKAGE);
        canonical
            .text(&self.vault_id)
            .text(&self.sender_device_id)
            .text(&self.recipient_device_id)
            .number(self.vault_epoch)
            .text(&self.entry_digest)
            .text(&self.ciphertext);
        canonical.bytes()
    }

    pub fn digest(&self) -> String {
        let mut canonical = Canonical::new(&format!("{LABEL_KEY_PACKAGE}-digest"));
        canonical
            .text(&self.vault_id)
            .text(&self.sender_device_id)
            .text(&self.recipient_device_id)
            .number(self.vault_epoch)
            .text(&self.entry_digest)
            .text(&self.ciphertext)
            .text(&self.signature);
        canonical.digest()
    }

    pub fn sign(mut self, key: &SigningKey) -> Self {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_payload()).to_bytes());
        self
    }

    pub fn validate(&self) -> ProofResult<()> {
        use super::canonical::{decode_exact, decode_range, opaque_id, SIGNATURE_BYTES};
        if !opaque_id(&self.vault_id)
            || !opaque_id(&self.sender_device_id)
            || !opaque_id(&self.recipient_device_id)
            || self.vault_epoch == 0
            || !crate::sync::canonical::valid_digest(&self.entry_digest)
        {
            return Err(ProofError::invalid("key package fields"));
        }
        if decode_range(&self.ciphertext, 16, MAX_KEY_PACKAGE_BYTES).is_none() {
            return Err(ProofError::invalid("key package ciphertext"));
        }
        if decode_exact(&self.signature, SIGNATURE_BYTES).is_none() {
            return Err(ProofError::invalid("key package signature"));
        }
        Ok(())
    }

    pub fn verify(&self, sender_signing_key: &str) -> ProofResult<()> {
        self.validate()?;
        verify_with_key(
            sender_signing_key,
            &self.signature,
            &self.signing_payload(),
            ProofError::history("key package signature"),
        )
    }
}
