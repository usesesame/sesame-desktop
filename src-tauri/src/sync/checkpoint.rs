use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use super::canonical::{
    decode_exact, opaque_id, valid_digest, Canonical, ProofError, ProofResult, LABEL_CHECKPOINT,
    SIGNATURE_BYTES, VERSION_V3,
};
use super::devicelist::{verify_with_key, DeviceList};
use super::header::Header;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub device_list_index: u64,
    pub device_list_digest: String,
    pub header_revision: u64,
    pub header_digest: String,
    pub observed_at: u64,
    pub signature: String,
}

impl Checkpoint {
    pub fn observe(
        list: &DeviceList,
        head: Option<&Header>,
        device_id: &str,
        observed_at: u64,
    ) -> Self {
        Self {
            version: VERSION_V3,
            vault_id: list.vault_id().to_string(),
            device_id: device_id.to_string(),
            device_list_index: list.head(),
            device_list_digest: list.head_digest().to_string(),
            header_revision: head.map_or(0, |header| header.revision),
            header_digest: head.map_or_else(String::new, Header::digest),
            observed_at,
            signature: String::new(),
        }
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let mut canonical = Canonical::new(LABEL_CHECKPOINT);
        canonical
            .number(u64::from(self.version))
            .text(&self.vault_id)
            .text(&self.device_id)
            .number(self.device_list_index)
            .text(&self.device_list_digest)
            .number(self.header_revision)
            .text(&self.header_digest)
            .number(self.observed_at);
        canonical.bytes()
    }

    pub fn sign(mut self, key: &SigningKey) -> Self {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_payload()).to_bytes());
        self
    }

    pub fn validate(&self) -> ProofResult<()> {
        if self.version != VERSION_V3 {
            return Err(ProofError::invalid("checkpoint version"));
        }
        if !opaque_id(&self.vault_id) || !opaque_id(&self.device_id) {
            return Err(ProofError::invalid("checkpoint identifiers"));
        }
        if self.device_list_index == 0 || !valid_digest(&self.device_list_digest) {
            return Err(ProofError::invalid("checkpoint device list head"));
        }
        if (self.header_revision == 0) != self.header_digest.is_empty() {
            return Err(ProofError::invalid("checkpoint header head"));
        }
        if !self.header_digest.is_empty() && !valid_digest(&self.header_digest) {
            return Err(ProofError::invalid("checkpoint header head"));
        }
        if self.observed_at == 0 {
            return Err(ProofError::invalid("checkpoint time"));
        }
        if decode_exact(&self.signature, SIGNATURE_BYTES).is_none() {
            return Err(ProofError::invalid("checkpoint signature"));
        }
        Ok(())
    }

    pub fn verify_signature(&self, encoded_key: &str) -> ProofResult<()> {
        self.validate()?;
        verify_with_key(
            encoded_key,
            &self.signature,
            &self.signing_payload(),
            ProofError::invalid("checkpoint signature"),
        )
    }
}
