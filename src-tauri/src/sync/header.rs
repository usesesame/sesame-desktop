use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::canonical::{
    decode_exact, opaque_id, valid_digest, Canonical, ProofError, ProofResult, LABEL_AAD,
    LABEL_HEADER, LABEL_HEADER_DIGEST, MAX_CIPHERTEXT_BYTES, NONCE_BYTES, SIGNATURE_BYTES,
    VERSION_V3,
};
use super::devicelist::{verify_with_key, DeviceList};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub revision: u64,
    pub vault_epoch: u64,
    pub device_list_index: u64,
    pub device_list_digest: String,
    pub previous_digest: String,
    pub ciphertext_digest: String,
    pub ciphertext_length: u64,
    pub nonce: String,
    pub signature: String,
}

impl Header {
    fn fields(&self, label: &str) -> Canonical {
        let mut canonical = Canonical::new(label);
        canonical
            .number(u64::from(self.version))
            .text(&self.vault_id)
            .text(&self.device_id)
            .number(self.revision)
            .number(self.vault_epoch)
            .number(self.device_list_index)
            .text(&self.device_list_digest)
            .text(&self.previous_digest)
            .text(&self.ciphertext_digest)
            .number(self.ciphertext_length)
            .text(&self.nonce);
        canonical
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        self.fields(LABEL_HEADER).bytes()
    }

    pub fn digest(&self) -> String {
        let mut canonical = self.fields(LABEL_HEADER_DIGEST);
        canonical.text(&self.signature);
        canonical.digest()
    }

    pub fn aad(&self) -> Vec<u8> {
        let mut canonical = Canonical::new(LABEL_AAD);
        canonical
            .number(u64::from(self.version))
            .text(&self.vault_id)
            .text(&self.device_id)
            .number(self.revision)
            .number(self.vault_epoch)
            .number(self.device_list_index)
            .text(&self.device_list_digest)
            .text(&self.previous_digest);
        canonical.bytes()
    }

    pub fn sign(mut self, key: &SigningKey) -> Self {
        self.signature = URL_SAFE_NO_PAD.encode(key.sign(&self.signing_payload()).to_bytes());
        self
    }

    pub fn validate(&self) -> ProofResult<()> {
        if self.version != VERSION_V3 {
            return Err(ProofError::invalid("version"));
        }
        if !opaque_id(&self.vault_id) || !opaque_id(&self.device_id) {
            return Err(ProofError::invalid("identifiers"));
        }
        if self.revision == 0 || self.vault_epoch == 0 || self.device_list_index == 0 {
            return Err(ProofError::invalid("revision, epoch or device list index"));
        }
        if (self.revision == 1) != self.previous_digest.is_empty() {
            return Err(ProofError::invalid("previous digest"));
        }
        if !self.previous_digest.is_empty() && !valid_digest(&self.previous_digest) {
            return Err(ProofError::invalid("previous digest"));
        }
        if !valid_digest(&self.device_list_digest) || !valid_digest(&self.ciphertext_digest) {
            return Err(ProofError::invalid("digest"));
        }
        if self.ciphertext_length < 16 || self.ciphertext_length > MAX_CIPHERTEXT_BYTES {
            return Err(ProofError::invalid("ciphertext length"));
        }
        if decode_exact(&self.nonce, NONCE_BYTES).is_none() {
            return Err(ProofError::invalid("nonce"));
        }
        if decode_exact(&self.signature, SIGNATURE_BYTES).is_none() {
            return Err(ProofError::invalid("signature"));
        }
        Ok(())
    }

    pub fn verify_ciphertext(&self, ciphertext: &[u8]) -> ProofResult<()> {
        if ciphertext.len() as u64 != self.ciphertext_length {
            return Err(ProofError::history("ciphertext length"));
        }
        let expected = decode_exact(&self.ciphertext_digest, 32)
            .ok_or_else(|| ProofError::history("ciphertext digest"))?;
        let actual = Sha256::digest(ciphertext);
        if actual.as_slice() != expected.as_slice() {
            return Err(ProofError::history("ciphertext digest"));
        }
        Ok(())
    }
}

pub fn verify_header(
    list: &DeviceList,
    previous: Option<&Header>,
    header: &Header,
) -> ProofResult<()> {
    header.validate()?;
    if header.vault_id != list.vault_id() {
        return Err(ProofError::history("vault"));
    }
    if header.device_list_index > list.head() {
        return Err(ProofError::history(
            "the header names a device list entry this device has not verified",
        ));
    }
    if list.digest_at(header.device_list_index) != Some(header.device_list_digest.as_str()) {
        return Err(ProofError::history("device list digest"));
    }
    if list.epoch_at(header.device_list_index) != Some(header.vault_epoch) {
        return Err(ProofError::history("epoch"));
    }
    if let Some(previous) = previous {
        verify_link(previous, header)?;
    }
    let signer = list
        .member_at(&header.device_id, header.device_list_index)
        .ok_or_else(|| ProofError::history("the signer was not a member"))?;
    verify_with_key(
        &signer.signing_key,
        &header.signature,
        &header.signing_payload(),
        ProofError::history("signature"),
    )
}

fn verify_link(previous: &Header, header: &Header) -> ProofResult<()> {
    if previous.revision.checked_add(1) != Some(header.revision) {
        return Err(ProofError::history("revision does not follow"));
    }
    if header.previous_digest != previous.digest() {
        return Err(ProofError::history("previous digest"));
    }
    if header.device_list_index < previous.device_list_index
        || header.vault_epoch < previous.vault_epoch
    {
        return Err(ProofError::history("device list or epoch went backwards"));
    }
    Ok(())
}

pub fn verify_header_chain(
    list: &DeviceList,
    previous: Option<&Header>,
    headers: &[Header],
) -> ProofResult<()> {
    let mut previous = previous;
    for header in headers {
        verify_header(list, previous, header)?;
        previous = Some(header);
    }
    Ok(())
}
