//! Sync envelope framing: the signed bytes must byte-match Go's `json.Marshal` of `syncproto.Envelope`.
//! Field order, compact encoding, and empty `tombstoneId` omission are all load-bearing; each has a test.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::vault::VaultResult;

/// Must match `syncproto.Version`.
pub const PROTOCOL_VERSION: u32 = 2;
pub const NONCE_BYTES: usize = 24;
pub const SIGNATURE_BYTES: usize = 64;
pub const MAX_CIPHERTEXT_BYTES: usize = 10 * 1024 * 1024;
/// Must match `syncproto.MaxEnvelopeBytes`; the encoded envelope is larger than its ciphertext.
pub const MAX_ENVELOPE_BYTES: usize = MAX_CIPHERTEXT_BYTES * 2;
const MIN_CIPHERTEXT_BYTES: usize = 16;

pub const OPERATION_SNAPSHOT: &str = "snapshot";
// The tombstone operation is gone; the wire field stays reserved and must be empty.

/// The wire envelope, serialised exactly as the API expects to receive it.
// Deserialize as well as Serialize: a downloaded envelope is parsed back so its signature
// can be verified against the sending device before anything is decrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    #[serde(rename = "vaultId")]
    pub vault_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub revision: u64,
    #[serde(rename = "previousRevision")]
    pub previous_revision: u64,
    #[serde(rename = "vaultEpoch")]
    pub vault_epoch: u64,
    #[serde(rename = "deviceEpoch")]
    pub device_epoch: u64,
    pub operation: String,
    #[serde(rename = "tombstoneId", skip_serializing_if = "String::is_empty")]
    pub tombstone_id: String,
    /// Digest of the revision this one follows, inside the signed payload so the service cannot rewrite the chain.
    #[serde(rename = "previousDigest", default)]
    pub previous_digest: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

/// Field order must match the anonymous struct in `syncproto.Envelope.signingPayload`; it is load-bearing.
#[derive(Serialize)]
struct SigningPayload<'a> {
    version: u32,
    #[serde(rename = "vaultId")]
    vault_id: &'a str,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
    revision: u64,
    #[serde(rename = "previousRevision")]
    previous_revision: u64,
    #[serde(rename = "vaultEpoch")]
    vault_epoch: u64,
    #[serde(rename = "deviceEpoch")]
    device_epoch: u64,
    operation: &'a str,
    #[serde(rename = "tombstoneId", skip_serializing_if = "str_is_empty")]
    tombstone_id: &'a str,
    #[serde(rename = "previousDigest")]
    previous_digest: &'a str,
    nonce: &'a str,
    ciphertext: &'a str,
}

fn str_is_empty(value: &&str) -> bool {
    value.is_empty()
}

pub struct EnvelopeDraft<'a> {
    pub vault_id: &'a str,
    pub device_id: &'a str,
    pub revision: u64,
    pub vault_epoch: u64,
    pub device_epoch: u64,
    pub operation: &'a str,
    pub tombstone_id: &'a str,
    pub previous_digest: &'a str,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
}

/// The exact bytes the server signs; cross-language fixture envelope-signing-payload.json.
pub fn signing_bytes(draft: &EnvelopeDraft<'_>) -> VaultResult<Vec<u8>> {
    let nonce = URL_SAFE_NO_PAD.encode(draft.nonce);
    let ciphertext = URL_SAFE_NO_PAD.encode(draft.ciphertext);
    let payload = SigningPayload {
        version: PROTOCOL_VERSION,
        vault_id: draft.vault_id,
        device_id: draft.device_id,
        revision: draft.revision,
        previous_revision: draft.revision.saturating_sub(1),
        vault_epoch: draft.vault_epoch,
        device_epoch: draft.device_epoch,
        operation: draft.operation,
        tombstone_id: draft.tombstone_id,
        previous_digest: draft.previous_digest,
        nonce: &nonce,
        ciphertext: &ciphertext,
    };
    serde_json::to_vec(&payload).map_err(|_| "The sync payload could not be prepared.".to_string())
}

pub fn seal(draft: &EnvelopeDraft<'_>, signing_key: &SigningKey) -> VaultResult<Envelope> {
    validate_draft(draft)?;
    let payload = signing_bytes(draft)?;
    let signature = signing_key.sign(&payload);
    Ok(Envelope {
        version: PROTOCOL_VERSION,
        vault_id: draft.vault_id.to_string(),
        device_id: draft.device_id.to_string(),
        revision: draft.revision,
        previous_revision: draft.revision.saturating_sub(1),
        vault_epoch: draft.vault_epoch,
        device_epoch: draft.device_epoch,
        operation: draft.operation.to_string(),
        tombstone_id: draft.tombstone_id.to_string(),
        previous_digest: draft.previous_digest.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(draft.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(draft.ciphertext),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Verifies with the sender's approved-device key; the service never says which key to use.
pub fn verify(envelope: &Envelope, verifying_key: &VerifyingKey) -> VaultResult<()> {
    let nonce = decode(&envelope.nonce)?;
    let ciphertext = decode(&envelope.ciphertext)?;
    let draft = EnvelopeDraft {
        vault_id: &envelope.vault_id,
        device_id: &envelope.device_id,
        revision: envelope.revision,
        vault_epoch: envelope.vault_epoch,
        device_epoch: envelope.device_epoch,
        operation: &envelope.operation,
        tombstone_id: &envelope.tombstone_id,
        previous_digest: &envelope.previous_digest,
        nonce: &nonce,
        ciphertext: &ciphertext,
    };
    validate_draft(&draft)?;
    // Revision 1 carries no predecessor digest; a gap in any later revision hides a truncated history.
    if (envelope.revision == 1) != envelope.previous_digest.is_empty() {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    if envelope.version != PROTOCOL_VERSION || envelope.previous_revision + 1 != envelope.revision {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    let signature_bytes = decode(&envelope.signature)?;
    let signature_array: [u8; SIGNATURE_BYTES] = signature_bytes
        .try_into()
        .map_err(|_| "This sync payload is not correctly signed.".to_string())?;
    let payload = signing_bytes(&draft)?;
    verifying_key
        .verify(&payload, &Signature::from_bytes(&signature_array))
        .map_err(|_| "This sync payload is not correctly signed.".to_string())
}

fn decode(value: &str) -> VaultResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "This sync payload could not be read.".to_string())
}

/// Mirrors `syncproto.Envelope.Validate`; rejection happens here, not after a round trip.
fn validate_draft(draft: &EnvelopeDraft<'_>) -> VaultResult<()> {
    if !opaque_id(draft.vault_id) || !opaque_id(draft.device_id) {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    if draft.revision == 0 || draft.vault_epoch == 0 || draft.device_epoch == 0 {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    // Snapshot is the only operation. See the note beside OPERATION_SNAPSHOT.
    if draft.operation != OPERATION_SNAPSHOT || !draft.tombstone_id.is_empty() {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    if draft.nonce.len() != NONCE_BYTES {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    if draft.ciphertext.len() < MIN_CIPHERTEXT_BYTES
        || draft.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err("This sync payload does not match the expected format.".to_string());
    }
    Ok(())
}

/// Matches the server's `^[A-Za-z0-9_-]{16,128}$`.
fn opaque_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Names one revision by its complete signed form, length-prefixed; Go counterpart asserts the shared fixture snapshot-aad.json.
pub fn digest(envelope: &Envelope) -> String {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(b"sesame-sync-envelope-digest-v1");
    for part in [
        envelope.vault_id.as_bytes(),
        envelope.device_id.as_bytes(),
        envelope.version.to_string().as_bytes(),
        envelope.revision.to_string().as_bytes(),
        envelope.previous_revision.to_string().as_bytes(),
        envelope.vault_epoch.to_string().as_bytes(),
        envelope.device_epoch.to_string().as_bytes(),
        envelope.operation.as_bytes(),
        envelope.tombstone_id.as_bytes(),
        envelope.previous_digest.as_bytes(),
        envelope.nonce.as_bytes(),
        envelope.ciphertext.as_bytes(),
        envelope.signature.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    URL_SAFE_NO_PAD.encode(hash.finalize())
}

/// Binds vault, device, and position in both the AEAD and signature layers; Go counterpart asserts the shared fixture.
pub fn snapshot_aad(
    vault_id: &str,
    device_id: &str,
    revision: u64,
    previous_revision: u64,
    vault_epoch: u64,
    device_epoch: u64,
    operation: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(b"sesame-sync-snapshot-v2");
    for part in [
        vault_id.as_bytes(),
        device_id.as_bytes(),
        PROTOCOL_VERSION.to_string().as_bytes(),
        revision.to_string().as_bytes(),
        previous_revision.to_string().as_bytes(),
        vault_epoch.to_string().as_bytes(),
        device_epoch.to_string().as_bytes(),
        operation.as_bytes(),
    ] {
        aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad
}

pub fn snapshot_aad_for(envelope: &Envelope) -> Vec<u8> {
    snapshot_aad(
        &envelope.vault_id,
        &envelope.device_id,
        envelope.revision,
        envelope.previous_revision,
        envelope.vault_epoch,
        envelope.device_epoch,
        &envelope.operation,
    )
}

pub fn snapshot_aad_for_draft(draft: &EnvelopeDraft<'_>) -> Vec<u8> {
    snapshot_aad(
        draft.vault_id,
        draft.device_id,
        draft.revision,
        draft.revision.saturating_sub(1),
        draft.vault_epoch,
        draft.device_epoch,
        draft.operation,
    )
}
