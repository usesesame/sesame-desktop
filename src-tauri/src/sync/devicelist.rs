use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::canonical::{
    decode_exact, decode_range, opaque_id, valid_digest, Canonical, ProofError, ProofResult,
    HYBRID_KEY_BYTES, KEY_BYTES, LABEL_DEVICE_LIST, LABEL_DEVICE_LIST_DIGEST, MAX_DEVICES,
    MAX_SEALED_LABEL_BYTES, MIN_SEALED_LABEL_BYTES, SIGNATURE_BYTES,
};

pub const ENTRY_CREATE: &str = "create";
pub const ENTRY_ADD: &str = "add";
pub const ENTRY_REMOVE: &str = "remove";
pub const ENTRY_KEY: &str = "key";
pub const ENTRY_ROTATE: &str = "rotate";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceListEntry {
    pub vault_id: String,
    pub index: u64,
    pub previous_digest: String,
    pub kind: String,
    pub signer_device_id: String,
    pub subject_device_id: String,
    pub subject_signing_key: String,
    pub subject_package_key: String,
    pub sealed_label: String,
    pub epoch_after: u64,
    pub snapshot_floor: u64,
    pub signature: String,
}

impl DeviceListEntry {
    fn fields(&self, label: &str) -> Canonical {
        let mut canonical = Canonical::new(label);
        canonical
            .text(&self.vault_id)
            .number(self.index)
            .text(&self.previous_digest)
            .text(&self.kind)
            .text(&self.signer_device_id)
            .text(&self.subject_device_id)
            .text(&self.subject_signing_key)
            .text(&self.subject_package_key)
            .text(&self.sealed_label)
            .number(self.epoch_after)
            .number(self.snapshot_floor);
        canonical
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        self.fields(LABEL_DEVICE_LIST).bytes()
    }

    pub fn digest(&self) -> String {
        let mut canonical = self.fields(LABEL_DEVICE_LIST_DIGEST);
        canonical.text(&self.signature);
        canonical.digest()
    }

    pub fn sign(mut self, key: &SigningKey) -> Self {
        let signature = key.sign(&self.signing_payload());
        self.signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        self
    }

    pub fn validate(&self) -> ProofResult<()> {
        if !opaque_id(&self.vault_id)
            || !opaque_id(&self.signer_device_id)
            || !opaque_id(&self.subject_device_id)
        {
            return Err(ProofError::invalid("identifiers"));
        }
        if self.index == 0 || self.epoch_after == 0 {
            return Err(ProofError::invalid("index or epoch"));
        }
        if (self.index == 1) != self.previous_digest.is_empty() {
            return Err(ProofError::invalid("previous digest"));
        }
        if !self.previous_digest.is_empty() && !valid_digest(&self.previous_digest) {
            return Err(ProofError::invalid("previous digest"));
        }
        match self.kind.as_str() {
            ENTRY_CREATE | ENTRY_ADD => {
                if decode_exact(&self.subject_signing_key, KEY_BYTES).is_none() {
                    return Err(ProofError::invalid("signing key"));
                }
                if decode_exact(&self.subject_package_key, KEY_BYTES).is_none()
                    && decode_exact(&self.subject_package_key, HYBRID_KEY_BYTES).is_none()
                {
                    return Err(ProofError::invalid("package key"));
                }
                if decode_range(
                    &self.sealed_label,
                    MIN_SEALED_LABEL_BYTES,
                    MAX_SEALED_LABEL_BYTES,
                )
                .is_none()
                {
                    return Err(ProofError::invalid("label"));
                }
            }
            ENTRY_REMOVE => {
                if !self.subject_signing_key.is_empty()
                    || !self.subject_package_key.is_empty()
                    || !self.sealed_label.is_empty()
                {
                    return Err(ProofError::invalid("a removal carries no key or label"));
                }
            }
            ENTRY_KEY => {
                if self.signer_device_id != self.subject_device_id
                    || !self.subject_signing_key.is_empty()
                    || !self.sealed_label.is_empty()
                {
                    return Err(ProofError::invalid(
                        "a key replacement is signed by its own device and carries only the new package key",
                    ));
                }
                if decode_exact(&self.subject_package_key, HYBRID_KEY_BYTES).is_none() {
                    return Err(ProofError::invalid("package key"));
                }
            }
            ENTRY_ROTATE => {
                if self.signer_device_id != self.subject_device_id
                    || !self.subject_signing_key.is_empty()
                    || !self.subject_package_key.is_empty()
                    || !self.sealed_label.is_empty()
                {
                    return Err(ProofError::invalid(
                        "a rotation is signed by its own device and carries no key or label",
                    ));
                }
            }
            _ => return Err(ProofError::invalid("kind")),
        }
        if self.kind != ENTRY_ADD && self.snapshot_floor != 0 {
            return Err(ProofError::invalid("snapshot floor"));
        }
        if decode_exact(&self.signature, SIGNATURE_BYTES).is_none() {
            return Err(ProofError::invalid("signature"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListMember {
    pub device_id: String,
    pub signing_key: String,
    pub package_key: String,
    pub sealed_label: String,
    pub added_index: u64,
    pub removed_index: u64,
}

impl DeviceListMember {
    fn member_at(&self, index: u64) -> bool {
        self.added_index <= index && (self.removed_index == 0 || index < self.removed_index)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeviceList {
    vault_id: String,
    members: HashMap<String, DeviceListMember>,
    digests: Vec<String>,
    epochs: Vec<u64>,
}

impl DeviceList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn verify(entries: &[DeviceListEntry]) -> ProofResult<Self> {
        let mut list = Self::new();
        for entry in entries {
            list.extend(entry)?;
        }
        Ok(list)
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn head(&self) -> u64 {
        self.digests.len() as u64
    }

    pub fn head_digest(&self) -> &str {
        self.digests.last().map(String::as_str).unwrap_or("")
    }

    pub fn epoch(&self) -> u64 {
        self.epochs.last().copied().unwrap_or(0)
    }

    pub fn digest_at(&self, index: u64) -> Option<&str> {
        let position = usize::try_from(index.checked_sub(1)?).ok()?;
        self.digests.get(position).map(String::as_str)
    }

    pub fn epoch_at(&self, index: u64) -> Option<u64> {
        let position = usize::try_from(index.checked_sub(1)?).ok()?;
        self.epochs.get(position).copied()
    }

    pub fn member(&self, device_id: &str) -> Option<&DeviceListMember> {
        self.members.get(device_id)
    }

    pub fn member_at(&self, device_id: &str, index: u64) -> Option<&DeviceListMember> {
        self.members
            .get(device_id)
            .filter(|member| member.member_at(index))
    }

    pub fn all_members(&self) -> Vec<&DeviceListMember> {
        self.members.values().collect()
    }

    pub fn current(&self) -> Vec<&DeviceListMember> {
        self.members
            .values()
            .filter(|member| member.removed_index == 0)
            .collect()
    }

    pub fn extend(&mut self, entry: &DeviceListEntry) -> ProofResult<()> {
        entry.validate()?;
        let next = self
            .head()
            .checked_add(1)
            .ok_or_else(|| ProofError::device_list("index overflow"))?;
        if entry.index != next {
            return Err(ProofError::device_list("index does not follow"));
        }
        if entry.index == 1 {
            return self.extend_create(entry);
        }
        if entry.vault_id != self.vault_id {
            return Err(ProofError::device_list("vault"));
        }
        if entry.previous_digest != self.head_digest() {
            return Err(ProofError::device_list("previous digest"));
        }
        let signer = self
            .members
            .get(&entry.signer_device_id)
            .filter(|member| member.removed_index == 0)
            .ok_or_else(|| ProofError::device_list("signer is not a member"))?;
        verify_signature(entry, &signer.signing_key)?;
        match entry.kind.as_str() {
            ENTRY_CREATE => Err(ProofError::device_list("only the first entry creates")),
            ENTRY_ADD => self.extend_add(entry),
            ENTRY_REMOVE => self.extend_remove(entry),
            ENTRY_KEY => self.extend_key(entry),
            ENTRY_ROTATE => self.extend_rotate(entry),
            _ => Err(ProofError::device_list("kind")),
        }
    }

    fn extend_create(&mut self, entry: &DeviceListEntry) -> ProofResult<()> {
        if entry.kind != ENTRY_CREATE
            || entry.signer_device_id != entry.subject_device_id
            || entry.epoch_after != 1
            || entry.snapshot_floor != 0
        {
            return Err(ProofError::device_list(
                "the first entry must be a self signed create at epoch 1",
            ));
        }
        verify_signature(entry, &entry.subject_signing_key)?;
        self.vault_id = entry.vault_id.clone();
        self.members
            .insert(entry.subject_device_id.clone(), member_from(entry));
        self.push(entry, 1);
        Ok(())
    }

    fn extend_add(&mut self, entry: &DeviceListEntry) -> ProofResult<()> {
        if self.members.contains_key(&entry.subject_device_id) {
            return Err(ProofError::device_list("device id was already used"));
        }
        if entry.epoch_after != self.epoch() {
            return Err(ProofError::device_list("an add does not change the epoch"));
        }
        if self.current().len() >= MAX_DEVICES {
            return Err(ProofError::device_list("too many devices"));
        }
        self.members
            .insert(entry.subject_device_id.clone(), member_from(entry));
        self.push(entry, entry.epoch_after);
        Ok(())
    }

    fn extend_remove(&mut self, entry: &DeviceListEntry) -> ProofResult<()> {
        let next_epoch = self
            .epoch()
            .checked_add(1)
            .ok_or_else(|| ProofError::device_list("epoch overflow"))?;
        if entry.epoch_after != next_epoch {
            return Err(ProofError::device_list("a removal raises the epoch by one"));
        }
        let subject = self
            .members
            .get_mut(&entry.subject_device_id)
            .filter(|member| member.removed_index == 0)
            .ok_or_else(|| ProofError::device_list("subject is not a member"))?;
        subject.removed_index = entry.index;
        self.push(entry, entry.epoch_after);
        Ok(())
    }

    fn extend_key(&mut self, entry: &DeviceListEntry) -> ProofResult<()> {
        if entry.epoch_after != self.epoch() {
            return Err(ProofError::device_list(
                "a key replacement does not change the epoch",
            ));
        }
        let signer = self
            .members
            .get_mut(&entry.signer_device_id)
            .filter(|member| member.removed_index == 0)
            .ok_or_else(|| ProofError::device_list("signer is not a member"))?;
        if decode_exact(&signer.package_key, KEY_BYTES).is_none() {
            return Err(ProofError::device_list(
                "only a device with the older package key can replace it",
            ));
        }
        signer.package_key = entry.subject_package_key.clone();
        self.push(entry, entry.epoch_after);
        Ok(())
    }

    fn extend_rotate(&mut self, entry: &DeviceListEntry) -> ProofResult<()> {
        let next_epoch = self
            .epoch()
            .checked_add(1)
            .ok_or_else(|| ProofError::device_list("epoch overflow"))?;
        if entry.epoch_after != next_epoch {
            return Err(ProofError::device_list(
                "a rotation raises the epoch by one",
            ));
        }
        self.push(entry, entry.epoch_after);
        Ok(())
    }

    fn push(&mut self, entry: &DeviceListEntry, epoch: u64) {
        self.digests.push(entry.digest());
        self.epochs.push(epoch);
    }
}

fn member_from(entry: &DeviceListEntry) -> DeviceListMember {
    DeviceListMember {
        device_id: entry.subject_device_id.clone(),
        signing_key: entry.subject_signing_key.clone(),
        package_key: entry.subject_package_key.clone(),
        sealed_label: entry.sealed_label.clone(),
        added_index: entry.index,
        removed_index: 0,
    }
}

fn verify_signature(entry: &DeviceListEntry, encoded_key: &str) -> ProofResult<()> {
    verify_with_key(
        encoded_key,
        &entry.signature,
        &entry.signing_payload(),
        ProofError::device_list("signature"),
    )
}

pub fn verify_with_key(
    encoded_key: &str,
    encoded_signature: &str,
    payload: &[u8],
    failure: ProofError,
) -> ProofResult<()> {
    let key: [u8; KEY_BYTES] = decode_exact(encoded_key, KEY_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| failure.clone())?;
    let signature: [u8; SIGNATURE_BYTES] = decode_exact(encoded_signature, SIGNATURE_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| failure.clone())?;
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| failure.clone())?;
    verifying
        .verify_strict(payload, &Signature::from_bytes(&signature))
        .map_err(|_| failure)
}

#[cfg(test)]
mod hybrid_key_tests {
    use super::*;
    use crate::sync::canonical::HYBRID_KEY_BYTES;
    use ed25519_dalek::SigningKey;

    fn entry_with(package_key: &str) -> DeviceListEntry {
        let signing = SigningKey::from_bytes(&[1u8; 32]);
        DeviceListEntry {
            vault_id: "vaultAAAAAAAAAAAA01".to_string(),
            index: 1,
            previous_digest: String::new(),
            kind: ENTRY_CREATE.to_string(),
            signer_device_id: "deviceAAAAAAAAAAA01".to_string(),
            subject_device_id: "deviceAAAAAAAAAAA01".to_string(),
            subject_signing_key: URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
            subject_package_key: package_key.to_string(),
            sealed_label: URL_SAFE_NO_PAD.encode([3u8; 48]),
            epoch_after: 1,
            snapshot_floor: 0,
            signature: String::new(),
        }
        .sign(&signing)
    }

    fn key_of(length: usize) -> String {
        URL_SAFE_NO_PAD.encode(vec![5u8; length])
    }

    #[test]
    fn an_entry_may_carry_a_classical_or_a_hybrid_package_key() {
        assert!(entry_with(&key_of(32)).validate().is_ok());
        assert!(entry_with(&key_of(HYBRID_KEY_BYTES)).validate().is_ok());
        assert_eq!(HYBRID_KEY_BYTES, 1216);
    }

    #[test]
    fn a_package_key_of_any_other_length_or_form_is_refused() {
        for length in [0, 1, 31, 33, 64, 1215, 1217, 64 * 1024] {
            assert!(entry_with(&key_of(length)).validate().is_err(), "{length}");
        }
        assert!(entry_with(&format!("{}=", key_of(HYBRID_KEY_BYTES)))
            .validate()
            .is_err());
        assert!(entry_with(&format!("{}\n", key_of(HYBRID_KEY_BYTES)))
            .validate()
            .is_err());
    }
}
