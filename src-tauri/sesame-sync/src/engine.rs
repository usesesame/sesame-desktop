use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::Deserialize;

use super::canonical::{ProofError, ProofResult, REQUEST_TIMESTAMP_SKEW, VERSION_V3};
use super::checkpoint::Checkpoint;
use super::devicelist::{
    DeviceList, DeviceListEntry, ENTRY_ADD, ENTRY_CREATE, ENTRY_KEY, ENTRY_REMOVE, ENTRY_ROTATE,
};
use super::header::{verify_header, verify_header_chain, Header};
use super::identity::DeviceIdentity;
use super::pairing::ApproverIdentity;
use super::request::{KeyPackageV3, Receipt};
use super::state::{StoredReceipt, SyncState};

pub const MAX_LABEL_CHARS: usize = 64;
const LABEL_AAD: &[u8] = b"sesame-sync-v3-label";
const LABEL_NONCE_BYTES: usize = 24;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServedHeader {
    #[serde(flatten)]
    pub header: Header,
    pub digest: String,
    pub receipt: String,
    pub accepted_at: String,
}

impl ServedHeader {
    pub fn accepted_at_unix(&self) -> Option<u64> {
        chrono::DateTime::parse_from_rfc3339(&self.accepted_at)
            .ok()
            .and_then(|time| u64::try_from(time.timestamp()).ok())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServedCheckpoint {
    #[serde(flatten)]
    pub checkpoint: Checkpoint,
}

pub struct PeerView<'a> {
    pub checkpoints: &'a [ServedCheckpoint],
    pub history: &'a [Header],
}

pub struct ServerView<'a> {
    pub entries_after: &'a [DeviceListEntry],
    pub headers: &'a [ServedHeader],
    pub latest_revision: u64,
}

#[derive(Debug)]
pub struct VerifiedUpdate {
    pub entries: Vec<DeviceListEntry>,
    pub list: DeviceList,
    pub head: Option<Header>,
    pub receipt: Option<StoredReceipt>,
}

pub fn floor_for(entries: &[DeviceListEntry], device_id: &str) -> u64 {
    entries
        .iter()
        .find(|entry| entry.kind == ENTRY_ADD && entry.subject_device_id == device_id)
        .map_or(0, |entry| entry.snapshot_floor)
}

fn check_receipt(served: &ServedHeader, instance_key: &str) -> ProofResult<StoredReceipt> {
    if served.header.digest() != served.digest {
        return Err(ProofError::history(
            "the service named a different header digest",
        ));
    }
    let accepted_at = served
        .accepted_at_unix()
        .ok_or_else(|| ProofError::history("the service sent an unreadable acceptance time"))?;
    Receipt {
        vault_id: &served.header.vault_id,
        revision: served.header.revision,
        header_digest: &served.digest,
        vault_epoch: served.header.vault_epoch,
        accepted_at,
    }
    .verify(instance_key, &served.receipt)?;
    Ok(StoredReceipt {
        signature: served.receipt.clone(),
        accepted_at,
    })
}

pub fn verify_server_view(
    state: &SyncState,
    instance_key: &str,
    view: &ServerView<'_>,
) -> ProofResult<VerifiedUpdate> {
    let mut list = state.list()?;
    let mut entries = state.entries.clone();
    for entry in view.entries_after {
        list.extend(entry)?;
        entries.push(entry.clone());
    }
    let own_floor = floor_for(&entries, &state.device_id);
    let floor = own_floor.max(state.floor);
    let mut receipt = state.receipt.clone();
    let mut head = state.head.clone();

    if let Some(current) = state.head.as_ref() {
        if view.latest_revision < current.revision {
            return Err(ProofError::history(
                "the service offered an older revision than this device already applied",
            ));
        }
        let mut headers = view.headers;
        if let Some(first) = headers.first() {
            if first.header.revision == current.revision {
                if first.header.digest() != current.digest() {
                    return Err(ProofError::history(
                        "the service shows a different revision than this device applied",
                    ));
                }
                headers = &headers[1..];
            }
        }
        if headers.is_empty() && view.latest_revision != current.revision {
            return Err(ProofError::history(
                "the service named a newer revision and sent no history for it",
            ));
        }
        let plain: Vec<Header> = headers.iter().map(|served| served.header.clone()).collect();
        verify_header_chain(&list, Some(current), &plain)?;
        for served in headers {
            receipt = Some(check_receipt(served, instance_key)?);
        }
        if let Some(last) = headers.last() {
            if last.header.revision != view.latest_revision {
                return Err(ProofError::history(
                    "the history the service sent stops before its latest revision",
                ));
            }
            head = Some(last.header.clone());
        }
    } else if let Some(newest) = view.headers.last() {
        verify_header(&list, None, &newest.header)?;
        if newest.header.revision < floor {
            return Err(ProofError::history(
                "the service offered a revision older than the one this device was added at",
            ));
        }
        if newest.header.revision != view.latest_revision {
            return Err(ProofError::history(
                "the history the service sent stops before its latest revision",
            ));
        }
        receipt = Some(check_receipt(newest, instance_key)?);
        head = Some(newest.header.clone());
    } else if view.latest_revision != 0 {
        return Err(ProofError::history(
            "the service named a revision and sent no header for it",
        ));
    }

    Ok(VerifiedUpdate {
        entries,
        list,
        head,
        receipt,
    })
}

pub fn oldest_revision_to_compare(
    head: Option<&Header>,
    own_device_id: &str,
    checkpoints: &[ServedCheckpoint],
) -> Option<u64> {
    let current = head?.revision;
    checkpoints
        .iter()
        .filter(|served| served.checkpoint.device_id != own_device_id)
        .map(|served| served.checkpoint.header_revision)
        .filter(|revision| *revision > 0 && *revision < current)
        .min()
}

pub fn check_peer_checkpoints(
    list: &DeviceList,
    head: Option<&Header>,
    own_device_id: &str,
    view: &PeerView<'_>,
    now: u64,
) -> ProofResult<Option<u64>> {
    let mut confirmed: Option<u64> = None;
    for served in view.checkpoints {
        let checkpoint = &served.checkpoint;
        if checkpoint.device_id == own_device_id {
            continue;
        }
        let Some(signer) = list.member_at(
            &checkpoint.device_id,
            checkpoint.device_list_index.min(list.head()),
        ) else {
            continue;
        };
        checkpoint.verify_signature(&signer.signing_key)?;
        if checkpoint.vault_id != list.vault_id() {
            return Err(ProofError::invalid("a checkpoint for another vault"));
        }
        if checkpoint.device_list_index > list.head() {
            return Err(ProofError::device_list(
                "another device has seen a newer device list than the service shows",
            ));
        }
        if list.digest_at(checkpoint.device_list_index)
            != Some(checkpoint.device_list_digest.as_str())
        {
            return Err(ProofError::device_list(
                "another device has seen a different device list",
            ));
        }
        if !headers_agree(checkpoint, head, view.history)? {
            continue;
        }
        if checkpoint.observed_at <= now.saturating_add(REQUEST_TIMESTAMP_SKEW) {
            confirmed = confirmed.max(Some(checkpoint.observed_at));
        }
    }
    Ok(confirmed)
}

fn headers_agree(
    checkpoint: &Checkpoint,
    head: Option<&Header>,
    history: &[Header],
) -> ProofResult<bool> {
    if checkpoint.header_revision == 0 {
        return Ok(true);
    }
    let Some(head) = head else {
        return Err(ProofError::history(
            "another device has seen a snapshot that the service no longer shows",
        ));
    };
    if checkpoint.header_revision > head.revision {
        return Err(ProofError::history(
            "another device has seen a newer snapshot than the service shows",
        ));
    }
    if checkpoint.header_revision == head.revision {
        if checkpoint.header_digest != head.digest() {
            return Err(ProofError::history(
                "another device has seen a different snapshot at the same revision",
            ));
        }
        return Ok(true);
    }
    match history
        .iter()
        .find(|header| header.revision == checkpoint.header_revision)
    {
        Some(header) if header.digest() == checkpoint.header_digest => Ok(true),
        Some(_) => Err(ProofError::history(
            "another device has seen a different snapshot than this history holds",
        )),
        None => Ok(false),
    }
}

pub fn seal_label(
    vault_key: &[u8],
    vault_id: &str,
    device_id: &str,
    label: &str,
) -> ProofResult<String> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return Err(ProofError::invalid("device name"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key)
        .map_err(|_| ProofError::invalid("vault key"))?;
    let mut nonce = [0u8; LABEL_NONCE_BYTES];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| ProofError::invalid("randomness"))?;
    let aad = label_aad(vault_id, device_id);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: label.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| ProofError::invalid("label"))?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(sealed))
}

pub fn open_label(
    vault_key: &[u8],
    vault_id: &str,
    device_id: &str,
    sealed: &str,
) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
    if bytes.len() <= LABEL_NONCE_BYTES {
        return None;
    }
    let (nonce, ciphertext) = bytes.split_at(LABEL_NONCE_BYTES);
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key).ok()?;
    let aad = label_aad(vault_id, device_id);
    let nonce: [u8; LABEL_NONCE_BYTES] = nonce.try_into().ok()?;
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()?;
    String::from_utf8(plain).ok()
}

fn label_aad(vault_id: &str, device_id: &str) -> Vec<u8> {
    let mut aad = LABEL_AAD.to_vec();
    for part in [vault_id.as_bytes(), device_id.as_bytes()] {
        aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad
}

fn encoded(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn create_entry(
    identity: &DeviceIdentity,
    vault_id: &str,
    sealed_label: &str,
) -> DeviceListEntry {
    identity.sign_entry(DeviceListEntry {
        vault_id: vault_id.to_string(),
        index: 1,
        previous_digest: String::new(),
        kind: ENTRY_CREATE.to_string(),
        signer_device_id: identity.device_id.clone(),
        subject_device_id: identity.device_id.clone(),
        subject_signing_key: encoded(&identity.signing_public_key()),
        subject_package_key: encoded(&identity.package_public_key()),
        sealed_label: sealed_label.to_string(),
        epoch_after: 1,
        snapshot_floor: 0,
        signature: String::new(),
    })
}

pub struct NewDevice<'a> {
    pub device_id: &'a str,
    pub signing_key: &'a str,
    pub package_key: &'a str,
}

pub fn add_entry(
    identity: &DeviceIdentity,
    list: &DeviceList,
    subject: &NewDevice<'_>,
    sealed_label: &str,
    floor: u64,
) -> ProofResult<DeviceListEntry> {
    let index = list
        .head()
        .checked_add(1)
        .ok_or_else(|| ProofError::device_list("index overflow"))?;
    Ok(identity.sign_entry(DeviceListEntry {
        vault_id: list.vault_id().to_string(),
        index,
        previous_digest: list.head_digest().to_string(),
        kind: ENTRY_ADD.to_string(),
        signer_device_id: identity.device_id.clone(),
        subject_device_id: subject.device_id.to_string(),
        subject_signing_key: subject.signing_key.to_string(),
        subject_package_key: subject.package_key.to_string(),
        sealed_label: sealed_label.to_string(),
        epoch_after: list.epoch(),
        snapshot_floor: floor,
        signature: String::new(),
    }))
}

pub fn remove_entry(
    identity: &DeviceIdentity,
    list: &DeviceList,
    subject_device_id: &str,
) -> ProofResult<DeviceListEntry> {
    let index = list
        .head()
        .checked_add(1)
        .ok_or_else(|| ProofError::device_list("index overflow"))?;
    let epoch = list
        .epoch()
        .checked_add(1)
        .ok_or_else(|| ProofError::device_list("epoch overflow"))?;
    Ok(identity.sign_entry(DeviceListEntry {
        vault_id: list.vault_id().to_string(),
        index,
        previous_digest: list.head_digest().to_string(),
        kind: ENTRY_REMOVE.to_string(),
        signer_device_id: identity.device_id.clone(),
        subject_device_id: subject_device_id.to_string(),
        subject_signing_key: String::new(),
        subject_package_key: String::new(),
        sealed_label: String::new(),
        epoch_after: epoch,
        snapshot_floor: 0,
        signature: String::new(),
    }))
}

pub fn key_entry(
    identity: &DeviceIdentity,
    list: &DeviceList,
    package_key: &str,
) -> ProofResult<DeviceListEntry> {
    let index = list
        .head()
        .checked_add(1)
        .ok_or_else(|| ProofError::device_list("index overflow"))?;
    Ok(identity.sign_entry(DeviceListEntry {
        vault_id: list.vault_id().to_string(),
        index,
        previous_digest: list.head_digest().to_string(),
        kind: ENTRY_KEY.to_string(),
        signer_device_id: identity.device_id.clone(),
        subject_device_id: identity.device_id.clone(),
        subject_signing_key: String::new(),
        subject_package_key: package_key.to_string(),
        sealed_label: String::new(),
        epoch_after: list.epoch(),
        snapshot_floor: 0,
        signature: String::new(),
    }))
}

pub fn rotate_entry(identity: &DeviceIdentity, list: &DeviceList) -> ProofResult<DeviceListEntry> {
    let index = list
        .head()
        .checked_add(1)
        .ok_or_else(|| ProofError::device_list("index overflow"))?;
    let epoch = list
        .epoch()
        .checked_add(1)
        .ok_or_else(|| ProofError::device_list("epoch overflow"))?;
    Ok(identity.sign_entry(DeviceListEntry {
        vault_id: list.vault_id().to_string(),
        index,
        previous_digest: list.head_digest().to_string(),
        kind: ENTRY_ROTATE.to_string(),
        signer_device_id: identity.device_id.clone(),
        subject_device_id: identity.device_id.clone(),
        subject_signing_key: String::new(),
        subject_package_key: String::new(),
        sealed_label: String::new(),
        epoch_after: epoch,
        snapshot_floor: 0,
        signature: String::new(),
    }))
}

pub struct HeaderPlan {
    pub vault_id: String,
    pub device_id: String,
    pub revision: u64,
    pub vault_epoch: u64,
    pub device_list_index: u64,
    pub device_list_digest: String,
    pub previous_digest: String,
}

impl HeaderPlan {
    pub fn aad(&self) -> Vec<u8> {
        self.header_with("", 0, "").aad()
    }

    fn header_with(&self, ciphertext_digest: &str, ciphertext_length: u64, nonce: &str) -> Header {
        Header {
            version: VERSION_V3,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            revision: self.revision,
            vault_epoch: self.vault_epoch,
            device_list_index: self.device_list_index,
            device_list_digest: self.device_list_digest.clone(),
            previous_digest: self.previous_digest.clone(),
            ciphertext_digest: ciphertext_digest.to_string(),
            ciphertext_length,
            nonce: nonce.to_string(),
            signature: String::new(),
        }
    }
}

pub fn plan_header(
    device_id: &str,
    list: &DeviceList,
    previous: Option<&Header>,
) -> ProofResult<HeaderPlan> {
    let index = list.head();
    let digest = list
        .digest_at(index)
        .ok_or_else(|| ProofError::device_list("no device list"))?
        .to_string();
    let epoch = list
        .epoch_at(index)
        .ok_or_else(|| ProofError::device_list("no device list"))?;
    let revision = match previous {
        Some(previous) => previous
            .revision
            .checked_add(1)
            .ok_or_else(|| ProofError::history("revision overflow"))?,
        None => 1,
    };
    Ok(HeaderPlan {
        vault_id: list.vault_id().to_string(),
        device_id: device_id.to_string(),
        revision,
        vault_epoch: epoch,
        device_list_index: index,
        device_list_digest: digest,
        previous_digest: previous.map(Header::digest).unwrap_or_default(),
    })
}

pub fn build_header(
    identity: &DeviceIdentity,
    plan: &HeaderPlan,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Header {
    use sha2::{Digest, Sha256};
    identity.sign_header(plan.header_with(
        &encoded(&Sha256::digest(ciphertext)),
        ciphertext.len() as u64,
        &encoded(nonce),
    ))
}

pub fn verify_accepted(
    header: &Header,
    accepted_digest: &str,
    accepted_revision: u64,
    receipt: &str,
    accepted_at: &str,
    instance_key: &str,
) -> ProofResult<StoredReceipt> {
    if accepted_revision != header.revision || accepted_digest != header.digest() {
        return Err(ProofError::history(
            "the service recorded a different version than this device sent",
        ));
    }
    check_receipt(
        &ServedHeader {
            header: header.clone(),
            digest: accepted_digest.to_string(),
            receipt: receipt.to_string(),
            accepted_at: accepted_at.to_string(),
        },
        instance_key,
    )
}

pub struct JoinCheck<'a> {
    pub device_id: &'a str,
    pub signing_key: &'a str,
    pub package_key: &'a str,
    pub approver: &'a ApproverIdentity,
}

pub fn verify_package_for_removal(
    entries: &[DeviceListEntry],
    package: &KeyPackageV3,
) -> ProofResult<()> {
    let entry = entries
        .iter()
        .find(|entry| {
            (entry.kind == ENTRY_REMOVE || entry.kind == ENTRY_ROTATE)
                && entry.epoch_after == package.vault_epoch
        })
        .ok_or_else(|| {
            ProofError::device_list(
                "the device list shows no removal or rotation that made this key",
            )
        })?;
    if package.entry_digest != entry.digest() || package.sender_device_id != entry.signer_device_id
    {
        return Err(ProofError::history(
            "the key package belongs to a different device list entry",
        ));
    }
    Ok(())
}

pub fn verify_join(
    check: &JoinCheck<'_>,
    entries: &[DeviceListEntry],
    package: &KeyPackageV3,
) -> ProofResult<DeviceList> {
    let list = DeviceList::verify(entries)?;
    if list.vault_id() != check.approver.vault_id {
        return Err(ProofError::device_list(
            "the vault the service offered is not the one the other device named",
        ));
    }
    list.member(check.device_id)
        .filter(|member| {
            member.removed_index == 0
                && member.signing_key == check.signing_key
                && member.package_key == check.package_key
        })
        .ok_or_else(|| {
            ProofError::device_list("the service did not add this device with its own keys")
        })?;
    let adding = entries
        .iter()
        .find(|entry| entry.kind == ENTRY_ADD && entry.subject_device_id == check.device_id)
        .ok_or_else(|| {
            ProofError::device_list("the device list does not show this device being added")
        })?;
    let approver = list
        .member_at(&check.approver.device_id, adding.index)
        .filter(|member| member.signing_key == check.approver.signing_key)
        .ok_or_else(|| {
            ProofError::device_list(
                "the device that added this one is not the device that gave the code",
            )
        })?;
    if adding.signer_device_id != approver.device_id {
        return Err(ProofError::device_list(
            "the device that added this one is not the device that gave the code",
        ));
    }
    if list.digest_at(adding.index.saturating_sub(1)) != Some(check.approver.head_digest.as_str()) {
        return Err(ProofError::device_list(
            "the device list changed while pairing",
        ));
    }
    package.verify(&check.approver.signing_key)?;
    if package.entry_digest != adding.digest() {
        return Err(ProofError::history(
            "the key package belongs to a different device list entry",
        ));
    }
    if package.recipient_device_id != check.device_id
        || package.sender_device_id != check.approver.device_id
        || package.vault_id != check.approver.vault_id
        || package.vault_epoch != list.epoch()
    {
        return Err(ProofError::history(
            "the key package is not the one this device was promised",
        ));
    }
    Ok(list)
}
