use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{decrypt_bytes, encrypt_bytes};
use crate::history::HISTORY_RETENTION_SECONDS;
use crate::snapshot::snapshot_for;
use crate::trash::TRASH_RETENTION_SECONDS;
use crate::types::{
    CipherBlob, Folder, HistoryEntry, ItemPreview, TaggedItem, TrashedItem, VaultPayload,
    VaultSnapshot,
};
use crate::util::{fill_random, unix_timestamp};
use crate::VaultResult;

const RECORD_AAD_PREFIX: &[u8] = b"sesame:memory-record:v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultHeader {
    vault_name: String,
    folders: Vec<Folder>,
    vault_id: Option<String>,
    revision: u64,
}

impl Zeroize for VaultHeader {
    fn zeroize(&mut self) {
        self.vault_name.zeroize();
        self.folders.zeroize();
        self.vault_id.zeroize();
        self.revision.zeroize();
    }
}

struct SealedRecord {
    id: String,
    kind: String,
    blob: CipherBlob,
}

pub struct VaultRecordStore {
    key: Zeroizing<[u8; 32]>,
    header: CipherBlob,
    index: VaultSnapshot,
    active: Vec<SealedRecord>,
    trash: Vec<SealedRecord>,
    history: Vec<SealedRecord>,
}

pub struct OpenedPayload(VaultPayload);

impl Deref for OpenedPayload {
    type Target = VaultPayload;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OpenedPayload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for OpenedPayload {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct OpenedItem(TaggedItem);

impl Deref for OpenedItem {
    type Target = TaggedItem;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for OpenedItem {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl VaultRecordStore {
    pub(crate) fn from_payload(payload: &VaultPayload) -> VaultResult<Self> {
        let mut key = Zeroizing::new([0_u8; 32]);
        fill_random(&mut *key);
        Self::from_payload_with_key(key, payload)
    }

    fn from_payload_with_key(
        key: Zeroizing<[u8; 32]>,
        payload: &VaultPayload,
    ) -> VaultResult<Self> {
        ensure_unique_active_ids(payload)?;
        let header_value = Zeroizing::new(VaultHeader {
            vault_name: payload.vault_name.clone(),
            folders: payload.folders.clone(),
            vault_id: payload.vault_id.clone(),
            revision: payload.revision,
        });
        let header = seal(&key, "header", "vault", "metadata", &*header_value)?;
        let mut active = Vec::new();
        macro_rules! seal_active {
            ($items:expr, $kind:expr) => {
                for item in $items {
                    active.push(seal_item(&key, "active", &item.id, $kind, item)?);
                }
            };
        }
        seal_active!(&payload.entries, "login");
        seal_active!(&payload.identities, "identity");
        seal_active!(&payload.secure_notes, "secure_note");
        seal_active!(&payload.cards, "card");
        seal_active!(&payload.wifi_networks, "wifi_network");
        seal_active!(&payload.ssh_keys, "ssh_key");
        seal_active!(&payload.software_licenses, "software_license");
        seal_active!(&payload.documents, "document");
        seal_active!(&payload.custom_records, "custom_record");
        let trash = payload
            .trash
            .iter()
            .map(|entry| seal_item(&key, "trash", entry.item.id(), entry.item.kind(), entry))
            .collect::<VaultResult<Vec<_>>>()?;
        let history = payload
            .history
            .iter()
            .map(|entry| seal_item(&key, "history", &entry.id, entry.item.kind(), entry))
            .collect::<VaultResult<Vec<_>>>()?;
        let index = snapshot_for(payload);
        Ok(Self {
            key,
            header,
            index,
            active,
            trash,
            history,
        })
    }

    pub fn open_payload(&self) -> VaultResult<OpenedPayload> {
        self.open_payload_with_key(&self.key)
    }

    pub fn snapshot(&self) -> VaultSnapshot {
        self.index.clone()
    }

    fn open_payload_with_key(&self, key: &[u8; 32]) -> VaultResult<OpenedPayload> {
        let header = Zeroizing::new(open::<VaultHeader>(
            key,
            "header",
            "vault",
            "metadata",
            &self.header,
        )?);
        let mut payload = OpenedPayload(VaultPayload {
            vault_name: header.vault_name.clone(),
            folders: header.folders.clone(),
            vault_id: header.vault_id.clone(),
            revision: header.revision,
            ..VaultPayload::default()
        });
        let mut active_ids = HashSet::new();
        for record in &self.active {
            if !active_ids.insert(record.id.as_str()) {
                return Err(invalid_store());
            }
            let mut item = open_active_record(key, record)?;
            if validate_item_locator(&item, record).is_err() {
                item.zeroize();
                return Err(invalid_store());
            }
            push_active(&mut payload, item);
        }
        for record in &self.trash {
            let mut entry: TrashedItem = open_record(key, "trash", record)?;
            if validate_item_locator(&entry.item, record).is_err() {
                entry.zeroize();
                return Err(invalid_store());
            }
            payload.trash.push(entry);
        }
        for record in &self.history {
            let mut entry: HistoryEntry = open_record(key, "history", record)?;
            if entry.id != record.id || entry.item.kind() != record.kind {
                entry.zeroize();
                return Err(invalid_store());
            }
            payload.history.push(entry);
        }
        Ok(payload)
    }

    pub fn open_item(&self, id: &str) -> VaultResult<OpenedItem> {
        let record = self
            .active
            .iter()
            .find(|record| record.id == id)
            .ok_or("That saved item no longer exists.")?;
        let mut item = open_active_record(&self.key, record)?;
        if validate_item_locator(&item, record).is_err() {
            item.zeroize();
            return Err(invalid_store());
        }
        Ok(OpenedItem(item))
    }

    pub fn trash_item_preview(&self, id: &str) -> VaultResult<ItemPreview> {
        let record = self
            .trash
            .iter()
            .find(|record| record.id == id)
            .ok_or("That deleted item is no longer in trash.")?;
        let entry = Zeroizing::new(open_record::<TrashedItem>(&self.key, "trash", record)?);
        validate_item_locator(&entry.item, record)?;
        let cutoff = unix_timestamp().saturating_sub(TRASH_RETENTION_SECONDS);
        if entry.deleted_at <= cutoff {
            return Err("That deleted item is no longer in trash.".into());
        }
        Ok(entry.item.preview())
    }

    pub fn history_item_preview(&self, id: &str) -> VaultResult<ItemPreview> {
        let record = self
            .history
            .iter()
            .find(|record| record.id == id)
            .ok_or("That version is no longer available.")?;
        let entry = Zeroizing::new(open_record::<HistoryEntry>(&self.key, "history", record)?);
        if entry.id != record.id || entry.item.kind() != record.kind {
            return Err(invalid_store());
        }
        let cutoff = unix_timestamp().saturating_sub(HISTORY_RETENTION_SECONDS);
        if entry.captured_at <= cutoff {
            return Err("That version is no longer available.".into());
        }
        Ok(entry.item.preview())
    }

    #[cfg(test)]
    fn replace_payload(&mut self, payload: &VaultPayload) -> VaultResult<()> {
        let mut replacement_key = Zeroizing::new([0_u8; 32]);
        fill_random(&mut *replacement_key);
        let replacement = Self::from_payload_with_key(replacement_key, payload)?;
        *self = replacement;
        Ok(())
    }
}

fn ensure_unique_active_ids(payload: &VaultPayload) -> VaultResult<()> {
    let mut ids = HashSet::new();
    macro_rules! check_ids {
        ($items:expr) => {
            for item in $items {
                if !ids.insert(item.id.as_str()) {
                    return Err(
                        "The vault contains duplicate item ids and cannot be saved safely.".into(),
                    );
                }
            }
        };
    }
    check_ids!(&payload.entries);
    check_ids!(&payload.identities);
    check_ids!(&payload.secure_notes);
    check_ids!(&payload.cards);
    check_ids!(&payload.wifi_networks);
    check_ids!(&payload.ssh_keys);
    check_ids!(&payload.software_licenses);
    check_ids!(&payload.documents);
    check_ids!(&payload.custom_records);
    Ok(())
}

fn seal_item<T: Serialize>(
    key: &[u8; 32],
    role: &str,
    id: &str,
    kind: &str,
    value: &T,
) -> VaultResult<SealedRecord> {
    Ok(SealedRecord {
        id: id.to_string(),
        kind: kind.to_string(),
        blob: seal(key, role, id, kind, value)?,
    })
}

fn seal<T: Serialize>(
    key: &[u8; 32],
    role: &str,
    id: &str,
    kind: &str,
    value: &T,
) -> VaultResult<CipherBlob> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|_| "Sesame could not protect the unlocked vault session.".to_string())?,
    );
    encrypt_bytes(key, &plaintext, &record_aad(role, id, kind))
        .map_err(|_| "Sesame could not protect the unlocked vault session.".to_string())
}

fn open_record<T: DeserializeOwned>(
    key: &[u8; 32],
    role: &str,
    record: &SealedRecord,
) -> VaultResult<T> {
    open(key, role, &record.id, &record.kind, &record.blob)
}

fn open_active_record(key: &[u8; 32], record: &SealedRecord) -> VaultResult<TaggedItem> {
    let item = match record.kind.as_str() {
        "login" => TaggedItem::Login(open_record(key, "active", record)?),
        "identity" => TaggedItem::Identity(open_record(key, "active", record)?),
        "secure_note" => TaggedItem::SecureNote(open_record(key, "active", record)?),
        "card" => TaggedItem::Card(open_record(key, "active", record)?),
        "wifi_network" => TaggedItem::WifiNetwork(open_record(key, "active", record)?),
        "ssh_key" => TaggedItem::SshKey(open_record(key, "active", record)?),
        "software_license" => TaggedItem::SoftwareLicense(open_record(key, "active", record)?),
        "document" => TaggedItem::Document(open_record(key, "active", record)?),
        "custom_record" => TaggedItem::CustomRecord(open_record(key, "active", record)?),
        _ => return Err(invalid_store()),
    };
    Ok(item)
}

fn push_active(payload: &mut VaultPayload, item: TaggedItem) {
    match item {
        TaggedItem::Login(item) => payload.entries.push(item),
        TaggedItem::Identity(item) => payload.identities.push(item),
        TaggedItem::SecureNote(item) => payload.secure_notes.push(item),
        TaggedItem::Card(item) => payload.cards.push(item),
        TaggedItem::WifiNetwork(item) => payload.wifi_networks.push(item),
        TaggedItem::SshKey(item) => payload.ssh_keys.push(item),
        TaggedItem::SoftwareLicense(item) => payload.software_licenses.push(item),
        TaggedItem::Document(item) => payload.documents.push(item),
        TaggedItem::CustomRecord(item) => payload.custom_records.push(item),
    }
}

fn open<T: DeserializeOwned>(
    key: &[u8; 32],
    role: &str,
    id: &str,
    kind: &str,
    blob: &CipherBlob,
) -> VaultResult<T> {
    let plaintext = Zeroizing::new(
        decrypt_bytes(key, blob, &record_aad(role, id, kind)).map_err(|_| invalid_store())?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| invalid_store())
}

fn validate_item_locator(item: &TaggedItem, record: &SealedRecord) -> VaultResult<()> {
    if item.id() != record.id || item.kind() != record.kind {
        return Err(invalid_store());
    }
    Ok(())
}

fn record_aad(role: &str, id: &str, kind: &str) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(RECORD_AAD_PREFIX.len() + role.len() + id.len() + kind.len() + 12);
    aad.extend_from_slice(RECORD_AAD_PREFIX);
    for value in [role.as_bytes(), id.as_bytes(), kind.as_bytes()] {
        aad.extend_from_slice(&(value.len() as u32).to_be_bytes());
        aad.extend_from_slice(value);
    }
    aad
}

fn invalid_store() -> String {
    "The unlocked vault session could not be authenticated. Lock and unlock Sesame again."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VaultEntry;

    fn payload() -> VaultPayload {
        VaultPayload {
            vault_name: "Fictional vault".to_string(),
            entries: vec![
                VaultEntry {
                    id: "login-a".to_string(),
                    title: "Northwind".to_string(),
                    password: "fictional-alpha-secret".to_string(),
                    ..VaultEntry::default()
                },
                VaultEntry {
                    id: "login-b".to_string(),
                    title: "Contoso".to_string(),
                    password: "fictional-beta-secret".to_string(),
                    ..VaultEntry::default()
                },
            ],
            vault_id: Some("vault-fictional".to_string()),
            revision: 7,
            ..VaultPayload::default()
        }
    }

    #[test]
    fn round_trip_keeps_records_and_metadata() {
        let store = VaultRecordStore::from_payload(&payload()).expect("record store");

        let opened = store.open_payload().expect("opened payload");

        assert_eq!(opened.vault_name, "Fictional vault");
        assert_eq!(opened.vault_id.as_deref(), Some("vault-fictional"));
        assert_eq!(opened.revision, 7);
        assert_eq!(opened.entries.len(), 2);
        assert_eq!(opened.entries[1].password, "fictional-beta-secret");
    }

    #[test]
    fn one_item_can_open_without_opening_the_other_records() {
        let store = VaultRecordStore::from_payload(&payload()).expect("record store");

        let opened = store.open_item("login-b").expect("opened item");

        let password = match &*opened {
            TaggedItem::Login(entry) => entry.password.as_str(),
            _ => "",
        };
        assert_eq!(password, "fictional-beta-secret");
    }

    #[test]
    fn wrong_key_cannot_open_records() {
        let store = VaultRecordStore::from_payload_with_key(Zeroizing::new([9_u8; 32]), &payload())
            .expect("record store");

        let result = store.open_payload_with_key(&[10_u8; 32]);

        assert!(result.is_err());
    }

    #[test]
    fn swapped_record_ciphertexts_are_rejected() {
        let mut store = VaultRecordStore::from_payload(&payload()).expect("record store");
        let (left, right) = store.active.split_at_mut(1);
        std::mem::swap(&mut left[0].blob, &mut right[0].blob);

        let result = store.open_payload();

        assert!(result.is_err());
    }

    #[test]
    fn relabelled_records_are_rejected() {
        let mut store = VaultRecordStore::from_payload(&payload()).expect("record store");
        let original_kind = store.active[0].kind.clone();
        store.active[0].kind = "card".to_string();

        assert!(store.open_payload().is_err());
        assert!(store.open_item("login-a").is_err());

        store.active[0].kind = original_kind;
        store.active[0].id = "login-b".to_string();

        assert!(store.open_payload().is_err());
        assert!(store.open_item("login-b").is_err());
    }

    #[test]
    fn opened_plaintext_zeroizes_in_place() {
        let store = VaultRecordStore::from_payload(&payload()).expect("record store");
        let mut opened = store.open_payload().expect("opened payload");

        opened.zeroize();

        assert!(opened.entries.is_empty());
        assert!(opened.history.is_empty());
        assert!(opened.vault_name.is_empty());

        let mut item = TaggedItem::Login(VaultEntry {
            id: "login-a".to_string(),
            password: "fictional-alpha-secret".to_string(),
            ..VaultEntry::default()
        });
        item.zeroize();

        assert!(matches!(&item, TaggedItem::Login(entry) if entry.password.is_empty()));
    }

    #[test]
    fn malformed_record_is_rejected() {
        let mut store = VaultRecordStore::from_payload(&payload()).expect("record store");
        store.active[0].blob.ciphertext = "not-base64".to_string();

        let result = store.open_payload();

        assert!(result.is_err());
    }

    #[test]
    fn failed_replacement_keeps_the_previous_records() {
        let mut store = VaultRecordStore::from_payload(&payload()).expect("record store");
        let mut invalid = payload();
        invalid.entries[1].id = invalid.entries[0].id.clone();

        let result = store.replace_payload(&invalid);

        assert!(result.is_err());
        let opened = store.open_payload().expect("previous payload");
        assert_eq!(opened.entries[0].id, "login-a");
        assert_eq!(opened.entries[1].id, "login-b");
    }

    #[test]
    fn idle_index_omits_secret_canaries() {
        let store = VaultRecordStore::from_payload(&payload()).expect("record store");

        let index = serde_json::to_string(&store.snapshot()).expect("serialized index");

        assert!(!index.contains("fictional-alpha-secret"));
        assert!(!index.contains("fictional-beta-secret"));
        assert!(index.contains("Northwind"));
        assert!(index.contains("Contoso"));
    }

    #[test]
    fn idle_index_does_not_open_tampered_records() {
        let mut store = VaultRecordStore::from_payload(&payload()).expect("record store");
        store.active[0].blob.ciphertext = "not-base64".to_string();

        let index = store.snapshot();

        assert_eq!(index.entries.len(), 2);
        assert!(store.open_item("login-a").is_err());
    }

    #[test]
    fn selected_trash_and_history_previews_do_not_return_secrets() {
        let mut value = payload();
        value.trash.push(TrashedItem {
            item: TaggedItem::Login(value.entries[0].clone()),
            deleted_at: unix_timestamp(),
        });
        value.history.push(HistoryEntry {
            id: "fictional-history".to_string(),
            item: TaggedItem::Login(value.entries[1].clone()),
            captured_at: unix_timestamp(),
            operation: Default::default(),
        });
        let store = VaultRecordStore::from_payload(&value).expect("record store");

        let trash = store.trash_item_preview("login-a").expect("trash preview");
        let history = store
            .history_item_preview("fictional-history")
            .expect("history preview");
        let previews = serde_json::to_string(&(trash, history)).expect("serialized previews");

        assert!(previews.contains("Northwind"));
        assert!(previews.contains("Contoso"));
        assert!(!previews.contains("fictional-alpha-secret"));
        assert!(!previews.contains("fictional-beta-secret"));
    }
}
