//! Vault-format migrations.
//! A migration runs only after the vault key has been proven, so a damaged or foreign file is never rewritten.

use std::collections::{HashMap, HashSet};

use crate::types::{ItemMetadata, VaultEntry};
use crate::util::{random_id, unix_timestamp};
use crate::{
    Folder, TaggedItem, VaultFile, VaultPayload, VaultResult, SETUP_STATE_FORMAT,
    VAULT_FORMAT_VERSION,
};

pub fn fresh_vault_id() -> String {
    random_id()
}

pub const MIN_SUPPORTED_VAULT_FORMAT: u8 = 2;

/// Removes the dead format-2 device wrap; returns whether the caller must rewrite the file.
pub(crate) fn migrate_vault_file(file: &mut VaultFile) -> VaultResult<bool> {
    if file.format_version < MIN_SUPPORTED_VAULT_FORMAT
        || file.format_version > VAULT_FORMAT_VERSION
    {
        return Err("This vault uses a format Sesame does not understand yet.".into());
    }

    let mut changed = false;
    // The device wrap is no longer an unlock method in any supported format.
    if file.legacy_device_wrap.take().is_some() {
        changed = true;
    }
    if file.format_version < VAULT_FORMAT_VERSION {
        if file.format_version < SETUP_STATE_FORMAT {
            file.setup_complete = true;
        }
        file.format_version = VAULT_FORMAT_VERSION;
        changed = true;
    }
    Ok(changed)
}

fn move_login_legacy_fields(entry: &mut VaultEntry) -> bool {
    if entry.legacy_fields.is_empty() {
        return false;
    }
    let moved = crate::custom_fields::from_legacy(&entry.legacy_fields);
    entry.custom_fields.extend(moved);
    zeroize::Zeroize::zeroize(&mut entry.legacy_fields);
    true
}

/// Pre-metadata creation times are stamped at migration, never invented.
pub(crate) fn migrate_payload(payload: &mut VaultPayload) -> bool {
    let now = unix_timestamp();
    let mut changed = false;

    if payload
        .vault_id
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        payload.vault_id = Some(fresh_vault_id());
        changed = true;
    }
    if payload.revision == 0 {
        payload.revision = 1;
        changed = true;
    }

    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    payload.folders.retain_mut(|folder| {
        let name = folder.name.trim().to_string();
        if name.is_empty() {
            changed = true;
            return false;
        }
        if folder.id.trim().is_empty() || ids.contains(&folder.id) {
            folder.id = random_id();
            changed = true;
        }
        if folder.name != name {
            folder.name = name;
            changed = true;
        }
        let normalized = folder.name.to_ascii_lowercase();
        if !names.insert(normalized) {
            changed = true;
            return false;
        }
        ids.insert(folder.id.clone());
        true
    });
    let mut folder_by_name = payload
        .folders
        .iter()
        .map(|folder| (folder.name.to_ascii_lowercase(), folder.id.clone()))
        .collect::<HashMap<_, _>>();

    for entry in &mut payload.entries {
        let legacy_name = entry.folder.trim();
        if !legacy_name.is_empty() {
            let normalized = legacy_name.to_ascii_lowercase();
            let folder_id = folder_by_name.entry(normalized).or_insert_with(|| {
                let id = random_id();
                payload.folders.push(Folder {
                    id: id.clone(),
                    name: legacy_name.to_string(),
                });
                ids.insert(id.clone());
                id
            });
            if entry.folder_id.as_deref() != Some(folder_id.as_str()) {
                entry.folder_id = Some(folder_id.clone());
            }
            entry.folder.clear();
            changed = true;
        } else if entry
            .folder_id
            .as_ref()
            .is_some_and(|folder_id| !ids.contains(folder_id))
        {
            // A dangling reference would leave a folder that cannot be managed.
            entry.folder_id = None;
            changed = true;
        }
        if entry.created_at == 0 {
            entry.created_at = now;
            changed = true;
        }
        if entry.updated_at == 0 {
            entry.updated_at = entry.created_at;
            changed = true;
        }
        if entry.password_updated_at == 0 {
            // Backfill to `updated_at`, the closest real signal, rather than inventing age.
            entry.password_updated_at = entry.updated_at;
            changed = true;
        }
        if entry.revision == 0 {
            entry.revision = 1;
            changed = true;
        }
        changed |= move_login_legacy_fields(entry);
    }
    for trashed in &mut payload.trash {
        if let TaggedItem::Login(entry) = &mut trashed.item {
            changed |= move_login_legacy_fields(entry);
        }
    }
    for entry in &mut payload.history {
        if let TaggedItem::Login(login) = &mut entry.item {
            changed |= move_login_legacy_fields(login);
        }
    }

    // Heal each active item directly: duplicate ids are still unrepaired here,
    // and an id lookup would heal only the first item that carries the id.
    macro_rules! heal_item_folder_refs {
        ($collection:expr) => {
            for item in &mut $collection {
                if item
                    .item_folder_id()
                    .is_some_and(|folder_id| !ids.contains(folder_id))
                {
                    item.set_item_folder_id(None);
                    item.mark_item_changed(now);
                    changed = true;
                }
            }
        };
    }
    heal_item_folder_refs!(payload.identities);
    heal_item_folder_refs!(payload.secure_notes);
    heal_item_folder_refs!(payload.cards);
    heal_item_folder_refs!(payload.wifi_networks);
    heal_item_folder_refs!(payload.ssh_keys);
    heal_item_folder_refs!(payload.software_licenses);
    heal_item_folder_refs!(payload.documents);
    heal_item_folder_refs!(payload.custom_records);
    for trashed in &mut payload.trash {
        if trashed
            .item
            .metadata()
            .item_folder_id()
            .is_some_and(|folder_id| !ids.contains(folder_id))
        {
            trashed.item.metadata_mut().set_item_folder_id(None);
            changed = true;
        }
    }
    for entry in &mut payload.history {
        if entry
            .item
            .metadata()
            .item_folder_id()
            .is_some_and(|folder_id| !ids.contains(folder_id))
        {
            entry.item.metadata_mut().set_item_folder_id(None);
            changed = true;
        }
    }

    let mut item_ids = HashSet::new();
    macro_rules! repair_item_ids {
        ($collection:expr) => {
            for item in &mut $collection {
                if item.id.trim().is_empty() || !item_ids.insert(item.id.clone()) {
                    item.id = random_id();
                    item_ids.insert(item.id.clone());
                    item.updated_at = now;
                    changed = true;
                }
            }
        };
    }
    repair_item_ids!(payload.entries);
    repair_item_ids!(payload.identities);
    repair_item_ids!(payload.secure_notes);
    repair_item_ids!(payload.cards);
    repair_item_ids!(payload.wifi_networks);
    repair_item_ids!(payload.ssh_keys);
    repair_item_ids!(payload.software_licenses);
    repair_item_ids!(payload.documents);
    repair_item_ids!(payload.custom_records);

    let mut trashed_ids = HashSet::new();
    for trashed in &mut payload.trash {
        let item_id = trashed.item.id().to_string();
        if item_id.trim().is_empty() || !trashed_ids.insert(item_id) {
            trashed.item.set_id(random_id());
            changed = true;
        }
    }
    let mut history_ids = HashSet::new();
    for entry in &mut payload.history {
        if entry.id.trim().is_empty() || !history_ids.insert(entry.id.clone()) {
            entry.id = random_id();
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Card, CustomFieldEntry, Folder, HistoryEntry, HistoryOperation, LegacyField, TaggedItem,
        TrashedItem, VaultEntry,
    };
    use crate::CipherBlob;

    fn login(id: &str) -> VaultEntry {
        let mut entry = VaultEntry::default();
        entry.id = id.to_string();
        entry.title = "Example".to_string();
        entry
    }

    fn card(id: &str) -> Card {
        let mut card = Card::default();
        card.id = id.to_string();
        card.title = "Example".to_string();
        card
    }

    #[test]
    fn duplicate_and_empty_ids_are_repaired_on_open() {
        let mut payload = VaultPayload::default();
        payload.entries.push(login("same"));
        payload.entries.push(login("same"));
        payload.entries.push(login(""));
        payload.trash.push(TrashedItem {
            item: TaggedItem::Login(login("gone")),
            deleted_at: 1,
        });
        payload.trash.push(TrashedItem {
            item: TaggedItem::Login(login("gone")),
            deleted_at: 2,
        });
        payload.history.push(HistoryEntry {
            id: "h".to_string(),
            item: TaggedItem::Login(login("old")),
            captured_at: 1,
            operation: HistoryOperation::Edit,
        });
        payload.history.push(HistoryEntry {
            id: "h".to_string(),
            item: TaggedItem::Login(login("older")),
            captured_at: 2,
            operation: HistoryOperation::Edit,
        });

        let changed = migrate_payload(&mut payload);

        assert!(changed);
        let ids: Vec<&str> = payload
            .entries
            .iter()
            .map(|entry| entry.id.as_str())
            .collect();
        assert!(ids.iter().all(|id| !id.trim().is_empty()));
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
        assert_ne!(payload.trash[0].item.id(), payload.trash[1].item.id());
        assert_ne!(payload.history[0].id, payload.history[1].id);
    }

    #[test]
    fn a_later_duplicate_is_healed_before_its_id_changes() {
        let mut payload = VaultPayload::default();
        payload.folders.push(Folder {
            id: "f1".to_string(),
            name: "Example".to_string(),
        });
        let mut healed = card("same");
        healed.set_item_folder_id(Some("f1".to_string()));
        let mut dangling = card("same");
        dangling.set_item_folder_id(Some("gone".to_string()));
        payload.cards.push(healed);
        payload.cards.push(dangling);

        let changed = migrate_payload(&mut payload);

        assert!(changed);
        assert_ne!(payload.cards[0].id.clone(), payload.cards[1].id.clone());
        for card in &payload.cards {
            if card.id == "same" {
                assert_eq!(
                    card.folder_id.as_deref(),
                    Some("f1"),
                    "the first copy keeps its valid folder reference"
                );
            } else {
                assert_eq!(
                    card.folder_id, None,
                    "the second copy is healed even though an id lookup would find the first copy"
                );
            }
        }
    }

    fn envelope(format_version: u8, setup_complete: bool) -> VaultFile {
        let blob = CipherBlob {
            nonce: String::new(),
            ciphertext: String::new(),
        };
        VaultFile {
            format_version,
            kdf: crate::crypto::default_kdf_params(),
            key_wrap: blob.clone(),
            legacy_device_wrap: None,
            recovery_kdf: None,
            recovery_wrap: None,
            pin_wrap: None,
            hello_wrap: None,
            setup_complete,
            payload: blob,
        }
    }

    #[test]
    fn only_formats_without_a_setup_state_are_marked_complete() {
        for (format, setup_complete, expected) in [
            (9, true, true),
            (10, true, true),
            (10, false, false),
            (VAULT_FORMAT_VERSION, false, false),
        ] {
            let mut file = envelope(format, setup_complete);
            let changed = migrate_vault_file(&mut file).expect("supported format");
            assert_eq!(changed, format < VAULT_FORMAT_VERSION, "format {format}");
            assert_eq!(file.format_version, VAULT_FORMAT_VERSION);
            assert_eq!(file.setup_complete, expected, "format {format}");
        }
        assert!(migrate_vault_file(&mut envelope(VAULT_FORMAT_VERSION + 1, true)).is_err());
    }

    fn login_with_legacy_fields(id: &str) -> VaultEntry {
        let mut entry = login(id);
        entry.legacy_fields = vec![
            LegacyField {
                label: "Visible".to_string(),
                value: "fictional visible".to_string(),
                secret: false,
            },
            LegacyField {
                label: "Hidden".to_string(),
                value: "fictional-secret-canary".to_string(),
                secret: true,
            },
        ];
        entry
    }

    fn moved_fields(entry: &VaultEntry) -> Vec<(String, String, String)> {
        assert!(entry.legacy_fields.is_empty());
        entry
            .custom_fields
            .iter()
            .map(|field| (field.label.clone(), field.value.clone(), field.kind.clone()))
            .collect()
    }

    #[test]
    fn login_legacy_fields_move_once_in_the_vault_trash_and_history() {
        let mut payload = VaultPayload::default();
        payload.entries.push(login_with_legacy_fields("login"));
        payload.trash.push(TrashedItem {
            item: TaggedItem::Login(login_with_legacy_fields("trashed")),
            deleted_at: 1,
        });
        payload.history.push(HistoryEntry {
            id: "history".to_string(),
            item: TaggedItem::Login(login_with_legacy_fields("login")),
            captured_at: 1,
            operation: HistoryOperation::Edit,
        });
        let expected = vec![
            (
                "Visible".to_string(),
                "fictional visible".to_string(),
                "text".to_string(),
            ),
            (
                "Hidden".to_string(),
                "fictional-secret-canary".to_string(),
                "secret".to_string(),
            ),
        ];

        assert!(migrate_payload(&mut payload));
        assert!(!migrate_payload(&mut payload));

        assert_eq!(moved_fields(&payload.entries[0]), expected);
        let TaggedItem::Login(trashed) = &payload.trash[0].item else {
            panic!("trashed login");
        };
        assert_eq!(moved_fields(trashed), expected);
        let TaggedItem::Login(previous) = &payload.history[0].item else {
            panic!("history login");
        };
        assert_eq!(moved_fields(previous), expected);
    }

    #[test]
    fn moved_legacy_fields_follow_existing_custom_fields() {
        let mut entry = login_with_legacy_fields("login");
        entry.custom_fields.push(CustomFieldEntry {
            label: "Existing".to_string(),
            value: "fictional existing".to_string(),
            kind: "text".to_string(),
        });
        let mut payload = VaultPayload::default();
        payload.entries.push(entry);

        assert!(migrate_payload(&mut payload));
        let labels = payload.entries[0]
            .custom_fields
            .iter()
            .map(|field| field.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(labels, ["Existing", "Visible", "Hidden"]);
    }
}
