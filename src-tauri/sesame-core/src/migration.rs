//! Vault-format migrations.
//! A migration runs only after the vault key has been proven, so a damaged or foreign file is never rewritten.

use std::collections::{HashMap, HashSet};

use crate::util::{random_id, unix_timestamp};
use crate::{Folder, VaultFile, VaultPayload, VaultResult, VAULT_FORMAT_VERSION};

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
        file.format_version = VAULT_FORMAT_VERSION;
        file.setup_complete = true;
        changed = true;
    }
    Ok(changed)
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
    }

    for id in payload.active_item_ids() {
        if let Some(item) = payload.item_metadata_mut(&id) {
            if item
                .item_folder_id()
                .is_some_and(|folder_id| !ids.contains(folder_id))
            {
                item.set_item_folder_id(None);
                item.mark_item_changed(now);
                changed = true;
            }
        }
    }
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
    use crate::types::{HistoryEntry, HistoryOperation, TaggedItem, TrashedItem, VaultEntry};

    fn login(id: &str) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            title: "Example".to_string(),
            ..VaultEntry::default()
        }
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
}
