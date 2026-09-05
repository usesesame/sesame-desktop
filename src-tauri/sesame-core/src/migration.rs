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
    changed
}
