use std::{collections::HashSet, path::Path};

use tauri::State;

use crate::vault::backup::snapshot_vault_revision;
use crate::vault::imports::{parse_import_entries, read_import_file, validate_import_entries};
use crate::vault::pending_import::{take_matching, PendingImport};
use crate::vault::snapshot::{
    duplicate_key, entries_by_duplicate_key, existing_import_relation, is_duplicate_key_eligible,
    should_skip_exact_duplicate,
};
use crate::vault::storage::{commit_payload_change, materialize_entry_folder};
use crate::vault::{
    Card, ExistingImportRelation, Identity, ImportPreview, ImportPreviewResult, ImportResult,
    SecureNote, SshKey, TaggedItem, VaultEntry, VaultPayload, VaultResult, VaultState,
};

/// Same global ID namespace as editor, history, and trash mutations.
fn insert_imported_items(
    payload: &mut VaultPayload,
    mut entries: Vec<VaultEntry>,
    secure_notes: Vec<SecureNote>,
    cards: Vec<Card>,
    identities: Vec<Identity>,
    ssh_keys: Vec<SshKey>,
) -> VaultResult<()> {
    for entry in &mut entries {
        materialize_entry_folder(payload, entry)?;
    }
    for entry in entries {
        payload.insert_active_item(TaggedItem::Login(entry))?;
    }
    for note in secure_notes {
        payload.insert_active_item(TaggedItem::SecureNote(note))?;
    }
    for card in cards {
        payload.insert_active_item(TaggedItem::Card(card))?;
    }
    for identity in identities {
        payload.insert_active_item(TaggedItem::Identity(identity))?;
    }
    for key in ssh_keys {
        payload.insert_active_item(TaggedItem::SshKey(key))?;
    }
    Ok(())
}

#[tauri::command]
pub fn preview_import(
    path: String,
    source: String,
    state: State<'_, VaultState>,
) -> VaultResult<ImportPreviewResult> {
    // Unlock check first: a locked renderer must not use this as a file-format oracle.
    let unlocked = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?
        .is_some();
    if !unlocked {
        return Err("Unlock your vault before importing.".into());
    }
    let content = read_import_file(Path::new(&path))?;
    let mut parsed = parse_import_entries(&content, &source)?;
    drop(content);
    let missing_urls = parsed
        .entries
        .iter()
        .filter(|entry| entry.url.is_empty())
        .count();
    let no_totp = parsed
        .entries
        .iter()
        .filter(|entry| entry.totp.as_deref().unwrap_or_default().is_empty())
        .count();
    let issues = validate_import_entries(&mut parsed.entries);
    let preserved_legacy_fields: usize = parsed
        .entries
        .iter()
        .map(|entry| entry.legacy_fields.len())
        .sum::<usize>()
        + parsed
            .secure_notes
            .iter()
            .map(|note| note.legacy_fields.len())
            .sum::<usize>()
        + parsed
            .cards
            .iter()
            .map(|card| card.legacy_fields.len())
            .sum::<usize>()
        + parsed
            .identities
            .iter()
            .map(|identity| identity.legacy_fields.len())
            .sum::<usize>();
    // Malformed values are only known after validation, so that disposition is folded in here.
    parsed.fidelity.logins.malformed += issues.invalid_urls + issues.invalid_totp;
    // Re-lock: the vault may have locked during the parse.
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault before importing.")?;
    let payload = session.open_payload()?;
    let existing_by_key = entries_by_duplicate_key(&payload.entries);
    let mut seen_import_keys = HashSet::new();
    let mut exact_duplicates = 0;
    let mut account_conflicts = 0;
    let mut duplicate_entries = 0;
    for entry in &parsed.entries {
        if is_duplicate_key_eligible(entry) {
            let key = duplicate_key(entry);
            match existing_import_relation(entry, &existing_by_key) {
                ExistingImportRelation::ExactDuplicate => exact_duplicates += 1,
                ExistingImportRelation::AccountConflict => account_conflicts += 1,
                ExistingImportRelation::None => {}
            }
            if !seen_import_keys.insert(key) {
                duplicate_entries += 1;
            }
        }
    }
    let preview = ImportPreview {
        total_entries: parsed.entries.len(),
        exact_duplicates,
        account_conflicts,
        duplicate_entries,
        missing_urls,
        invalid_urls: issues.invalid_urls,
        no_totp,
        invalid_totp: issues.invalid_totp,
        preserved_legacy_fields,
        secure_notes: parsed.secure_notes.len(),
        cards: parsed.cards.len(),
        identities: parsed.identities.len(),
        ssh_keys: parsed.ssh_keys.len(),
        passkeys_not_imported: parsed.passkeys_not_imported,
        intentionally_omitted_items: parsed.intentionally_omitted_items,
        fidelity: parsed.fidelity.clone(),
    };
    let pending = PendingImport::new(parsed);
    let import_id = pending.id.clone();
    *state
        .pending_import
        .lock()
        .map_err(|_| "Sesame could not hold this import.".to_string())? = Some(pending);
    Ok(ImportPreviewResult { import_id, preview })
}

#[tauri::command]
pub fn cancel_import(state: State<'_, VaultState>) -> VaultResult<()> {
    state.discard_pending_import();
    Ok(())
}

#[tauri::command]
pub fn commit_import(
    import_id: String,
    skip_exact_duplicates: bool,
    state: State<'_, VaultState>,
) -> VaultResult<ImportResult> {
    // Session lock first: taking the pending lock first could deadlock against restore or deletion.
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before importing.")?;
    let (imported, secure_notes, cards, identities, ssh_keys) = {
        let mut slot = state
            .pending_import
            .lock()
            .map_err(|_| "Sesame could not read this import.".to_string())?;
        take_matching(&mut slot, import_id.trim())?.into_parts()
    };
    let revision_backup_name = snapshot_vault_revision(&session.path, "import")?;
    let payload = session.open_payload()?;
    let existing_by_key = entries_by_duplicate_key(&payload.entries);
    let mut skipped_exact_duplicates = 0;
    let entries = if skip_exact_duplicates {
        imported
            .into_iter()
            .filter(|entry| {
                let skip = should_skip_exact_duplicate(entry, &existing_by_key);
                if skip {
                    skipped_exact_duplicates += 1;
                }
                !skip
            })
            .collect::<Vec<_>>()
    } else {
        imported
    };
    let imported_entries = entries.len();
    let imported_secure_notes = secure_notes.len();
    let imported_cards = cards.len();
    let imported_identities = identities.len();
    let imported_ssh_keys = ssh_keys.len();
    // No duplicate-key model for notes, cards, identities, and SSH keys: every one is kept.
    let mut next_payload = payload.clone();
    insert_imported_items(
        &mut next_payload,
        entries,
        secure_notes,
        cards,
        identities,
        ssh_keys,
    )?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(ImportResult {
        snapshot: session.snapshot(),
        imported_secure_notes,
        imported_cards,
        imported_identities,
        imported_ssh_keys,
        imported_entries,
        skipped_exact_duplicates,
        revision_backup_name,
    })
}
