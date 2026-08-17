use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{
    DeleteSecureNoteResult, SaveSecureNoteResult, SecureNote, SecureNoteInput, TaggedItem,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

fn secure_note_from_input(input: SecureNoteInput) -> VaultResult<SecureNote> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this note a title so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That note title is too long.".into());
    }
    if input.content.chars().count() > 20_000 {
        return Err("That note is too long.".into());
    }
    for tag in &input.tags {
        if tag.chars().count() > 64 {
            return Err("A tag is too long.".into());
        }
    }
    let now = unix_timestamp();
    Ok(SecureNote {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        content: input.content.trim().to_string(),
        tags: input
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        legacy_fields: Vec::new(),
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

fn payload_without_secure_note(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    let mut next = payload.clone();
    match next.take_active_item(id) {
        Some(TaggedItem::SecureNote(_)) => {}
        _ => return Err("That saved note no longer exists.".into()),
    }
    Ok(next)
}

#[tauri::command]
pub fn get_secure_note(id: String, state: State<'_, VaultState>) -> VaultResult<SecureNote> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    match session.payload.active_item(&id) {
        Some(TaggedItem::SecureNote(note)) => Ok(note),
        _ => Err("That saved note no longer exists.".into()),
    }
}

#[tauri::command]
pub fn save_secure_note(
    input: SecureNoteInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveSecureNoteResult> {
    let mut note = secure_note_from_input(input)?;
    let note_id = note.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a note.")?;
    let mut next_payload = session.payload.clone();
    if let Some(previous) = next_payload.take_active_item(&note_id) {
        let TaggedItem::SecureNote(existing) = previous else {
            return Err("That item id belongs to a different kind of saved item.".into());
        };
        note.created_at = existing.created_at;
        note.revision = existing.revision.saturating_add(1);
        note.legacy_fields = existing.legacy_fields.clone();
        crate::vault::history::capture_history(&mut next_payload, TaggedItem::SecureNote(existing));
    }
    next_payload.insert_active_item(TaggedItem::SecureNote(note))?;
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveSecureNoteResult {
        id: note_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_secure_note(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<DeleteSecureNoteResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved note to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a note.")?;
    let note = match session.payload.active_item(id) {
        Some(TaggedItem::SecureNote(note)) => note,
        _ => return Err("That saved note no longer exists.".into()),
    };
    let mut next_payload = payload_without_secure_note(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::SecureNote(note));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteSecureNoteResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
