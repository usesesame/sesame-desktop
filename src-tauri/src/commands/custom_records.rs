//! Saved Custom Records: a free list of labelled fields for anything that does not fit a typed item.

use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{
    CustomFieldEntry, CustomRecord, CustomRecordInput, DeleteCustomRecordResult,
    SaveCustomRecordResult, TaggedItem,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

const FIELD_KINDS: [&str; 3] = ["text", "secret", "date"];
const MAX_FIELDS: usize = 50;

fn normalised_field(field: CustomFieldEntry) -> VaultResult<CustomFieldEntry> {
    let label = field.label.trim();
    if label.is_empty() {
        return Err("Give every field a label.".into());
    }
    if label.chars().count() > 160 {
        return Err("A field label is too long.".into());
    }
    if field.value.chars().count() > 4_000 {
        return Err("A field value is too long.".into());
    }
    let kind = if FIELD_KINDS.contains(&field.kind.as_str()) {
        field.kind
    } else {
        "text".to_string()
    };
    Ok(CustomFieldEntry {
        label: label.to_string(),
        value: field.value.trim().to_string(),
        kind,
    })
}

fn custom_record_from_input(input: CustomRecordInput) -> VaultResult<CustomRecord> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this record a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That record name is too long.".into());
    }
    if input.fields.len() > MAX_FIELDS {
        return Err("That record has too many fields.".into());
    }
    if input.notes.chars().count() > 4_000 {
        return Err("That note is too long.".into());
    }
    for tag in &input.tags {
        if tag.chars().count() > 64 {
            return Err("A tag is too long.".into());
        }
    }
    let fields = input
        .fields
        .into_iter()
        .map(normalised_field)
        .collect::<VaultResult<Vec<_>>>()?;
    let now = unix_timestamp();
    Ok(CustomRecord {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        fields,
        notes: input.notes.trim().to_string(),
        tags: input
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

fn payload_without_custom_record(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload.custom_records.iter().any(|record| record.id == id) {
        return Err("That saved record no longer exists.".into());
    }
    let mut next = payload.clone();
    next.custom_records.retain(|record| record.id != id);
    Ok(next)
}

#[tauri::command]
pub fn get_custom_record(id: String, state: State<'_, VaultState>) -> VaultResult<CustomRecord> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session
        .payload
        .custom_records
        .iter()
        .find(|record| record.id == id)
        .cloned()
        .ok_or_else(|| "That saved record no longer exists.".to_string())
}

#[tauri::command]
pub fn save_custom_record(
    input: CustomRecordInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveCustomRecordResult> {
    let mut record = custom_record_from_input(input)?;
    let record_id = record.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a record.")?;
    let mut next_payload = session.payload.clone();
    if let Some(existing) = next_payload
        .custom_records
        .iter_mut()
        .find(|saved| saved.id == record_id)
    {
        let previous = existing.clone();
        record.created_at = existing.created_at;
        record.revision = existing.revision.saturating_add(1);
        *existing = record;
        crate::vault::history::capture_history(
            &mut next_payload,
            TaggedItem::CustomRecord(previous),
        );
    } else {
        next_payload.custom_records.push(record);
    }
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveCustomRecordResult {
        id: record_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_custom_record(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<DeleteCustomRecordResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved record to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a record.")?;
    let record = session
        .payload
        .custom_records
        .iter()
        .find(|record| record.id == id)
        .cloned()
        .ok_or("That saved record no longer exists.")?;
    let mut next_payload = payload_without_custom_record(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::CustomRecord(record));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteCustomRecordResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
