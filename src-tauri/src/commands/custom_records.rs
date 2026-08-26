//! Saved Custom Records: a free list of labelled fields for anything that does not fit a typed item.

use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    CustomFieldEntry, CustomRecord, CustomRecordInput, DeleteCustomRecordResult,
    SaveCustomRecordResult,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

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
        folder_id: None,
        favourite: false,
        last_used_at: None,
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

impl_record_commands! {
    item: CustomRecord,
    input: CustomRecordInput,
    variant: CustomRecord,
    save_result: SaveCustomRecordResult,
    delete_result: DeleteCustomRecordResult,
    from_input: custom_record_from_input,
    get_fn: get_custom_record,
    save_fn: save_custom_record,
    delete_fn: delete_custom_record,
    missing_noun: "record",
    save_unlock_msg: "Unlock your vault before saving a record.",
    delete_unlock_msg: "Unlock your vault before deleting a record.",
    delete_empty_msg: "Choose a saved record to delete.",
}
