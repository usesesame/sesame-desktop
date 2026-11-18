//! Saved Custom Records: a free list of labelled fields for anything that does not fit a typed item.

use crate::application::record_writes::{
    check_note_length, check_tag_lengths, normalised_tags, record_title, MAX_RECORD_NOTE_CHARS,
};
use crate::commands::record_commands::impl_record_commands;
use sesame_core::custom_fields::{normalised_fields, RECORD_FIELDS};

use crate::vault::types::{
    CustomRecord, CustomRecordInput, DeleteCustomRecordResult, SaveCustomRecordResult,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

fn custom_record_from_input(input: CustomRecordInput) -> VaultResult<CustomRecord> {
    let title = record_title(
        &input.title,
        "Give this record a name so you can find it again.",
        "That record name is too long.",
    )?;
    if input.fields.len() > RECORD_FIELDS.max_fields {
        return Err("That record has too many fields.".into());
    }
    check_note_length(&input.notes, MAX_RECORD_NOTE_CHARS)?;
    check_tag_lengths(&input.tags)?;
    let fields = normalised_fields(input.fields, &RECORD_FIELDS)?;
    let now = unix_timestamp();
    Ok(CustomRecord {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        fields,
        notes: input.notes.trim().to_string(),
        tags: normalised_tags(input.tags),
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
    save_in_state_fn: save_custom_record_in_state,
    delete_fn: delete_custom_record,
    missing_noun: "record",
    save_unlock_msg: "Unlock your vault before saving a record.",
    delete_unlock_msg: "Unlock your vault before deleting a record.",
    delete_empty_msg: "Choose a saved record to delete.",
}
