use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    DeleteSecureNoteResult, SaveSecureNoteResult, SecureNote, SecureNoteInput,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

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
        folder_id: None,
        favourite: false,
        last_used_at: None,
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

impl_record_commands! {
    item: SecureNote,
    input: SecureNoteInput,
    variant: SecureNote,
    save_result: SaveSecureNoteResult,
    delete_result: DeleteSecureNoteResult,
    from_input: secure_note_from_input,
    get_fn: get_secure_note,
    save_fn: save_secure_note,
    delete_fn: delete_secure_note,
    missing_noun: "note",
    save_unlock_msg: "Unlock your vault before saving a note.",
    delete_unlock_msg: "Unlock your vault before deleting a note.",
    delete_empty_msg: "Choose a saved note to delete.",
    extra_carry: |item, existing| item.legacy_fields = existing.legacy_fields.clone(),
}
