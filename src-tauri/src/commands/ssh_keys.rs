use crate::application::record_writes::{
    check_note_length, check_tag_lengths, normalised_tags, record_title, MAX_RECORD_NOTE_CHARS,
};
use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{DeleteSshKeyResult, SaveSshKeyResult, SshKey, SshKeyInput};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

fn ssh_key_from_input(input: SshKeyInput) -> VaultResult<SshKey> {
    let title = record_title(
        &input.title,
        "Give this key a name so you can find it again.",
        "That key name is too long.",
    )?;
    for (value, limit, message) in [
        (&input.key_type, 32, "That key type is too long."),
        (&input.private_key, 16_000, "That private key is too long."),
        (&input.public_key, 4_000, "That public key is too long."),
        (&input.passphrase, 256, "That passphrase is too long."),
    ] {
        if value.chars().count() > limit {
            return Err(message.into());
        }
    }
    check_note_length(&input.notes, MAX_RECORD_NOTE_CHARS)?;
    check_tag_lengths(&input.tags)?;
    let now = unix_timestamp();
    Ok(SshKey {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        key_type: input.key_type.trim().to_string(),
        private_key: input.private_key.trim().to_string(),
        public_key: input.public_key.trim().to_string(),
        passphrase: input.passphrase.trim().to_string(),
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
    item: SshKey,
    input: SshKeyInput,
    variant: SshKey,
    save_result: SaveSshKeyResult,
    delete_result: DeleteSshKeyResult,
    from_input: ssh_key_from_input,
    get_fn: get_ssh_key,
    save_fn: save_ssh_key,
    save_in_state_fn: save_ssh_key_in_state,
    delete_fn: delete_ssh_key,
    missing_noun: "key",
    save_unlock_msg: "Unlock your vault before saving a key.",
    delete_unlock_msg: "Unlock your vault before deleting a key.",
    delete_empty_msg: "Choose a saved key to delete.",
}
