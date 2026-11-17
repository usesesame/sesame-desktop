use crate::application::record_writes::{
    check_note_length, check_tag_lengths, normalised_tags, record_title, MAX_RECORD_NOTE_CHARS,
};
use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    DeleteSoftwareLicenseResult, SaveSoftwareLicenseResult, SoftwareLicense, SoftwareLicenseInput,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

fn software_license_from_input(input: SoftwareLicenseInput) -> VaultResult<SoftwareLicense> {
    let title = record_title(
        &input.title,
        "Give this licence a name so you can find it again.",
        "That licence name is too long.",
    )?;
    for (value, limit, message) in [
        (&input.license_key, 512, "That licence key is too long."),
        (&input.product_name, 256, "That product name is too long."),
        (&input.purchased_from, 256, "That seller name is too long."),
        (&input.purchase_date, 32, "That purchase date is too long."),
    ] {
        if value.chars().count() > limit {
            return Err(message.into());
        }
    }
    check_note_length(&input.notes, MAX_RECORD_NOTE_CHARS)?;
    check_tag_lengths(&input.tags)?;
    let now = unix_timestamp();
    Ok(SoftwareLicense {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        license_key: input.license_key.trim().to_string(),
        product_name: input.product_name.trim().to_string(),
        purchased_from: input.purchased_from.trim().to_string(),
        purchase_date: input.purchase_date.trim().to_string(),
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
    item: SoftwareLicense,
    input: SoftwareLicenseInput,
    variant: SoftwareLicense,
    save_result: SaveSoftwareLicenseResult,
    delete_result: DeleteSoftwareLicenseResult,
    from_input: software_license_from_input,
    get_fn: get_software_license,
    save_fn: save_software_license,
    save_in_state_fn: save_software_license_in_state,
    delete_fn: delete_software_license,
    missing_noun: "licence",
    save_unlock_msg: "Unlock your vault before saving a licence.",
    delete_unlock_msg: "Unlock your vault before deleting a licence.",
    delete_empty_msg: "Choose a saved licence to delete.",
}
