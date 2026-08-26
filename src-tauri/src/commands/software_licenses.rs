use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    DeleteSoftwareLicenseResult, SaveSoftwareLicenseResult, SoftwareLicense, SoftwareLicenseInput,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

fn software_license_from_input(input: SoftwareLicenseInput) -> VaultResult<SoftwareLicense> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this licence a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That licence name is too long.".into());
    }
    for (value, limit, message) in [
        (&input.license_key, 512, "That licence key is too long."),
        (&input.product_name, 256, "That product name is too long."),
        (&input.purchased_from, 256, "That seller name is too long."),
        (&input.purchase_date, 32, "That purchase date is too long."),
        (&input.notes, 4_000, "That note is too long."),
    ] {
        if value.chars().count() > limit {
            return Err(message.into());
        }
    }
    for tag in &input.tags {
        if tag.chars().count() > 64 {
            return Err("A tag is too long.".into());
        }
    }
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
    item: SoftwareLicense,
    input: SoftwareLicenseInput,
    variant: SoftwareLicense,
    save_result: SaveSoftwareLicenseResult,
    delete_result: DeleteSoftwareLicenseResult,
    from_input: software_license_from_input,
    get_fn: get_software_license,
    save_fn: save_software_license,
    delete_fn: delete_software_license,
    missing_noun: "licence",
    save_unlock_msg: "Unlock your vault before saving a licence.",
    delete_unlock_msg: "Unlock your vault before deleting a licence.",
    delete_empty_msg: "Choose a saved licence to delete.",
}
