//! Saved identities: the person behind several accounts, kept once so signup forms are not retyped.

use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{DeleteIdentityResult, Identity, IdentityInput, SaveIdentityResult};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

fn identity_from_input(input: IdentityInput) -> VaultResult<Identity> {
    let label = input.label.trim();
    if label.is_empty() {
        return Err("Give this identity a name so you can find it again.".into());
    }
    if label.chars().count() > 160 {
        return Err("That identity name is too long.".into());
    }
    for (value, limit, message) in [
        (&input.full_name, 256, "The name is too long."),
        (&input.email, 320, "The email is too long."),
        (&input.phone, 64, "The phone number is too long."),
        (&input.address_line1, 256, "The address is too long."),
        (&input.address_line2, 256, "The address is too long."),
        (&input.city, 128, "The city is too long."),
        (&input.region, 128, "The region is too long."),
        (&input.postal_code, 32, "The postal code is too long."),
        (&input.country, 128, "The country is too long."),
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
    Ok(Identity {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        label: label.to_string(),
        full_name: input.full_name.trim().to_string(),
        email: input.email.trim().to_string(),
        phone: input.phone.trim().to_string(),
        address_line1: input.address_line1.trim().to_string(),
        address_line2: input.address_line2.trim().to_string(),
        city: input.city.trim().to_string(),
        region: input.region.trim().to_string(),
        postal_code: input.postal_code.trim().to_string(),
        country: input.country.trim().to_string(),
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
    item: Identity,
    input: IdentityInput,
    variant: Identity,
    save_result: SaveIdentityResult,
    delete_result: DeleteIdentityResult,
    from_input: identity_from_input,
    get_fn: get_identity,
    save_fn: save_identity,
    delete_fn: delete_identity,
    missing_noun: "identity",
    save_unlock_msg: "Unlock your vault before saving an identity.",
    delete_unlock_msg: "Unlock your vault before deleting an identity.",
    delete_empty_msg: "Choose a saved identity to delete.",
    extra_carry: |item, existing| item.legacy_fields = existing.legacy_fields.clone(),
}
