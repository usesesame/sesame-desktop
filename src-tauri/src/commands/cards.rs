use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{Card, CardInput, DeleteCardResult, SaveCardResult};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

fn card_from_input(input: CardInput) -> VaultResult<Card> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this card a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That card name is too long.".into());
    }
    for (value, limit, message) in [
        (
            &input.cardholder_name,
            256,
            "The cardholder name is too long.",
        ),
        (&input.number, 32, "That card number is too long."),
        (&input.expiry_month, 8, "That expiry month is too long."),
        (&input.expiry_year, 8, "That expiry year is too long."),
        (&input.security_code, 8, "That security code is too long."),
        (&input.brand, 64, "The card network is too long."),
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
    Ok(Card {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        cardholder_name: input.cardholder_name.trim().to_string(),
        number: input.number.trim().to_string(),
        expiry_month: input.expiry_month.trim().to_string(),
        expiry_year: input.expiry_year.trim().to_string(),
        security_code: input.security_code.trim().to_string(),
        brand: input.brand.trim().to_string(),
        notes: input.notes.trim().to_string(),
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
    item: Card,
    input: CardInput,
    variant: Card,
    save_result: SaveCardResult,
    delete_result: DeleteCardResult,
    from_input: card_from_input,
    get_fn: get_card,
    save_fn: save_card,
    delete_fn: delete_card,
    missing_noun: "card",
    save_unlock_msg: "Unlock your vault before saving a card.",
    delete_unlock_msg: "Unlock your vault before deleting a card.",
    delete_empty_msg: "Choose a saved card to delete.",
    extra_carry: |item, existing| item.legacy_fields = existing.legacy_fields.clone(),
}
