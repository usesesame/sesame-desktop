use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{Card, CardInput, DeleteCardResult, SaveCardResult, TaggedItem};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

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
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

fn payload_without_card(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    let mut next = payload.clone();
    match next.take_active_item(id) {
        Some(TaggedItem::Card(_)) => {}
        _ => return Err("That saved card no longer exists.".into()),
    }
    Ok(next)
}

#[tauri::command]
pub fn get_card(id: String, state: State<'_, VaultState>) -> VaultResult<Card> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    match session.payload.active_item(&id) {
        Some(TaggedItem::Card(card)) => Ok(card),
        _ => Err("That saved card no longer exists.".into()),
    }
}

#[tauri::command]
pub fn save_card(input: CardInput, state: State<'_, VaultState>) -> VaultResult<SaveCardResult> {
    let mut card = card_from_input(input)?;
    let card_id = card.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a card.")?;
    let mut next_payload = session.payload.clone();
    if let Some(previous) = next_payload.take_active_item(&card_id) {
        let TaggedItem::Card(existing) = previous else {
            return Err("That item id belongs to a different kind of saved item.".into());
        };
        card.created_at = existing.created_at;
        card.revision = existing.revision.saturating_add(1);
        card.legacy_fields = existing.legacy_fields.clone();
        crate::vault::history::capture_history(&mut next_payload, TaggedItem::Card(existing));
    }
    next_payload.insert_active_item(TaggedItem::Card(card))?;
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveCardResult {
        id: card_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_card(id: String, state: State<'_, VaultState>) -> VaultResult<DeleteCardResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved card to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a card.")?;
    let card = match session.payload.active_item(id) {
        Some(TaggedItem::Card(card)) => card,
        _ => return Err("That saved card no longer exists.".into()),
    };
    let mut next_payload = payload_without_card(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::Card(card));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteCardResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
