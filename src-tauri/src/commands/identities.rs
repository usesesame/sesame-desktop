//! Saved identities: the person behind several accounts, kept once so signup forms are not retyped.

use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{
    DeleteIdentityResult, Identity, IdentityInput, SaveIdentityResult, TaggedItem,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

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

fn payload_without_identity(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload.identities.iter().any(|identity| identity.id == id) {
        return Err("That saved identity no longer exists.".into());
    }
    let mut next = payload.clone();
    next.identities.retain(|identity| identity.id != id);
    Ok(next)
}

#[tauri::command]
pub fn get_identity(id: String, state: State<'_, VaultState>) -> VaultResult<Identity> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session
        .payload
        .identities
        .iter()
        .find(|identity| identity.id == id)
        .cloned()
        .ok_or_else(|| "That saved identity no longer exists.".to_string())
}

#[tauri::command]
pub fn save_identity(
    input: IdentityInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveIdentityResult> {
    let mut identity = identity_from_input(input)?;
    let identity_id = identity.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving an identity.")?;
    let mut next_payload = session.payload.clone();
    if let Some(existing) = next_payload
        .identities
        .iter_mut()
        .find(|saved| saved.id == identity_id)
    {
        let previous = existing.clone();
        identity.created_at = existing.created_at;
        identity.revision = existing.revision.saturating_add(1);
        identity.folder_id = existing.folder_id.clone();
        identity.favourite = existing.favourite;
        identity.last_used_at = existing.last_used_at;
        identity.legacy_fields = existing.legacy_fields.clone();
        *existing = identity;
        crate::vault::history::capture_history(&mut next_payload, TaggedItem::Identity(previous));
    } else {
        next_payload.identities.push(identity);
    }
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveIdentityResult {
        id: identity_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_identity(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<DeleteIdentityResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved identity to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting an identity.")?;
    let identity = session
        .payload
        .identities
        .iter()
        .find(|identity| identity.id == id)
        .cloned()
        .ok_or("That saved identity no longer exists.")?;
    let mut next_payload = payload_without_identity(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::Identity(identity));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteIdentityResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
