use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{
    DeleteSoftwareLicenseResult, SaveSoftwareLicenseResult, SoftwareLicense, SoftwareLicenseInput,
    TaggedItem,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

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
        created_at: now,
        updated_at: now,
        revision: 1,
    })
}

fn payload_without_software_license(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload
        .software_licenses
        .iter()
        .any(|license| license.id == id)
    {
        return Err("That saved licence no longer exists.".into());
    }
    let mut next = payload.clone();
    next.software_licenses.retain(|license| license.id != id);
    Ok(next)
}

#[tauri::command]
pub fn get_software_license(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<SoftwareLicense> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session
        .payload
        .software_licenses
        .iter()
        .find(|license| license.id == id)
        .cloned()
        .ok_or_else(|| "That saved licence no longer exists.".to_string())
}

#[tauri::command]
pub fn save_software_license(
    input: SoftwareLicenseInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveSoftwareLicenseResult> {
    let mut license = software_license_from_input(input)?;
    let license_id = license.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a licence.")?;
    let mut next_payload = session.payload.clone();
    if let Some(existing) = next_payload
        .software_licenses
        .iter_mut()
        .find(|saved| saved.id == license_id)
    {
        let previous = existing.clone();
        license.created_at = existing.created_at;
        license.revision = existing.revision.saturating_add(1);
        *existing = license;
        crate::vault::history::capture_history(
            &mut next_payload,
            TaggedItem::SoftwareLicense(previous),
        );
    } else {
        next_payload.software_licenses.push(license);
    }
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveSoftwareLicenseResult {
        id: license_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_software_license(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<DeleteSoftwareLicenseResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved licence to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a licence.")?;
    let license = session
        .payload
        .software_licenses
        .iter()
        .find(|license| license.id == id)
        .cloned()
        .ok_or("That saved licence no longer exists.")?;
    let mut next_payload = payload_without_software_license(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::SoftwareLicense(license));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteSoftwareLicenseResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
