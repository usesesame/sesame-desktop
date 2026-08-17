use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{DeleteSshKeyResult, SaveSshKeyResult, SshKey, SshKeyInput, TaggedItem};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

fn ssh_key_from_input(input: SshKeyInput) -> VaultResult<SshKey> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this key a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That key name is too long.".into());
    }
    for (value, limit, message) in [
        (&input.key_type, 32, "That key type is too long."),
        (&input.private_key, 16_000, "That private key is too long."),
        (&input.public_key, 4_000, "That public key is too long."),
        (&input.passphrase, 256, "That passphrase is too long."),
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

fn payload_without_ssh_key(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload.ssh_keys.iter().any(|key| key.id == id) {
        return Err("That saved key no longer exists.".into());
    }
    let mut next = payload.clone();
    next.ssh_keys.retain(|key| key.id != id);
    Ok(next)
}

#[tauri::command]
pub fn get_ssh_key(id: String, state: State<'_, VaultState>) -> VaultResult<SshKey> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session
        .payload
        .ssh_keys
        .iter()
        .find(|key| key.id == id)
        .cloned()
        .ok_or_else(|| "That saved key no longer exists.".to_string())
}

#[tauri::command]
pub fn save_ssh_key(
    input: SshKeyInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveSshKeyResult> {
    let mut key = ssh_key_from_input(input)?;
    let key_id = key.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a key.")?;
    let mut next_payload = session.payload.clone();
    if let Some(existing) = next_payload
        .ssh_keys
        .iter_mut()
        .find(|saved| saved.id == key_id)
    {
        let previous = existing.clone();
        key.created_at = existing.created_at;
        key.revision = existing.revision.saturating_add(1);
        *existing = key;
        crate::vault::history::capture_history(&mut next_payload, TaggedItem::SshKey(previous));
    } else {
        next_payload.ssh_keys.push(key);
    }
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveSshKeyResult {
        id: key_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_ssh_key(id: String, state: State<'_, VaultState>) -> VaultResult<DeleteSshKeyResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved key to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a key.")?;
    let key = session
        .payload
        .ssh_keys
        .iter()
        .find(|key| key.id == id)
        .cloned()
        .ok_or("That saved key no longer exists.")?;
    let mut next_payload = payload_without_ssh_key(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::SshKey(key));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteSshKeyResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
