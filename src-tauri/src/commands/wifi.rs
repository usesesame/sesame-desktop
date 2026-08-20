use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::trash_item;
use crate::vault::types::{
    DeleteWifiNetworkResult, SaveWifiNetworkResult, TaggedItem, WifiNetwork, WifiNetworkInput,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::{VaultPayload, VaultResult, VaultState};

fn wifi_network_from_input(input: WifiNetworkInput) -> VaultResult<WifiNetwork> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this network a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That network name is too long.".into());
    }
    for (value, limit, message) in [
        (&input.ssid, 64, "That network's SSID is too long."),
        (&input.password, 256, "That network password is too long."),
        (&input.security_type, 32, "That security type is too long."),
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
    Ok(WifiNetwork {
        id: input
            .id
            .and_then(crate::vault::util::non_empty)
            .unwrap_or_else(random_id),
        title: title.to_string(),
        ssid: input.ssid.trim().to_string(),
        password: input.password.trim().to_string(),
        security_type: input.security_type.trim().to_string(),
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

fn payload_without_wifi_network(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    if !payload.wifi_networks.iter().any(|network| network.id == id) {
        return Err("That saved network no longer exists.".into());
    }
    let mut next = payload.clone();
    next.wifi_networks.retain(|network| network.id != id);
    Ok(next)
}

#[tauri::command]
pub fn get_wifi_network(id: String, state: State<'_, VaultState>) -> VaultResult<WifiNetwork> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session
        .payload
        .wifi_networks
        .iter()
        .find(|network| network.id == id)
        .cloned()
        .ok_or_else(|| "That saved network no longer exists.".to_string())
}

#[tauri::command]
pub fn save_wifi_network(
    input: WifiNetworkInput,
    state: State<'_, VaultState>,
) -> VaultResult<SaveWifiNetworkResult> {
    let mut network = wifi_network_from_input(input)?;
    let network_id = network.id.clone();
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before saving a network.")?;
    let mut next_payload = session.payload.clone();
    if let Some(existing) = next_payload
        .wifi_networks
        .iter_mut()
        .find(|saved| saved.id == network_id)
    {
        let previous = existing.clone();
        network.created_at = existing.created_at;
        network.revision = existing.revision.saturating_add(1);
        network.folder_id = existing.folder_id.clone();
        network.favourite = existing.favourite;
        network.last_used_at = existing.last_used_at;
        *existing = network;
        crate::vault::history::capture_history(
            &mut next_payload,
            TaggedItem::WifiNetwork(previous),
        );
    } else {
        next_payload.wifi_networks.push(network);
    }
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(SaveWifiNetworkResult {
        id: network_id,
        snapshot: snapshot_for(&session.payload),
    })
}

#[tauri::command]
pub fn delete_wifi_network(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<DeleteWifiNetworkResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a saved network to delete.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before deleting a network.")?;
    let network = session
        .payload
        .wifi_networks
        .iter()
        .find(|network| network.id == id)
        .cloned()
        .ok_or("That saved network no longer exists.")?;
    let mut next_payload = payload_without_wifi_network(&session.payload, id)?;
    trash_item(&mut next_payload, TaggedItem::WifiNetwork(network));
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(DeleteWifiNetworkResult {
        deleted_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
