use crate::commands::record_commands::impl_record_commands;
use crate::vault::types::{
    DeleteWifiNetworkResult, SaveWifiNetworkResult, WifiNetwork, WifiNetworkInput,
};
use crate::vault::util::{random_id, unix_timestamp};
use crate::vault::VaultResult;

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

impl_record_commands! {
    item: WifiNetwork,
    input: WifiNetworkInput,
    variant: WifiNetwork,
    save_result: SaveWifiNetworkResult,
    delete_result: DeleteWifiNetworkResult,
    from_input: wifi_network_from_input,
    get_fn: get_wifi_network,
    save_fn: save_wifi_network,
    delete_fn: delete_wifi_network,
    missing_noun: "network",
    save_unlock_msg: "Unlock your vault before saving a network.",
    delete_unlock_msg: "Unlock your vault before deleting a network.",
    delete_empty_msg: "Choose a saved network to delete.",
}
