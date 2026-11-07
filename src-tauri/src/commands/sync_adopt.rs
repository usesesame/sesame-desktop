use serde::Serialize;
use tauri::AppHandle;

use super::sync::local_data_dir;
use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::application::sync::SyncStore;
use crate::vault::{VaultPayload, VaultState};

pub(super) use crate::application::sync_adopt::digest_after_commit;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncAdoptResult {
    pub entry_count: usize,
    pub revision: u64,
    pub recovery_kit: String,
}

pub(super) fn finish_adoption(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
    key: [u8; 32],
    payload: VaultPayload,
    master_password: &str,
    vault_id: &str,
) -> Result<String, String> {
    let store = SyncStore::new(local_data_dir(app)?);
    crate::application::sync_adopt::finish_adoption_in_state(
        state,
        &store,
        &DesktopHostEffects::new(app),
        key,
        payload,
        master_password,
        vault_id,
    )
}
