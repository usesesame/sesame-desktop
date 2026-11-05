use tauri::{AppHandle, State};

use crate::commands::require_release_presence;
use crate::pc_link::service::{AppHandleHost, PcLinkService, PcLinkStatus};
use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

#[tauri::command]
pub fn get_pc_link_status(
    app: AppHandle,
    service: State<'_, PcLinkService>,
) -> VaultResult<PcLinkStatus> {
    let host = AppHandleHost::shared(&app)?;
    service.status(&host)
}

#[tauri::command]
pub fn start_pc_link_pairing(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    service: State<'_, PcLinkService>,
) -> VaultResult<PcLinkStatus> {
    require_release_presence(&state, &presence)?;
    let host = AppHandleHost::shared(&app)?;
    service.start_pairing(&host)
}

#[tauri::command]
pub fn confirm_pc_link_pairing(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    service: State<'_, PcLinkService>,
    enrollment_id: String,
) -> VaultResult<PcLinkStatus> {
    require_release_presence(&state, &presence)?;
    let host = AppHandleHost::shared(&app)?;
    service.confirm_pairing(&host, &enrollment_id)
}

#[tauri::command]
pub fn reject_pc_link_pairing(
    app: AppHandle,
    service: State<'_, PcLinkService>,
    enrollment_id: String,
) -> VaultResult<PcLinkStatus> {
    let host = AppHandleHost::shared(&app)?;
    service.reject_pairing(&host, &enrollment_id)
}

#[tauri::command]
pub fn cancel_pc_link_pairing(
    app: AppHandle,
    service: State<'_, PcLinkService>,
) -> VaultResult<PcLinkStatus> {
    let host = AppHandleHost::shared(&app)?;
    service.cancel_pairing(&host)
}

#[tauri::command]
pub fn revoke_pc_link(
    app: AppHandle,
    service: State<'_, PcLinkService>,
    link_id: String,
) -> VaultResult<PcLinkStatus> {
    let host = AppHandleHost::shared(&app)?;
    service.revoke_link(&host, &link_id)
}
