use tauri::State;
use zeroize::Zeroizing;

use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

pub(crate) use crate::application::release::require_release_presence;

#[tauri::command(async)]
pub fn grant_presence(
    secret: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<()> {
    let secret = Zeroizing::new(secret);
    presence.grant_with_password_in(&state, &secret)
}

#[tauri::command]
pub fn check_release_presence(
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<()> {
    require_release_presence(&state, &presence)
}
