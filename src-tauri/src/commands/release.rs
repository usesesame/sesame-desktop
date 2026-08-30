use tauri::State;
use zeroize::Zeroizing;

use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

#[tauri::command]
pub fn grant_presence(
    secret: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<()> {
    let secret = Zeroizing::new(secret);
    let epoch = state.session_epoch();
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    presence.grant_with_password(session, epoch, &secret)
}

pub(crate) fn require_release_presence(
    state: &VaultState,
    presence: &ReleasePresence,
) -> VaultResult<()> {
    presence.require(state.session_epoch())
}
