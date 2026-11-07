use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

pub(crate) fn require_release_presence(
    state: &VaultState,
    presence: &ReleasePresence,
) -> VaultResult<()> {
    presence.require(state.session_epoch())
}
