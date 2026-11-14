use sesame_core::secret_fields::secret_value;
use zeroize::Zeroizing;

use crate::application::release::require_release_presence;
use crate::application::DesktopEffects;
use crate::release::ReleasePresence;
use crate::vault::{TaggedItem, VaultResult, VaultState};

const BACKUP_CODES: &str = "backupCodes";

fn record_item(state: &VaultState, id: &str, kind: &str) -> VaultResult<TaggedItem> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id.trim())?;
    if item.kind() != kind {
        return Err("That saved item no longer exists.".into());
    }
    Ok((*item).clone())
}

pub fn item_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    id: &str,
    kind: &str,
    field: &str,
) -> VaultResult<Zeroizing<String>> {
    require_release_presence(state, presence)?;
    let item = record_item(state, id, kind)?;
    let field = field.trim();
    let value = match &item {
        TaggedItem::Login(entry) if field == BACKUP_CODES => {
            Some(Zeroizing::new(entry.backup_codes.join("\n")))
        }
        _ => secret_value(&item, field),
    };
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Nothing is saved in that field for this item.".to_string())
}

pub fn copy_item_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
    id: &str,
    kind: &str,
    field: &str,
    clear_after_ms: Option<u64>,
) -> VaultResult<u64> {
    let value = item_field_in_state(state, presence, id, kind, field)?;
    effects.copy_secret(value, clear_after_ms)
}
