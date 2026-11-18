use sesame_core::secret_fields::secret_value;
use zeroize::Zeroizing;

use crate::application::release::require_release_presence;
use crate::application::release_record::{record, record_in};
use crate::application::DesktopEffects;
use crate::release::ReleasePresence;
use crate::vault::release_record::{EntryKind, Outcome, ReleaseDraft};
use crate::vault::{TaggedItem, UnlockedVault, VaultResult, VaultState};

const BACKUP_CODES: &str = "backupCodes";
pub const TERMINAL_SOURCE: &str = "terminal";
pub const VAULT_CHANGED: &str = "vaultChanged";

fn item_in(session: &UnlockedVault, id: &str, kind: &str) -> VaultResult<TaggedItem> {
    let item = session.open_item(id.trim())?;
    if item.kind() != kind {
        return Err("That saved item no longer exists.".into());
    }
    Ok((*item).clone())
}

fn record_item(state: &VaultState, id: &str, kind: &str) -> VaultResult<TaggedItem> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    item_in(session, id, kind)
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
    field_value(&item, field)
}

fn field_value(item: &TaggedItem, field: &str) -> VaultResult<Zeroizing<String>> {
    let field = field.trim();
    let value = match item {
        TaggedItem::Login(entry) if field == BACKUP_CODES => {
            Some(Zeroizing::new(entry.backup_codes.join("\n")))
        }
        _ => secret_value(item, field),
    };
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Nothing is saved in that field for this item.".to_string())
}

fn record_field(state: &VaultState, entry: EntryKind, id: &str, kind: &str, field: &str) {
    record(
        state,
        ReleaseDraft::new(entry, Outcome::Released)
            .item(id.trim(), kind)
            .field(field),
    );
}

fn terminal_draft(entry: EntryKind, id: &str, kind: &str, field: &str) -> ReleaseDraft {
    ReleaseDraft::new(entry, Outcome::Released)
        .item(id.trim(), kind)
        .field(field)
        .host(TERMINAL_SOURCE)
}

pub fn record_terminal_release_in(
    state: &VaultState,
    session: &UnlockedVault,
    entry: EntryKind,
    id: &str,
    kind: &str,
    field: &str,
) {
    record_in(state, Some(session), terminal_draft(entry, id, kind, field));
}

pub fn with_session_at<T>(
    state: &VaultState,
    epoch: u64,
    read: impl FnOnce(&UnlockedVault) -> VaultResult<T>,
) -> VaultResult<T> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    if state.session_epoch() != epoch {
        return Err(VAULT_CHANGED.into());
    }
    read(session)
}

fn terminal_field(
    session: &UnlockedVault,
    presence: &ReleasePresence,
    epoch: u64,
    id: &str,
    kind: &str,
    field: &str,
) -> VaultResult<Zeroizing<String>> {
    presence.require(epoch)?;
    let item = item_in(session, id, kind)?;
    field_value(&item, field)
}

pub fn reveal_item_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    id: &str,
    kind: &str,
    field: &str,
) -> VaultResult<Zeroizing<String>> {
    let value = item_field_in_state(state, presence, id, kind, field)?;
    record_field(state, EntryKind::Reveal, id, kind, field);
    Ok(value)
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
    let copied = effects.copy_secret(value, clear_after_ms)?;
    record_field(state, EntryKind::Copy, id, kind, field);
    Ok(copied)
}

pub struct TerminalField<'a> {
    pub epoch: u64,
    pub id: &'a str,
    pub kind: &'a str,
    pub field: &'a str,
}

pub fn terminal_item_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    wanted: TerminalField<'_>,
    fits: &dyn Fn(&str) -> bool,
) -> VaultResult<Option<Zeroizing<String>>> {
    with_session_at(state, wanted.epoch, |session| {
        let value = terminal_field(
            session,
            presence,
            wanted.epoch,
            wanted.id,
            wanted.kind,
            wanted.field,
        )?;
        if !fits(&value) {
            return Ok(None);
        }
        record_terminal_release_in(
            state,
            session,
            EntryKind::Reveal,
            wanted.id,
            wanted.kind,
            wanted.field,
        );
        Ok(Some(value))
    })
}

pub fn terminal_copy_item_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    effects: &dyn DesktopEffects,
    wanted: TerminalField<'_>,
    clear_after_ms: Option<u64>,
) -> VaultResult<u64> {
    with_session_at(state, wanted.epoch, |session| {
        let value = terminal_field(
            session,
            presence,
            wanted.epoch,
            wanted.id,
            wanted.kind,
            wanted.field,
        )?;
        let copied = effects.copy_secret(value, clear_after_ms)?;
        record_terminal_release_in(
            state,
            session,
            EntryKind::Copy,
            wanted.id,
            wanted.kind,
            wanted.field,
        );
        Ok(copied)
    })
}
