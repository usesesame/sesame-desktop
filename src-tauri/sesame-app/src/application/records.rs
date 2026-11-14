use serde::Serialize;
use sesame_core::secret_fields::{redact, SecretSlots};

use crate::vault::snapshot::{login_card_for, login_summary_for};
use crate::vault::{LoginCard, LoginSummary, TaggedItem, VaultResult, VaultSnapshot, VaultState};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordView<T> {
    #[serde(flatten)]
    pub record: T,
    pub secret_fields: Vec<String>,
}

pub fn redacted_view<T: SecretSlots>(mut record: T) -> RecordView<T> {
    let secret_fields = redact(&mut record);
    RecordView {
        record,
        secret_fields,
    }
}

pub fn vault_snapshot_in_state(state: &VaultState) -> VaultResult<VaultSnapshot> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    Ok(session.snapshot())
}

pub fn login_card_in_state(state: &VaultState, id: &str) -> VaultResult<LoginCard> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    let index = session.snapshot();
    Ok(login_card_for(&index.folders, entry))
}

pub fn login_summary_in_state(state: &VaultState, id: &str) -> VaultResult<LoginSummary> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id)?;
    let TaggedItem::Login(entry) = &*item else {
        return Err("That saved login no longer exists.".into());
    };
    Ok(login_summary_for(entry))
}

pub fn record_view_in_state<T>(
    state: &VaultState,
    id: &str,
    missing_noun: &str,
    pick: fn(&TaggedItem) -> Option<&T>,
) -> VaultResult<RecordView<T>>
where
    T: SecretSlots + Clone,
{
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let item = session.open_item(id)?;
    let record =
        pick(&item).ok_or_else(|| format!("That saved {missing_noun} no longer exists."))?;
    Ok(redacted_view(record.clone()))
}
