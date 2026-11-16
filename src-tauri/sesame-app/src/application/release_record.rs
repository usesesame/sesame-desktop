use serde::{Deserialize, Serialize};

use crate::vault::release_record::{
    Appended, EntryKind, FieldKind, MatchKind, Outcome, RecordEntry, RecordNotice, RecordStatus,
    ReleaseDraft,
};
use crate::vault::{UnlockedVault, VaultResult, VaultState};

use super::browser_fill::ApprovalKind;
use super::browser_fill_broker::BrowserFillState;
use super::release::require_release_presence;
use crate::release::ReleasePresence;

pub const RECENT_DENIAL_SECS: u64 = 14 * 86_400;

pub const DEFAULT_PAGE_SIZE: usize = 200;
pub const MAX_PAGE_SIZE: usize = 1_000;

pub fn record(vault: &VaultState, draft: ReleaseDraft) -> Appended {
    match vault.session.lock() {
        Ok(session) => record_in(vault, session.as_ref(), draft),
        Err(_) => vault.release_record.append_locked(draft),
    }
}

pub fn record_in(
    vault: &VaultState,
    session: Option<&UnlockedVault>,
    draft: ReleaseDraft,
) -> Appended {
    match session {
        Some(session) => vault.release_record.append(session, draft),
        None => vault.release_record.append_locked(draft),
    }
}

pub fn entry_kind(kind: ApprovalKind) -> EntryKind {
    match kind {
        ApprovalKind::Fill => EntryKind::BrowserFill,
        ApprovalKind::Save => EntryKind::BrowserSave,
        ApprovalKind::Identity => EntryKind::BrowserIdentity,
        ApprovalKind::Card => EntryKind::BrowserCard,
        ApprovalKind::Totp => EntryKind::BrowserTotp,
        ApprovalKind::Change => EntryKind::BrowserChange,
        ApprovalKind::Create => EntryKind::BrowserCreate,
    }
}

pub fn browser_draft(kind: ApprovalKind, outcome: Outcome, host: &str) -> ReleaseDraft {
    ReleaseDraft::new(entry_kind(kind), outcome).host(host)
}

pub fn wait_outcome(reason: &str) -> Outcome {
    match reason {
        "approvalTimeout" => Outcome::TimedOut,
        "staleRequest" => Outcome::ConnectionClosed,
        _ => Outcome::Withdrawn,
    }
}

#[derive(Deserialize, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", default)]
pub struct ReleaseRecordQuery {
    pub item_id: Option<String>,
    pub refused_only: bool,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseEntryView {
    pub seq: u64,
    pub at: u64,
    pub kind: EntryKind,
    pub outcome: Outcome,
    pub item_id: Option<String>,
    pub item_kind: Option<String>,
    pub fields: Vec<FieldKind>,
    pub host: Option<String>,
    pub similar_to: Option<String>,
    pub match_kind: Option<MatchKind>,
    pub count: u32,
    pub late: bool,
}

impl From<RecordEntry> for ReleaseEntryView {
    fn from(entry: RecordEntry) -> Self {
        Self {
            seq: entry.seq,
            at: entry.at,
            kind: entry.kind,
            outcome: entry.outcome,
            item_id: entry.item_id,
            item_kind: entry.item_kind,
            fields: entry.fields,
            host: entry.host,
            similar_to: entry.similar_to,
            match_kind: entry.match_kind,
            count: entry.count,
            late: entry.late,
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRecordStatus {
    pub available: bool,
    pub entry_count: u32,
    pub starts_at: Option<u64>,
    pub complete_since: Option<u64>,
    pub retention_days: u32,
    pub unwritten: u32,
    pub notice: Option<ReleaseRecordNotice>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum ReleaseRecordNotice {
    Unreadable,
    Interrupted,
    FileChanged,
}

impl From<RecordStatus> for ReleaseRecordStatus {
    fn from(status: RecordStatus) -> Self {
        Self {
            available: status.open,
            entry_count: u32::try_from(status.entry_count).unwrap_or(u32::MAX),
            starts_at: status.starts_at,
            complete_since: status.complete_since,
            retention_days: status.retention_days,
            unwritten: u32::try_from(status.unwritten).unwrap_or(u32::MAX),
            notice: status.notice.map(|notice| match notice {
                RecordNotice::Unreadable => ReleaseRecordNotice::Unreadable,
                RecordNotice::Interrupted => ReleaseRecordNotice::Interrupted,
                RecordNotice::FileChanged => ReleaseRecordNotice::FileChanged,
            }),
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRecordPage {
    pub entries: Vec<ReleaseEntryView>,
    pub total: u32,
    pub status: ReleaseRecordStatus,
}

pub fn release_record_status_in_state(vault: &VaultState) -> ReleaseRecordStatus {
    vault.release_record.status().into()
}

pub fn release_record_page_in_state(
    vault: &VaultState,
    query: ReleaseRecordQuery,
) -> VaultResult<ReleaseRecordPage> {
    let entries = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_ref().ok_or("Unlock your vault first.")?;
        vault.release_record.entries(session)?
    };
    let item_id = query.item_id.as_deref().map(str::trim);
    let mut matching: Vec<RecordEntry> = entries
        .into_iter()
        .filter(|entry| item_id.is_none_or(|id| entry.item_id.as_deref() == Some(id)))
        .filter(|entry| !query.refused_only || entry.outcome.is_refusal())
        .collect();
    matching.sort_by(|left, right| right.at.cmp(&left.at).then(right.seq.cmp(&left.seq)));
    let total = u32::try_from(matching.len()).unwrap_or(u32::MAX);
    let offset = query.offset.unwrap_or(0) as usize;
    let limit = query
        .limit
        .map_or(DEFAULT_PAGE_SIZE, |limit| limit as usize)
        .clamp(1, MAX_PAGE_SIZE);
    Ok(ReleaseRecordPage {
        entries: matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(ReleaseEntryView::from)
            .collect(),
        total,
        status: release_record_status_in_state(vault),
    })
}

pub fn open_release_record(vault: &VaultState, session: &UnlockedVault) {
    let _ = vault.release_record.open(session);
}

pub fn field_kinds<'a>(keys: impl IntoIterator<Item = &'a String>) -> Vec<FieldKind> {
    keys.into_iter()
        .map(|key| FieldKind::from_key(key))
        .collect()
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseItemHint {
    pub item_id: String,
    pub released_here: u32,
    pub last_released_at: Option<u64>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRecordHint {
    pub approval_id: String,
    pub host: String,
    pub items: Vec<ReleaseItemHint>,
    pub record_since: u64,
    pub incomplete: bool,
    pub denied_recently: u32,
    pub last_denied_at: Option<u64>,
}

pub fn release_record_hint_in_state(
    vault: &VaultState,
    fill_state: &BrowserFillState,
    approval_id: &str,
    now: u64,
) -> VaultResult<Option<ReleaseRecordHint>> {
    let Some((origin, kind, item_ids)) = fill_state.pending_subject(approval_id) else {
        return Ok(None);
    };
    let entries = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_ref().ok_or("Unlock your vault first.")?;
        vault.release_record.entries(session)?
    };
    let status = vault.release_record.status();
    let host = origin.hostname.as_str();
    let at_host: Vec<&RecordEntry> = entries
        .iter()
        .filter(|entry| entry.kind.is_browser() && entry.host.as_deref() == Some(host))
        .collect();
    let items = item_ids
        .into_iter()
        .map(|item_id| {
            let released: Vec<&&RecordEntry> = at_host
                .iter()
                .filter(|entry| {
                    entry.outcome == Outcome::Released
                        && entry.kind == entry_kind(kind)
                        && entry.item_id.as_deref() == Some(item_id.as_str())
                })
                .collect();
            ReleaseItemHint {
                released_here: released.iter().map(|entry| entry.count).sum(),
                last_released_at: released.iter().map(|entry| entry.at).max(),
                item_id,
            }
        })
        .collect();
    let denied: Vec<&&RecordEntry> = at_host
        .iter()
        .filter(|entry| {
            entry.outcome == Outcome::Denied && entry.at.saturating_add(RECENT_DENIAL_SECS) >= now
        })
        .collect();
    Ok(Some(ReleaseRecordHint {
        approval_id: approval_id.to_string(),
        host: host.to_string(),
        items,
        record_since: status.complete_since.unwrap_or(now),
        incomplete: status.unwritten > 0 || status.notice.is_some(),
        denied_recently: denied.iter().map(|entry| entry.count).sum(),
        last_denied_at: denied.iter().map(|entry| entry.at).max(),
    }))
}

pub const RETENTION_CHOICES: [u32; 4] = [30, 90, 180, 365];

pub fn set_release_record_retention_in_state(
    vault: &VaultState,
    days: u32,
) -> VaultResult<ReleaseRecordStatus> {
    if !RETENTION_CHOICES.contains(&days) {
        return Err("Choose how long Sesame keeps activity from the list.".into());
    }
    vault.release_record.set_retention_days(days);
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    if let Some(session) = session.as_ref() {
        vault.release_record.apply_retention(session)?;
    }
    drop(session);
    Ok(release_record_status_in_state(vault))
}

pub fn clear_release_record_in_state(
    vault: &VaultState,
    presence: &ReleasePresence,
) -> VaultResult<ReleaseRecordStatus> {
    require_release_presence(vault, presence)?;
    {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_ref().ok_or("Unlock your vault first.")?;
        vault.release_record.clear(session)?;
    }
    Ok(release_record_status_in_state(vault))
}
