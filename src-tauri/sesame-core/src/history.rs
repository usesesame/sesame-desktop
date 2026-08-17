//! Local item history: prior versions captured before a save overwrote an item.
//! Distinct from `vault::trash`: trash recovers a deleted item, history recovers an edited one.

use crate::types::{
    HistoryEntry, HistoryOperation, HistorySummary, ItemPreview, TaggedItem, VaultPayload,
};
use crate::util::{random_id, unix_timestamp};
use crate::VaultResult;

pub const HISTORY_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Cap bounds growth from repeated saves, which the time cutoff alone does not.
pub const MAX_VERSIONS_PER_ITEM: usize = 20;

/// Capture and replacement land in one atomic `commit_payload_change`.
pub fn capture_history(payload: &mut VaultPayload, item: TaggedItem) {
    capture_history_for_operation(payload, item, HistoryOperation::Edit);
}

fn capture_history_for_operation(
    payload: &mut VaultPayload,
    item: TaggedItem,
    operation: HistoryOperation,
) {
    payload.history.push(HistoryEntry {
        id: random_id(),
        item,
        captured_at: unix_timestamp(),
        operation,
    });
    prune_expired_history(payload);
}

pub fn prune_expired_history(payload: &mut VaultPayload) {
    let cutoff = unix_timestamp().saturating_sub(HISTORY_RETENTION_SECONDS);
    payload.history.retain(|entry| entry.captured_at > cutoff);

    let mut counts: std::collections::HashMap<(&'static str, String), usize> =
        std::collections::HashMap::new();
    // Newest first, so the entries counted past the cap are the oldest ones.
    let mut ordered: Vec<usize> = (0..payload.history.len()).collect();
    ordered.sort_by(|&left, &right| {
        payload.history[right]
            .captured_at
            .cmp(&payload.history[left].captured_at)
    });
    let mut keep = vec![false; payload.history.len()];
    for index in ordered {
        let entry = &payload.history[index];
        let key = (entry.item.kind(), entry.item.id().to_string());
        let count = counts.entry(key).or_insert(0);
        if *count < MAX_VERSIONS_PER_ITEM {
            keep[index] = true;
            *count += 1;
        }
    }
    let mut kept = keep.into_iter();
    payload.history.retain(|_| kept.next().unwrap_or(false));
}

pub fn history_summaries(payload: &VaultPayload) -> Vec<HistorySummary> {
    let cutoff = unix_timestamp().saturating_sub(HISTORY_RETENTION_SECONDS);
    let mut summaries = payload
        .history
        .iter()
        .filter(|entry| entry.captured_at > cutoff)
        .map(|entry| HistorySummary {
            id: entry.id.clone(),
            item_id: entry.item.id().to_string(),
            kind: entry.item.kind().to_string(),
            captured_at: entry.captured_at,
            operation: entry.operation,
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| right.captured_at.cmp(&left.captured_at));
    summaries
}

/// Non-secret preview for one explicitly chosen version; never part of the bulk summaries.
pub fn history_version_preview(
    payload: &VaultPayload,
    history_id: &str,
) -> VaultResult<ItemPreview> {
    let cutoff = unix_timestamp().saturating_sub(HISTORY_RETENTION_SECONDS);
    payload
        .history
        .iter()
        .filter(|entry| entry.captured_at > cutoff)
        .find(|entry| entry.id == history_id)
        .map(|entry| entry.item.preview())
        .ok_or_else(|| "That version is no longer available.".to_string())
}

const NOT_ACTIVE: &str = "Restore the item from trash first, then choose a version to restore.";

/// Restore is reversible like an edit: the current state is captured first; a deleted item's version is refused.
pub fn restore_version(
    payload: &VaultPayload,
    history_id: &str,
) -> VaultResult<(VaultPayload, String)> {
    let mut next = payload.clone();
    let entry = next
        .history
        .iter()
        .find(|entry| entry.id == history_id)
        .cloned()
        .ok_or("That version is no longer available.")?;
    let restored_id = entry.item.id().to_string();
    let now = unix_timestamp();

    let previous = next.take_active_item(&restored_id).ok_or(NOT_ACTIVE)?;
    let restored = entry.item.restored_over(previous.clone(), now)?;
    next.insert_active_item(restored)?;
    capture_history_for_operation(&mut next, previous, HistoryOperation::Restore);
    Ok((next, restored_id))
}
