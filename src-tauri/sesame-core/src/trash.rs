//! Local item trash: a 30-day recovery window for deleted items.
//! History for edits is a separate capability; this module covers delete and restore only.

use crate::types::{ItemPreview, TaggedItem, TrashSummary, TrashedItem, VaultPayload};
use crate::util::unix_timestamp;
use crate::VaultResult;

pub const TRASH_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Trash move and active-collection removal land in one atomic commit.
pub fn trash_item(payload: &mut VaultPayload, item: TaggedItem) {
    payload.trash.push(TrashedItem {
        item,
        deleted_at: unix_timestamp(),
    });
    prune_expired_trash(payload);
}

pub fn prune_expired_trash(payload: &mut VaultPayload) {
    let cutoff = unix_timestamp().saturating_sub(TRASH_RETENTION_SECONDS);
    payload.trash.retain(|trashed| trashed.deleted_at > cutoff);
}

/// Filters expired entries even before a lazy prune, so retention is never looser than advertised.
pub fn trash_summaries(payload: &VaultPayload) -> Vec<TrashSummary> {
    let cutoff = unix_timestamp().saturating_sub(TRASH_RETENTION_SECONDS);
    payload
        .trash
        .iter()
        .filter(|trashed| trashed.deleted_at > cutoff)
        .map(|trashed| TrashSummary {
            id: trashed.item.id().to_string(),
            kind: trashed.item.kind().to_string(),
            deleted_at: trashed.deleted_at,
        })
        .collect()
}

/// Non-secret preview for one explicitly chosen id; never part of the bulk summaries.
pub fn trash_item_preview(payload: &VaultPayload, id: &str) -> VaultResult<ItemPreview> {
    let cutoff = unix_timestamp().saturating_sub(TRASH_RETENTION_SECONDS);
    payload
        .trash
        .iter()
        .filter(|trashed| trashed.deleted_at > cutoff)
        .find(|trashed| trashed.item.id() == id)
        .map(|trashed| trashed.item.preview())
        .ok_or_else(|| "That deleted item is no longer in trash.".to_string())
}

/// Refuses an occupied id rather than overwriting or aliasing either item.
pub fn restore_item(payload: &VaultPayload, id: &str) -> VaultResult<VaultPayload> {
    let mut next = payload.clone();
    prune_expired_trash(&mut next);
    let position = next
        .trash
        .iter()
        .position(|trashed| trashed.item.id() == id)
        .ok_or("That deleted item is no longer in trash.")?;
    let trashed = next.trash.remove(position);
    next.insert_active_item(trashed.item)
        .map_err(|_| occupied_id_error())?;
    Ok(next)
}

fn occupied_id_error() -> String {
    "A saved item with that id already exists. Restore refused rather than \
     overwriting it; remove or rename the newer item first."
        .to_string()
}
