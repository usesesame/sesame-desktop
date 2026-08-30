//! Local item history: prior versions captured before a save overwrote an item.
//! Distinct from `vault::trash`: trash recovers a deleted item, history recovers an edited one.

use crate::types::{
    HistoryEntry, HistoryOperation, HistorySummary, ItemPreview, TaggedItem, VaultPayload,
};
use crate::util::{random_id, unix_timestamp};
use crate::VaultResult;
use zeroize::Zeroize;

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

/// Bookkeeping the person did not change, so it never reads as an edit.
const UNCHANGED_BY_HAND: &[&str] = &[
    "id",
    "createdAt",
    "updatedAt",
    "revision",
    "passwordUpdatedAt",
    "lastUsedAt",
    "importSource",
    "recoveryNotApplicable",
];

fn item_value(item: &TaggedItem) -> serde_json::Value {
    let value = match item {
        TaggedItem::Login(item) => serde_json::to_value(item),
        TaggedItem::Identity(item) => serde_json::to_value(item),
        TaggedItem::SecureNote(item) => serde_json::to_value(item),
        TaggedItem::Card(item) => serde_json::to_value(item),
        TaggedItem::WifiNetwork(item) => serde_json::to_value(item),
        TaggedItem::SshKey(item) => serde_json::to_value(item),
        TaggedItem::SoftwareLicense(item) => serde_json::to_value(item),
        TaggedItem::Document(item) => serde_json::to_value(item),
        TaggedItem::CustomRecord(item) => serde_json::to_value(item),
    };
    value.unwrap_or(serde_json::Value::Null)
}

/// camelCase key to the words someone would use for the field.
fn field_label(key: &str) -> String {
    match key {
        "url" | "urls" => return "website".to_string(),
        "totp" => return "2FA code".to_string(),
        "backupCodes" => return "backup codes".to_string(),
        "securityCode" => return "security code".to_string(),
        "ssid" => return "network name".to_string(),
        "keyType" => return "key type".to_string(),
        "privateKey" => return "private key".to_string(),
        "publicKey" => return "public key".to_string(),
        "legacyFields" => return "imported fields".to_string(),
        "favourite" => return "favourite".to_string(),
        _ => {}
    }
    let mut label = String::new();
    for character in key.chars() {
        if character.is_ascii_uppercase() {
            label.push(' ');
            label.push(character.to_ascii_lowercase());
        } else {
            label.push(character);
        }
    }
    label
}

/// Names the fields that differ, so a version can be told apart without opening
/// it. Compares serialized values, so a field added later is covered by default
/// rather than silently missing from the list. Values never leave Rust.
fn changed_fields(previous: &TaggedItem, successor: &TaggedItem) -> Vec<String> {
    let (previous, successor) = (item_value(previous), item_value(successor));
    let (Some(previous), Some(successor)) = (previous.as_object(), successor.as_object()) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = previous.keys().chain(successor.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut changed = Vec::new();
    for key in keys {
        if UNCHANGED_BY_HAND.contains(&key.as_str()) {
            continue;
        }
        if previous.get(key) != successor.get(key) {
            let label = field_label(key);
            if !changed.contains(&label) {
                changed.push(label);
            }
        }
    }
    changed
}

pub fn history_summaries(payload: &VaultPayload) -> Vec<HistorySummary> {
    let cutoff = unix_timestamp().saturating_sub(HISTORY_RETENTION_SECONDS);
    let mut live: Vec<TaggedItem> = payload.item_views();
    let mut entries: Vec<&HistoryEntry> = payload
        .history
        .iter()
        .filter(|entry| entry.captured_at > cutoff)
        .collect();
    entries.sort_by(|left, right| right.captured_at.cmp(&left.captured_at));

    let mut summaries = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let item_id = entry.item.id().to_string();
        // The newer neighbour for this same item, if this is not the newest one.
        let successor = entries[..index]
            .iter()
            .rev()
            .find(|candidate| candidate.item.id() == entry.item.id())
            .map(|candidate| &candidate.item)
            .or_else(|| {
                live.iter()
                    .find(|candidate| candidate.id() == entry.item.id())
            });
        summaries.push(HistorySummary {
            id: entry.id.clone(),
            item_id,
            kind: entry.item.kind().to_string(),
            captured_at: entry.captured_at,
            operation: entry.operation,
            changed: successor
                .map(|successor| changed_fields(&entry.item, successor))
                .unwrap_or_default(),
        });
    }
    live.zeroize();
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

#[cfg(test)]
mod change_tests {
    use super::*;
    use crate::types::{Card, VaultEntry};

    fn login(password: &str, username: &str) -> TaggedItem {
        TaggedItem::Login(VaultEntry {
            id: "one".to_string(),
            title: "Example".to_string(),
            password: password.to_string(),
            username: username.to_string(),
            ..VaultEntry::default()
        })
    }

    #[test]
    fn a_changed_password_is_named() {
        let changed = changed_fields(&login("old", "person"), &login("new", "person"));
        assert_eq!(changed, vec!["password".to_string()]);
    }

    #[test]
    fn several_changes_are_all_named() {
        let changed = changed_fields(&login("old", "person"), &login("new", "someone"));
        assert!(changed.contains(&"password".to_string()));
        assert!(changed.contains(&"username".to_string()));
        assert_eq!(changed.len(), 2);
    }

    /// Saving without editing anything must not invent a change.
    #[test]
    fn an_identical_version_names_nothing() {
        assert!(changed_fields(&login("same", "person"), &login("same", "person")).is_empty());
    }

    /// Timestamps and revision counters move on every save and are not edits.
    #[test]
    fn bookkeeping_fields_are_not_reported_as_edits() {
        let before = TaggedItem::Login(VaultEntry {
            id: "one".to_string(),
            revision: 1,
            updated_at: 100,
            password_updated_at: 100,
            ..VaultEntry::default()
        });
        let after = TaggedItem::Login(VaultEntry {
            id: "one".to_string(),
            revision: 9,
            updated_at: 999,
            password_updated_at: 999,
            ..VaultEntry::default()
        });
        assert!(changed_fields(&before, &after).is_empty());
    }

    #[test]
    fn field_names_read_as_words_rather_than_keys() {
        let before = TaggedItem::Card(Card {
            id: "c".to_string(),
            security_code: "123".to_string(),
            ..Card::default()
        });
        let after = TaggedItem::Card(Card {
            id: "c".to_string(),
            security_code: "456".to_string(),
            ..Card::default()
        });
        assert_eq!(
            changed_fields(&before, &after),
            vec!["security code".to_string()]
        );
    }
}
