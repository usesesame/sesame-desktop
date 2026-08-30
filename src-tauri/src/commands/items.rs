//! Search across every kind of saved record. Matching happens here because the
//! snapshot deliberately omits usernames, network names, and note contents;
//! only the ids of the matches cross back to the interface.

use crate::vault::{Folder, TaggedItem, VaultResult, VaultState};
use tauri::State;

#[tauri::command]
pub fn search_items(query: String, state: State<'_, VaultState>) -> VaultResult<Vec<String>> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let index = session.snapshot();
    let mut matches = Vec::new();
    for id in index
        .entries
        .iter()
        .map(|item| item.id.as_str())
        .chain(index.items.iter().map(|item| item.id.as_str()))
    {
        let item = session.open_item(id)?;
        if item_matches_search(&index.folders, &item, &needle) {
            matches.push(id.to_string());
        }
    }
    Ok(matches)
}

fn item_matches_search(folders: &[Folder], item: &TaggedItem, needle: &str) -> bool {
    let metadata = item.metadata();
    if metadata.item_title().to_lowercase().contains(needle)
        || metadata
            .item_tags()
            .iter()
            .any(|tag| tag.to_lowercase().contains(needle))
        || folder_name(folders, metadata.item_folder_id())
            .to_lowercase()
            .contains(needle)
    {
        return true;
    }
    searchable_fields(item)
        .iter()
        .any(|field| field.to_lowercase().contains(needle))
}

fn folder_name(folders: &[Folder], id: Option<&str>) -> String {
    id.and_then(|id| folders.iter().find(|folder| folder.id == id))
        .map(|folder| folder.name.clone())
        .unwrap_or_default()
}

/// Everything a search may read. Passwords, keys, licence keys, security
/// codes, and card numbers are absent on purpose: a match on one of those
/// would confirm its value to whoever typed the guess.
fn searchable_fields(item: &TaggedItem) -> Vec<&str> {
    match item {
        TaggedItem::Login(entry) => vec![
            entry.username.as_str(),
            entry.email.as_str(),
            entry.url.as_str(),
            entry.notes.as_deref().unwrap_or_default(),
        ],
        TaggedItem::Identity(identity) => vec![
            identity.full_name.as_str(),
            identity.email.as_str(),
            identity.phone.as_str(),
            identity.city.as_str(),
            identity.country.as_str(),
        ],
        TaggedItem::SecureNote(note) => vec![note.content.as_str()],
        TaggedItem::Card(card) => vec![
            card.brand.as_str(),
            card.cardholder_name.as_str(),
            card.notes.as_str(),
        ],
        TaggedItem::WifiNetwork(network) => {
            vec![network.ssid.as_str(), network.notes.as_str()]
        }
        TaggedItem::SshKey(key) => vec![key.key_type.as_str(), key.notes.as_str()],
        TaggedItem::SoftwareLicense(license) => vec![
            license.product_name.as_str(),
            license.purchased_from.as_str(),
            license.notes.as_str(),
        ],
        TaggedItem::Document(document) => vec![
            document.document_type.as_str(),
            document.document_number.as_str(),
            document.issuing_authority.as_str(),
            document.notes.as_str(),
        ],
        TaggedItem::CustomRecord(record) => {
            let mut fields = vec![record.notes.as_str()];
            // Field labels describe the record; a custom field's value may be a secret.
            fields.extend(record.fields.iter().map(|field| field.label.as_str()));
            fields
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultEntry;

    fn login() -> TaggedItem {
        TaggedItem::Login(VaultEntry {
            id: "fictional-login".to_string(),
            title: "Northwind".to_string(),
            username: "casey".to_string(),
            password: "fictional-secret-canary".to_string(),
            folder_id: Some("fictional-folder".to_string()),
            ..VaultEntry::default()
        })
    }

    #[test]
    fn search_matches_allowed_record_fields_and_redacted_folders() {
        let folders = vec![Folder {
            id: "fictional-folder".to_string(),
            name: "Work".to_string(),
        }];
        let item = login();

        assert!(item_matches_search(&folders, &item, "north"));
        assert!(item_matches_search(&folders, &item, "casey"));
        assert!(item_matches_search(&folders, &item, "work"));
    }

    #[test]
    fn search_does_not_match_secret_fields() {
        assert!(!item_matches_search(&[], &login(), "secret-canary"));
    }
}
