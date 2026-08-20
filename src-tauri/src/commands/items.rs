//! Search across every kind of saved record. Matching happens here because the
//! snapshot deliberately omits usernames, network names, and note contents;
//! only the ids of the matches cross back to the interface.

use tauri::State;

use crate::vault::snapshot::folder_name;
use crate::vault::{TaggedItem, VaultPayload, VaultResult, VaultState};

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
    let payload = &session.payload;
    Ok(payload
        .item_views()
        .into_iter()
        .filter(|item| item_matches_search(payload, item, &needle))
        .map(|item| item.id().to_string())
        .collect())
}

fn item_matches_search(payload: &VaultPayload, item: &TaggedItem, needle: &str) -> bool {
    let metadata = item.metadata();
    if metadata.item_title().to_lowercase().contains(needle)
        || metadata
            .item_tags()
            .iter()
            .any(|tag| tag.to_lowercase().contains(needle))
        || folder_name(payload, metadata.item_folder_id())
            .to_lowercase()
            .contains(needle)
    {
        return true;
    }
    searchable_fields(item)
        .iter()
        .any(|field| field.to_lowercase().contains(needle))
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
