//! Search across every kind of saved record. Matching happens here because the
//! snapshot deliberately omits usernames, network names, and note contents;
//! only the ids of the matches cross back to the interface.

use crate::vault::{Folder, TaggedItem, UnlockedVault, VaultResult, VaultSnapshot, VaultState};
use tauri::State;

#[tauri::command]
pub fn search_items(query: String, state: State<'_, VaultState>) -> VaultResult<Vec<String>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    search_index(session, &session.snapshot(), &query)
}

fn search_index(
    session: &UnlockedVault,
    index: &VaultSnapshot,
    query: &str,
) -> VaultResult<Vec<String>> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
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
    use crate::vault::{random_id, VaultEntry};
    use sesame_core::api::create_vault;
    use std::time::Instant;

    const LATENCY_VAULT_ITEMS: usize = 5_000;
    const LATENCY_RUNS: usize = 5;

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

    fn latency_session(count: usize) -> UnlockedVault {
        let (mut opened, _) =
            create_vault("fictional master password", "Fictional vault").expect("created vault");
        for index in 0..count {
            opened.payload.entries.push(VaultEntry {
                id: format!("fictional-login-{index:05}"),
                title: format!("Northwind account {index:05}"),
                username: format!("casey.{index:05}"),
                email: format!("casey.{index:05}@northwind.example"),
                url: format!("https://portal.example/{index:05}"),
                notes: Some(format!("Fictional note {index:05}")),
                password: format!("fictional-secret-{index:05}"),
                updated_at: 41,
                ..VaultEntry::default()
            });
        }
        let path = std::env::temp_dir().join(format!("sesame-search-{}", random_id()));
        UnlockedVault::from_opened(path, &opened).expect("unlocked vault")
    }

    fn measure(
        session: &UnlockedVault,
        index: &VaultSnapshot,
        query: &str,
    ) -> (usize, std::time::Duration, std::time::Duration) {
        let mut durations = Vec::with_capacity(LATENCY_RUNS);
        let mut hits = 0;
        for _ in 0..LATENCY_RUNS {
            let started = Instant::now();
            let ids = search_index(session, index, query).expect("search");
            durations.push(started.elapsed());
            hits = ids.len();
        }
        durations.sort();
        (hits, durations[0], durations[LATENCY_RUNS / 2])
    }

    #[test]
    fn search_latency_over_a_five_thousand_item_vault() {
        let session = latency_session(LATENCY_VAULT_ITEMS);
        let index = session.snapshot();
        for (query, expected_hits) in [
            ("northwind", Some(LATENCY_VAULT_ITEMS)),
            ("casey.00999", Some(1)),
            ("account 00420", None),
            ("northwnd", None),
        ] {
            let (hits, min, median) = measure(&session, &index, query);
            println!("search latency query={query:?} hits={hits} min={min:?} median={median:?}");
            if let Some(expected) = expected_hits {
                assert_eq!(hits, expected, "query {query:?}");
            }
        }
    }
}
