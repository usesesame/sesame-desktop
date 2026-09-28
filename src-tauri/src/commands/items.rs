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
    let tokens = query_tokens(query);
    if tokens.is_empty() {
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
        if let Some(score) = search_match_score(&index.folders, &item, &tokens) {
            matches.push(SearchMatch {
                id: id.to_string(),
                score,
                title: item.metadata().item_title().to_lowercase(),
            });
        }
    }
    Ok(ordered_match_ids(matches))
}

struct SearchMatch {
    id: String,
    score: i64,
    title: String,
}

fn ordered_match_ids(mut matches: Vec<SearchMatch>) -> Vec<String> {
    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.id.cmp(&right.id))
    });
    matches.into_iter().map(|entry| entry.id).collect()
}

const TITLE_WEIGHT: i64 = 100;
const TAG_WEIGHT: i64 = 60;
const HANDLE_WEIGHT: i64 = 40;
const FOLDER_WEIGHT: i64 = 30;
const DETAIL_WEIGHT: i64 = 20;
const EXACT_BONUS: i64 = 24;
const PREFIX_BONUS: i64 = 16;
const CONTAINS_BONUS: i64 = 8;
const POSITION_PENALTY_STEP: i64 = 2;
const POSITION_PENALTY_LIMIT: usize = 16;
const TYPO_DISTANCE_MINIMUM_LENGTH: usize = 4;
const WIDE_TYPO_MINIMUM_LENGTH: usize = 8;
const WIDE_TYPO_DISTANCE: usize = 2;
const NARROW_TYPO_DISTANCE: usize = 1;

#[derive(Clone, Copy)]
enum FieldTier {
    Title,
    Tag,
    Handle,
    Folder,
    Detail,
}

impl FieldTier {
    fn weight(self) -> i64 {
        match self {
            FieldTier::Title => TITLE_WEIGHT,
            FieldTier::Tag => TAG_WEIGHT,
            FieldTier::Handle => HANDLE_WEIGHT,
            FieldTier::Folder => FOLDER_WEIGHT,
            FieldTier::Detail => DETAIL_WEIGHT,
        }
    }
}

struct RankedField<'a> {
    tier: FieldTier,
    value: &'a str,
}

struct SearchToken {
    text: String,
    max_distance: usize,
}

enum MatchQuality {
    Exact,
    Prefix,
    Contains,
    Typo(usize),
}

impl MatchQuality {
    fn bonus(self) -> i64 {
        match self {
            MatchQuality::Exact => EXACT_BONUS,
            MatchQuality::Prefix => PREFIX_BONUS,
            MatchQuality::Contains => CONTAINS_BONUS,
            MatchQuality::Typo(distance) => -(distance as i64),
        }
    }
}

fn query_tokens(query: &str) -> Vec<SearchToken> {
    let mut tokens: Vec<SearchToken> = Vec::new();
    for word in query.trim().to_lowercase().split_whitespace() {
        if tokens.iter().any(|token| token.text == word) {
            continue;
        }
        tokens.push(SearchToken {
            text: word.to_string(),
            max_distance: max_edit_distance(word.chars().count()),
        });
    }
    tokens
}

fn max_edit_distance(length: usize) -> usize {
    if length >= WIDE_TYPO_MINIMUM_LENGTH {
        WIDE_TYPO_DISTANCE
    } else if length >= TYPO_DISTANCE_MINIMUM_LENGTH {
        NARROW_TYPO_DISTANCE
    } else {
        0
    }
}

fn search_match_score(
    folders: &[Folder],
    item: &TaggedItem,
    tokens: &[SearchToken],
) -> Option<i64> {
    if tokens.is_empty() {
        return None;
    }
    let fields = searchable_field_groups(folders, item);
    let mut total = 0;
    for token in tokens {
        let best = fields
            .iter()
            .filter_map(|field| field_match_score(field.tier, field.value, token))
            .max()?;
        total += best;
    }
    Some(total)
}

fn searchable_field_groups<'a>(
    folders: &'a [Folder],
    item: &'a TaggedItem,
) -> Vec<RankedField<'a>> {
    let metadata = item.metadata();
    let mut fields = vec![
        RankedField {
            tier: FieldTier::Title,
            value: metadata.item_title(),
        },
        RankedField {
            tier: FieldTier::Folder,
            value: folder_name(folders, metadata.item_folder_id()),
        },
    ];
    fields.extend(metadata.item_tags().iter().map(|tag| RankedField {
        tier: FieldTier::Tag,
        value: tag.as_str(),
    }));
    fields.extend(
        searchable_fields(item)
            .into_iter()
            .enumerate()
            .map(|(index, value)| RankedField {
                tier: field_tier(item, index),
                value,
            }),
    );
    fields
}

fn field_tier(item: &TaggedItem, index: usize) -> FieldTier {
    searchable_field_tiers(item)
        .get(index)
        .copied()
        .unwrap_or(FieldTier::Detail)
}

fn searchable_field_tiers(item: &TaggedItem) -> &'static [FieldTier] {
    match item {
        TaggedItem::Login(_) => &[
            FieldTier::Handle,
            FieldTier::Handle,
            FieldTier::Handle,
            FieldTier::Detail,
        ],
        TaggedItem::Identity(_) => &[
            FieldTier::Handle,
            FieldTier::Handle,
            FieldTier::Detail,
            FieldTier::Detail,
            FieldTier::Detail,
        ],
        TaggedItem::SecureNote(_) => &[FieldTier::Detail],
        TaggedItem::Card(_) => &[FieldTier::Detail, FieldTier::Handle, FieldTier::Detail],
        TaggedItem::WifiNetwork(_) => &[FieldTier::Handle, FieldTier::Detail],
        TaggedItem::SshKey(_) => &[FieldTier::Detail, FieldTier::Detail],
        TaggedItem::SoftwareLicense(_) => {
            &[FieldTier::Handle, FieldTier::Detail, FieldTier::Detail]
        }
        TaggedItem::Document(_) => &[
            FieldTier::Detail,
            FieldTier::Handle,
            FieldTier::Detail,
            FieldTier::Detail,
        ],
        TaggedItem::CustomRecord(_) => &[FieldTier::Detail, FieldTier::Detail],
    }
}

fn field_match_score(tier: FieldTier, value: &str, token: &SearchToken) -> Option<i64> {
    let haystack = value.to_lowercase();
    if haystack.is_empty() {
        return None;
    }
    let mut best: Option<i64> = None;
    for (offset, word) in words_with_offsets(&haystack) {
        let quality = if word == token.text.as_str() {
            MatchQuality::Exact
        } else if word.starts_with(&token.text) {
            MatchQuality::Prefix
        } else if word.contains(&token.text) {
            MatchQuality::Contains
        } else {
            match typo_distance(word, token) {
                Some(distance) => MatchQuality::Typo(distance),
                None => continue,
            }
        };
        let score = tier.weight() + quality.bonus() - position_penalty(offset);
        best = Some(best.map_or(score, |current| current.max(score)));
    }
    if best.is_none() {
        if let Some(offset) = haystack.find(&token.text) {
            best = Some(tier.weight() + CONTAINS_BONUS - position_penalty(offset));
        }
    }
    best
}

fn words_with_offsets(haystack: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    for (index, character) in haystack.char_indices() {
        if character.is_alphanumeric() {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(word_start) = start.take() {
            words.push((word_start, &haystack[word_start..index]));
        }
    }
    if let Some(word_start) = start {
        words.push((word_start, &haystack[word_start..]));
    }
    words
}

fn position_penalty(offset: usize) -> i64 {
    (offset.min(POSITION_PENALTY_LIMIT) as i64) / POSITION_PENALTY_STEP
}

fn typo_distance(word: &str, token: &SearchToken) -> Option<usize> {
    if token.max_distance == 0 || word.chars().next() != token.text.chars().next() {
        return None;
    }
    let word_length = word.chars().count();
    let token_length = token.text.chars().count();
    if word_length.abs_diff(token_length) > token.max_distance {
        return None;
    }
    let distance = edit_distance(word, &token.text);
    (distance <= token.max_distance).then_some(distance)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (row, left_character) in left.iter().enumerate() {
        current[0] = row + 1;
        for (column, right_character) in right.iter().enumerate() {
            let substitution = previous[column] + usize::from(left_character != right_character);
            current[column + 1] = (previous[column + 1] + 1)
                .min(current[column] + 1)
                .min(substitution);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

#[cfg(test)]
fn item_matches_search(folders: &[Folder], item: &TaggedItem, needle: &str) -> bool {
    let tokens = query_tokens(needle);
    search_match_score(folders, item, &tokens).is_some()
}

fn folder_name<'a>(folders: &'a [Folder], id: Option<&str>) -> &'a str {
    id.and_then(|id| folders.iter().find(|folder| folder.id == id))
        .map(|folder| folder.name.as_str())
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

    fn entry(
        id: &str,
        title: &str,
        username: &str,
        tags: &[&str],
        notes: Option<&str>,
    ) -> TaggedItem {
        TaggedItem::Login(VaultEntry {
            id: id.to_string(),
            title: title.to_string(),
            username: username.to_string(),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            notes: notes.map(str::to_string),
            ..VaultEntry::default()
        })
    }

    fn match_score(item: &TaggedItem, query: &str) -> i64 {
        let tokens = query_tokens(query);
        search_match_score(&[], item, &tokens).expect("expected a match")
    }

    #[test]
    fn title_matches_outrank_tag_handle_and_detail_matches() {
        let title_match = entry("title", "Northwind", "", &[], None);
        let tag_match = entry("tag", "Elsewhere", "", &["northwind"], None);
        let handle_match = entry("handle", "Elsewhere", "northwind", &[], None);
        let detail_match = entry("detail", "Elsewhere", "", &[], Some("northwind"));

        assert!(match_score(&title_match, "northwind") > match_score(&tag_match, "northwind"));
        assert!(match_score(&tag_match, "northwind") > match_score(&handle_match, "northwind"));
        assert!(match_score(&handle_match, "northwind") > match_score(&detail_match, "northwind"));
    }

    #[test]
    fn earlier_matches_outrank_later_matches() {
        let early = entry("early", "Northwind portal", "", &[], None);
        let late = entry("late", "Portal northwind", "", &[], None);

        assert!(match_score(&early, "northwind") > match_score(&late, "northwind"));
    }

    #[test]
    fn whole_token_and_prefix_matches_outrank_mid_word_matches() {
        let exact = entry("exact", "Work tools", "", &[], None);
        let prefix = entry("prefix", "Workspace", "", &[], None);
        let mid_word = entry("mid", "Paperwork", "", &[], None);

        assert!(match_score(&exact, "work") > match_score(&prefix, "work"));
        assert!(match_score(&prefix, "work") > match_score(&mid_word, "work"));
    }

    #[test]
    fn every_query_token_must_match() {
        let item = entry("login", "Northwind", "casey", &[], None);

        assert!(item_matches_search(&[], &item, "northwind casey"));
        assert!(!item_matches_search(&[], &item, "northwind missing"));
    }

    #[test]
    fn typos_match_within_the_token_budget() {
        let item = entry("login", "Northwind", "casey", &[], None);

        assert!(item_matches_search(&[], &item, "northwnd"));
        assert!(item_matches_search(&[], &item, "northwidn"));
        assert!(item_matches_search(&[], &item, "casei"));
        assert!(!item_matches_search(&[], &item, "sorthwind"));
        assert!(!item_matches_search(&[], &item, "nortwnd"));
        assert!(!item_matches_search(&[], &item, "nro"));
        assert!(!item_matches_search(&[], &item, "xy"));
    }

    #[test]
    fn score_ties_break_by_title_then_id() {
        let matches = vec![
            SearchMatch {
                id: "z".to_string(),
                score: 5,
                title: "beta".to_string(),
            },
            SearchMatch {
                id: "a".to_string(),
                score: 5,
                title: "alpha".to_string(),
            },
            SearchMatch {
                id: "b".to_string(),
                score: 5,
                title: "beta".to_string(),
            },
        ];

        assert_eq!(ordered_match_ids(matches), vec!["a", "b", "z"]);
    }

    fn one_of_each_kind() -> Vec<TaggedItem> {
        use crate::vault::{
            Card, CustomRecord, DocumentMetadata, Identity, SecureNote, SoftwareLicense, SshKey,
            WifiNetwork,
        };

        vec![
            TaggedItem::Login(VaultEntry {
                id: "login".to_string(),
                title: "Northwind".to_string(),
                username: "casey".to_string(),
                password: "fictional-login-canary".to_string(),
                ..VaultEntry::default()
            }),
            TaggedItem::Identity(Identity {
                id: "identity".to_string(),
                full_name: "Casey North".to_string(),
                ..Identity::default()
            }),
            TaggedItem::SecureNote(SecureNote {
                id: "note".to_string(),
                content: "fictional note body".to_string(),
                ..SecureNote::default()
            }),
            TaggedItem::Card(Card {
                id: "card".to_string(),
                number: "fictional-card-number-canary".to_string(),
                security_code: "fictional-card-code-canary".to_string(),
                ..Card::default()
            }),
            TaggedItem::WifiNetwork(WifiNetwork {
                id: "wifi".to_string(),
                ssid: "Fictional Cafe".to_string(),
                password: "fictional-wifi-canary".to_string(),
                ..WifiNetwork::default()
            }),
            TaggedItem::SshKey(SshKey {
                id: "ssh".to_string(),
                key_type: "ed25519".to_string(),
                private_key: "fictional-ssh-canary".to_string(),
                passphrase: "fictional-ssh-passphrase-canary".to_string(),
                ..SshKey::default()
            }),
            TaggedItem::SoftwareLicense(SoftwareLicense {
                id: "license".to_string(),
                product_name: "Fictional Editor".to_string(),
                license_key: "fictional-licence-canary".to_string(),
                ..SoftwareLicense::default()
            }),
            TaggedItem::Document(DocumentMetadata {
                id: "document".to_string(),
                document_number: "fictional-document-canary".to_string(),
                ..DocumentMetadata::default()
            }),
            TaggedItem::CustomRecord(CustomRecord {
                id: "record".to_string(),
                fields: vec![crate::vault::CustomFieldEntry {
                    label: "Fictional field".to_string(),
                    value: "fictional-field-canary".to_string(),
                    kind: "text".to_string(),
                }],
                ..CustomRecord::default()
            }),
        ]
    }

    #[test]
    fn searchable_field_groups_keep_the_allowlist_exactly() {
        for item in one_of_each_kind() {
            let metadata = item.metadata();
            let expected: Vec<&str> = std::iter::once(metadata.item_title())
                .chain(std::iter::once(""))
                .chain(metadata.item_tags().iter().map(String::as_str))
                .chain(searchable_fields(&item))
                .collect();
            let actual: Vec<&str> = searchable_field_groups(&[], &item)
                .iter()
                .map(|field| field.value)
                .collect();
            assert_eq!(actual, expected, "kind {}", item.kind());
            assert!(
                searchable_field_tiers(&item).len() <= searchable_fields(&item).len(),
                "tier list longer than the allowlist for {}",
                item.kind()
            );
            for (index, tier) in searchable_field_tiers(&item).iter().enumerate() {
                assert_eq!(
                    field_tier(&item, index).weight(),
                    tier.weight(),
                    "kind {} field {index}",
                    item.kind()
                );
            }
        }
    }

    #[test]
    fn search_never_matches_secret_material() {
        for (item, canary) in [
            (
                one_of_each_kind().remove(0),
                "fictional-login-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(3),
                "fictional-card-number-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(3),
                "fictional-card-code-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(4),
                "fictional-wifi-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(5),
                "fictional-ssh-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(5),
                "fictional-ssh-passphrase-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(6),
                "fictional-licence-canary".to_string(),
            ),
            (
                one_of_each_kind().remove(8),
                "fictional-field-canary".to_string(),
            ),
        ] {
            assert!(
                !item_matches_search(&[], &item, &canary),
                "{} revealed {canary}",
                item.kind()
            );
        }
    }

    #[test]
    fn search_index_orders_matches_and_skips_secrets() {
        let (mut opened, _) =
            create_vault("fictional master password", "Fictional vault").expect("created vault");
        opened.payload.entries.push(VaultEntry {
            id: "login-b".to_string(),
            title: "Portal northwind".to_string(),
            ..VaultEntry::default()
        });
        opened.payload.entries.push(VaultEntry {
            id: "login-a".to_string(),
            title: "Northwind portal".to_string(),
            username: "casey".to_string(),
            ..VaultEntry::default()
        });
        opened.payload.entries.push(VaultEntry {
            id: "login-c".to_string(),
            title: "Elsewhere".to_string(),
            password: "fictional-secret-canary".to_string(),
            ..VaultEntry::default()
        });
        let path = std::env::temp_dir().join(format!("sesame-search-{}", random_id()));
        let session = UnlockedVault::from_opened(path, &opened).expect("unlocked vault");

        let ids = search_index(&session, &session.snapshot(), "northwind").expect("search");
        assert_eq!(ids, vec!["login-a", "login-b"]);
        let secret =
            search_index(&session, &session.snapshot(), "fictional-secret-canary").expect("search");
        assert!(secret.is_empty());
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
