use tauri::State;

use crate::application::logins::{
    add_items_tag_in_state, bulk_assign_folder_in_state, create_folder_in_state,
    delete_folder_in_state, delete_login_in_state, duplicate_groups_in_state,
    merge_comparison_in_state, merge_duplicate_logins_in_state, record_item_use_in_state,
    refresh_totp_in_state, rename_folder_in_state, reveal_login_secret_in_state,
    save_login_in_state, set_item_favourite_in_state, set_login_folders_in_state,
    totp_codes_in_state,
};
use crate::application::records::{
    login_card_in_state, login_summary_in_state, vault_snapshot_in_state,
};
use crate::release::ReleasePresence;
use crate::vault::{
    DeleteLoginResult, DuplicateGroup, LoginInput, MergeComparison, MergeDuplicateLoginsRequest,
    MergeDuplicateLoginsResult, SaveLoginResult, TaggedItem, TotpCodeEntry, TotpRefresh,
    VaultResult, VaultSnapshot, VaultState,
};

#[tauri::command]
pub fn get_vault_snapshot(state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    vault_snapshot_in_state(&state)
}

/// Small on purpose: a shortcut for retyping an address, not a directory.
const MAX_SUGGESTIONS: usize = 8;

struct Candidate {
    value: String,
    same_site: bool,
    last_used: u64,
}

fn host_of(text: &str) -> String {
    let text = text.trim();
    let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = authority.to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or("");
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.contains('.') || host == "localhost" {
        host.to_string()
    } else {
        String::new()
    }
}

fn sites_related(left: &str, right: &str) -> bool {
    let (left, right) = (host_of(left), host_of(right));
    !left.is_empty()
        && !right.is_empty()
        && (left == right
            || left.ends_with(&format!(".{right}"))
            || right.ends_with(&format!(".{left}")))
}

/// Values for this site first, then the ones used on the most logins, then the most recent.
fn rank_suggestions(candidates: Vec<Candidate>) -> Vec<String> {
    struct Tally {
        value: String,
        same_site: bool,
        count: usize,
        last_used: u64,
        first_seen: usize,
    }
    let mut tallies: Vec<Tally> = Vec::new();
    for (position, candidate) in candidates.into_iter().enumerate() {
        match tallies
            .iter_mut()
            .find(|tally| tally.value == candidate.value)
        {
            Some(tally) => {
                tally.same_site |= candidate.same_site;
                tally.count += 1;
                tally.last_used = tally.last_used.max(candidate.last_used);
            }
            None => tallies.push(Tally {
                value: candidate.value,
                same_site: candidate.same_site,
                count: 1,
                last_used: candidate.last_used,
                first_seen: position,
            }),
        }
    }
    tallies.sort_by(|left, right| {
        right
            .same_site
            .cmp(&left.same_site)
            .then(right.count.cmp(&left.count))
            .then(right.last_used.cmp(&left.last_used))
            .then(left.first_seen.cmp(&right.first_seen))
    });
    tallies
        .into_iter()
        .take(MAX_SUGGESTIONS)
        .map(|tally| tally.value)
        .collect()
}

/// Deliberate bounded disclosure at the moment of typing, not a session-long leak.
#[tauri::command]
pub fn suggest_field_values(
    field: String,
    site: Option<String>,
    state: State<'_, VaultState>,
) -> VaultResult<Vec<String>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    if !matches!(field.as_str(), "username" | "email") {
        return Ok(Vec::new());
    }
    let site = site.unwrap_or_default();
    let index = session.snapshot();
    let mut candidates = Vec::new();
    for summary in &index.entries {
        let item = session.open_item(&summary.id)?;
        let TaggedItem::Login(entry) = &*item else {
            continue;
        };
        let value = if field == "username" {
            entry.username.as_str()
        } else {
            entry.email.as_str()
        }
        .trim();
        if value.is_empty() {
            continue;
        }
        candidates.push(Candidate {
            value: value.to_string(),
            same_site: sites_related(&site, &summary.site),
            last_used: summary.last_used_at.unwrap_or(0).max(summary.updated_at),
        });
    }
    if field == "email" {
        for summary in index.items.iter().filter(|item| item.kind == "identity") {
            let item = session.open_item(&summary.id)?;
            let TaggedItem::Identity(identity) = &*item else {
                continue;
            };
            let value = identity.email.trim();
            if !value.is_empty() {
                candidates.push(Candidate {
                    value: value.to_string(),
                    same_site: false,
                    last_used: 0,
                });
            }
        }
    }
    Ok(rank_suggestions(candidates))
}

#[tauri::command]
pub fn get_login_card(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<crate::vault::types::LoginCard> {
    login_card_in_state(&state, &id)
}

#[tauri::command]
pub fn get_login_summary(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<crate::vault::types::LoginSummary> {
    login_summary_in_state(&state, &id)
}

#[tauri::command]
pub fn get_duplicate_groups(state: State<'_, VaultState>) -> VaultResult<Vec<DuplicateGroup>> {
    duplicate_groups_in_state(&state)
}

#[tauri::command]
pub fn list_totp_codes(state: State<'_, VaultState>) -> VaultResult<Vec<TotpCodeEntry>> {
    totp_codes_in_state(&state)
}

#[tauri::command]
pub fn refresh_totp(id: String, state: State<'_, VaultState>) -> VaultResult<TotpRefresh> {
    refresh_totp_in_state(&state, &id)
}

#[tauri::command]
pub fn save_login(input: LoginInput, state: State<'_, VaultState>) -> VaultResult<SaveLoginResult> {
    save_login_in_state(&state, input)
}

#[tauri::command]
pub fn set_login_folders(
    ids: Vec<String>,
    folder: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    set_login_folders_in_state(&state, ids, &folder)
}

#[tauri::command]
pub fn bulk_assign_folder(
    ids: Vec<String>,
    folder_id: Option<String>,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    bulk_assign_folder_in_state(&state, ids, folder_id.as_deref())
}

#[tauri::command]
pub fn add_items_tag(
    ids: Vec<String>,
    tag: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    add_items_tag_in_state(&state, ids, &tag)
}

#[tauri::command]
pub fn create_folder(name: String, state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    create_folder_in_state(&state, &name)
}

#[tauri::command]
pub fn rename_folder(
    folder_id: String,
    name: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    rename_folder_in_state(&state, &folder_id, &name)
}

#[tauri::command]
pub fn delete_folder(
    folder_id: String,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    delete_folder_in_state(&state, &folder_id)
}

#[tauri::command]
pub fn set_item_favourite(
    id: String,
    favourite: bool,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    set_item_favourite_in_state(&state, &id, favourite)
}

#[tauri::command]
pub fn record_item_use(id: String, state: State<'_, VaultState>) -> VaultResult<VaultSnapshot> {
    record_item_use_in_state(&state, &id)
}

#[tauri::command]
pub fn delete_login(id: String, state: State<'_, VaultState>) -> VaultResult<DeleteLoginResult> {
    delete_login_in_state(&state, &id)
}

#[tauri::command]
pub fn merge_duplicate_logins(
    request: MergeDuplicateLoginsRequest,
    state: State<'_, VaultState>,
) -> VaultResult<MergeDuplicateLoginsResult> {
    merge_duplicate_logins_in_state(&state, request)
}

#[tauri::command]
pub fn get_merge_comparison(
    ids: Vec<String>,
    state: State<'_, VaultState>,
) -> VaultResult<MergeComparison> {
    merge_comparison_in_state(&state, ids)
}

#[tauri::command]
pub fn reveal_login_secret(
    id: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    reveal_login_secret_in_state(&state, &presence, &id)
}

#[cfg(test)]
mod suggestion_ranking_tests {
    use super::*;

    fn candidate(value: &str, same_site: bool, last_used: u64) -> Candidate {
        Candidate {
            value: value.to_string(),
            same_site,
            last_used,
        }
    }

    #[test]
    fn a_value_used_on_this_site_comes_before_one_used_more_often_elsewhere() {
        let ranked = rank_suggestions(vec![
            candidate("everywhere@example.test", false, 9),
            candidate("everywhere@example.test", false, 9),
            candidate("everywhere@example.test", false, 9),
            candidate("here@example.test", true, 1),
        ]);
        assert_eq!(ranked, ["here@example.test", "everywhere@example.test"]);
    }

    #[test]
    fn the_most_used_comes_first_then_the_most_recent_then_the_first_seen() {
        let ranked = rank_suggestions(vec![
            candidate("once-old", false, 1),
            candidate("twice", false, 1),
            candidate("once-new", false, 9),
            candidate("twice", false, 1),
            candidate("once-new-too", false, 9),
        ]);
        assert_eq!(ranked, ["twice", "once-new", "once-new-too", "once-old"]);
    }

    #[test]
    fn a_value_is_listed_once_and_the_list_stays_small() {
        let many: Vec<Candidate> = (0..20)
            .map(|number| candidate(&format!("name{number}"), false, number))
            .chain(std::iter::once(candidate("name0", false, 0)))
            .collect();
        let ranked = rank_suggestions(many);
        assert_eq!(ranked.len(), MAX_SUGGESTIONS);
        assert_eq!(ranked[0], "name0");
        assert_eq!(
            ranked
                .iter()
                .filter(|value| value.as_str() == "name0")
                .count(),
            1
        );
    }

    #[test]
    fn a_site_is_matched_by_host_and_by_parent_domain_and_never_by_a_suffix_lookalike() {
        assert!(sites_related(
            "https://www.Example.test/login",
            "example.test"
        ));
        assert!(sites_related("login.example.test", "example.test"));
        assert!(sites_related("example.test:8443", "login.example.test"));
        assert!(!sites_related("example.test", "notexample.test"));
        assert!(!sites_related("gith", "gith"));
        assert!(!sites_related("", "example.test"));
        assert!(!sites_related("example.test", "No website saved"));
    }

    #[test]
    fn a_password_typed_into_the_address_is_never_part_of_the_host() {
        assert_eq!(
            host_of("https://fictional-user:fictional-secret@example.test/x"),
            "example.test"
        );
    }
}
