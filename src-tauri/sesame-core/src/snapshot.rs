use std::collections::HashMap;
use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};

use crate::{
    password_analysis::analyse_password,
    types::*,
    util::{domain_from_url, initials_for, unix_timestamp},
    VaultEntry, VaultPayload,
};

pub fn snapshot_for(payload: &VaultPayload) -> VaultSnapshot {
    let security = security_summary(payload);
    let duplicate_keys = duplicate_key_counts(payload);
    let password_counts = password_counts(payload);
    let mut entries = Vec::new();
    let mut items = Vec::new();
    for item in payload.item_views() {
        if let TaggedItem::Login(entry) = &item {
            let reused = !entry.password.is_empty()
                && password_counts.get(&entry.password).copied().unwrap_or(0) > 1;
            let password = analyse_password(entry, reused);
            let issue_kinds = issue_kinds_for(entry, &duplicate_keys, &password_counts);
            entries.push(VaultEntrySummary {
                id: entry.id.clone(),
                title: entry.title.clone(),
                site: domain_from_url(&entry.url),
                initials: initials_for(&entry.title),
                folder_id: entry.folder_id.clone(),
                folder: folder_name_for(payload, entry),
                favourite: entry.favourite,
                last_used_at: entry.last_used_at,
                password_score: password.score,
                password_issues: password.issues,
                security_level: if issue_kinds.is_empty() {
                    "good"
                } else {
                    "needs-work"
                },
                issue_kinds,
                tags: entry.tags.clone(),
                updated_at: entry.updated_at,
            });
            continue;
        }
        items.push(item_summary_for(payload, &item));
    }
    entries.sort_by(|left, right| left.title.to_lowercase().cmp(&right.title.to_lowercase()));
    items.sort_by(|left, right| left.title.to_lowercase().cmp(&right.title.to_lowercase()));
    let mut trash = crate::trash::trash_summaries(payload);
    trash.sort_by(|left, right| right.deleted_at.cmp(&left.deleted_at));
    let history = crate::history::history_summaries(payload);
    VaultSnapshot {
        vault_name: payload.vault_name.clone(),
        vault_id: payload.vault_id.clone(),
        revision: payload.revision,
        folders: payload.folders.clone(),
        entries,
        items,
        trash,
        history,
        security,
    }
}

fn item_summary_for(payload: &VaultPayload, item: &TaggedItem) -> VaultItemSummary {
    let preview = item.preview();
    let metadata = item.metadata();
    VaultItemSummary {
        id: item.id().to_string(),
        kind: item.kind(),
        initials: initials_for(&preview.title),
        title: preview.title,
        subtitle: preview.detail.unwrap_or_default(),
        folder: folder_name(payload, metadata.item_folder_id()),
        folder_id: metadata.item_folder_id().map(str::to_string),
        favourite: metadata.item_favourite(),
        last_used_at: metadata.item_last_used_at(),
        updated_at: metadata.item_updated_at(),
        tags: metadata.item_tags().to_vec(),
    }
}

pub fn security_summary(payload: &VaultPayload) -> SecuritySummary {
    let duplicate_keys = duplicate_key_counts(payload);
    let passwords = password_counts(payload);
    let mut good = 0;
    let mut duplicate_candidates = 0;
    let mut weak_or_reused_count = 0;
    let mut weak_passwords = 0;
    let mut common_passwords = 0;
    let mut reused_passwords = 0;
    let mut compromised_patterns = 0;
    let mut old_passwords = 0;
    let mut missing_urls = 0;
    let mut no_totp = 0;
    let mut missing_recovery = 0;

    for entry in &payload.entries {
        let duplicate = duplicate_keys
            .get(&duplicate_key(entry))
            .copied()
            .unwrap_or(0)
            > 1;
        let reused =
            !entry.password.is_empty() && passwords.get(&entry.password).copied().unwrap_or(0) > 1;
        let password = analyse_password(entry, reused);
        let password_needs_work = !password.issues.is_empty();
        let url_missing = entry.url.is_empty();
        let totp_missing = entry.totp.as_deref().unwrap_or_default().is_empty();
        let recovery_missing = !entry.recovery_not_applicable
            && entry.backup_codes.is_empty()
            && entry
                .recovery_email
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            && entry
                .recovery_phone
                .as_deref()
                .unwrap_or_default()
                .is_empty();
        if !duplicate && !password_needs_work && !url_missing && !totp_missing && !recovery_missing
        {
            good += 1;
        }
        if duplicate {
            duplicate_candidates += 1;
        }
        if password_needs_work {
            weak_or_reused_count += 1;
        }
        weak_passwords += usize::from(password.has("weak-password"));
        common_passwords += usize::from(password.has("common-password"));
        reused_passwords += usize::from(password.has("reused-password"));
        compromised_patterns += usize::from(password.has("compromised-pattern"));
        old_passwords += usize::from(password.has("old-password"));
        if url_missing {
            missing_urls += 1;
        }
        if totp_missing {
            no_totp += 1;
        }
        if recovery_missing {
            missing_recovery += 1;
        }
    }

    SecuritySummary {
        good,
        needs_attention: duplicate_candidates
            + weak_or_reused_count
            + missing_urls
            + no_totp
            + missing_recovery,
        duplicate_candidates,
        weak_or_reused: weak_or_reused_count,
        weak_passwords,
        common_passwords,
        reused_passwords,
        compromised_patterns,
        old_passwords,
        missing_urls,
        no_totp,
        missing_recovery,
    }
}

pub fn login_card_for(payload: &VaultPayload, entry: &VaultEntry) -> LoginCard {
    let (totp_code, totp_remaining) = entry
        .totp
        .as_deref()
        .and_then(current_totp)
        .map(|(code, remaining, _)| (code, remaining))
        .map_or((None, None), |(code, remaining)| {
            (Some(code), Some(remaining))
        });
    LoginCard {
        id: entry.id.clone(),
        title: entry.title.clone(),
        site: domain_from_url(&entry.url),
        initials: initials_for(&entry.title),
        url: entry.url.clone(),
        urls: entry.urls.clone(),
        tags: entry.tags.clone(),
        username: entry.username.clone(),
        email: entry.email.clone(),
        password: entry.password.clone(),
        folder_id: entry.folder_id.clone(),
        folder: folder_name_for(payload, entry),
        favourite: entry.favourite,
        last_used_at: entry.last_used_at,
        has_totp: entry.totp.as_deref().is_some_and(|seed| !seed.is_empty()),
        totp_code,
        totp_remaining,
        backup_codes: (!entry.backup_codes.is_empty()).then(|| entry.backup_codes.clone()),
        recovery_email: entry.recovery_email.clone(),
        recovery_phone: entry.recovery_phone.clone(),
        recovery_not_applicable: entry.recovery_not_applicable,
        notes: entry.notes.clone(),
        legacy_fields: entry.legacy_fields.clone(),
    }
}

pub fn merge_comparison_for(group: &[&VaultEntry]) -> MergeComparison {
    let field = |name: &str, label: &str, secret: bool, read: &dyn Fn(&VaultEntry) -> String| {
        let options: Vec<MergeFieldOption> = group
            .iter()
            .map(|entry| {
                let value = read(entry);
                MergeFieldOption {
                    entry_id: entry.id.clone(),
                    present: !value.is_empty(),
                    value,
                }
            })
            .collect();
        let first = options.first().map(|option| option.value.clone());
        let differs = options
            .iter()
            .any(|option| Some(&option.value) != first.as_ref());
        MergeField {
            field: name.to_string(),
            label: label.to_string(),
            secret,
            differs,
            options,
        }
    };

    MergeComparison {
        entries: group
            .iter()
            .map(|entry| MergeCandidate {
                id: entry.id.clone(),
                title: entry.title.clone(),
                site: domain_from_url(&entry.url),
                username: entry.username.clone(),
                updated_at: entry.updated_at,
                revision: entry.revision,
            })
            .collect(),
        fields: vec![
            field("title", "Name", false, &|entry| entry.title.clone()),
            field("url", "Website", false, &|entry| entry.url.clone()),
            field("username", "Username", false, &|entry| {
                entry.username.clone()
            }),
            field("email", "Email", false, &|entry| entry.email.clone()),
            field("password", "Password", true, &|entry| {
                entry.password.clone()
            }),
            field("totp", "2FA secret", true, &|entry| {
                entry.totp.clone().unwrap_or_default()
            }),
            field("notes", "Notes", true, &|entry| {
                entry.notes.clone().unwrap_or_default()
            }),
            field("recoveryEmail", "Recovery email", false, &|entry| {
                entry.recovery_email.clone().unwrap_or_default()
            }),
            field("recoveryPhone", "Recovery phone", false, &|entry| {
                entry.recovery_phone.clone().unwrap_or_default()
            }),
            field("backupCodes", "Backup codes", true, &|entry| {
                entry.backup_codes.join("\n")
            }),
        ],
    }
}

pub fn login_summary_for(entry: &VaultEntry) -> LoginSummary {
    LoginSummary {
        id: entry.id.clone(),
        title: entry.title.clone(),
        site: domain_from_url(&entry.url),
        username: entry.username.clone(),
        initials: initials_for(&entry.title),
        duplicate_key: duplicate_key(entry),
    }
}

pub fn duplicate_groups_for(payload: &VaultPayload) -> Vec<DuplicateGroup> {
    let mut groups = entries_by_duplicate_key(&payload.entries)
        .into_iter()
        .filter_map(|(id, entries)| {
            if entries.len() < 2 {
                return None;
            }
            let site = domain_from_url(&entries[0].url);
            let label = if site.is_empty() {
                entries[0].title.clone()
            } else {
                site.clone()
            };
            Some(DuplicateGroup {
                id,
                label,
                site,
                entries: entries
                    .into_iter()
                    .map(|entry| CleanupEntry {
                        id: entry.id.clone(),
                        title: entry.title.clone(),
                        site: domain_from_url(&entry.url),
                        username: entry.username.clone(),
                        initials: initials_for(&entry.title),
                        reason: "Same website and username",
                    })
                    .collect(),
            })
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    groups
}

/// Returns the code, the seconds left in the window, and the window length.
pub fn current_totp(value: &str) -> Option<(String, u64, u64)> {
    let totp = totp_from_value(value)?;
    let code = totp.generate_current().ok()?;
    let remaining = totp.step - (unix_timestamp() % totp.step);
    Some((code, remaining, totp.step))
}

// Real sites issue 80-bit secrets; the RFC's 128-bit floor would reject ordinary 2FA.
const MIN_TOTP_SECRET_BYTES: usize = 10;

pub fn totp_from_value(value: &str) -> Option<TOTP> {
    let value = value.trim();
    if value.starts_with("otpauth://") {
        // `from_url_unchecked` skips the stricter length floor, holding otpauth URLs to the same minimum as pasted secrets.
        let totp = TOTP::from_url_unchecked(value).ok()?;
        if totp.secret.len() < MIN_TOTP_SECRET_BYTES {
            return None;
        }
        return Some(totp);
    }
    let secret = value.replace([' ', '-'], "").to_ascii_uppercase();
    let secret = Secret::Encoded(secret).to_bytes().ok()?;
    if secret.len() < MIN_TOTP_SECRET_BYTES {
        return None;
    }
    Some(TOTP::new_unchecked(
        TotpAlgorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        String::new(),
    ))
}

pub fn duplicate_key_counts(payload: &VaultPayload) -> HashMap<String, usize> {
    let mut keys = HashMap::new();
    for entry in &payload.entries {
        if !is_duplicate_key_eligible(entry) {
            continue;
        }
        *keys.entry(duplicate_key(entry)).or_insert(0) += 1;
    }
    keys
}

pub fn is_duplicate_key_eligible(entry: &VaultEntry) -> bool {
    !entry.url.is_empty() || !entry.username.is_empty()
}

pub fn entries_by_duplicate_key(entries: &[VaultEntry]) -> HashMap<String, Vec<&VaultEntry>> {
    let mut by_key = HashMap::new();
    for entry in entries {
        if !is_duplicate_key_eligible(entry) {
            continue;
        }
        by_key
            .entry(duplicate_key(entry))
            .or_insert_with(Vec::new)
            .push(entry);
    }
    by_key
}

pub fn existing_import_relation(
    imported: &VaultEntry,
    existing_by_key: &HashMap<String, Vec<&VaultEntry>>,
) -> ExistingImportRelation {
    if !is_duplicate_key_eligible(imported) {
        return ExistingImportRelation::None;
    }
    let Some(existing) = existing_by_key.get(&duplicate_key(imported)) else {
        return ExistingImportRelation::None;
    };
    if existing
        .iter()
        .any(|entry| entry_contents_match(entry, imported))
    {
        ExistingImportRelation::ExactDuplicate
    } else {
        ExistingImportRelation::AccountConflict
    }
}

pub fn should_skip_exact_duplicate(
    imported: &VaultEntry,
    existing_by_key: &HashMap<String, Vec<&VaultEntry>>,
) -> bool {
    existing_import_relation(imported, existing_by_key) == ExistingImportRelation::ExactDuplicate
}

pub fn entry_contents_match(left: &VaultEntry, right: &VaultEntry) -> bool {
    left.title == right.title
        && left.url == right.url
        && left.username == right.username
        && left.password == right.password
        && left.totp == right.totp
        && left.backup_codes == right.backup_codes
        && left.recovery_email == right.recovery_email
        && left.recovery_phone == right.recovery_phone
        && left.recovery_not_applicable == right.recovery_not_applicable
        && left.notes == right.notes
}

pub fn password_counts(payload: &VaultPayload) -> HashMap<String, usize> {
    let mut passwords = HashMap::new();
    for entry in &payload.entries {
        if !entry.password.is_empty() {
            *passwords.entry(entry.password.clone()).or_insert(0) += 1;
        }
    }
    passwords
}

pub fn issue_kinds_for(
    entry: &VaultEntry,
    duplicate_keys: &HashMap<String, usize>,
    passwords: &HashMap<String, usize>,
) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if duplicate_keys
        .get(&duplicate_key(entry))
        .copied()
        .unwrap_or(0)
        > 1
    {
        issues.push("duplicate");
    }
    let reused =
        !entry.password.is_empty() && passwords.get(&entry.password).copied().unwrap_or(0) > 1;
    issues.extend(
        analyse_password(entry, reused)
            .issues
            .into_iter()
            .map(|issue| issue.kind),
    );
    // A code-only entry holds a 2FA secret and no password. A missing website or
    // missing recovery detail describes a login, so neither is a finding here.
    let code_only =
        entry.password.is_empty() && !entry.totp.as_deref().unwrap_or_default().is_empty();
    if entry.url.is_empty() && !code_only {
        issues.push("url");
    }
    if entry.totp.as_deref().unwrap_or_default().is_empty() {
        issues.push("totp");
    }
    if !code_only
        && !entry.recovery_not_applicable
        && entry.backup_codes.is_empty()
        && entry
            .recovery_email
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        && entry
            .recovery_phone
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    {
        issues.push("recovery");
    }
    issues
}

pub fn folder_name(payload: &VaultPayload, folder_id: Option<&str>) -> String {
    folder_id
        .and_then(|folder_id| payload.folders.iter().find(|folder| folder.id == folder_id))
        .map(|folder| folder.name.clone())
        .unwrap_or_default()
}

pub fn folder_name_for(payload: &VaultPayload, entry: &VaultEntry) -> String {
    let name = folder_name(payload, entry.folder_id.as_deref());
    if name.is_empty() {
        // Only transient imports and pre-migration payloads have this value.
        return entry.folder.clone();
    }
    name
}

pub fn duplicate_key(entry: &VaultEntry) -> String {
    format!(
        "{}:{}",
        domain_from_url(&entry.url).to_lowercase(),
        entry.username.trim().to_lowercase()
    )
}
