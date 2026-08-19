//! Deterministic, local-only password checks.
//! `compromised-pattern` means the value follows a pattern attackers routinely try, never a breach claim.

use serde::Serialize;

use crate::util::unix_timestamp;
use crate::{PasswordIssue, VaultEntry};

/// A once-a-year prompt, not a security proof.
pub const OLD_PASSWORD_THRESHOLD_SECONDS: u64 = 365 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordAnalysis {
    pub score: u8,
    pub issues: Vec<PasswordIssue>,
}

impl PasswordAnalysis {
    pub fn has(&self, kind: &str) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// No vault context: no reuse or account-token checks, same scoring underneath.
pub fn analyse_password_value(password: &str) -> PasswordAnalysis {
    let common = is_common_password(password);
    let known_pattern = has_known_pattern(password);
    let mut score = base_score(password);
    if common {
        score = score.min(1);
    }
    if known_pattern {
        score = score.saturating_sub(1);
    }

    let mut issues = Vec::new();
    if score < 3 {
        issues.push(PasswordIssue {
            kind: "weak-password",
            explanation: "This password is short or has too little character variety.",
        });
    }
    if common {
        issues.push(PasswordIssue {
            kind: "common-password",
            explanation: "This is a commonly guessed password.",
        });
    }
    if known_pattern {
        issues.push(PasswordIssue {
            kind: "compromised-pattern",
            explanation: "This password contains a pattern attackers commonly try.",
        });
    }

    PasswordAnalysis { score, issues }
}

pub fn analyse_password(entry: &VaultEntry, reused: bool) -> PasswordAnalysis {
    let password = entry.password.as_str();
    let common = is_common_password(password);
    let compromised_pattern = has_compromised_pattern(entry);
    let mut score = base_score(password);
    if common {
        score = score.min(1);
    }
    if compromised_pattern {
        score = score.saturating_sub(1);
    }

    let mut issues = Vec::new();
    // A code-only entry saves a 2FA secret and no password. Calling that weak
    // reports a password problem where there is no password at all, and is_old
    // already treats an empty password the same way.
    if score < 3 && !password.is_empty() {
        issues.push(PasswordIssue {
            kind: "weak-password",
            explanation: "This password is short or has too little character variety.",
        });
    }
    if common {
        issues.push(PasswordIssue {
            kind: "common-password",
            explanation: "This is a commonly guessed password.",
        });
    }
    if reused && !password.is_empty() {
        issues.push(PasswordIssue {
            kind: "reused-password",
            explanation: "The same password is saved on another login.",
        });
    }
    if compromised_pattern {
        issues.push(PasswordIssue {
            kind: "compromised-pattern",
            explanation:
                "This password contains an account detail or a pattern attackers commonly try.",
        });
    }
    if is_old(entry) {
        issues.push(PasswordIssue {
            kind: "old-password",
            explanation: "This password has not been changed in over a year.",
        });
    }

    PasswordAnalysis { score, issues }
}

/// Zero `password_updated_at` is an unmigrated entry, not a measured age.
fn is_old(entry: &VaultEntry) -> bool {
    if entry.password.is_empty() || entry.password_updated_at == 0 {
        return false;
    }
    unix_timestamp().saturating_sub(entry.password_updated_at) > OLD_PASSWORD_THRESHOLD_SECONDS
}

fn base_score(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }
    let length = password.chars().count();
    let mut score: u8 = match length {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=19 => 3,
        _ => 4,
    };
    let classes = [
        password.chars().any(|character| character.is_lowercase()),
        password.chars().any(|character| character.is_uppercase()),
        password.chars().any(|character| character.is_ascii_digit()),
        password
            .chars()
            .any(|character| !character.is_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if length >= 12 && classes >= 3 {
        score = score.saturating_add(1).min(4);
    }
    if length >= 16 && classes == 4 {
        score = score.saturating_add(1).min(4);
    }

    let mut unique = std::collections::HashSet::new();
    for character in password.chars() {
        unique.insert(character);
    }
    if length >= 8 && unique.len() * 3 < length {
        score = score.saturating_sub(1);
    }
    score
}

fn is_common_password(password: &str) -> bool {
    const COMMON: &[&str] = &[
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "111111",
        "abc123",
        "admin",
        "dragon",
        "football",
        "iloveyou",
        "letmein",
        "login",
        "master",
        "monkey",
        "passw0rd",
        "password",
        "password1",
        "princess",
        "qwerty",
        "qwerty123",
        "secret",
        "sunshine",
        "trustno1",
        "welcome",
        "welcome1",
    ];
    let normalized = password.trim().to_ascii_lowercase();
    COMMON.contains(&normalized.as_str())
}

fn has_known_pattern(password: &str) -> bool {
    let password = password.to_ascii_lowercase();
    if password.is_empty() {
        return false;
    }
    const SEQUENCES: &[&str] = &["012345", "123456", "abcdef", "asdfgh", "qwerty", "zxcvbn"];
    SEQUENCES.iter().any(|sequence| password.contains(sequence)) || has_repeated_run(&password, 4)
}

fn has_compromised_pattern(entry: &VaultEntry) -> bool {
    if has_known_pattern(&entry.password) {
        return true;
    }
    let password = entry.password.to_ascii_lowercase();
    account_tokens(entry)
        .into_iter()
        .any(|token| token.len() >= 4 && password.contains(&token))
}

fn has_repeated_run(value: &str, minimum: usize) -> bool {
    let mut previous = None;
    let mut run = 0;
    for character in value.chars() {
        if previous == Some(character) {
            run += 1;
        } else {
            previous = Some(character);
            run = 1;
        }
        if run >= minimum {
            return true;
        }
    }
    false
}

fn account_tokens(entry: &VaultEntry) -> Vec<String> {
    let mut tokens = Vec::new();
    tokens.extend(words(&entry.title));
    let username = entry.username.split('@').next().unwrap_or_default();
    tokens.extend(words(username));
    if let Ok(url) = url::Url::parse(&entry.url) {
        if let Some(host) = url.host_str() {
            let host = host.trim_start_matches("www.");
            if let Some(label) = host.split('.').next() {
                tokens.extend(words(label));
            }
        }
    }
    tokens
}

fn words(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|word| word.len() >= 4)
        .collect()
}
