use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::VaultResult;

/// Bounded read for every vault, backup, import, and auxiliary file; `NotFound` and `InvalidData` are distinguished.
pub fn read_file_with_limit(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file size outside safe bounds",
        ));
    }
    std::fs::read(path)
}

pub fn require_file_with_limit(
    path: &Path,
    max_bytes: u64,
    error_message: &str,
) -> VaultResult<Vec<u8>> {
    read_file_with_limit(path, max_bytes).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => error_message.to_string(),
        std::io::ErrorKind::InvalidData => "That file has an unexpected size.".to_string(),
        std::io::ErrorKind::PermissionDenied => {
            "Sesame could not read that file because access was denied.".to_string()
        }
        _ => error_message.to_string(),
    })
}

pub fn random_id() -> String {
    let mut bytes = [0_u8; 12];
    fill_random(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn fill_random(bytes: &mut [u8]) {
    rand::rng().fill_bytes(bytes)
}

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}

pub fn normalise_header(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
}

pub fn normalise_url(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    if value.starts_with("https://") || value.starts_with("http://") {
        value.into()
    } else {
        format!("https://{value}")
    }
}

pub fn domain_from_url(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "No website saved".into();
    }
    let without_scheme = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    // A saved URL may carry user:password@ before the host, and showing that
    // back as the site label would put the secret on screen.
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host.is_empty() {
        return "No website saved".into();
    }
    host.to_string()
}

pub fn initials_for(value: &str) -> String {
    let initials: String = value
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .take(2)
        .collect();
    if initials.is_empty() {
        "?".into()
    } else {
        initials.to_uppercase()
    }
}

pub fn split_backup_codes(value: &str) -> Vec<String> {
    value
        .lines()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn generate_recovery_kit() -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0_u8; 25];
    fill_random(&mut bytes);
    bytes
        .iter()
        .enumerate()
        .fold(String::with_capacity(29), |mut kit, (index, byte)| {
            if index > 0 && index % 5 == 0 {
                kit.push('-');
            }
            kit.push(ALPHABET[(byte & 31) as usize] as char);
            kit
        })
}

pub fn record_value(
    record: &csv::StringRecord,
    headers: &HashMap<String, usize>,
    names: &[&str],
) -> String {
    names
        .iter()
        .find_map(|name| headers.get(*name).and_then(|index| record.get(*index)))
        .unwrap_or_default()
        .trim()
        .to_string()
}

// A password is stored exactly as it was exported. Trimming it would change
// the secret and lock the owner out of the account it belongs to.
pub fn record_secret(
    record: &csv::StringRecord,
    headers: &HashMap<String, usize>,
    names: &[&str],
) -> String {
    names
        .iter()
        .find_map(|name| headers.get(*name).and_then(|index| record.get(*index)))
        .unwrap_or_default()
        .to_string()
}

pub fn backup_file_name(path: &std::path::Path) -> VaultResult<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or("Sesame could not read the backup file name.".into())
}
