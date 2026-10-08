use std::collections::{HashMap, HashSet};
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    snapshot::totp_from_value,
    types::*,
    util::{
        domain_from_url, non_empty, normalise_header, normalise_url, random_id, record_secret,
        record_value, split_backup_codes, unix_timestamp,
    },
    VaultEntry, VaultResult,
};

const MAX_IMPORT_BYTES: u64 = 25 * 1024 * 1024;
const MAX_IMPORT_ITEMS: usize = 100_000;
const MAX_IMPORT_FIELD_BYTES: usize = 64 * 1024;
const IMPORT_TOO_MANY_ENTRIES: &str =
    "That import contains too many entries for Sesame to process safely.";

fn check_import_item_count(count: usize) -> VaultResult<()> {
    if count > MAX_IMPORT_ITEMS {
        Err(IMPORT_TOO_MANY_ENTRIES.to_string())
    } else {
        Ok(())
    }
}

fn bounded_import_field(field: &str, value: String) -> VaultResult<String> {
    if value.len() > MAX_IMPORT_FIELD_BYTES {
        return Err(format!(
            "The {field} field in this import is larger than Sesame can import safely."
        ));
    }
    Ok(value)
}

fn clean_import_field(field: &str, value: String) -> VaultResult<String> {
    let mut value = bounded_import_field(field, value)?;
    value.retain(|character| !is_import_control(character));
    Ok(value)
}

fn clean_import_multiline_field(field: &str, value: String) -> VaultResult<String> {
    let mut value = bounded_import_field(field, value)?;
    value.retain(|character| is_import_line_break(character) || !is_import_control(character));
    Ok(value)
}

fn is_import_control(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001F}'
            | '\u{0080}'..='\u{009F}'
            | '\u{061C}'
            | '\u{200B}'
            | '\u{200E}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

fn is_import_line_break(character: char) -> bool {
    matches!(character, '\n' | '\r' | '\t')
}

/// The plaintext export never crosses the IPC boundary; Rust reads the file the user picked.
pub fn read_import_file(path: &Path) -> VaultResult<Zeroizing<String>> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "csv" | "json" | "txt") {
        return Err("Choose a .csv, .json, or .txt export file.".into());
    }
    let bytes = Zeroizing::new(crate::util::require_file_with_limit(
        path,
        MAX_IMPORT_BYTES,
        "Sesame could not read that export file.",
    )?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "That export file is not valid text.".to_string())?;
    Ok(Zeroizing::new(text.to_string()))
}

#[derive(Default)]
pub struct ImportIssues {
    pub invalid_totp: usize,
    pub invalid_urls: usize,
}

/// Clears and counts unusable 2FA secrets and addresses before they can ever be committed.
pub fn validate_import_entries(entries: &mut [VaultEntry]) -> ImportIssues {
    let mut issues = ImportIssues::default();
    for entry in entries.iter_mut() {
        if let Some(totp) = entry.totp.as_deref() {
            if totp_from_value(totp).is_none() {
                let mut invalid = entry.totp.take().unwrap_or_default();
                invalid.zeroize();
                issues.invalid_totp += 1;
            }
        }
        if !entry.url.is_empty() && !usable_web_url(&entry.url) {
            entry.url = String::new();
            issues.invalid_urls += 1;
        }
    }
    issues
}

fn usable_web_url(value: &str) -> bool {
    url::Url::parse(value)
        .map(|parsed| {
            matches!(parsed.scheme(), "http" | "https")
                && parsed.host_str().is_some_and(|host| !host.is_empty())
        })
        .unwrap_or(false)
}

#[derive(Default)]
pub struct ParsedImport {
    pub entries: Vec<VaultEntry>,
    pub secure_notes: Vec<SecureNote>,
    pub cards: Vec<Card>,
    pub identities: Vec<Identity>,
    pub ssh_keys: Vec<SshKey>,
    /// Readable in the export, but Sesame has no passkey item: reported, never dropped in silence.
    pub passkeys_not_imported: usize,
    /// Aggregate-only: disclosure must not release import content to the webview.
    pub intentionally_omitted_items: usize,
    pub accounting: ImportAccounting,
    /// Field-level disposition counts; see the import fidelity report.
    pub fidelity: ImportFidelity,
}

pub fn parse_import_entries(content: &str, source: &str) -> VaultResult<ParsedImport> {
    if content.len() > 25 * 1024 * 1024 {
        return Err("This import file is too large for Sesame to process safely.".into());
    }
    let mut parsed = match source {
        "bitwarden-csv" => {
            let (entries, logins, omissions) = import_bitwarden_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "bitwarden-json" => import_bitwarden_json_entries(content)?,
        "otpauth-txt" => {
            let (entries, logins, omissions) = import_otpauth_list_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "aegis-json" => {
            let (entries, logins, omissions) = import_aegis_json_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "2fas-json" => {
            let (entries, logins, omissions) = import_2fas_json_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "lastpass-csv" => {
            let (entries, logins, omissions) = import_lastpass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "dashlane-csv" => {
            let (entries, logins, omissions) = import_dashlane_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "onepassword-csv" => {
            let (entries, logins, omissions) = import_onepassword_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "keepass-csv" => {
            let (entries, logins, omissions) = import_keepass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "chrome-csv" => {
            let (entries, logins, omissions) = import_browser_csv_entries(content, "Chrome")?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "edge-csv" => {
            let (entries, logins, omissions) = import_browser_csv_entries(content, "Edge")?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "brave-csv" => {
            let (entries, logins, omissions) = import_browser_csv_entries(content, "Brave")?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "google-csv" => {
            let (entries, logins, omissions) = import_browser_csv_entries(content, "Google")?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "apple-csv" => {
            let (entries, logins, omissions) = import_apple_passwords_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "firefox-csv" => {
            let (entries, logins, omissions) = import_firefox_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "proton-pass-csv" => {
            let (entries, logins, omissions) = import_proton_pass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "keeper-csv" => {
            let (entries, logins, omissions) = import_keeper_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        "nordpass-csv" => {
            let (entries, logins, omissions) = import_nordpass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omissions)
        }
        _ => return Err("Choose a supported import type before selecting a file.".into()),
    };
    if parsed.entries.is_empty()
        && parsed.secure_notes.is_empty()
        && parsed.cards.is_empty()
        && parsed.identities.is_empty()
        && parsed.ssh_keys.is_empty()
    {
        return Err("No login entries were found in that import file.".into());
    }
    check_import_item_count(
        parsed.entries.len()
            + parsed.secure_notes.len()
            + parsed.cards.len()
            + parsed.identities.len()
            + parsed.ssh_keys.len(),
    )?;
    for entry in &mut parsed.entries {
        entry.import_source = Some(source.to_string());
    }
    let mut accounting = std::mem::take(&mut parsed.accounting);
    record_stored_items(&mut accounting, &parsed);
    parsed.accounting = accounting;
    parsed.intentionally_omitted_items = parsed.accounting.unsupported;
    Ok(parsed)
}

fn record_stored_items(accounting: &mut ImportAccounting, parsed: &ParsedImport) {
    let with_legacy = parsed
        .entries
        .iter()
        .filter(|entry| !entry.legacy_fields.is_empty())
        .count()
        + parsed
            .secure_notes
            .iter()
            .filter(|note| !note.legacy_fields.is_empty())
            .count()
        + parsed
            .cards
            .iter()
            .filter(|card| !card.legacy_fields.is_empty())
            .count()
        + parsed
            .identities
            .iter()
            .filter(|identity| !identity.legacy_fields.is_empty())
            .count();
    let stored = parsed.entries.len()
        + parsed.secure_notes.len()
        + parsed.cards.len()
        + parsed.identities.len()
        + parsed.ssh_keys.len();
    accounting.record_stored(stored - with_legacy, with_legacy);
}

fn record_has_content(record: &csv::StringRecord) -> bool {
    record.iter().any(|value| !value.trim().is_empty())
}

fn record_row_without_credentials(omissions: &mut ImportAccounting, record: &csv::StringRecord) {
    if record_has_content(record) {
        omissions.omit(ImportItemReason::MissingCredentials);
    }
}

fn login_only_parsed_import(
    entries: Vec<VaultEntry>,
    logins: FidelityCounts,
    omissions: ImportAccounting,
) -> ParsedImport {
    let mut fidelity = ImportFidelity {
        logins,
        ..ImportFidelity::default()
    };
    for _ in 0..omissions.unsupported {
        fidelity
            .unsupported_items
            .record(FieldDisposition::IntentionallyOmitted);
    }
    ParsedImport {
        entries,
        accounting: omissions,
        fidelity,
        ..ParsedImport::default()
    }
}

pub fn import_bitwarden_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    for row in reader.deserialize::<BitwardenCsvEntry>() {
        let row = row.map_err(|_| {
            "Sesame could not read that Bitwarden CSV. Export it again and try once more."
                .to_string()
        })?;
        if !row.item_type.is_empty() && !row.item_type.eq_ignore_ascii_case("login") {
            omissions.omit(ImportItemReason::UnsupportedItemType);
            continue;
        }
        if row.name.is_empty() && row.login_username.is_empty() && row.login_password.is_empty() {
            if [&row.login_uri, &row.notes, &row.login_totp]
                .iter()
                .any(|value| !value.trim().is_empty())
            {
                omissions.omit(ImportItemReason::MissingCredentials);
            }
            continue;
        }
        let folder = normalise_folder(&row.folder)?;
        let addresses = row
            .login_uri
            .lines()
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut entry = imported_entry(
            row.name,
            addresses.first().cloned().unwrap_or_default(),
            row.login_username,
            row.login_password,
            non_empty(row.login_totp),
            Vec::new(),
            None,
            None,
            non_empty(row.notes),
            &mut fidelity,
        )?;
        entry.folder = folder;
        if addresses.len() > 1 {
            entry.urls = usable_unique_urls(addresses.into_iter())?;
        }
        imported.push(entry);
        check_import_item_count(imported.len())?;
    }
    Ok((imported, fidelity, omissions))
}

fn usable_unique_urls(addresses: impl Iterator<Item = String>) -> VaultResult<Vec<String>> {
    let mut urls: Vec<String> = Vec::new();
    for address in addresses {
        let url = normalise_url(&clean_import_field("website address", address)?);
        if usable_web_url(&url) && !urls.iter().any(|saved| saved == &url) {
            urls.push(url);
        }
    }
    Ok(urls)
}

pub fn import_bitwarden_json_entries(content: &str) -> VaultResult<ParsedImport> {
    let export: BitwardenJsonExport = serde_json::from_str(content).map_err(|_| {
        "Sesame could not read that Bitwarden JSON export. Export it again and try once more."
            .to_string()
    })?;
    let folders = export
        .folders
        .into_iter()
        .map(|folder| Ok((folder.id, normalise_folder(&folder.name)?)))
        .collect::<VaultResult<HashMap<String, String>>>()?;
    let mut imported = Vec::new();
    let mut secure_notes = Vec::new();
    let mut cards = Vec::new();
    let mut identities = Vec::new();
    let mut ssh_keys = Vec::new();
    let mut imported_count = 0;
    let mut passkeys_not_imported = 0;
    let mut omissions = ImportAccounting::default();
    let mut fidelity = ImportFidelity::default();
    for item in export.items {
        // Bitwarden item types: 1 login, 2 note, 3 card, 4 identity, 5 SSH key; anything past 5 is counted as omitted.
        match item.item_type {
            Some(2) => {
                secure_notes.push(bitwarden_json_secure_note(
                    item,
                    &mut fidelity.secure_notes,
                )?);
                imported_count += 1;
                check_import_item_count(imported_count)?;
                continue;
            }
            Some(3) => {
                cards.push(bitwarden_json_card(item, &mut fidelity.cards)?);
                imported_count += 1;
                check_import_item_count(imported_count)?;
                continue;
            }
            Some(4) => {
                identities.push(bitwarden_json_identity(item, &mut fidelity.identities)?);
                imported_count += 1;
                check_import_item_count(imported_count)?;
                continue;
            }
            Some(5) => {
                ssh_keys.push(bitwarden_json_ssh_key(item, &mut fidelity.ssh_keys)?);
                imported_count += 1;
                check_import_item_count(imported_count)?;
                continue;
            }
            Some(other) if other != 1 => {
                omissions.omit(ImportItemReason::UnsupportedItemType);
                fidelity
                    .unsupported_items
                    .record(FieldDisposition::IntentionallyOmitted);
                continue;
            }
            _ => {}
        }
        let folder = item
            .folder_id
            .as_ref()
            .and_then(|id| folders.get(id))
            .cloned()
            .unwrap_or_default();
        let attachment_count = item.attachments.len();
        let Some(mut login) = item.login else {
            omissions.omit(ImportItemReason::UnreadableRow);
            continue;
        };
        login.username = clean_import_field("username", login.username)?;
        login.password = bounded_import_field("password", login.password)?;
        login.totp = bounded_import_field("2FA secret", login.totp)?;
        for uri in &mut login.uris {
            uri.uri = clean_import_field("website address", std::mem::take(&mut uri.uri))?;
        }
        for _ in 0..attachment_count {
            fidelity
                .logins
                .record(FieldDisposition::IntentionallyOmitted);
        }
        for _ in 0..login.fido2_credentials.len() {
            passkeys_not_imported += 1;
            fidelity
                .passkeys
                .record(FieldDisposition::IntentionallyOmitted);
        }
        let item_name = clean_import_field("login name", item.name)?;
        let item_notes = clean_import_multiline_field("notes", item.notes)?;
        if item_name.is_empty() && login.username.is_empty() && login.password.is_empty() {
            let has_other_content = !item_notes.trim().is_empty()
                || !login.totp.trim().is_empty()
                || login.uris.iter().any(|uri| !uri.uri.trim().is_empty())
                || item.fields.iter().any(|field| {
                    field
                        .value
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                });
            if has_other_content {
                omissions.omit(ImportItemReason::MissingCredentials);
            }
            continue;
        }
        let mut backup_codes = Vec::new();
        let mut recovery_email = None;
        let mut recovery_phone = None;
        let mut legacy_fields = Vec::new();
        for field in item.fields {
            let field_name = normalise_header(&field.name);
            let Some(value) = field.value.and_then(non_empty) else {
                continue;
            };
            let value = bounded_import_field("custom field value", value)?;
            if field_name.contains("backup") && field_name.contains("code") {
                backup_codes.extend(split_backup_codes(&value));
            } else if field_name.contains("recovery") && field_name.contains("email") {
                recovery_email = Some(value);
            } else if field_name.contains("recovery")
                && (field_name.contains("phone") || field_name.contains("mobile"))
            {
                recovery_phone = Some(value);
            } else if let Some(field) = legacy_field(&field.name, value, field.field_type)? {
                fidelity.logins.record(FieldDisposition::Legacy);
                legacy_fields.push(field);
            }
        }
        let urls = login
            .uris
            .into_iter()
            .filter_map(|uri| non_empty(uri.uri))
            .map(|url| normalise_url(&url))
            .filter(|url| usable_web_url(url))
            .fold(Vec::new(), |mut urls, url| {
                if !urls.iter().any(|saved| saved == &url) {
                    urls.push(url);
                }
                urls
            });
        let url = urls.first().cloned().unwrap_or_default();
        let mut entry = imported_entry(
            item_name,
            url,
            login.username,
            login.password,
            non_empty(login.totp),
            backup_codes,
            recovery_email,
            recovery_phone,
            non_empty(item_notes),
            &mut fidelity.logins,
        )?;
        entry.folder = folder;
        entry.urls = urls;
        entry.legacy_fields = legacy_fields;
        imported.push(entry);
        imported_count += 1;
        check_import_item_count(imported_count)?;
    }
    Ok(ParsedImport {
        entries: imported,
        secure_notes,
        cards,
        identities,
        ssh_keys,
        passkeys_not_imported,
        intentionally_omitted_items: 0,
        accounting: omissions,
        fidelity,
    })
}

fn bitwarden_json_card(
    item: BitwardenJsonItem,
    fidelity: &mut FidelityCounts,
) -> VaultResult<Card> {
    for _ in 0..item.attachments.len() {
        fidelity.record(FieldDisposition::IntentionallyOmitted);
    }
    let mut card = item.card.unwrap_or_default();
    card.cardholder_name = clean_import_field("cardholder name", card.cardholder_name)?;
    card.number = bounded_import_field("card number", card.number)?;
    card.exp_month = bounded_import_field("expiry month", card.exp_month)?;
    card.exp_year = bounded_import_field("expiry year", card.exp_year)?;
    card.code = bounded_import_field("security code", card.code)?;
    card.brand = clean_import_field("card brand", card.brand)?;
    let notes = clean_import_multiline_field("notes", item.notes)?;
    if !notes.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    let mut legacy_fields = Vec::new();
    for field in item.fields {
        let Some(value) = field.value.and_then(non_empty) else {
            continue;
        };
        if let Some(field) = legacy_field(&field.name, value, field.field_type)? {
            fidelity.record(FieldDisposition::Legacy);
            legacy_fields.push(field);
        }
    }
    for value in [
        &card.cardholder_name,
        &card.number,
        &card.exp_month,
        &card.exp_year,
        &card.code,
        &card.brand,
    ] {
        if !value.trim().is_empty() {
            fidelity.record(FieldDisposition::Imported);
        }
    }
    let title = clean_import_field("card name", item.name)?;
    let now = unix_timestamp();
    Ok(Card {
        id: random_id(),
        title: non_empty(title).unwrap_or_else(|| "Imported card".to_string()),
        cardholder_name: card.cardholder_name.trim().to_string(),
        number: card.number.trim().to_string(),
        expiry_month: card.exp_month.trim().to_string(),
        expiry_year: card.exp_year.trim().to_string(),
        security_code: card.code.trim().to_string(),
        brand: card.brand.trim().to_string(),
        notes,
        tags: Vec::new(),
        legacy_fields,
        created_at: now,
        updated_at: now,
        revision: 1,
        folder_id: None,
        favourite: false,
        last_used_at: None,
    })
}

fn bitwarden_json_ssh_key(
    item: BitwardenJsonItem,
    fidelity: &mut FidelityCounts,
) -> VaultResult<SshKey> {
    for _ in 0..item.attachments.len() {
        fidelity.record(FieldDisposition::IntentionallyOmitted);
    }
    let mut key = item.ssh_key.unwrap_or_default();
    key.private_key = bounded_import_field("private key", key.private_key)?;
    key.public_key = bounded_import_field("public key", key.public_key)?;
    for value in [&key.private_key, &key.public_key] {
        if !value.trim().is_empty() {
            fidelity.record(FieldDisposition::Imported);
        }
    }
    // Bitwarden stores no key type of its own; the public key names its algorithm.
    let key_type = key
        .public_key
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let notes = clean_import_multiline_field("notes", item.notes)?;
    if !notes.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    // The fingerprint has no Sesame field and is derivable from the public key.
    if !key.key_fingerprint.trim().is_empty() {
        fidelity.record(FieldDisposition::IntentionallyOmitted);
    }
    // SshKey has no legacy_fields, so custom fields cannot be carried. Count them
    // rather than letting the report claim nothing was left behind.
    for field in &item.fields {
        if field
            .value
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            fidelity.record(FieldDisposition::IntentionallyOmitted);
        }
    }
    let title = clean_import_field("SSH key name", item.name)?;
    let now = unix_timestamp();
    Ok(SshKey {
        id: random_id(),
        title: non_empty(title).unwrap_or_else(|| "Imported SSH key".to_string()),
        key_type,
        private_key: key.private_key.trim().to_string(),
        public_key: key.public_key.trim().to_string(),
        passphrase: String::new(),
        notes,
        tags: Vec::new(),
        created_at: now,
        updated_at: now,
        revision: 1,
        folder_id: None,
        favourite: false,
        last_used_at: None,
    })
}

fn bitwarden_json_secure_note(
    item: BitwardenJsonItem,
    fidelity: &mut FidelityCounts,
) -> VaultResult<SecureNote> {
    for _ in 0..item.attachments.len() {
        fidelity.record(FieldDisposition::IntentionallyOmitted);
    }
    let content = clean_import_multiline_field("notes", item.notes)?;
    if !content.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    let mut legacy_fields = Vec::new();
    for field in item.fields {
        let Some(value) = field.value.and_then(non_empty) else {
            continue;
        };
        if let Some(field) = legacy_field(&field.name, value, field.field_type)? {
            fidelity.record(FieldDisposition::Legacy);
            legacy_fields.push(field);
        }
    }
    let title = clean_import_field("note name", item.name)?;
    let now = unix_timestamp();
    Ok(SecureNote {
        id: random_id(),
        title: non_empty(title).unwrap_or_else(|| "Imported note".to_string()),
        content,
        tags: Vec::new(),
        legacy_fields,
        created_at: now,
        updated_at: now,
        revision: 1,
        folder_id: None,
        favourite: false,
        last_used_at: None,
    })
}

fn bitwarden_json_identity(
    item: BitwardenJsonItem,
    fidelity: &mut FidelityCounts,
) -> VaultResult<Identity> {
    for _ in 0..item.attachments.len() {
        fidelity.record(FieldDisposition::IntentionallyOmitted);
    }
    let mut identity = item.identity.unwrap_or_default();
    for (label, value) in [
        ("identity title", &mut identity.title),
        ("first name", &mut identity.first_name),
        ("middle name", &mut identity.middle_name),
        ("last name", &mut identity.last_name),
        ("city", &mut identity.city),
        ("region", &mut identity.state),
        ("postal code", &mut identity.postal_code),
        ("country", &mut identity.country),
        ("company", &mut identity.company),
        ("email", &mut identity.email),
        ("phone", &mut identity.phone),
        ("social security number", &mut identity.ssn),
        ("username", &mut identity.username),
        ("passport number", &mut identity.passport_number),
        ("licence number", &mut identity.license_number),
    ] {
        *value = clean_import_field(label, std::mem::take(value))?;
    }
    for value in [
        &mut identity.address1,
        &mut identity.address2,
        &mut identity.address3,
    ] {
        *value = clean_import_multiline_field("address", std::mem::take(value))?;
    }
    let identity_name = clean_import_field("identity name", item.name)?;
    let mut legacy_fields = Vec::new();

    let name_parts = [
        identity.first_name.trim(),
        identity.middle_name.trim(),
        identity.last_name.trim(),
    ];
    let full_name = name_parts
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    if !full_name.is_empty() {
        fidelity.record(FieldDisposition::Transformed);
    }

    for value in [
        &identity.email,
        &identity.phone,
        &identity.address1,
        &identity.address2,
        &identity.city,
        &identity.state,
        &identity.postal_code,
        &identity.country,
    ] {
        if !value.trim().is_empty() {
            fidelity.record(FieldDisposition::Imported);
        }
    }

    for (label, value) in [
        ("Title", identity.title),
        ("Company", identity.company),
        ("Username", identity.username),
        ("Address line 3", identity.address3),
        ("Social security number", identity.ssn),
        ("Passport number", identity.passport_number),
        ("Licence number", identity.license_number),
    ] {
        if let Some(value) = non_empty(value) {
            if let Some(field) = legacy_field(label, value, None)? {
                fidelity.record(FieldDisposition::Legacy);
                legacy_fields.push(field);
            }
        }
    }

    for field in item.fields {
        let Some(value) = field.value.and_then(non_empty) else {
            continue;
        };
        if let Some(field) = legacy_field(&field.name, value, field.field_type)? {
            fidelity.record(FieldDisposition::Legacy);
            legacy_fields.push(field);
        }
    }

    let now = unix_timestamp();
    Ok(Identity {
        id: random_id(),
        label: non_empty(identity_name).unwrap_or_else(|| "Imported identity".to_string()),
        full_name,
        email: identity.email.trim().to_string(),
        phone: identity.phone.trim().to_string(),
        address_line1: identity.address1.trim().to_string(),
        address_line2: identity.address2.trim().to_string(),
        city: identity.city.trim().to_string(),
        region: identity.state.trim().to_string(),
        postal_code: identity.postal_code.trim().to_string(),
        country: identity.country.trim().to_string(),
        legacy_fields,
        created_at: now,
        updated_at: now,
        revision: 1,
        tags: Vec::new(),
        folder_id: None,
        favourite: false,
        last_used_at: None,
    })
}

pub fn import_lastpass_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    for row in reader.deserialize::<LastPassCsvEntry>() {
        let row = row.map_err(|_| {
            "Sesame could not read that LastPass CSV. Export it again and try once more."
                .to_string()
        })?;
        if row.name.is_empty() && row.username.is_empty() && row.password.is_empty() {
            if !row.url.trim().is_empty() || !row.extra.trim().is_empty() {
                omissions.omit(ImportItemReason::MissingCredentials);
            }
            continue;
        }
        let folder = normalise_folder(&row.grouping)?;
        let mut entry = imported_entry(
            row.name,
            row.url,
            row.username,
            row.password,
            None,
            Vec::new(),
            None,
            None,
            non_empty(row.extra),
            &mut fidelity,
        )?;
        entry.folder = folder;
        imported.push(entry);
        check_import_item_count(imported.len())?;
    }
    Ok((imported, fidelity, omissions))
}

pub fn import_dashlane_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| {
            "Sesame could not read that Dashlane CSV. Export it again and try once more."
                .to_string()
        })?
        .iter()
        .enumerate()
        .map(|(index, name)| (normalise_header(name), index))
        .collect::<HashMap<_, _>>();
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read a Dashlane entry. Export it again and try once more.".to_string()
        })?;
        let title = record_value(&record, &headers, &["title", "name", "website"]);
        let username = record_value(&record, &headers, &["username", "login", "email"]);
        let password = record_secret(&record, &headers, &["password"]);
        if title.is_empty() && username.is_empty() && password.is_empty() {
            record_row_without_credentials(&mut omissions, &record);
            continue;
        }
        let url = record_value(&record, &headers, &["url", "website", "webaddress"]);
        let notes = non_empty(record_value(&record, &headers, &["note", "notes"]));
        let totp = non_empty(record_value(
            &record,
            &headers,
            &["otpsecret", "totp", "otpauth"],
        ));
        imported.push(imported_entry(
            title,
            url,
            username,
            password,
            totp,
            Vec::new(),
            None,
            None,
            notes,
            &mut fidelity,
        )?);
        check_import_item_count(imported.len())?;
    }
    Ok((imported, fidelity, omissions))
}

pub fn import_onepassword_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    import_flexible_csv_entries(
        content,
        "1Password",
        &["title", "name"],
        &["website", "url"],
        &["username", "login"],
        &["password"],
        &["onetimepassword", "otp", "otpauth", "totp"],
        &["notes", "note"],
        &["tags"],
    )
}

pub fn import_keepass_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    import_flexible_csv_entries(
        content,
        "KeePass",
        &["title", "name"],
        &["url", "website"],
        &["username", "user name"],
        &["password"],
        &["otp", "totp", "onetimepassword"],
        &["notes", "note"],
        &["tags"],
    )
}

pub fn import_apple_passwords_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    import_flexible_csv_entries(
        content,
        "Apple Passwords",
        &["title"],
        &["url"],
        &["username"],
        &["password"],
        &["otpauth"],
        &["notes"],
        &[],
    )
}

pub fn import_browser_csv_entries(
    content: &str,
    browser: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    import_flexible_csv_entries(
        content,
        browser,
        &["name", "title"],
        &["url", "website", "origin"],
        &["username", "login"],
        &["password"],
        &[],
        &["note", "notes"],
        &[],
    )
}

pub fn import_firefox_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    import_flexible_csv_entries(
        content,
        "Firefox",
        &["title", "name"],
        &["url", "hostname", "origin"],
        &["username"],
        &["password"],
        &[],
        &[],
        &[],
    )
}

/// Columns matched by name like Proton's own export builder; JSON-stringified non-login rows are omitted, not guessed at.
pub fn import_proton_pass_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| {
            "Sesame could not read that Proton Pass CSV. Export it again and try once more."
                .to_string()
        })?
        .iter()
        .enumerate()
        .map(|(index, name)| (normalise_header(name), index))
        .collect::<HashMap<_, _>>();
    if !headers.contains_key("password") || !headers.contains_key("name") {
        return Err("That file does not look like a Proton Pass password export.".to_string());
    }
    let mapped_headers: HashSet<&str> = [
        "type",
        "name",
        "url",
        "email",
        "username",
        "password",
        "note",
        "totp",
        "createtime",
        "modifytime",
        "vault",
    ]
    .into_iter()
    .collect();
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read a Proton Pass entry. Export it again and try once more."
                .to_string()
        })?;
        let item_type = record_value(&record, &headers, &["type"]).to_ascii_lowercase();
        if !item_type.is_empty() && item_type != "login" && item_type != "alias" {
            omissions.omit(ImportItemReason::UnsupportedItemType);
            continue;
        }
        let title = record_value(&record, &headers, &["name"]);
        let username = record_value(&record, &headers, &["username"]);
        let password = record_secret(&record, &headers, &["password"]);
        let email = record_value(&record, &headers, &["email"]);
        if title.is_empty() && username.is_empty() && password.is_empty() && email.is_empty() {
            record_row_without_credentials(&mut omissions, &record);
            continue;
        }
        // Proton joins multiple URLs on one item as "url1, url2".
        let raw_url = record_value(&record, &headers, &["url"]);
        let mut raw_urls = raw_url.split(", ").filter(|value| !value.trim().is_empty());
        let first_url = raw_urls.next().unwrap_or_default().to_string();
        let mut extra_urls = Vec::new();
        for value in raw_urls {
            let url = normalise_url(&clean_import_field("website address", value.to_string())?);
            if usable_web_url(&url) {
                extra_urls.push(url);
            }
        }
        let mut entry = imported_entry(
            title,
            first_url,
            username,
            password,
            non_empty(record_value(&record, &headers, &["totp"])),
            Vec::new(),
            None,
            None,
            non_empty(record_value(&record, &headers, &["note"])),
            &mut fidelity,
        )?;
        if !extra_urls.is_empty() {
            fidelity.record(FieldDisposition::Transformed);
            let mut urls = Vec::new();
            if !entry.url.is_empty() {
                urls.push(entry.url.clone());
            }
            for value in extra_urls {
                if !urls.iter().any(|saved| saved == &value) {
                    urls.push(value);
                }
            }
            entry.urls = urls;
        }
        if let Some(email) = non_empty(email) {
            entry.email = clean_import_field("email", email)?;
            fidelity.record(FieldDisposition::Imported);
        }
        let vault = record_value(&record, &headers, &["vault"]);
        if !vault.is_empty() {
            entry.folder = normalise_folder(&vault)?;
            fidelity.record(FieldDisposition::Transformed);
        }
        let mut legacy_columns = Vec::new();
        for (name, index) in &headers {
            if mapped_headers.contains(name.as_str()) {
                continue;
            }
            let Some(value) = record
                .get(*index)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if let Some(field) = legacy_field(name, value.to_string(), None)? {
                legacy_columns.push(field);
            }
        }
        legacy_columns.sort_by(|left, right| left.label.cmp(&right.label));
        for _ in &legacy_columns {
            fidelity.record(FieldDisposition::Legacy);
        }
        entry.legacy_fields.append(&mut legacy_columns);
        imported.push(entry);
        check_import_item_count(imported.len())?;
    }
    Ok((imported, fidelity, omissions))
}

/// No header row; `$oneTimeCode` becomes TOTP, `$type` marks omitted rows, everything else stays Legacy.
pub fn import_keeper_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(false)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    let mut saw_a_row = false;
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read that Keeper CSV. Export it again and try once more.".to_string()
        })?;
        if record.len() < 6 {
            if record_has_content(&record) {
                omissions.omit(ImportItemReason::UnreadableRow);
            }
            continue;
        }
        saw_a_row = true;
        let folder = record.get(0).unwrap_or_default().trim().to_string();
        let title = record.get(1).unwrap_or_default().trim().to_string();
        let username = record.get(2).unwrap_or_default().trim().to_string();
        let password = record.get(3).unwrap_or_default().to_string();
        let url = record.get(4).unwrap_or_default().trim().to_string();
        let notes = record.get(5).unwrap_or_default().trim().to_string();
        let mut totp = None;
        let mut record_type: Option<String> = None;
        let mut legacy_fields = Vec::new();
        let mut index = 7; // Column 6 is the shared-folder name; custom fields start at 7.
        while index + 1 < record.len() {
            let name = clean_import_field(
                "custom field name",
                record.get(index).unwrap_or_default().trim().to_string(),
            )?;
            let value = bounded_import_field(
                "custom field value",
                record.get(index + 1).unwrap_or_default().trim().to_string(),
            )?;
            index += 2;
            if name.is_empty() || value.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("$onetimecode") {
                totp = non_empty(value);
                continue;
            }
            if name.eq_ignore_ascii_case("$type") {
                record_type = Some(value);
                continue;
            }
            let label = name.strip_prefix('$').unwrap_or(&name);
            if let Some(field) = legacy_field(label, value, None)? {
                fidelity.record(FieldDisposition::Legacy);
                legacy_fields.push(field);
            }
        }
        if let Some(record_type) = record_type {
            if !record_type.eq_ignore_ascii_case("login") {
                omissions.omit(ImportItemReason::UnsupportedItemType);
                continue;
            }
        }
        if title.is_empty() && username.is_empty() && password.is_empty() {
            record_row_without_credentials(&mut omissions, &record);
            continue;
        }
        let mut entry = imported_entry(
            title,
            url,
            username,
            password,
            totp,
            Vec::new(),
            None,
            None,
            non_empty(notes),
            &mut fidelity,
        )?;
        entry.folder = normalise_folder(&folder)?;
        entry.legacy_fields = legacy_fields;
        imported.push(entry);
        check_import_item_count(imported.len())?;
    }
    if !saw_a_row {
        return Err("That file does not look like a Keeper password export.".to_string());
    }
    Ok((imported, fidelity, omissions))
}

/// No official schema; columns match by name, `custom_fields` with a one-time-code label becomes TOTP.
pub fn import_nordpass_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| {
            "Sesame could not read that NordPass CSV. Export it again and try once more."
                .to_string()
        })?
        .iter()
        .enumerate()
        .map(|(index, name)| (normalise_header(name), index))
        .collect::<HashMap<_, _>>();
    if !headers.contains_key("password") || !headers.contains_key("name") {
        return Err("That file does not look like a NordPass password export.".to_string());
    }
    let mapped_headers: HashSet<&str> = [
        "name",
        "url",
        "additionalurls",
        "username",
        "password",
        "note",
        "folder",
        "type",
        "customfields",
    ]
    .into_iter()
    .collect();
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read a NordPass entry. Export it again and try once more.".to_string()
        })?;
        let title = record_value(&record, &headers, &["name"]);
        let item_type = record_value(&record, &headers, &["type"]).to_ascii_lowercase();
        let username = record_value(&record, &headers, &["username"]);
        let password = record_secret(&record, &headers, &["password"]);
        let placeholder_values = [
            record_value(&record, &headers, &["url"]),
            record_value(&record, &headers, &["additionalurls"]),
            record_value(&record, &headers, &["note"]),
            record_value(&record, &headers, &["customfields"]),
        ];
        if title.is_empty()
            && item_type.is_empty()
            && username.is_empty()
            && password.is_empty()
            && placeholder_values.iter().all(String::is_empty)
        {
            continue;
        }
        if !item_type.is_empty() && item_type != "password" {
            omissions.omit(ImportItemReason::UnsupportedItemType);
            continue;
        }
        if title.is_empty() && username.is_empty() && password.is_empty() {
            record_row_without_credentials(&mut omissions, &record);
            continue;
        }
        let mut entry = imported_entry(
            title,
            record_value(&record, &headers, &["url"]),
            username,
            password,
            None,
            Vec::new(),
            None,
            None,
            non_empty(record_value(&record, &headers, &["note"])),
            &mut fidelity,
        )?;
        let folder = record_value(&record, &headers, &["folder"]);
        if !folder.is_empty() {
            entry.folder = normalise_folder(&folder)?;
        }
        let mut urls = if entry.url.is_empty() {
            Vec::new()
        } else {
            vec![entry.url.clone()]
        };
        let additional_urls = record_value(&record, &headers, &["additionalurls"]);
        if let Ok(serde_json::Value::Array(values)) =
            serde_json::from_str::<serde_json::Value>(&additional_urls)
        {
            let mut added_any = false;
            for value in values
                .into_iter()
                .filter_map(|value| value.as_str().map(str::to_string))
            {
                let url = normalise_url(&clean_import_field("website address", value)?);
                if usable_web_url(&url) && !urls.iter().any(|saved| saved == &url) {
                    urls.push(url);
                    added_any = true;
                }
            }
            if added_any {
                fidelity.record(FieldDisposition::Transformed);
            }
        } else if !additional_urls.is_empty() {
            fidelity.record(FieldDisposition::Malformed);
        }
        entry.urls = urls;
        let custom_fields = record_value(&record, &headers, &["customfields"]);
        let mut legacy_fields = Vec::new();
        if let Ok(serde_json::Value::Array(values)) =
            serde_json::from_str::<serde_json::Value>(&custom_fields)
        {
            for field in values {
                let label = field
                    .get("label")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let Some(value) = field
                    .get("value")
                    .and_then(|value| value.as_str())
                    .and_then(|value| non_empty(value.to_string()))
                else {
                    continue;
                };
                let looks_like_totp = {
                    let normalised = normalise_header(label);
                    normalised.contains("totp")
                        || normalised.contains("otp")
                        || normalised.contains("2fa")
                        || (normalised.contains("onetime") && normalised.contains("code"))
                };
                if looks_like_totp && entry.totp.is_none() {
                    entry.totp = non_empty(bounded_import_field("2FA secret", value)?);
                    fidelity.record(FieldDisposition::Imported);
                    continue;
                }
                if let Some(field) = legacy_field(label, value, None)? {
                    fidelity.record(FieldDisposition::Legacy);
                    legacy_fields.push(field);
                }
            }
        } else if !custom_fields.is_empty() {
            fidelity.record(FieldDisposition::Malformed);
        }
        // Stray card/identity values on a password row stay Legacy, never dropped.
        let mut stray_columns = Vec::new();
        for (name, index) in &headers {
            if mapped_headers.contains(name.as_str()) {
                continue;
            }
            let Some(value) = record
                .get(*index)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if let Some(field) = legacy_field(name, value.to_string(), None)? {
                stray_columns.push(field);
            }
        }
        stray_columns.sort_by(|left, right| left.label.cmp(&right.label));
        for _ in &stray_columns {
            fidelity.record(FieldDisposition::Legacy);
        }
        legacy_fields.append(&mut stray_columns);
        entry.legacy_fields = legacy_fields;
        imported.push(entry);
        check_import_item_count(imported.len())?;
    }
    Ok((imported, fidelity, omissions))
}

pub fn import_flexible_csv_entries(
    content: &str,
    product: &str,
    title_names: &[&str],
    url_names: &[&str],
    username_names: &[&str],
    password_names: &[&str],
    totp_names: &[&str],
    note_names: &[&str],
    tag_names: &[&str],
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| {
            format!("Sesame could not read that {product} CSV. Export it again and try once more.")
        })?
        .iter()
        .enumerate()
        .map(|(index, name)| (normalise_header(name), index))
        .collect::<HashMap<_, _>>();
    if !password_names
        .iter()
        .any(|name| headers.contains_key(*name))
        || !url_names.iter().any(|name| headers.contains_key(*name))
    {
        return Err(format!(
            "That file does not look like a {product} password export."
        ));
    }
    let mapped_headers = title_names
        .iter()
        .chain(url_names)
        .chain(username_names)
        .chain(password_names)
        .chain(totp_names)
        .chain(note_names)
        .chain(tag_names)
        .copied()
        .collect::<HashSet<_>>();
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut omissions = ImportAccounting::default();
    for record in reader.records() {
        let record = record.map_err(|_| {
            format!("Sesame could not read a {product} entry. Export it again and try once more.")
        })?;
        let title = record_value(&record, &headers, title_names);
        let url = record_value(&record, &headers, url_names);
        let username = record_value(&record, &headers, username_names);
        let password = record_secret(&record, &headers, password_names);
        if title.is_empty() && username.is_empty() && password.is_empty() {
            record_row_without_credentials(&mut omissions, &record);
            continue;
        }
        let mut entry = imported_entry(
            title,
            url,
            username,
            password,
            non_empty(record_value(&record, &headers, totp_names)),
            Vec::new(),
            None,
            None,
            non_empty(record_value(&record, &headers, note_names)),
            &mut fidelity,
        )?;
        let raw_tags = record_value(&record, &headers, tag_names);
        entry.tags = normalise_tags(vec![raw_tags.clone()])?;
        if !entry.tags.is_empty() {
            fidelity.record(FieldDisposition::Transformed);
        }
        let mut legacy_columns = Vec::new();
        for (name, index) in &headers {
            if mapped_headers.contains(name.as_str()) {
                continue;
            }
            let Some(value) = record
                .get(*index)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if let Some(field) = legacy_field(name, value.to_string(), None)? {
                legacy_columns.push(field);
            }
        }
        legacy_columns.sort_by(|left, right| left.label.cmp(&right.label));
        for _ in &legacy_columns {
            fidelity.record(FieldDisposition::Legacy);
        }
        entry.legacy_fields.append(&mut legacy_columns);
        imported.push(entry);
        check_import_item_count(imported.len())?;
    }
    Ok((imported, fidelity, omissions))
}

/// A 2FA code has no password, so these entries carry a title and a secret only.
fn totp_entry(
    issuer: &str,
    account: &str,
    otpauth: String,
    fidelity: &mut FidelityCounts,
) -> VaultResult<Option<VaultEntry>> {
    let issuer = clean_import_field("issuer", issuer.to_string())?;
    let account = clean_import_field("account", account.to_string())?;
    let otpauth = bounded_import_field("2FA secret", otpauth)?;
    if totp_from_value(&otpauth).is_none() {
        return Ok(None);
    }
    // A link may carry no label at all. The secret is the valuable part and the
    // name can be edited, so name it rather than dropping it in silence.
    let title = match (issuer.trim(), account.trim()) {
        ("", "") => "Imported code".to_string(),
        ("", account) => account.to_string(),
        (issuer, _) => issuer.to_string(),
    };
    fidelity.record(FieldDisposition::Imported);
    Ok(Some(imported_entry(
        title,
        String::new(),
        account.trim().to_string(),
        String::new(),
        Some(otpauth),
        Vec::new(),
        None,
        None,
        None,
        fidelity,
    )?))
}

fn unsupported_code_reason(kind: &str) -> ImportItemReason {
    match kind.trim().to_ascii_lowercase().as_str() {
        "hotp" => ImportItemReason::CounterBasedCode,
        "steam" => ImportItemReason::SteamCode,
        _ => ImportItemReason::UnsupportedCodeType,
    }
}

fn unsupported_otpauth_reason(line: &str) -> Option<ImportItemReason> {
    let after_scheme = line.trim_start_matches("otpauth://");
    let kind = after_scheme.split(['/', '?']).next().unwrap_or("");
    if !kind.eq_ignore_ascii_case("totp") {
        return Some(unsupported_code_reason(kind));
    }
    let steam_encoder = line
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(key, value)| {
            key.eq_ignore_ascii_case("encoder") && value.eq_ignore_ascii_case("steam")
        });
    steam_encoder.then_some(ImportItemReason::SteamCode)
}

/// Aegis, Ente Auth and KeePassXC all export a plain list of otpauth links.
pub fn import_otpauth_list_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let mut fidelity = FidelityCounts::default();
    let mut accounting = ImportAccounting::default();
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("otpauth-migration://") {
            accounting.omit(ImportItemReason::TransferLink);
            continue;
        }
        if line.is_empty() || !line.starts_with("otpauth://") {
            continue;
        }
        if let Some(reason) = unsupported_otpauth_reason(line) {
            accounting.omit(reason);
            continue;
        }
        let (issuer, account) = otpauth_labels(line);
        match totp_entry(&issuer, &account, line.to_string(), &mut fidelity)? {
            Some(entry) => {
                entries.push(entry);
                check_import_item_count(entries.len())?;
            }
            None => accounting.omit(ImportItemReason::UnusableCode),
        }
    }
    if entries.is_empty() {
        return Err(
            "That file has no otpauth:// links in it. Export your codes again as plain text."
                .into(),
        );
    }
    Ok((entries, fidelity, accounting))
}

/// Reads the issuer and account out of an otpauth link without a URL crate.
fn otpauth_labels(url: &str) -> (String, String) {
    let after_scheme = url.trim_start_matches("otpauth://");
    let path = after_scheme
        .split_once('/')
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let (label, query) = path.split_once('?').unwrap_or((path, ""));
    // Split first, decode second: an encoded colon belongs to the text, not the separator.
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (
            percent_decode(issuer).trim().to_string(),
            percent_decode(account).trim().to_string(),
        ),
        None => (String::new(), percent_decode(label).trim().to_string()),
    };
    let query_issuer = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "issuer")
        .map(|(_, value)| percent_decode(value))
        .unwrap_or_default();
    let issuer = if query_issuer.is_empty() {
        label_issuer
    } else {
        query_issuer
    };
    (issuer, account)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Builds the otpauth link the vault stores, so digits and period survive the import.
/// SHA1 is the otpauth default. An unknown name must not fall back to it: the
/// entry would parse, import, and then generate codes that never work.
fn normalised_algorithm(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        "" | "SHA1" => Some("SHA1"),
        "SHA256" => Some("SHA256"),
        "SHA512" => Some("SHA512"),
        _ => None,
    }
}

fn algorithm_omission(value: &str) -> ImportItemReason {
    match value.trim().to_ascii_uppercase().as_str() {
        "SHA224" | "SHA384" => ImportItemReason::UnsupportedAlgorithm,
        _ => ImportItemReason::UnknownAlgorithm,
    }
}

fn otpauth_url(
    issuer: &str,
    account: &str,
    secret: &str,
    digits: u32,
    period: u64,
    algorithm: &str,
) -> String {
    let label = if issuer.trim().is_empty() {
        encode_component(account)
    } else {
        format!("{}:{}", encode_component(issuer), encode_component(account))
    };
    let mut url = format!(
        "otpauth://totp/{label}?secret={}",
        secret.replace([' ', '-'], "").to_ascii_uppercase()
    );
    if !issuer.trim().is_empty() {
        url.push_str(&format!("&issuer={}", encode_component(issuer)));
    }
    url.push_str(&format!(
        "&digits={digits}&period={period}&algorithm={algorithm}"
    ));
    url
}

fn encode_component(value: &str) -> String {
    let mut out = String::new();
    for byte in value.trim().bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn import_aegis_json_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let export: AegisExport = serde_json::from_str(content).map_err(|_| {
        "Sesame could not read that Aegis export. Export it again as an unencrypted JSON file."
            .to_string()
    })?;
    let mut fidelity = FidelityCounts::default();
    let mut accounting = ImportAccounting::default();
    let mut entries = Vec::new();
    for item in export.db.entries {
        if !item.entry_type.eq_ignore_ascii_case("totp") {
            accounting.omit(unsupported_code_reason(&item.entry_type));
            continue;
        }
        let Some(algorithm) = normalised_algorithm(&item.info.algo) else {
            accounting.omit(algorithm_omission(&item.info.algo));
            continue;
        };
        let url = otpauth_url(
            &item.issuer,
            &item.name,
            &item.info.secret,
            item.info.digits.unwrap_or(6),
            item.info.period.unwrap_or(30),
            algorithm,
        );
        match totp_entry(&item.issuer, &item.name, url, &mut fidelity)? {
            Some(entry) => {
                entries.push(entry);
                check_import_item_count(entries.len())?;
            }
            None => accounting.omit(ImportItemReason::UnusableCode),
        }
    }
    if entries.is_empty() {
        return Err("That Aegis export has no time-based codes in it.".into());
    }
    Ok((entries, fidelity, accounting))
}

pub fn import_2fas_json_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, ImportAccounting)> {
    let export: TwoFasExport = serde_json::from_str(content).map_err(|_| {
        "Sesame could not read that 2FAS export. Export it again without a password.".to_string()
    })?;
    if !export.services_encrypted.trim().is_empty() {
        return Err(
            "That 2FAS export is password protected. Export it again without a password.".into(),
        );
    }
    let mut fidelity = FidelityCounts::default();
    let mut accounting = ImportAccounting::default();
    let mut entries = Vec::new();
    for service in export.services {
        let otp = service.otp.unwrap_or_default();
        if !otp.token_type.is_empty() && !otp.token_type.eq_ignore_ascii_case("totp") {
            accounting.omit(unsupported_code_reason(&otp.token_type));
            continue;
        }
        let issuer = if otp.issuer.trim().is_empty() {
            service.name.clone()
        } else {
            otp.issuer.clone()
        };
        let Some(algorithm) = normalised_algorithm(&otp.algorithm) else {
            accounting.omit(algorithm_omission(&otp.algorithm));
            continue;
        };
        let url = otpauth_url(
            &issuer,
            &otp.account,
            &service.secret,
            otp.digits.unwrap_or(6),
            otp.period.unwrap_or(30),
            algorithm,
        );
        match totp_entry(&issuer, &otp.account, url, &mut fidelity)? {
            Some(entry) => {
                entries.push(entry);
                check_import_item_count(entries.len())?;
            }
            None => accounting.omit(ImportItemReason::UnusableCode),
        }
    }
    if entries.is_empty() {
        return Err("That 2FAS export has no time-based codes in it.".into());
    }
    Ok((entries, fidelity, accounting))
}

pub fn imported_entry(
    title: String,
    url: String,
    username: String,
    password: String,
    totp: Option<String>,
    backup_codes: Vec<String>,
    recovery_email: Option<String>,
    recovery_phone: Option<String>,
    notes: Option<String>,
    fidelity: &mut FidelityCounts,
) -> VaultResult<VaultEntry> {
    let title = clean_import_field("login name", title)?;
    let url = clean_import_field("website address", url)?;
    let username = clean_import_field("username", username)?;
    let password = bounded_import_field("password", password)?;
    let totp = totp
        .map(|value| bounded_import_field("2FA secret", value))
        .transpose()?;
    let backup_codes = backup_codes
        .into_iter()
        .map(|code| bounded_import_field("backup code", code))
        .collect::<VaultResult<Vec<_>>>()?;
    let recovery_email = recovery_email
        .map(|value| clean_import_field("recovery email", value))
        .transpose()?;
    let recovery_phone = recovery_phone
        .map(|value| clean_import_field("recovery phone", value))
        .transpose()?;
    let notes = notes
        .map(|value| clean_import_multiline_field("notes", value))
        .transpose()?;
    let trimmed_url = url.trim();
    let normalised_url = normalise_url(&url);
    if !trimmed_url.is_empty() {
        if normalised_url == trimmed_url {
            fidelity.record(FieldDisposition::Imported);
        } else {
            fidelity.record(FieldDisposition::Transformed);
        }
    }
    if !username.trim().is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    if !password.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    if totp.is_some() {
        fidelity.record(FieldDisposition::Imported);
    }
    if notes.is_some() {
        fidelity.record(FieldDisposition::Imported);
    }
    if !backup_codes.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    if recovery_email.is_some() {
        fidelity.record(FieldDisposition::Imported);
    }
    if recovery_phone.is_some() {
        fidelity.record(FieldDisposition::Imported);
    }
    let now = unix_timestamp();
    Ok(VaultEntry {
        id: random_id(),
        title: if title.trim().is_empty() {
            domain_from_url(&normalised_url)
        } else {
            title.trim().to_string()
        },
        url: normalised_url,
        urls: Vec::new(),
        tags: Vec::new(),
        username,
        // No export distinguishes email from username; duplicating it would misrepresent the source.
        email: String::new(),
        password,
        folder: String::new(),
        folder_id: None,
        favourite: false,
        last_used_at: None,
        totp,
        backup_codes,
        recovery_email,
        recovery_phone,
        recovery_not_applicable: false,
        notes,
        created_at: now,
        updated_at: now,
        password_updated_at: now,
        revision: 1,
        // parse_import_entries stamps the importer that produced this entry.
        import_source: None,
        legacy_fields: Vec::new(),
    })
}

fn legacy_field(
    label: &str,
    value: String,
    field_type: Option<u8>,
) -> VaultResult<Option<LegacyField>> {
    let label = clean_import_field("custom field name", label.to_string())?;
    let value = bounded_import_field("custom field value", value)?;
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 160 || value.chars().count() > 20_000 {
        return Ok(None);
    }
    Ok(Some(LegacyField {
        label: label.to_string(),
        value,
        // Unknown field types are concealed: an importer must not decide a value is safe to show.
        secret: field_type != Some(0),
    }))
}

fn normalise_folder(value: &str) -> VaultResult<String> {
    let value = clean_import_field("folder", value.to_string())?;
    Ok(value.trim().chars().take(100).collect())
}

fn normalise_tags(values: Vec<String>) -> VaultResult<Vec<String>> {
    let mut tags = Vec::new();
    for value in values {
        if value.len() > MAX_IMPORT_FIELD_BYTES {
            return Err(
                "The tag field in this import is larger than Sesame can import safely.".to_string(),
            );
        }
        for tag in value.split([',', '\n', ';']) {
            let tag = clean_import_field("tag", tag.trim().to_string())?;
            if tag.is_empty() || tag.chars().count() > 100 || tags.iter().any(|saved| saved == &tag)
            {
                continue;
            }
            tags.push(tag);
        }
    }
    Ok(tags)
}

pub fn resolved_totp(input_totp: Option<String>, stored_totp: Option<String>) -> Option<String> {
    match input_totp {
        Some(value) => non_empty(value),
        None => stored_totp,
    }
}

pub fn entry_from_input(input: LoginInput) -> VaultResult<VaultEntry> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err("Give this login a name so you can find it again.".into());
    }
    if title.chars().count() > 160 {
        return Err("That login name is too long.".into());
    }
    if input.url.chars().count() > 2_048
        || input.urls.len() > 100
        || input.urls.iter().any(|url| url.chars().count() > 2_048)
        || input.username.chars().count() > 2_048
        || input.email.chars().count() > 2_048
        || input.password.chars().count() > 8_192
    {
        return Err("One of the sign-in fields is too long for Sesame to save safely.".into());
    }
    if input.notes.chars().count() > 20_000 {
        return Err("Keep notes under 20,000 characters.".into());
    }
    if input.folder.chars().count() > 100 {
        return Err("Keep folder names under 100 characters.".into());
    }
    if input
        .folder_id
        .as_deref()
        .is_some_and(|folder_id| folder_id.chars().count() > 128)
    {
        return Err("That folder identifier is invalid.".into());
    }
    if input.backup_codes.len() > 1_000
        || input
            .backup_codes
            .iter()
            .any(|code| code.chars().count() > 512)
    {
        return Err("There are too many backup codes, or one is too long.".into());
    }

    let totp = input.totp.and_then(non_empty);
    if let Some(value) = totp.as_deref() {
        if totp_from_value(value).is_none() {
            return Err(
                "The 2FA secret is not valid. Paste a base32 secret or an otpauth:// link.".into(),
            );
        }
    }

    let canonical_url = normalise_url(&input.url);
    if !canonical_url.is_empty() && !usable_web_url(&canonical_url) {
        return Err("Enter a valid http or https website address.".into());
    }
    let mut urls = Vec::new();
    if !canonical_url.is_empty() {
        urls.push(canonical_url.clone());
    }
    for raw_url in &input.urls {
        let url = normalise_url(raw_url);
        if url.is_empty() {
            continue;
        }
        if !usable_web_url(&url) {
            return Err("Each website address must use http or https.".into());
        }
        if !urls.iter().any(|saved| saved == &url) {
            urls.push(url);
        }
    }
    let recovery_not_applicable = input.recovery_not_applicable;
    let now = unix_timestamp();
    Ok(VaultEntry {
        id: input.id.and_then(non_empty).unwrap_or_else(random_id),
        title: title.to_string(),
        url: canonical_url,
        urls,
        tags: normalise_tags(input.tags)?,
        username: input.username.trim().to_string(),
        email: input.email.trim().to_string(),
        password: input.password,
        folder: input.folder.trim().to_string(),
        folder_id: input.folder_id.and_then(non_empty),
        favourite: false,
        last_used_at: None,
        totp,
        backup_codes: if recovery_not_applicable {
            Vec::new()
        } else {
            input
                .backup_codes
                .into_iter()
                .flat_map(|codes| split_backup_codes(&codes))
                .collect()
        },
        recovery_email: if recovery_not_applicable {
            None
        } else {
            non_empty(input.recovery_email)
        },
        recovery_phone: if recovery_not_applicable {
            None
        } else {
            non_empty(input.recovery_phone)
        },
        recovery_not_applicable,
        notes: non_empty(input.notes),
        created_at: now,
        updated_at: now,
        password_updated_at: now,
        revision: 1,
        import_source: None,
        legacy_fields: Vec::new(),
    })
}
