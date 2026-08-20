use std::collections::{HashMap, HashSet};
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    snapshot::totp_from_value,
    types::*,
    util::{
        domain_from_url, non_empty, normalise_header, normalise_url, random_id, record_secret,
        record_value,
        split_backup_codes, unix_timestamp,
    },
    VaultEntry, VaultResult,
};

const MAX_IMPORT_BYTES: u64 = 25 * 1024 * 1024;

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
    /// Field-level disposition counts; see the import fidelity report.
    pub fidelity: ImportFidelity,
}

pub fn parse_import_entries(content: &str, source: &str) -> VaultResult<ParsedImport> {
    if content.len() > 25 * 1024 * 1024 {
        return Err("This import file is too large for Sesame to process safely.".into());
    }
    let mut parsed = match source {
        "bitwarden-csv" => {
            let (entries, logins, omitted) = import_bitwarden_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omitted)
        }
        "bitwarden-json" => import_bitwarden_json_entries(content)?,
        "otpauth-txt" => {
            let (entries, logins) = import_otpauth_list_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "aegis-json" => {
            let (entries, logins) = import_aegis_json_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "2fas-json" => {
            let (entries, logins) = import_2fas_json_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "lastpass-csv" => {
            let (entries, logins) = import_lastpass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "dashlane-csv" => {
            let (entries, logins) = import_dashlane_csv_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "onepassword-csv" => {
            let (entries, logins) = import_onepassword_csv_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "keepass-csv" => {
            let (entries, logins) = import_keepass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "chrome-csv" => {
            let (entries, logins) = import_browser_csv_entries(content, "Chrome")?;
            login_only_parsed_import(entries, logins, 0)
        }
        "edge-csv" => {
            let (entries, logins) = import_browser_csv_entries(content, "Edge")?;
            login_only_parsed_import(entries, logins, 0)
        }
        "brave-csv" => {
            let (entries, logins) = import_browser_csv_entries(content, "Brave")?;
            login_only_parsed_import(entries, logins, 0)
        }
        "google-csv" => {
            let (entries, logins) = import_browser_csv_entries(content, "Google")?;
            login_only_parsed_import(entries, logins, 0)
        }
        "apple-csv" => {
            let (entries, logins) = import_apple_passwords_csv_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "firefox-csv" => {
            let (entries, logins) = import_firefox_csv_entries(content)?;
            login_only_parsed_import(entries, logins, 0)
        }
        "proton-pass-csv" => {
            let (entries, logins, omitted) = import_proton_pass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omitted)
        }
        "keeper-csv" => {
            let (entries, logins, omitted) = import_keeper_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omitted)
        }
        "nordpass-csv" => {
            let (entries, logins, omitted) = import_nordpass_csv_entries(content)?;
            login_only_parsed_import(entries, logins, omitted)
        }
        _ => return Err("Choose a supported import type before selecting a file.".into()),
    };
    if parsed.entries.is_empty()
        && parsed.secure_notes.is_empty()
        && parsed.cards.is_empty()
        && parsed.identities.is_empty()
    {
        return Err("No login entries were found in that import file.".into());
    }
    if parsed.entries.len()
        + parsed.secure_notes.len()
        + parsed.cards.len()
        + parsed.identities.len()
        > 100_000
    {
        return Err("That import contains too many entries for Sesame to process safely.".into());
    }
    for entry in &mut parsed.entries {
        entry.import_source = Some(source.to_string());
    }
    Ok(parsed)
}

fn login_only_parsed_import(
    entries: Vec<VaultEntry>,
    logins: FidelityCounts,
    intentionally_omitted: usize,
) -> ParsedImport {
    let mut fidelity = ImportFidelity {
        logins,
        ..ImportFidelity::default()
    };
    for _ in 0..intentionally_omitted {
        fidelity
            .unsupported_items
            .record(FieldDisposition::IntentionallyOmitted);
    }
    ParsedImport {
        entries,
        intentionally_omitted_items: intentionally_omitted,
        fidelity,
        ..ParsedImport::default()
    }
}

pub fn import_bitwarden_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, usize)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut intentionally_omitted = 0;
    for row in reader.deserialize::<BitwardenCsvEntry>() {
        let row = row.map_err(|_| {
            "Sesame could not read that Bitwarden CSV. Export it again and try once more."
                .to_string()
        })?;
        if !row.item_type.is_empty() && !row.item_type.eq_ignore_ascii_case("login") {
            intentionally_omitted += 1;
            continue;
        }
        if row.name.is_empty() && row.login_username.is_empty() && row.login_password.is_empty() {
            continue;
        }
        let folder = normalise_folder(&row.folder);
        let mut entry = imported_entry(
            row.name,
            row.login_uri,
            row.login_username,
            row.login_password,
            non_empty(row.login_totp),
            Vec::new(),
            None,
            None,
            non_empty(row.notes),
            &mut fidelity,
        );
        entry.folder = folder;
        imported.push(entry);
    }
    Ok((imported, fidelity, intentionally_omitted))
}

pub fn import_bitwarden_json_entries(content: &str) -> VaultResult<ParsedImport> {
    let export: BitwardenJsonExport = serde_json::from_str(content).map_err(|_| {
        "Sesame could not read that Bitwarden JSON export. Export it again and try once more."
            .to_string()
    })?;
    let folders = export
        .folders
        .into_iter()
        .map(|folder| (folder.id, normalise_folder(&folder.name)))
        .collect::<HashMap<_, _>>();
    let mut imported = Vec::new();
    let mut secure_notes = Vec::new();
    let mut cards = Vec::new();
    let mut identities = Vec::new();
    let mut ssh_keys = Vec::new();
    let mut passkeys_not_imported = 0;
    let mut intentionally_omitted_items = 0;
    let mut fidelity = ImportFidelity::default();
    for item in export.items {
        // Bitwarden item types: 1 login, 2 note, 3 card, 4 identity, 5 SSH key; anything past 5 is counted as omitted.
        match item.item_type {
            Some(2) => {
                secure_notes.push(bitwarden_json_secure_note(item, &mut fidelity.secure_notes));
                continue;
            }
            Some(3) => {
                cards.push(bitwarden_json_card(item, &mut fidelity.cards));
                continue;
            }
            Some(4) => {
                identities.push(bitwarden_json_identity(item, &mut fidelity.identities));
                continue;
            }
            Some(5) => {
                ssh_keys.push(bitwarden_json_ssh_key(item, &mut fidelity.ssh_keys));
                continue;
            }
            Some(other) if other != 1 => {
                intentionally_omitted_items += 1;
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
        let Some(login) = item.login else {
            continue;
        };
        for _ in 0..login.fido2_credentials.len() {
            passkeys_not_imported += 1;
            fidelity
                .passkeys
                .record(FieldDisposition::IntentionallyOmitted);
        }
        if item.name.is_empty() && login.username.is_empty() && login.password.is_empty() {
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
            if field_name.contains("backup") && field_name.contains("code") {
                backup_codes.extend(split_backup_codes(&value));
            } else if field_name.contains("recovery") && field_name.contains("email") {
                recovery_email = Some(value);
            } else if field_name.contains("recovery")
                && (field_name.contains("phone") || field_name.contains("mobile"))
            {
                recovery_phone = Some(value);
            } else if let Some(field) = legacy_field(&field.name, value, field.field_type) {
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
            item.name,
            url,
            login.username,
            login.password,
            non_empty(login.totp),
            backup_codes,
            recovery_email,
            recovery_phone,
            non_empty(item.notes),
            &mut fidelity.logins,
        );
        entry.folder = folder;
        entry.urls = urls;
        entry.legacy_fields = legacy_fields;
        imported.push(entry);
    }
    Ok(ParsedImport {
        entries: imported,
        secure_notes,
        cards,
        identities,
        ssh_keys,
        passkeys_not_imported,
        intentionally_omitted_items,
        fidelity,
    })
}

fn bitwarden_json_card(item: BitwardenJsonItem, fidelity: &mut FidelityCounts) -> Card {
    let card = item.card.unwrap_or_default();
    let notes = item.notes;
    if !notes.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    let mut legacy_fields = Vec::new();
    for field in item.fields {
        let Some(value) = field.value.and_then(non_empty) else {
            continue;
        };
        if let Some(field) = legacy_field(&field.name, value, field.field_type) {
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
    let now = unix_timestamp();
    Card {
        id: random_id(),
        title: non_empty(item.name).unwrap_or_else(|| "Imported card".to_string()),
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
    }
}

fn bitwarden_json_ssh_key(item: BitwardenJsonItem, fidelity: &mut FidelityCounts) -> SshKey {
    let key = item.ssh_key.unwrap_or_default();
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
    if !item.notes.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    // The fingerprint has no Sesame field and is derivable from the public key.
    if !key.key_fingerprint.trim().is_empty() {
        fidelity.record(FieldDisposition::IntentionallyOmitted);
    }
    // SshKey has no legacy_fields, so custom fields cannot be carried. Count them
    // rather than letting the report claim nothing was left behind.
    for field in &item.fields {
        if field.value.as_deref().is_some_and(|value| !value.trim().is_empty()) {
            fidelity.record(FieldDisposition::IntentionallyOmitted);
        }
    }
    let now = unix_timestamp();
    SshKey {
        id: random_id(),
        title: non_empty(item.name).unwrap_or_else(|| "Imported SSH key".to_string()),
        key_type,
        private_key: key.private_key.trim().to_string(),
        public_key: key.public_key.trim().to_string(),
        passphrase: String::new(),
        notes: item.notes,
        tags: Vec::new(),
        created_at: now,
        updated_at: now,
        revision: 1,
        folder_id: None,
        favourite: false,
        last_used_at: None,
    }
}

fn bitwarden_json_secure_note(
    item: BitwardenJsonItem,
    fidelity: &mut FidelityCounts,
) -> SecureNote {
    let content = item.notes;
    if !content.is_empty() {
        fidelity.record(FieldDisposition::Imported);
    }
    let mut legacy_fields = Vec::new();
    for field in item.fields {
        let Some(value) = field.value.and_then(non_empty) else {
            continue;
        };
        if let Some(field) = legacy_field(&field.name, value, field.field_type) {
            fidelity.record(FieldDisposition::Legacy);
            legacy_fields.push(field);
        }
    }
    let now = unix_timestamp();
    SecureNote {
        id: random_id(),
        title: non_empty(item.name).unwrap_or_else(|| "Imported note".to_string()),
        content,
        tags: Vec::new(),
        legacy_fields,
        created_at: now,
        updated_at: now,
        revision: 1,
        folder_id: None,
        favourite: false,
        last_used_at: None,
    }
}

fn bitwarden_json_identity(item: BitwardenJsonItem, fidelity: &mut FidelityCounts) -> Identity {
    let identity = item.identity.unwrap_or_default();
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
            if let Some(field) = legacy_field(label, value, None) {
                fidelity.record(FieldDisposition::Legacy);
                legacy_fields.push(field);
            }
        }
    }

    for field in item.fields {
        let Some(value) = field.value.and_then(non_empty) else {
            continue;
        };
        if let Some(field) = legacy_field(&field.name, value, field.field_type) {
            fidelity.record(FieldDisposition::Legacy);
            legacy_fields.push(field);
        }
    }

    let now = unix_timestamp();
    Identity {
        id: random_id(),
        label: non_empty(item.name).unwrap_or_else(|| "Imported identity".to_string()),
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
    }
}

pub fn import_lastpass_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    for row in reader.deserialize::<LastPassCsvEntry>() {
        let row = row.map_err(|_| {
            "Sesame could not read that LastPass CSV. Export it again and try once more."
                .to_string()
        })?;
        if row.name.is_empty() && row.username.is_empty() && row.password.is_empty() {
            continue;
        }
        let folder = normalise_folder(&row.grouping);
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
        );
        entry.folder = folder;
        imported.push(entry);
    }
    Ok((imported, fidelity))
}

pub fn import_dashlane_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read a Dashlane entry. Export it again and try once more.".to_string()
        })?;
        let title = record_value(&record, &headers, &["title", "name", "website"]);
        let username = record_value(&record, &headers, &["username", "login", "email"]);
        let password = record_secret(&record, &headers, &["password"]);
        if title.is_empty() && username.is_empty() && password.is_empty() {
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
        ));
    }
    Ok((imported, fidelity))
}

pub fn import_onepassword_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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

pub fn import_keepass_csv_entries(content: &str) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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

pub fn import_firefox_csv_entries(content: &str) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, usize)> {
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
    let mut intentionally_omitted = 0;
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read a Proton Pass entry. Export it again and try once more."
                .to_string()
        })?;
        let item_type = record_value(&record, &headers, &["type"]).to_ascii_lowercase();
        if !item_type.is_empty() && item_type != "login" && item_type != "alias" {
            intentionally_omitted += 1;
            continue;
        }
        let title = record_value(&record, &headers, &["name"]);
        let username = record_value(&record, &headers, &["username"]);
        let password = record_secret(&record, &headers, &["password"]);
        let email = record_value(&record, &headers, &["email"]);
        if title.is_empty() && username.is_empty() && password.is_empty() && email.is_empty() {
            continue;
        }
        // Proton joins multiple URLs on one item as "url1, url2".
        let raw_url = record_value(&record, &headers, &["url"]);
        let mut raw_urls = raw_url.split(", ").filter(|value| !value.trim().is_empty());
        let first_url = raw_urls.next().unwrap_or_default().to_string();
        let extra_urls = raw_urls
            .map(normalise_url)
            .filter(|value| usable_web_url(value))
            .collect::<Vec<_>>();
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
        );
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
            entry.email = email;
            fidelity.record(FieldDisposition::Imported);
        }
        let vault = record_value(&record, &headers, &["vault"]);
        if !vault.is_empty() {
            entry.folder = normalise_folder(&vault);
            fidelity.record(FieldDisposition::Transformed);
        }
        let mut legacy_columns = headers
            .iter()
            .filter(|(name, _)| !mapped_headers.contains(name.as_str()))
            .filter_map(|(name, index)| {
                record
                    .get(*index)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .and_then(|value| legacy_field(name, value.to_string(), None))
            })
            .collect::<Vec<_>>();
        legacy_columns.sort_by(|left, right| left.label.cmp(&right.label));
        for _ in &legacy_columns {
            fidelity.record(FieldDisposition::Legacy);
        }
        entry.legacy_fields.append(&mut legacy_columns);
        imported.push(entry);
    }
    Ok((imported, fidelity, intentionally_omitted))
}

/// No header row; `$oneTimeCode` becomes TOTP, `$type` marks omitted rows, everything else stays Legacy.
pub fn import_keeper_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, usize)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(false)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let mut imported = Vec::new();
    let mut fidelity = FidelityCounts::default();
    let mut intentionally_omitted = 0;
    let mut saw_a_row = false;
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read that Keeper CSV. Export it again and try once more.".to_string()
        })?;
        if record.len() < 6 {
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
            let name = record.get(index).unwrap_or_default().trim().to_string();
            let value = record.get(index + 1).unwrap_or_default().trim().to_string();
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
            if let Some(field) = legacy_field(label, value, None) {
                fidelity.record(FieldDisposition::Legacy);
                legacy_fields.push(field);
            }
        }
        if let Some(record_type) = record_type {
            if !record_type.eq_ignore_ascii_case("login") {
                intentionally_omitted += 1;
                continue;
            }
        }
        if title.is_empty() && username.is_empty() && password.is_empty() {
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
        );
        entry.folder = normalise_folder(&folder);
        entry.legacy_fields = legacy_fields;
        imported.push(entry);
    }
    if !saw_a_row {
        return Err("That file does not look like a Keeper password export.".to_string());
    }
    Ok((imported, fidelity, intentionally_omitted))
}

/// No official schema; columns match by name, `custom_fields` with a one-time-code label becomes TOTP.
pub fn import_nordpass_csv_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts, usize)> {
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
    let mut intentionally_omitted = 0;
    for record in reader.records() {
        let record = record.map_err(|_| {
            "Sesame could not read a NordPass entry. Export it again and try once more.".to_string()
        })?;
        let title = record_value(&record, &headers, &["name"]);
        let item_type = record_value(&record, &headers, &["type"]).to_ascii_lowercase();
        let username = record_value(&record, &headers, &["username"]);
        let password = record_secret(&record, &headers, &["password"]);
        if title.is_empty() && item_type.is_empty() && username.is_empty() && password.is_empty() {
            // Empty-folder placeholder row.
            continue;
        }
        if !item_type.is_empty() && item_type != "password" {
            intentionally_omitted += 1;
            continue;
        }
        if title.is_empty() && username.is_empty() && password.is_empty() {
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
        );
        let folder = record_value(&record, &headers, &["folder"]);
        if !folder.is_empty() {
            entry.folder = normalise_folder(&folder);
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
                let url = normalise_url(&value);
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
                    entry.totp = non_empty(value);
                    fidelity.record(FieldDisposition::Imported);
                    continue;
                }
                if let Some(field) = legacy_field(label, value, None) {
                    fidelity.record(FieldDisposition::Legacy);
                    legacy_fields.push(field);
                }
            }
        } else if !custom_fields.is_empty() {
            fidelity.record(FieldDisposition::Malformed);
        }
        // Stray card/identity values on a password row stay Legacy, never dropped.
        let mut stray_columns = headers
            .iter()
            .filter(|(name, _)| !mapped_headers.contains(name.as_str()))
            .filter_map(|(name, index)| {
                record
                    .get(*index)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .and_then(|value| legacy_field(name, value.to_string(), None))
            })
            .collect::<Vec<_>>();
        stray_columns.sort_by(|left, right| left.label.cmp(&right.label));
        for _ in &stray_columns {
            fidelity.record(FieldDisposition::Legacy);
        }
        legacy_fields.append(&mut stray_columns);
        entry.legacy_fields = legacy_fields;
        imported.push(entry);
    }
    Ok((imported, fidelity, intentionally_omitted))
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
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
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
    for record in reader.records() {
        let record = record.map_err(|_| {
            format!("Sesame could not read a {product} entry. Export it again and try once more.")
        })?;
        let title = record_value(&record, &headers, title_names);
        let url = record_value(&record, &headers, url_names);
        let username = record_value(&record, &headers, username_names);
        let password = record_secret(&record, &headers, password_names);
        if title.is_empty() && username.is_empty() && password.is_empty() {
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
        );
        let raw_tags = record_value(&record, &headers, tag_names);
        entry.tags = normalise_tags(vec![raw_tags.clone()]);
        if !entry.tags.is_empty() {
            fidelity.record(FieldDisposition::Transformed);
        }
        let mut legacy_columns = headers
            .iter()
            .filter(|(name, _)| !mapped_headers.contains(name.as_str()))
            .filter_map(|(name, index)| {
                record
                    .get(*index)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .and_then(|value| legacy_field(name, value.to_string(), None))
            })
            .collect::<Vec<_>>();
        legacy_columns.sort_by(|left, right| left.label.cmp(&right.label));
        for _ in &legacy_columns {
            fidelity.record(FieldDisposition::Legacy);
        }
        entry.legacy_fields.append(&mut legacy_columns);
        imported.push(entry);
    }
    Ok((imported, fidelity))
}

/// A 2FA code has no password, so these entries carry a title and a secret only.
fn totp_entry(
    issuer: &str,
    account: &str,
    otpauth: String,
    fidelity: &mut FidelityCounts,
) -> Option<VaultEntry> {
    if totp_from_value(&otpauth).is_none() {
        fidelity.record(FieldDisposition::Malformed);
        return None;
    }
    // A link may carry no label at all. The secret is the valuable part and the
    // name can be edited, so name it rather than dropping it in silence.
    let title = match (issuer.trim(), account.trim()) {
        ("", "") => "Imported code".to_string(),
        ("", account) => account.to_string(),
        (issuer, _) => issuer.to_string(),
    };
    fidelity.record(FieldDisposition::Imported);
    Some(imported_entry(
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
    ))
}

/// Aegis, Ente Auth and KeePassXC all export a plain list of otpauth links.
pub fn import_otpauth_list_entries(
    content: &str,
) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
    let mut fidelity = FidelityCounts::default();
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with("otpauth://") {
            continue;
        }
        let (issuer, account) = otpauth_labels(line);
        if let Some(entry) = totp_entry(&issuer, &account, line.to_string(), &mut fidelity) {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return Err(
            "That file has no otpauth:// links in it. Export your codes again as plain text."
                .into(),
        );
    }
    Ok((entries, fidelity))
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
    url.push_str(&format!("&digits={digits}&period={period}&algorithm={algorithm}"));
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

pub fn import_aegis_json_entries(content: &str) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
    let export: AegisExport = serde_json::from_str(content).map_err(|_| {
        "Sesame could not read that Aegis export. Export it again as an unencrypted JSON file."
            .to_string()
    })?;
    let mut fidelity = FidelityCounts::default();
    let mut entries = Vec::new();
    for item in export.db.entries {
        // Aegis exports HOTP and Steam entries too, and Sesame stores time-based codes.
        if !item.entry_type.eq_ignore_ascii_case("totp") {
            fidelity.record(FieldDisposition::IntentionallyOmitted);
            continue;
        }
        let Some(algorithm) = normalised_algorithm(&item.info.algo) else {
            fidelity.record(FieldDisposition::Malformed);
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
        if let Some(entry) = totp_entry(&item.issuer, &item.name, url, &mut fidelity) {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return Err("That Aegis export has no time-based codes in it.".into());
    }
    Ok((entries, fidelity))
}

pub fn import_2fas_json_entries(content: &str) -> VaultResult<(Vec<VaultEntry>, FidelityCounts)> {
    let export: TwoFasExport = serde_json::from_str(content).map_err(|_| {
        "Sesame could not read that 2FAS export. Export it again without a password.".to_string()
    })?;
    if !export.services_encrypted.trim().is_empty() {
        return Err(
            "That 2FAS export is password protected. Export it again without a password.".into(),
        );
    }
    let mut fidelity = FidelityCounts::default();
    let mut entries = Vec::new();
    for service in export.services {
        let otp = service.otp.unwrap_or_default();
        if !otp.token_type.is_empty() && !otp.token_type.eq_ignore_ascii_case("totp") {
            fidelity.record(FieldDisposition::IntentionallyOmitted);
            continue;
        }
        let issuer = if otp.issuer.trim().is_empty() {
            service.name.clone()
        } else {
            otp.issuer.clone()
        };
        let Some(algorithm) = normalised_algorithm(&otp.algorithm) else {
            fidelity.record(FieldDisposition::Malformed);
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
        if let Some(entry) = totp_entry(&issuer, &otp.account, url, &mut fidelity) {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return Err("That 2FAS export has no time-based codes in it.".into());
    }
    Ok((entries, fidelity))
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
) -> VaultEntry {
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
    VaultEntry {
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
    }
}

fn legacy_field(label: &str, value: String, field_type: Option<u8>) -> Option<LegacyField> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 160 || value.chars().count() > 20_000 {
        return None;
    }
    Some(LegacyField {
        label: label.to_string(),
        value,
        // Unknown field types are concealed: an importer must not decide a value is safe to show.
        secret: field_type != Some(0),
    })
}

fn normalise_folder(value: &str) -> String {
    value.trim().chars().take(100).collect()
}

fn normalise_tags(values: Vec<String>) -> Vec<String> {
    let mut tags = Vec::new();
    for value in values {
        for tag in value.split([',', '\n', ';']) {
            let tag = tag.trim();
            if tag.is_empty() || tag.chars().count() > 100 || tags.iter().any(|saved| saved == tag)
            {
                continue;
            }
            tags.push(tag.to_string());
        }
    }
    tags
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

    let totp = non_empty(input.totp);
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
        let url = normalise_url(&raw_url);
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
        tags: normalise_tags(input.tags),
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
