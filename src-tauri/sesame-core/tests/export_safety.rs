use sesame_core::backup::{csv_export_bytes, identities_csv_bytes};
use sesame_core::types::{Identity, VaultEntry, VaultPayload};
use sesame_core::util::split_backup_codes;

fn export_with(entry: VaultEntry) -> String {
    let mut payload = VaultPayload::default();
    payload.entries = vec![entry];
    String::from_utf8(csv_export_bytes(&payload).expect("export")).expect("utf8")
}

fn reimport(csv: &str) -> VaultEntry {
    let mut reader = csv::Reader::from_reader(csv.as_bytes());
    let headers = reader.headers().expect("headers").clone();
    let record = reader
        .records()
        .next()
        .expect("a data row")
        .expect("a record");
    let value = |name: &str| {
        headers
            .iter()
            .position(|header| header == name)
            .and_then(|index| record.get(index))
            .unwrap_or_default()
            .to_string()
    };
    let joined_backup_codes = value("backup_codes");
    let mut entry = VaultEntry::default();
    entry.title = value("name");
    entry.url = value("url");
    entry.username = value("username");
    entry.email = value("email");
    entry.password = value("password");
    entry.totp = Some(value("totp"));
    entry.backup_codes = split_backup_codes(&joined_backup_codes);
    entry.recovery_email = Some(value("recovery_email"));
    entry.recovery_phone = Some(value("recovery_phone"));
    entry.notes = Some(value("notes"));
    entry
}

#[test]
fn a_password_that_looks_like_a_formula_survives_export_and_reimport() {
    let password = "=cmd|'/c calc'!A1";
    let mut entry = VaultEntry::default();
    entry.title = "Example".into();
    entry.password = password.into();
    let csv = export_with(entry);

    assert!(
        csv.contains(password),
        "the password was rewritten during export:\n{csv}"
    );
    assert_eq!(reimport(&csv).password, password);
}

#[test]
fn a_totp_seed_and_a_backup_code_survive_export_and_reimport() {
    let totp = "=JBSWY3DPEHPK3PXP";
    let backup_code = "=1234-5678";
    let mut entry = VaultEntry::default();
    entry.title = "Example".into();
    entry.totp = Some(totp.into());
    entry.backup_codes = vec![backup_code.into()];
    let csv = export_with(entry);

    let reimported = reimport(&csv);
    assert_eq!(reimported.totp.as_deref(), Some(totp));
    assert_eq!(reimported.backup_codes, vec![backup_code.to_string()]);
}

#[test]
fn a_leading_control_character_survives_export_and_reimport() {
    let title = "\tExample".to_string();
    let mut entry = VaultEntry::default();
    entry.title = title.clone();
    let csv = export_with(entry);

    assert!(csv.contains(&title), "the title was rewritten:\n{csv}");
    assert_eq!(reimport(&csv).title, title);
}

#[test]
fn an_identity_that_looks_like_a_formula_is_exported_unchanged() {
    let full_name = "=cmd|'/c calc'!A1".to_string();
    let mut identity = Identity::default();
    identity.full_name = full_name.clone();
    let mut payload = VaultPayload::default();
    payload.identities = vec![identity];
    let csv = String::from_utf8(identities_csv_bytes(&payload).expect("export")).expect("utf8");

    assert!(
        csv.contains(&full_name),
        "the identity was rewritten:\n{csv}"
    );
}

#[test]
fn an_ordinary_value_is_exported_unchanged() {
    let mut entry = VaultEntry::default();
    entry.title = "Example".into();
    entry.username = "person@example.test".into();
    entry.password = "ordinary-secret".into();
    let csv = export_with(entry);
    assert!(csv.contains("ordinary-secret"), "{csv}");
    assert!(!csv.contains("'ordinary-secret"), "{csv}");
}

#[cfg(unix)]
#[test]
fn an_exported_file_is_private_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let directory =
        std::env::temp_dir().join(format!("sesame-export-{}", sesame_core::util::random_id()));
    std::fs::create_dir_all(&directory).expect("test directory");
    let path = directory.join("export.csv");
    let mut entry = VaultEntry::default();
    entry.title = "Example".into();
    entry.password = "ordinary-secret".into();
    let csv = export_with(entry);

    sesame_core::storage::write_export_file(&path, csv.as_bytes()).expect("export written");
    let mode = || {
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(), 0o600);

    sesame_core::storage::write_export_file(&path, csv.as_bytes()).expect("export replaced");
    assert_eq!(mode(), 0o600);

    std::fs::remove_dir_all(&directory).expect("removed test directory");
}
