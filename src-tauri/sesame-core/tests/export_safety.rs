use sesame_core::backup::{csv_export_bytes, identities_csv_bytes};
use sesame_core::types::{Identity, VaultEntry, VaultPayload};
use sesame_core::util::split_backup_codes;

fn export_with(entry: VaultEntry) -> String {
    let payload = VaultPayload {
        entries: vec![entry],
        ..VaultPayload::default()
    };
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
    VaultEntry {
        title: value("name"),
        url: value("url"),
        username: value("username"),
        email: value("email"),
        password: value("password"),
        totp: Some(value("totp")),
        backup_codes: split_backup_codes(&joined_backup_codes),
        recovery_email: Some(value("recovery_email")),
        recovery_phone: Some(value("recovery_phone")),
        notes: Some(value("notes")),
        ..VaultEntry::default()
    }
}

#[test]
fn a_password_that_looks_like_a_formula_survives_export_and_reimport() {
    let password = "=cmd|'/c calc'!A1";
    let csv = export_with(VaultEntry {
        title: "Example".into(),
        password: password.into(),
        ..VaultEntry::default()
    });

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
    let csv = export_with(VaultEntry {
        title: "Example".into(),
        totp: Some(totp.into()),
        backup_codes: vec![backup_code.into()],
        ..VaultEntry::default()
    });

    let reimported = reimport(&csv);
    assert_eq!(reimported.totp.as_deref(), Some(totp));
    assert_eq!(reimported.backup_codes, vec![backup_code.to_string()]);
}

#[test]
fn a_leading_control_character_survives_export_and_reimport() {
    let title = "\tExample".to_string();
    let csv = export_with(VaultEntry {
        title: title.clone(),
        ..VaultEntry::default()
    });

    assert!(csv.contains(&title), "the title was rewritten:\n{csv}");
    assert_eq!(reimport(&csv).title, title);
}

#[test]
fn an_identity_that_looks_like_a_formula_is_exported_unchanged() {
    let full_name = "=cmd|'/c calc'!A1".to_string();
    let payload = VaultPayload {
        identities: vec![Identity {
            full_name: full_name.clone(),
            ..Identity::default()
        }],
        ..VaultPayload::default()
    };
    let csv = String::from_utf8(identities_csv_bytes(&payload).expect("export")).expect("utf8");

    assert!(
        csv.contains(&full_name),
        "the identity was rewritten:\n{csv}"
    );
}

#[test]
fn an_ordinary_value_is_exported_unchanged() {
    let csv = export_with(VaultEntry {
        title: "Example".into(),
        username: "person@example.test".into(),
        password: "ordinary-secret".into(),
        ..VaultEntry::default()
    });
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
    let csv = export_with(VaultEntry {
        title: "Example".into(),
        password: "ordinary-secret".into(),
        ..VaultEntry::default()
    });

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
