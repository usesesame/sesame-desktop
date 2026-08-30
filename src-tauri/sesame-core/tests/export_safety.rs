use sesame_core::backup::csv_export_bytes;
use sesame_core::types::{VaultEntry, VaultPayload};

fn export_with(entry: VaultEntry) -> String {
    let payload = VaultPayload {
        entries: vec![entry],
        ..VaultPayload::default()
    };
    String::from_utf8(csv_export_bytes(&payload).expect("export")).expect("utf8")
}

#[test]
fn a_field_that_a_spreadsheet_would_run_as_a_formula_is_neutralised() {
    for dangerous in ["=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(A1)"] {
        let csv = export_with(VaultEntry {
            title: dangerous.to_string(),
            ..VaultEntry::default()
        });
        let cell = csv.lines().nth(1).expect("a data row");
        assert!(
            !cell.contains(&format!(",{dangerous}")) || cell.contains(&format!("'{dangerous}")),
            "{dangerous} was exported so a spreadsheet would evaluate it:\n{csv}"
        );
        assert!(csv.contains('\''), "{dangerous} was not prefixed:\n{csv}");
    }
}

#[test]
fn the_guard_covers_the_password_column_too_not_only_the_name() {
    let csv = export_with(VaultEntry {
        title: "Example".into(),
        password: "=1+1".into(),
        ..VaultEntry::default()
    });
    assert!(
        csv.contains("'=1+1"),
        "password was exported unguarded:\n{csv}"
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

#[test]
fn a_leading_control_character_is_neutralised_as_well() {
    let csv = export_with(VaultEntry {
        title: "\tExample".into(),
        ..VaultEntry::default()
    });
    assert!(csv.contains('\''), "tab-led value was not prefixed:\n{csv}");
}
