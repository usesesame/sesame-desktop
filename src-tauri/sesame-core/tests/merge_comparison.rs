use sesame_core::snapshot::merge_comparison_for;
use sesame_core::types::{MergeComparison, VaultEntry};

const SECRETS: [&str; 8] = [
    "fictional-bank-password",
    "fictional-mail-password",
    "FICTIONALSEEDBANK2222",
    "FICTIONALSEEDMAIL3333",
    "fictional bank note about the safe",
    "fictional mail note about the shed",
    "fictional-backup-code-bank",
    "fictional-backup-code-mail",
];

fn login(id: &str, password: &str, totp: &str, notes: &str, backup_code: &str) -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = id.into();
    entry.title = format!("Fictional {id}");
    entry.url = "https://northwind.example".into();
    entry.username = "fictional-user".into();
    entry.password = password.into();
    entry.totp = (!totp.is_empty()).then(|| totp.to_string());
    entry.notes = (!notes.is_empty()).then(|| notes.to_string());
    entry.backup_codes = if backup_code.is_empty() {
        Vec::new()
    } else {
        vec![backup_code.to_string()]
    };
    entry
}

fn differing_pair() -> (VaultEntry, VaultEntry) {
    (
        login("bank", SECRETS[0], SECRETS[2], SECRETS[4], SECRETS[6]),
        login("mail", SECRETS[1], SECRETS[3], SECRETS[5], SECRETS[7]),
    )
}

fn field<'a>(comparison: &'a MergeComparison, name: &str) -> &'a sesame_core::types::MergeField {
    comparison
        .fields
        .iter()
        .find(|field| field.field == name)
        .expect("compared field")
}

#[test]
fn the_serialized_comparison_holds_no_secret_value() {
    let (bank, mail) = differing_pair();
    let comparison = merge_comparison_for(&[&bank, &mail]);

    let json = serde_json::to_string(&comparison).expect("serialized comparison");

    for secret in SECRETS {
        assert!(!json.contains(secret), "the comparison leaked {secret}");
    }
}

#[test]
fn secret_fields_keep_their_present_and_differs_flags() {
    let (bank, mail) = differing_pair();
    let comparison = merge_comparison_for(&[&bank, &mail]);

    for name in ["password", "totp", "notes", "backupCodes"] {
        let compared = field(&comparison, name);
        assert!(compared.secret, "{name} is secret");
        assert!(compared.differs, "{name} differs");
        assert!(compared.options.iter().all(|option| option.present));
    }
}

#[test]
fn an_empty_secret_is_absent_and_still_differs_from_a_saved_one() {
    let (bank, _) = differing_pair();
    let bare = login("bare", "", "", "", "");
    let comparison = merge_comparison_for(&[&bank, &bare]);

    for name in ["password", "totp", "notes", "backupCodes"] {
        let compared = field(&comparison, name);
        assert!(compared.differs, "{name} differs");
        assert!(compared.options[0].present);
        assert!(!compared.options[1].present);
    }
}

#[test]
fn equal_secrets_do_not_differ() {
    let first = login("one", SECRETS[0], SECRETS[2], SECRETS[4], SECRETS[6]);
    let second = login("two", SECRETS[0], SECRETS[2], SECRETS[4], SECRETS[6]);
    let comparison = merge_comparison_for(&[&first, &second]);

    for name in ["password", "totp", "notes", "backupCodes"] {
        assert!(!field(&comparison, name).differs, "{name} agrees");
    }
    let json = serde_json::to_string(&comparison).expect("serialized comparison");
    for secret in SECRETS {
        assert!(!json.contains(secret));
    }
}

#[test]
fn plain_fields_still_carry_their_values() {
    let (bank, mail) = differing_pair();
    let comparison = merge_comparison_for(&[&bank, &mail]);

    let json = serde_json::to_value(&comparison).expect("serialized comparison");
    let plain_values = |name: &str| -> Vec<String> {
        json["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .find(|compared| compared["field"] == name)
            .expect("compared field")["options"]
            .as_array()
            .expect("options")
            .iter()
            .map(|option| option["value"].as_str().expect("plain value").to_string())
            .collect()
    };
    assert!(!field(&comparison, "title").secret);
    assert!(field(&comparison, "title").differs);
    assert_eq!(plain_values("title"), ["Fictional bank", "Fictional mail"]);
    assert_eq!(
        plain_values("username"),
        ["fictional-user", "fictional-user"]
    );
}

#[test]
fn only_plain_options_carry_a_value_key_in_the_json() {
    let (bank, mail) = differing_pair();
    let comparison = merge_comparison_for(&[&bank, &mail]);

    let json = serde_json::to_value(&comparison).expect("serialized comparison");
    for compared in json["fields"].as_array().expect("fields") {
        let secret = compared["secret"].as_bool().expect("secret flag");
        for option in compared["options"].as_array().expect("options") {
            assert_eq!(option.get("value").is_some(), !secret);
        }
    }
}
