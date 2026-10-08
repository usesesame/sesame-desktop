use sesame_core::imports::parse_import_entries;
use sesame_core::types::{ImportAccounting, ImportItemReason, VaultEntry};

const AEGIS: &str = include_str!("fixtures/imports/aegis-vault-1-db-3-mixed.json");
const TWOFAS: &str = include_str!("fixtures/imports/2fas-schema-4-mixed.json");
const OTPAUTH: &str = include_str!("fixtures/imports/otpauth-list-mixed.txt");

fn reason_count(accounting: &ImportAccounting, reason: ImportItemReason) -> usize {
    accounting
        .reasons
        .iter()
        .find(|known| known.reason == reason)
        .map_or(0, |known| known.count)
}

fn json_items(document: &str, path: &[&str]) -> usize {
    let mut value: &serde_json::Value = &serde_json::from_str(document).expect("fixture is JSON");
    for key in path {
        value = value.get(*key).expect("fixture has the key");
    }
    value.as_array().expect("fixture key holds a list").len()
}

fn stored_link(entry: &VaultEntry) -> &str {
    entry.totp.as_deref().expect("an accepted code has a link")
}

fn stored_secret(entry: &VaultEntry) -> String {
    stored_link(entry)
        .split_once('?')
        .expect("the stored link has a query")
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix("secret="))
        .expect("the stored link has a secret")
        .to_string()
}

fn entry_named<'a>(entries: &'a [VaultEntry], title: &str) -> &'a VaultEntry {
    entries
        .iter()
        .find(|entry| entry.title == title)
        .unwrap_or_else(|| panic!("no accepted code is titled {title}"))
}

fn assert_accounts_for_every_item(accounting: &ImportAccounting, supplied: usize) {
    assert_eq!(accounting.supplied, supplied);
    assert_eq!(
        accounting.accepted + accounting.retained + accounting.unsupported + accounting.malformed,
        supplied
    );
    assert!(accounting.is_balanced());
}

#[test]
fn a_mixed_aegis_export_accounts_for_every_item() {
    let supplied = json_items(AEGIS, &["db", "entries"]);
    let parsed = parse_import_entries(AEGIS, "aegis-json").expect("aegis import");
    let accounting = &parsed.accounting;
    assert_accounts_for_every_item(accounting, supplied);
    assert_eq!(accounting.accepted, 2);
    assert_eq!(accounting.retained, 0);
    assert_eq!(accounting.unsupported, 2);
    assert_eq!(accounting.malformed, 2);
    assert_eq!(
        reason_count(accounting, ImportItemReason::CounterBasedCode),
        1
    );
    assert_eq!(reason_count(accounting, ImportItemReason::SteamCode), 1);
    assert_eq!(
        reason_count(accounting, ImportItemReason::UnknownAlgorithm),
        1
    );
    assert_eq!(reason_count(accounting, ImportItemReason::UnusableCode), 1);
    assert_eq!(parsed.entries.len(), accounting.accepted);
    assert_eq!(parsed.intentionally_omitted_items, accounting.unsupported);
}

#[test]
fn aegis_accepted_codes_keep_their_names_and_raw_secrets() {
    let parsed = parse_import_entries(AEGIS, "aegis-json").expect("aegis import");
    let lithuanian = entry_named(&parsed.entries, "Žalias paštas");
    assert_eq!(lithuanian.username, "marta@žalias.test");
    assert_eq!(stored_secret(lithuanian), "KRSXG5CTMVRXEZLU");
    let japanese = entry_named(&parsed.entries, "例えバンク");
    assert_eq!(japanese.username, "雪@例え.test");
    assert_eq!(stored_secret(japanese), "MFRGGZDFMZTWQ2LK");
    assert!(stored_link(japanese).contains("algorithm=SHA256"));
    for omitted in ["Žemės bankas", "Steam", "Naïve Café", "Tuščias"] {
        assert!(
            parsed.entries.iter().all(|entry| entry.title != omitted),
            "{omitted} should not be saved"
        );
    }
}

#[test]
fn a_mixed_2fas_export_accounts_for_every_item() {
    let supplied = json_items(TWOFAS, &["services"]);
    let parsed = parse_import_entries(TWOFAS, "2fas-json").expect("2fas import");
    let accounting = &parsed.accounting;
    assert_accounts_for_every_item(accounting, supplied);
    assert_eq!(accounting.accepted, 2);
    assert_eq!(accounting.unsupported, 3);
    assert_eq!(accounting.malformed, 1);
    assert_eq!(
        reason_count(accounting, ImportItemReason::CounterBasedCode),
        1
    );
    assert_eq!(reason_count(accounting, ImportItemReason::SteamCode), 1);
    assert_eq!(
        reason_count(accounting, ImportItemReason::UnsupportedAlgorithm),
        1
    );
    assert_eq!(reason_count(accounting, ImportItemReason::UnusableCode), 1);
    assert_eq!(parsed.entries.len(), accounting.accepted);
    assert_eq!(parsed.intentionally_omitted_items, accounting.unsupported);
}

#[test]
fn twofas_accepted_codes_keep_their_names_and_raw_secrets() {
    let parsed = parse_import_entries(TWOFAS, "2fas-json").expect("2fas import");
    let lithuanian = entry_named(&parsed.entries, "Žalias paštas");
    assert_eq!(lithuanian.username, "marta@žalias.test");
    assert_eq!(stored_secret(lithuanian), "KRSXG5CTMVRXEZLU");
    let japanese = entry_named(&parsed.entries, "例えバンク");
    assert_eq!(stored_secret(japanese), "MFRGGZDFMZTWQ2LK");
    assert!(stored_link(japanese).contains("algorithm=SHA512"));
}

#[test]
fn a_mixed_otpauth_list_accounts_for_every_link() {
    let supplied = OTPAUTH
        .lines()
        .filter(|line| line.starts_with("otpauth"))
        .count();
    let parsed = parse_import_entries(OTPAUTH, "otpauth-txt").expect("otpauth import");
    let accounting = &parsed.accounting;
    assert_accounts_for_every_item(accounting, supplied);
    assert_eq!(accounting.accepted, 2);
    assert_eq!(accounting.unsupported, 3);
    assert_eq!(accounting.malformed, 1);
    assert_eq!(
        reason_count(accounting, ImportItemReason::CounterBasedCode),
        1
    );
    assert_eq!(reason_count(accounting, ImportItemReason::SteamCode), 1);
    assert_eq!(reason_count(accounting, ImportItemReason::TransferLink), 1);
    assert_eq!(reason_count(accounting, ImportItemReason::UnusableCode), 1);
    let lithuanian = entry_named(&parsed.entries, "Žalias paštas");
    assert_eq!(stored_secret(lithuanian), "KRSXG5CTMVRXEZLU");
    let japanese = entry_named(&parsed.entries, "例えバンク");
    assert_eq!(stored_secret(japanese), "MFRGGZDFMZTWQ2LK");
}

#[test]
fn omitted_codes_do_not_inflate_the_field_level_counts() {
    let parsed = parse_import_entries(AEGIS, "aegis-json").expect("aegis import");
    assert_eq!(parsed.fidelity.logins.intentionally_omitted, 0);
    assert_eq!(parsed.fidelity.logins.malformed, 0);
    assert_eq!(parsed.fidelity.unsupported_items.intentionally_omitted, 2);
}

#[test]
fn an_export_of_only_usable_codes_has_nothing_omitted() {
    let export = r#"{ "db": { "entries": [
        { "type": "totp", "name": "me", "issuer": "Plain",
          "info": { "secret": "KRSXG5CTMVRXEZLU", "algo": "SHA1" } } ] } }"#;
    let parsed = parse_import_entries(export, "aegis-json").expect("aegis import");
    assert_accounts_for_every_item(&parsed.accounting, 1);
    assert_eq!(parsed.accounting.accepted, 1);
    assert_eq!(parsed.accounting.omitted(), 0);
    assert!(parsed.accounting.reasons.is_empty());
}

#[test]
fn a_login_export_reports_unsupported_items_and_extra_fields_as_item_counts() {
    let export = r#"{
      "items": [
        { "type": 1, "name": "Plain", "notes": "",
          "login": { "username": "person", "password": "secret", "uris": [ { "uri": "https://plain.test" } ] } },
        { "type": 1, "name": "Extra", "notes": "",
          "fields": [ { "name": "pet", "value": "cat", "type": 0 } ],
          "login": { "username": "person", "password": "secret", "uris": [ { "uri": "https://extra.test" } ] } },
        { "type": 9, "name": "Future kind", "notes": "" }
      ]
    }"#;
    let parsed = parse_import_entries(export, "bitwarden-json").expect("Bitwarden import");
    let accounting = &parsed.accounting;
    assert_accounts_for_every_item(accounting, 3);
    assert_eq!(accounting.accepted, 1);
    assert_eq!(accounting.retained, 1);
    assert_eq!(accounting.unsupported, 1);
    assert_eq!(
        reason_count(accounting, ImportItemReason::UnsupportedItemType),
        1
    );
}

#[test]
fn bitwarden_csv_keeps_several_addresses_from_one_cell() {
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
Work,1,login,Example,,pet: cat,0,\"https://one.test\nhttps://two.test\r\nhttps://one.test\",person,secret,\n";
    let parsed = parse_import_entries(csv, "bitwarden-csv").expect("Bitwarden CSV import");
    let entry = &parsed.entries[0];
    assert_eq!(entry.url, "https://one.test");
    assert_eq!(entry.urls, ["https://one.test", "https://two.test"]);
    assert!(entry.legacy_fields.is_empty());
    assert!(!entry.favourite);
}

#[test]
fn bitwarden_csv_with_one_address_sets_no_secondary_list() {
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
Work,0,login,Example,,,0,https://one.test,person,secret,\n";
    let parsed = parse_import_entries(csv, "bitwarden-csv").expect("Bitwarden CSV import");
    assert_eq!(parsed.entries[0].url, "https://one.test");
    assert!(parsed.entries[0].urls.is_empty());
}

#[test]
fn bitwarden_json_keeps_custom_fields_and_secondary_addresses() {
    let export = r#"{ "items": [
        { "type": 1, "name": "Example", "notes": "", "favorite": true,
          "fields": [ { "name": "pet", "value": "cat", "type": 0 } ],
          "login": { "username": "person", "password": "secret",
            "uris": [ { "uri": "https://one.test" }, { "uri": "https://two.test" } ] } } ] }"#;
    let parsed = parse_import_entries(export, "bitwarden-json").expect("Bitwarden JSON import");
    let entry = &parsed.entries[0];
    assert_eq!(entry.legacy_fields.len(), 1);
    assert_eq!(entry.urls.len(), 2);
    assert!(!entry.favourite);
}

const GOOD_AND_CREDENTIALLESS: [(&str, &str); 10] = [
    (
        "bitwarden-csv",
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,0,login,Žalias paštas,,,0,https://one.test,person,secret,\n,0,login,,only a note,,0,https://two.test,,,\n,,,,,,,,,,\n",
    ),
    (
        "lastpass-csv",
        "url,username,password,extra,name,grouping\nhttps://one.test,person,secret,,Žalias paštas,\nhttps://two.test,,,only a note,,\n",
    ),
    (
        "dashlane-csv",
        "title,url,username,password,note\nŽalias paštas,https://one.test,person,secret,\n,https://two.test,,,only a note\n",
    ),
    (
        "onepassword-csv",
        "Title,Website,Username,Password,OTPAuth,Notes\nŽalias paštas,https://one.test,person,secret,,\n,https://two.test,,,,only a note\n",
    ),
    (
        "keepass-csv",
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\"Root\",\"Žalias paštas\",\"person\",\"secret\",\"https://one.test\",\"\"\n\"Root\",\"\",\"\",\"\",\"https://two.test\",\"only a note\"\n",
    ),
    (
        "chrome-csv",
        "name,url,username,password,note\nŽalias paštas,https://one.test,person,secret,\n,https://two.test,,,only a note\n",
    ),
    (
        "firefox-csv",
        "url,username,password,httpRealm\nhttps://one.test,person,secret,\nhttps://two.test,,,Realm\n",
    ),
    (
        "proton-pass-csv",
        "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\nlogin,Žalias paštas,https://one.test,,person,secret,,,,,Personal\nlogin,,https://two.test,,,,only a note,,,,Personal\n",
    ),
    (
        "keeper-csv",
        "Root,Žalias paštas,person,secret,https://one.test,,\nRoot,,,,https://two.test,only a note,\n",
    ),
    (
        "nordpass-csv",
        "name,url,additional_urls,username,password,note,folder,type,custom_fields\nŽalias paštas,https://one.test,,person,secret,,,password,\n,https://two.test,,,,only a note,,password,\n",
    ),
];

#[test]
fn every_login_source_accounts_for_a_row_with_no_credentials() {
    for (source, csv) in GOOD_AND_CREDENTIALLESS {
        let parsed =
            parse_import_entries(csv, source).unwrap_or_else(|error| panic!("{source}: {error}"));
        let accounting = &parsed.accounting;
        assert_accounts_for_every_item(accounting, 2);
        assert_eq!(accounting.accepted + accounting.retained, 1, "{source}");
        assert_eq!(accounting.malformed, 1, "{source}");
        assert_eq!(
            reason_count(accounting, ImportItemReason::MissingCredentials),
            1,
            "{source}"
        );
        assert_eq!(parsed.entries.len(), 1, "{source}");
        assert_eq!(parsed.entries[0].password, "secret", "{source}");
    }
}

#[test]
fn an_apple_passwords_row_with_no_credentials_is_accounted_for() {
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\nŽalias paštas,https://one.test,person,secret,,\n,https://two.test,,,only a note,\n";
    let parsed = parse_import_entries(csv, "apple-csv").expect("Apple Passwords import");
    assert_accounts_for_every_item(&parsed.accounting, 2);
    assert_eq!(
        reason_count(&parsed.accounting, ImportItemReason::MissingCredentials),
        1
    );
}

#[test]
fn a_short_keeper_row_with_content_is_accounted_for_as_unreadable() {
    let csv = "Root,Žalias paštas,person,secret,https://one.test,,\nstray,text\n";
    let parsed = parse_import_entries(csv, "keeper-csv").expect("Keeper import");
    assert_accounts_for_every_item(&parsed.accounting, 2);
    assert_eq!(
        reason_count(&parsed.accounting, ImportItemReason::UnreadableRow),
        1
    );
}

#[test]
fn a_nordpass_folder_placeholder_is_not_counted_as_an_item() {
    let csv = "name,url,additional_urls,username,password,note,folder,type,custom_fields\nŽalias paštas,https://one.test,,person,secret,,,password,\n,,,,,,Empty folder,,\n";
    let parsed = parse_import_entries(csv, "nordpass-csv").expect("NordPass import");
    assert_accounts_for_every_item(&parsed.accounting, 1);
}

#[test]
fn bitwarden_json_accounts_for_logins_it_cannot_read() {
    let export = r#"{ "items": [
        { "type": 1, "name": "Žalias paštas", "notes": "",
          "login": { "username": "person", "password": "secret", "uris": [ { "uri": "https://one.test" } ] } },
        { "type": 1, "name": "No login object", "notes": "" },
        { "type": 1, "name": "", "notes": "only a note",
          "login": { "username": "", "password": "", "uris": [ { "uri": "https://two.test" } ] } }
    ] }"#;
    let parsed = parse_import_entries(export, "bitwarden-json").expect("Bitwarden JSON import");
    assert_accounts_for_every_item(&parsed.accounting, 3);
    assert_eq!(parsed.accounting.accepted, 1);
    assert_eq!(parsed.accounting.malformed, 2);
    assert_eq!(
        reason_count(&parsed.accounting, ImportItemReason::UnreadableRow),
        1
    );
    assert_eq!(
        reason_count(&parsed.accounting, ImportItemReason::MissingCredentials),
        1
    );
}
