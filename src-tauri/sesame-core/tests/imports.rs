use sesame_core::imports::{
    import_browser_csv_entries, import_firefox_csv_entries, import_keepass_csv_entries,
    parse_import_entries,
};

fn chrome(csv: &str) -> Vec<sesame_core::types::VaultEntry> {
    import_browser_csv_entries(csv, "Chrome").expect("Chrome import").0
}

#[test]
fn a_password_keeps_the_whitespace_it_was_exported_with() {
    let entries = chrome(
        "name,url,username,password\nExample,https://example.test,person,\"  spaced  \"\n",
    );
    assert_eq!(entries[0].password, "  spaced  ");
}

#[test]
fn a_password_keeps_an_interior_comma_and_quote() {
    let entries = chrome(
        "name,url,username,password\nExample,https://example.test,person,\"a,b\"\"c\"\n",
    );
    assert_eq!(entries[0].password, "a,b\"c");
}

#[test]
fn a_password_keeps_an_embedded_newline() {
    let entries = chrome(
        "name,url,username,password\nExample,https://example.test,person,\"line1\nline2\"\n",
    );
    assert_eq!(entries[0].password, "line1\nline2");
}

#[test]
fn surrounding_whitespace_is_still_cleaned_off_the_fields_that_are_not_secret() {
    let entries = chrome(
        "name,url,username,password\n\"  Example  \",https://example.test,\"  person  \",secret\n",
    );
    assert_eq!(entries[0].title, "Example");
    assert_eq!(entries[0].username, "person");
}

#[test]
fn a_row_with_nothing_in_it_is_skipped_rather_than_imported_empty() {
    let entries = chrome("name,url,username,password\n,https://example.test,,\nReal,https://real.test,person,secret\n");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title, "Real");
}

#[test]
fn a_file_without_the_expected_columns_is_refused_with_a_readable_message() {
    let Err(error) = import_browser_csv_entries("colour,size\nred,large\n", "Chrome") else {
        panic!("a shopping list is not a password export");
    };
    assert!(error.to_string().contains("Chrome"), "{error}");
}

#[test]
fn headers_are_matched_regardless_of_case_and_spacing() {
    let entries = chrome("Name, URL , Username ,Password\nExample,https://example.test,person,secret\n");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].password, "secret");
}

#[test]
fn firefox_and_keepass_exports_are_read_by_their_own_column_names() {
    let firefox = import_firefox_csv_entries(
        "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nhttps://example.test,person,secret,,,,,,\n",
    )
    .expect("Firefox import")
    .0;
    assert_eq!(firefox[0].password, "secret");

    let keepass = import_keepass_csv_entries(
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\"Root\",\"Example\",\"person\",\"  secret  \",\"https://example.test\",\"\"\n",
    )
    .expect("KeePass import")
    .0;
    assert_eq!(keepass[0].password, "  secret  ");
}

#[test]
fn an_unreasonably_large_file_is_refused_before_it_is_parsed() {
    let huge = format!("name,url,username,password\n{}", "x".repeat(26 * 1024 * 1024));
    let Err(error) = parse_import_entries(&huge, "chrome-csv") else {
        panic!("a file past the ceiling must be refused");
    };
    assert!(error.to_string().contains("too large"), "{error}");
}

#[test]
fn an_unknown_source_is_refused_rather_than_guessed_at() {
    assert!(parse_import_entries("name,url,username,password\n", "not-a-real-manager").is_err());
}

const BITWARDEN_SSH_AND_PASSKEY: &str = r#"{
  "folders": [],
  "items": [
    {
      "type": 5,
      "name": "Deploy key",
      "notes": "build server",
      "sshKey": {
        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
        "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@build",
        "keyFingerprint": "SHA256:zzz"
      }
    },
    {
      "type": 1,
      "name": "Example",
      "login": {
        "username": "person",
        "password": "secret",
        "uris": [{ "uri": "https://example.test" }],
        "fido2Credentials": [
          { "credentialId": "one", "rpId": "example.test" },
          { "credentialId": "two", "rpId": "example.test" }
        ]
      }
    }
  ]
}"#;

#[test]
fn a_bitwarden_ssh_key_becomes_an_ssh_key_item() {
    let parsed = parse_import_entries(BITWARDEN_SSH_AND_PASSKEY, "bitwarden-json")
        .expect("Bitwarden JSON import");
    assert_eq!(parsed.ssh_keys.len(), 1);
    let key = &parsed.ssh_keys[0];
    assert_eq!(key.title, "Deploy key");
    assert_eq!(key.key_type, "ssh-ed25519");
    assert!(key.private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert_eq!(key.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@build");
    assert_eq!(key.notes, "build server");
}

#[test]
fn a_bitwarden_ssh_key_is_no_longer_counted_as_unsupported() {
    let parsed = parse_import_entries(BITWARDEN_SSH_AND_PASSKEY, "bitwarden-json")
        .expect("Bitwarden JSON import");
    assert_eq!(parsed.intentionally_omitted_items, 0);
    assert_eq!(parsed.fidelity.unsupported_items.intentionally_omitted, 0);
}

#[test]
fn bitwarden_passkeys_are_reported_rather_than_dropped_in_silence() {
    let parsed = parse_import_entries(BITWARDEN_SSH_AND_PASSKEY, "bitwarden-json")
        .expect("Bitwarden JSON import");
    assert_eq!(parsed.passkeys_not_imported, 2);
    assert_eq!(parsed.fidelity.passkeys.intentionally_omitted, 2);
    // The login carrying them still imports normally.
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].password, "secret");
}

const OTPAUTH_LIST: &str = "\
otpauth://totp/GitHub:me%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30
# a comment line that is not a link
otpauth://totp/Fastmail?secret=JBSWY3DPEHPK3PXP&digits=8&period=60
";

#[test]
fn an_otpauth_list_becomes_code_only_entries() {
    let parsed = parse_import_entries(OTPAUTH_LIST, "otpauth-txt").expect("otpauth import");
    assert_eq!(parsed.entries.len(), 2);
    let github = &parsed.entries[0];
    assert_eq!(github.title, "GitHub");
    assert_eq!(github.username, "me@example.test");
    // A code has no password to save, which is the whole point of the format.
    assert!(github.password.is_empty());
    assert!(github.totp.is_some());
    assert_eq!(parsed.entries[1].title, "Fastmail");
}

#[test]
fn a_file_with_no_links_is_refused_with_a_readable_message() {
    let error = parse_import_entries("nothing to see here\n", "otpauth-txt").err().expect("should be refused");
    assert!(error.contains("otpauth://"), "unexpected message: {error}");
}

const AEGIS_JSON: &str = r#"{
  "db": { "entries": [
    { "type": "totp", "name": "me@example.test", "issuer": "GitHub",
      "info": { "secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30 } },
    { "type": "hotp", "name": "counter", "issuer": "Legacy",
      "info": { "secret": "JBSWY3DPEHPK3PXP" } }
  ] }
}"#;

#[test]
fn aegis_time_based_codes_import_and_counter_based_ones_are_counted() {
    let parsed = parse_import_entries(AEGIS_JSON, "aegis-json").expect("aegis import");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].title, "GitHub");
    assert_eq!(parsed.entries[0].username, "me@example.test");
    assert_eq!(parsed.fidelity.logins.intentionally_omitted, 1);
}

const TWOFAS_JSON: &str = r#"{
  "services": [
    { "name": "GitHub", "secret": "JBSWY3DPEHPK3PXP",
      "otp": { "account": "me@example.test", "issuer": "GitHub", "digits": 6, "period": 30, "tokenType": "TOTP" } },
    { "name": "NoOtpBlock", "secret": "JBSWY3DPEHPK3PXP" }
  ]
}"#;

#[test]
fn twofas_services_import_with_and_without_an_otp_block() {
    let parsed = parse_import_entries(TWOFAS_JSON, "2fas-json").expect("2fas import");
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].title, "GitHub");
    assert_eq!(parsed.entries[1].title, "NoOtpBlock");
}

#[test]
fn a_malformed_secret_is_counted_rather_than_saved_as_a_broken_code() {
    let broken = r#"{ "services": [ { "name": "Bad", "secret": "!!!!", "otp": { "account": "x" } } ] }"#;
    let error = parse_import_entries(broken, "2fas-json").err().expect("should be refused");
    assert!(error.contains("no time-based codes"), "unexpected: {error}");
}
