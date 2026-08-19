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
