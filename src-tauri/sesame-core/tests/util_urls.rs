use sesame_core::util::{domain_from_url, normalise_url};

#[test]
fn a_password_embedded_in_a_url_is_never_shown_as_the_site() {
    assert_eq!(
        domain_from_url("https://user:hunter2@example.test/login"),
        "example.test"
    );
    assert_eq!(
        domain_from_url("https://token@example.test"),
        "example.test"
    );
}

#[test]
fn a_query_string_is_not_part_of_the_site_label() {
    assert_eq!(
        domain_from_url("https://example.test?token=abc123"),
        "example.test"
    );
    assert_eq!(
        domain_from_url("https://example.test/path?a=b#c"),
        "example.test"
    );
}

#[test]
fn one_site_gets_one_label_whatever_case_it_was_saved_in() {
    assert_eq!(
        domain_from_url("https://WWW.Example.TEST/x"),
        "example.test"
    );
    assert_eq!(domain_from_url("https://www.example.test"), "example.test");
    assert_eq!(domain_from_url("example.test"), "example.test");
}

#[test]
fn a_port_stays_because_it_identifies_a_different_service() {
    assert_eq!(
        domain_from_url("https://example.test:8443/path"),
        "example.test:8443"
    );
}

#[test]
fn a_url_with_no_host_reads_as_nothing_saved() {
    assert_eq!(domain_from_url(""), "No website saved");
    assert_eq!(domain_from_url("   "), "No website saved");
    assert_eq!(domain_from_url("https://"), "No website saved");
}

#[test]
fn normalising_assumes_https_only_when_no_scheme_was_given() {
    assert_eq!(normalise_url("example.test"), "https://example.test");
    assert_eq!(normalise_url("http://example.test"), "http://example.test");
    assert_eq!(
        normalise_url("https://example.test"),
        "https://example.test"
    );
    assert_eq!(normalise_url("  "), "");
}
