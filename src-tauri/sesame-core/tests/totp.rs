use sesame_core::snapshot::totp_from_value;

// RFC 6238 test key "12345678901234567890" in base32.
const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn codes_match_the_rfc_6238_reference_vectors() {
    let Some(totp) = totp_from_value(RFC_KEY) else {
        panic!("the reference key was rejected");
    };
    assert_eq!(totp.generate(59), "287082");
    assert_eq!(totp.generate(1_111_111_109), "081804");
    assert_eq!(totp.generate(1_111_111_111), "050471");
    assert_eq!(totp.generate(1_234_567_890), "005924");
}

#[test]
fn a_secret_is_read_however_the_site_printed_it() {
    let spaced = totp_from_value("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ");
    let dashed = totp_from_value("GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ");
    let lower = totp_from_value("gezdgnbvgy3tqojqgezdgnbvgy3tqojq");
    for (name, parsed) in [("spaced", spaced), ("dashed", dashed), ("lowercase", lower)] {
        let Some(totp) = parsed else {
            panic!("{name} secret was rejected");
        };
        assert_eq!(totp.generate(59), "287082", "{name} produced a different code");
    }
}

#[test]
fn an_otpauth_url_is_accepted_and_agrees_with_the_bare_secret() {
    let url = format!("otpauth://totp/Example:person@example.test?secret={RFC_KEY}&issuer=Example");
    let Some(totp) = totp_from_value(&url) else {
        panic!("an otpauth URL was rejected");
    };
    assert_eq!(totp.generate(59), "287082");
}

#[test]
fn a_secret_too_short_to_be_a_real_one_is_refused() {
    assert!(totp_from_value("GEZDGNBV").is_none());
    assert!(totp_from_value("").is_none());
}

#[test]
fn something_that_is_not_a_secret_is_refused_rather_than_producing_a_code() {
    assert!(totp_from_value("not base32 at all!!").is_none());
    assert!(totp_from_value("https://example.test").is_none());
}

#[test]
fn surrounding_whitespace_does_not_stop_a_secret_being_read() {
    let Some(totp) = totp_from_value(&format!("  {RFC_KEY}  ")) else {
        panic!("a padded secret was rejected");
    };
    assert_eq!(totp.generate(59), "287082");
}
