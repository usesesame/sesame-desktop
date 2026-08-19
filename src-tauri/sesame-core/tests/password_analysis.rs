use sesame_core::password_analysis::analyse_password_value;

#[test]
fn a_long_varied_password_scores_at_the_top_with_nothing_to_report() {
    let analysis = analyse_password_value("Tr0ub4dor&3-Xanthic-Quilt");
    assert_eq!(analysis.score, 4);
    assert!(analysis.issues.is_empty(), "unexpected issues");
}

#[test]
fn an_empty_password_scores_nothing() {
    assert_eq!(analyse_password_value("").score, 0);
}

#[test]
fn a_short_password_is_reported_as_weak() {
    let analysis = analyse_password_value("abc123");
    assert!(analysis.score < 3);
    assert!(analysis.has("weak-password"));
}

#[test]
fn a_password_from_the_common_list_is_named_as_such_whatever_its_case() {
    for value in ["password", "PASSWORD", "  Password  "] {
        let analysis = analyse_password_value(value);
        assert!(analysis.has("common-password"), "{value} was not recognised");
        assert!(analysis.score <= 1, "{value} scored {}", analysis.score);
    }
}

#[test]
fn a_keyboard_run_is_reported_as_a_pattern_attackers_try() {
    assert!(analyse_password_value("myqwertyphrase").has("compromised-pattern"));
    assert!(analyse_password_value("aaaa-filler-text").has("compromised-pattern"));
}

#[test]
fn length_alone_does_not_earn_a_top_score_without_variety() {
    let analysis = analyse_password_value("aaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(analysis.score < 4, "scored {}", analysis.score);
}

#[test]
fn a_passphrase_of_ordinary_words_is_still_credited_for_length() {
    let analysis = analyse_password_value("correct horse battery staple");
    assert!(analysis.score >= 3, "scored {}", analysis.score);
}
