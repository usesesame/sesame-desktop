use sesame_core::api::create_vault;
use sesame_core::check_new_master_password;

#[test]
fn a_long_or_varied_master_password_is_accepted() {
    for accepted in [
        "fictional master password",
        "correct-horse-battery-staple",
        "Fictional-Vault-Key-2026!",
        "glimmer orbit lantern cobalt",
    ] {
        assert!(
            check_new_master_password(accepted).is_ok(),
            "{accepted} was refused"
        );
    }
}

#[test]
fn a_short_master_password_names_the_minimum() {
    let error = check_new_master_password("Fict1onal!").expect_err("short password");
    assert!(error.contains("at least 12 characters"), "{error}");
}

#[test]
fn a_guessable_master_password_is_refused_even_when_long_enough() {
    for refused in [
        "abcdefghijkl",
        "fictionalpwd",
        "Abcdefgh123!",
        "qwertyuiop12",
        "aaaabbbbcccc",
        "passwordpassword",
        "Fict1onal!Fict1onal!",
        "glimmer glimmer glimmer ",
    ] {
        assert!(
            check_new_master_password(refused).is_err(),
            "{refused} was accepted"
        );
    }
}

#[test]
fn creating_a_vault_applies_the_policy() {
    assert!(create_vault("fictionalpwd", "Fictional vault").is_err());
    assert!(create_vault("fictional master password", "Fictional vault").is_ok());
}
