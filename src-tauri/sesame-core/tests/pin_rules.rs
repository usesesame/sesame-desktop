use sesame_core::storage::{validate_new_unlock_pin, validate_unlock_pin};

#[test]
fn a_pin_must_be_six_digits() {
    assert!(validate_unlock_pin("123456").is_ok());
    assert!(validate_unlock_pin("12345").is_err());
    assert!(validate_unlock_pin("1234567").is_err());
    assert!(validate_unlock_pin("12345a").is_err());
    assert!(validate_unlock_pin("").is_err());
}

#[test]
fn choosing_a_pin_refuses_the_ones_an_attacker_tries_first() {
    for trivial in ["000000", "111111", "999999", "123456", "654321", "012345"] {
        assert!(
            validate_new_unlock_pin(trivial).is_err(),
            "{trivial} was accepted as a new PIN"
        );
    }
}

#[test]
fn choosing_a_pin_accepts_an_ordinary_one() {
    for reasonable in ["472913", "100200", "918273", "122334"] {
        assert!(
            validate_new_unlock_pin(reasonable).is_ok(),
            "{reasonable} was refused"
        );
    }
}

#[test]
fn unlocking_still_accepts_a_pin_that_was_already_set() {
    for existing in ["000000", "123456", "111111"] {
        assert!(
            validate_unlock_pin(existing).is_ok(),
            "{existing} would lock out someone who already uses it"
        );
    }
}
