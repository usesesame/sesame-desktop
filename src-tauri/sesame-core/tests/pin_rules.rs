use sesame_core::storage::{
    validate_new_unlock_pin, validate_unlock_pin, MAX_PIN_DIGITS, MIN_PIN_DIGITS,
};

#[test]
fn a_pin_is_six_to_twelve_digits() {
    assert_eq!((MIN_PIN_DIGITS, MAX_PIN_DIGITS), (6, 12));
    for valid in ["123456", "1234567", "48291736", "482917365012"] {
        assert!(validate_unlock_pin(valid).is_ok(), "{valid} was refused");
    }
    for invalid in [
        "",
        "12345",
        "1234567890123",
        "12345a",
        "48291736501x",
        "４８２９１７",
        " 482917",
        "482917\n",
    ] {
        assert!(
            validate_unlock_pin(invalid).is_err(),
            "{invalid:?} was accepted"
        );
    }
}

#[test]
fn choosing_a_pin_refuses_the_ones_an_attacker_tries_first() {
    for trivial in [
        "000000",
        "111111",
        "999999",
        "123456",
        "654321",
        "012345",
        "00000000",
        "1234567890",
        "9876543210",
        "555555555555",
    ] {
        assert!(
            validate_new_unlock_pin(trivial).is_err(),
            "{trivial} was accepted as a new PIN"
        );
    }
}

#[test]
fn choosing_a_pin_accepts_an_ordinary_one() {
    for reasonable in [
        "472913",
        "100200",
        "918273",
        "122334",
        "4729138",
        "472913850261",
    ] {
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
