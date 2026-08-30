use sesame_core::throttle::{PinAttemptGuard, PIN_FAILURES_BEFORE_LOCKOUT};

const NOW: u64 = 1_700_000_000_000;

fn guard_after_failures(count: u32, now_ms: u64) -> PinAttemptGuard {
    let mut guard = PinAttemptGuard::default();
    for _ in 0..count {
        guard.record_failure_at(now_ms);
    }
    guard
}

#[test]
fn attempts_below_the_threshold_are_not_held_up() {
    let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT - 1, NOW);
    assert!(guard.check_at(NOW).is_ok());
}

#[test]
fn the_threshold_starts_a_cooldown_reported_in_whole_seconds() {
    let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT, NOW);
    let Err(seconds) = guard.check_at(NOW) else {
        panic!("the fifth wrong PIN did not start a cooldown");
    };
    assert_eq!(seconds, 15);
}

#[test]
fn the_cooldown_ends_on_its_own() {
    let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT, NOW);
    assert!(guard.check_at(NOW + 14_000).is_err());
    assert!(guard.check_at(NOW + 15_001).is_ok());
}

#[test]
fn each_further_wrong_pin_costs_more_than_the_last() {
    let mut seen = Vec::new();
    for extra in 0..4 {
        let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT + extra, NOW);
        let Err(seconds) = guard.check_at(NOW) else {
            panic!(
                "no cooldown after {} failures",
                PIN_FAILURES_BEFORE_LOCKOUT + extra
            );
        };
        seen.push(seconds);
    }
    assert_eq!(seen, vec![15, 30, 60, 120]);
}

#[test]
fn the_wait_stops_growing_at_five_minutes() {
    let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT + 40, NOW);
    let Err(seconds) = guard.check_at(NOW) else {
        panic!("a long run of failures left no cooldown");
    };
    assert_eq!(seconds, 300);
}

#[test]
fn a_correct_pin_clears_the_record_completely() {
    let mut guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT + 3, NOW);
    assert!(guard.check_at(NOW).is_err());
    guard.record_success();
    assert!(guard.check_at(NOW).is_ok());
    assert_eq!(guard.persisted().failures, 0);
    assert!(guard.persisted().locked_until_unix_ms.is_none());
}

#[test]
fn the_count_survives_being_written_out_and_read_back() {
    let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT + 1, NOW);
    let restored = PinAttemptGuard::from_persisted(guard.persisted());
    assert_eq!(restored.check_at(NOW), guard.check_at(NOW));
    assert_eq!(
        restored.persisted().failures,
        PIN_FAILURES_BEFORE_LOCKOUT + 1
    );
}

#[test]
fn a_clock_moved_backwards_keeps_the_lock_rather_than_releasing_it() {
    let guard = guard_after_failures(PIN_FAILURES_BEFORE_LOCKOUT, NOW);
    assert!(
        guard.check_at(NOW - 3_600_000).is_err(),
        "winding the clock back released the cooldown"
    );
}
