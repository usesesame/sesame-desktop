/// Terminal answers are never retried: revocation, entitlement, and incompatibility halt.
fn classify_transfer_failure(message: &str) -> crate::sync::coordinator::Outcome {
    use crate::sync::coordinator::{Halt, Outcome};

    if message == crate::sync::floor::REFUSAL {
        return Outcome::Halt(Halt::Incompatible);
    }
    if message == crate::sync::floor::DAMAGED_REFUSAL {
        return Outcome::Halt(Halt::FloorDamaged);
    }
    if let Some(revision) = message.strip_prefix("sync_conflict:") {
        return Outcome::Halt(Halt::Conflict { server_revision: revision.parse().unwrap_or(0) });
    }
    if message == NOT_ACTIVATED { return Outcome::Halt(Halt::NeedsNewKey); }
    if message == "sync_locked" || message.contains("Unlock Sesame") { return Outcome::Halt(Halt::Locked); }
    if message.starts_with("sync_fork:") { return Outcome::Halt(Halt::Fork); }
    if message.contains("not approved") || message.contains("no longer") { return Outcome::Halt(Halt::Revoked); }
    if message.starts_with("sync_not_entitled:") { return Outcome::Halt(Halt::NotEntitled); }
    if message.contains("does not match the expected format") || message.contains("version") { return Outcome::Halt(Halt::Incompatible); }
    Outcome::Transient
}

#[cfg(test)]
mod coordinator_classification_tests {
    use super::classify_transfer_failure;
    use crate::sync::coordinator::{Halt, Outcome};

    #[test]
    fn an_entitlement_code_halts_the_coordinator() {
        let message = super::present(crate::sync::client::SyncError::NotEntitled);
        assert_eq!(classify_transfer_failure(&message), Outcome::Halt(Halt::NotEntitled));
    }

    #[test]
    fn the_word_subscription_in_a_message_no_longer_halts_anything() {
        for message in [
            "Your subscription has lapsed.",
            "This account's Sesame subscription is not active.",
            "subscription",
        ] {
            assert_eq!(classify_transfer_failure(message), Outcome::Transient, "{message}");
        }
    }

    #[test]
    fn a_message_that_only_resembles_the_entitlement_code_does_not_halt() {
        for message in ["sync_not_entitled", "x sync_not_entitled:", "Sync_Not_Entitled:"] {
            assert_eq!(classify_transfer_failure(message), Outcome::Transient, "{message}");
        }
    }

    #[test]
    fn the_kill_switch_refusal_halts_as_incompatible_and_never_as_a_removed_device() {
        assert_eq!(
            classify_transfer_failure(crate::sync::floor::REFUSAL),
            Outcome::Halt(Halt::Incompatible)
        );
    }

    #[test]
    fn a_damaged_floor_file_halts_with_its_own_reason_and_not_as_an_old_version() {
        assert_eq!(
            classify_transfer_failure(crate::sync::floor::DAMAGED_REFUSAL),
            Outcome::Halt(Halt::FloorDamaged)
        );
    }

    #[test]
    fn a_device_that_has_not_taken_the_new_key_halts_with_its_own_reason_and_never_looks_offline() {
        let message = "This device has not taken the new vault key yet. Open Sync and take it.";
        assert_eq!(
            classify_transfer_failure(message),
            Outcome::Halt(Halt::NeedsNewKey)
        );
        assert_eq!(
            classify_transfer_failure(super::NOT_ACTIVATED),
            Outcome::Halt(Halt::NeedsNewKey)
        );
    }

    #[test]
    fn other_terminal_answers_still_halt() {
        assert_eq!(
            classify_transfer_failure("sync_conflict:7"),
            Outcome::Halt(Halt::Conflict { server_revision: 7 })
        );
        assert_eq!(classify_transfer_failure("sync_locked"), Outcome::Halt(Halt::Locked));
        assert_eq!(
            classify_transfer_failure("This device is not approved to sync."),
            Outcome::Halt(Halt::Revoked)
        );
    }
}
