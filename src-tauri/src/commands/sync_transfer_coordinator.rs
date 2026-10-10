/// Terminal answers are never retried: revocation, entitlement, and incompatibility halt.
fn classify_transfer_failure(message: &str) -> crate::sync::coordinator::Outcome {
    use crate::sync::coordinator::{Halt, Outcome};

    if let Some(revision) = message.strip_prefix("sync_conflict:") {
        return Outcome::Halt(Halt::Conflict { server_revision: revision.parse().unwrap_or(0) });
    }
    if message == "sync_locked" || message.contains("Unlock Sesame") { return Outcome::Halt(Halt::Locked); }
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
