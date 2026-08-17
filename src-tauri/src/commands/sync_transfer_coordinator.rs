/// Terminal answers are never retried: revocation, entitlement, and incompatibility halt.
fn classify_transfer_failure(message: &str) -> crate::sync::coordinator::Outcome {
    use crate::sync::coordinator::{Halt, Outcome};

    if let Some(revision) = message.strip_prefix("sync_conflict:") {
        return Outcome::Halt(Halt::Conflict { server_revision: revision.parse().unwrap_or(0) });
    }
    if message == "sync_locked" || message.contains("Unlock Sesame") { return Outcome::Halt(Halt::Locked); }
    if message.contains("not approved") || message.contains("no longer") { return Outcome::Halt(Halt::Revoked); }
    if message.contains("subscription") { return Outcome::Halt(Halt::NotEntitled); }
    if message.contains("does not match the expected format") || message.contains("version") { return Outcome::Halt(Halt::Incompatible); }
    Outcome::Transient
}
