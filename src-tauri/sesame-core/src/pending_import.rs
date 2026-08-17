//! Parsed-but-uncommitted imports.
//! Entries stay in Rust; the interface only receives counts and an opaque id, and the entries are wiped on commit, cancel, expiry, or lock.

use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::imports::ParsedImport;
use crate::types::{Card, Identity, SecureNote, VaultEntry};
use crate::util::random_id;
use crate::VaultResult;

pub const PENDING_IMPORT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub struct PendingImport {
    pub id: String,
    pub entries: Vec<VaultEntry>,
    pub secure_notes: Vec<SecureNote>,
    pub cards: Vec<Card>,
    pub identities: Vec<Identity>,
    created: Instant,
}

impl PendingImport {
    pub fn new(parsed: ParsedImport) -> Self {
        Self::new_at(parsed, Instant::now())
    }

    fn new_at(parsed: ParsedImport, created: Instant) -> Self {
        Self {
            id: random_id(),
            entries: parsed.entries,
            secure_notes: parsed.secure_notes,
            cards: parsed.cards,
            identities: parsed.identities,
            created,
        }
    }

    fn expired_at(&self, now: Instant) -> bool {
        // Valid strictly before the boundary: exact-boundary expiry is deterministic in tests.
        now.saturating_duration_since(self.created) >= PENDING_IMPORT_TIMEOUT
    }

    /// Moves everything out so the drop guard has nothing left to wipe.
    pub fn into_parts(mut self) -> (Vec<VaultEntry>, Vec<SecureNote>, Vec<Card>, Vec<Identity>) {
        (
            std::mem::take(&mut self.entries),
            std::mem::take(&mut self.secure_notes),
            std::mem::take(&mut self.cards),
            std::mem::take(&mut self.identities),
        )
    }
}

impl Drop for PendingImport {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.zeroize();
        }
        for note in &mut self.secure_notes {
            note.zeroize();
        }
        for card in &mut self.cards {
            card.zeroize();
        }
        for identity in &mut self.identities {
            identity.zeroize();
        }
    }
}

/// A stale identifier can never commit secrets the user has moved on from.
pub fn take_matching(
    slot: &mut Option<PendingImport>,
    import_id: &str,
) -> VaultResult<PendingImport> {
    take_matching_at(slot, import_id, Instant::now())
}

fn take_matching_at(
    slot: &mut Option<PendingImport>,
    import_id: &str,
    now: Instant,
) -> VaultResult<PendingImport> {
    let Some(pending) = slot.take() else {
        return Err("That import is no longer pending. Choose the export file again.".into());
    };
    if pending.id != import_id {
        return Err("That import is no longer pending. Choose the export file again.".into());
    }
    if pending.expired_at(now) {
        return Err(
            "That import expired before it was added. Choose the export file again.".into(),
        );
    }
    Ok(pending)
}
