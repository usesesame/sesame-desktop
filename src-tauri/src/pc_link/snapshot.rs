use std::sync::{Arc, Mutex};

use zeroize::{Zeroize, Zeroizing};

use super::authority::{validate_link_certificate, validate_link_id, AuthorityStore};
use super::{PcLinkState, SNAPSHOT_CHUNK_BYTES, SNAPSHOT_LEASE_SECONDS};
use crate::vault::{unix_timestamp, VaultResult, VaultState};
use sesame_core::loader::VaultLoader;

const UNLOCK_REQUIRED: &str = "Unlock your vault before sharing it with a linked phone.";
const SETUP_REQUIRED: &str = "Finish setting up this vault before linking a phone.";
const NOT_APPROVED: &str = "The desktop has not approved this phone for this vault.";
const AUTHORITY_CHANGED: &str =
    "The PC link authority changed before the snapshot was read. Start retrieval again.";
const AUTHORITY_UNAVAILABLE: &str = "Sesame could not read the PC link authority.";
const SESSION_UNAVAILABLE: &str = "Sesame could not read the unlocked vault.";
const TRANSFER_CANCELLED: &str = "This PC link transfer was canceled.";
const TRANSFER_EXPIRED: &str = "This PC link transfer expired. Start retrieval again.";
const TRANSFER_LOCKED: &str = "The vault locked while the snapshot was being sent.";
const TRANSFER_REVOKED: &str = "The link was revoked while the snapshot was being sent.";
const TRANSFER_VAULT_CHANGED: &str = "The vault changed while the snapshot was being sent.";
const VAULT_ID_REQUIRED: &str = "This vault does not have a valid identity for PC link.";

pub struct SnapshotLease {
    authority: Arc<Mutex<AuthorityStore>>,
    authority_revision: u64,
    session_epoch: u64,
    vault_id: String,
    link_id: String,
    leaf_certificate_der: Vec<u8>,
    revision: u64,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    expires_at: u64,
    cancelled: bool,
}

impl SnapshotLease {
    pub fn content_length(&self) -> usize {
        self.bytes.len()
    }

    pub fn remaining_bytes(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn link_id(&self) -> &str {
        &self.link_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn next_chunk(&mut self, state: &VaultState) -> VaultResult<Option<Vec<u8>>> {
        self.next_chunk_at(state, unix_timestamp())
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.bytes.as_mut_slice().zeroize();
        self.bytes.clear();
        self.offset = 0;
    }

    pub(crate) fn next_chunk_at(
        &mut self,
        state: &VaultState,
        now: u64,
    ) -> VaultResult<Option<Vec<u8>>> {
        self.ensure_active(state, now)?;
        if self.offset >= self.bytes.len() {
            return Ok(None);
        }
        let end = self
            .offset
            .saturating_add(SNAPSHOT_CHUNK_BYTES)
            .min(self.bytes.len());
        let chunk = self.bytes[self.offset..end].to_vec();
        self.offset = end;
        Ok(Some(chunk))
    }

    fn ensure_active(&mut self, state: &VaultState, now: u64) -> VaultResult<()> {
        if self.cancelled {
            return Err(TRANSFER_CANCELLED.to_string());
        }
        if now >= self.expires_at {
            self.cancel();
            return Err(TRANSFER_EXPIRED.to_string());
        }
        if state.session_epoch() != self.session_epoch {
            self.cancel();
            return Err(TRANSFER_LOCKED.to_string());
        }
        let authorized = {
            let authority = self
                .authority
                .lock()
                .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
            authority.revision == self.authority_revision
                && authority.is_approved(
                    &self.vault_id,
                    &self.link_id,
                    &self.leaf_certificate_der,
                    now,
                )
        };
        if !authorized {
            self.cancel();
            return Err(TRANSFER_REVOKED.to_string());
        }
        let current_vault = {
            let session = state
                .session
                .lock()
                .map_err(|_| SESSION_UNAVAILABLE.to_string())?;
            session.as_ref().and_then(|session| {
                session
                    .setup_complete
                    .then(|| session.snapshot().vault_id)
                    .flatten()
            })
        };
        if current_vault.as_deref() != Some(self.vault_id.as_str()) {
            self.cancel();
            return Err(TRANSFER_VAULT_CHANGED.to_string());
        }
        Ok(())
    }
}

impl Drop for SnapshotLease {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl PcLinkState {
    pub fn capture_snapshot(
        &self,
        state: &VaultState,
        link_id: &str,
        verified_leaf_certificate_der: &[u8],
    ) -> VaultResult<SnapshotLease> {
        self.capture_snapshot_at(
            state,
            link_id,
            verified_leaf_certificate_der,
            unix_timestamp(),
        )
    }

    pub(crate) fn capture_snapshot_at(
        &self,
        state: &VaultState,
        link_id: &str,
        verified_leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<SnapshotLease> {
        validate_link_id(link_id)?;
        validate_link_certificate(verified_leaf_certificate_der)?;
        let session = state
            .session
            .lock()
            .map_err(|_| SESSION_UNAVAILABLE.to_string())?;
        let session = session
            .as_ref()
            .ok_or_else(|| UNLOCK_REQUIRED.to_string())?;
        if !session.setup_complete {
            return Err(SETUP_REQUIRED.to_string());
        }
        let snapshot = session.snapshot();
        let vault_id = snapshot
            .vault_id
            .clone()
            .filter(|vault_id| !vault_id.is_empty())
            .ok_or_else(|| VAULT_ID_REQUIRED.to_string())?;
        let session_epoch = state.session_epoch();
        let authority_revision = {
            let authority = self
                .authority
                .lock()
                .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
            if !authority.is_approved(&vault_id, link_id, verified_leaf_certificate_der, now) {
                return Err(NOT_APPROVED.to_string());
            }
            authority.revision
        };
        let bytes = VaultLoader::read_bytes(&session.path).map_err(String::from)?;
        let committed = VaultLoader::parse(&bytes).map_err(String::from)?;
        if !committed.setup_complete {
            return Err(SETUP_REQUIRED.to_string());
        }
        {
            let authority = self
                .authority
                .lock()
                .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
            if authority.revision != authority_revision
                || !authority.is_approved(&vault_id, link_id, verified_leaf_certificate_der, now)
            {
                return Err(AUTHORITY_CHANGED.to_string());
            }
        }
        Ok(SnapshotLease {
            authority: Arc::clone(&self.authority),
            authority_revision,
            session_epoch,
            vault_id,
            link_id: link_id.to_string(),
            leaf_certificate_der: verified_leaf_certificate_der.to_vec(),
            revision: snapshot.revision,
            bytes,
            offset: 0,
            expires_at: now.saturating_add(SNAPSHOT_LEASE_SECONDS),
            cancelled: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::TestVault;
    use crate::pc_link::envelope::TestProtection;
    use crate::pc_link::{ApprovedPeer, PendingPairing};
    use crate::release::ReleasePresence;
    use crate::vault::{VaultFile, MAX_VAULT_FILE_BYTES};
    use rcgen::PublicKeyData;
    use sesame_core::api;
    use std::time::{Duration, Instant};

    const NOW: u64 = 1_000;

    fn directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sesame-pc-link-snapshot-{name}-{}",
            crate::vault::random_id()
        ));
        std::fs::create_dir_all(&path).expect("test directory");
        path
    }

    fn phone_public_key() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("phone key");
        key.der_bytes().to_vec()
    }

    fn link(name: &str) -> PcLinkState {
        let root = directory(name);
        PcLinkState::open_with_protection(&root, Box::new(TestProtection { fail: false }))
            .expect("pc link")
    }

    fn presence(vault: &TestVault) -> ReleasePresence {
        let presence = ReleasePresence::default();
        presence.grant_until(
            vault.state.session_epoch(),
            Instant::now() + Duration::from_secs(600),
        );
        presence
    }

    fn begin(
        pc_link: &PcLinkState,
        vault: &TestVault,
        phone_public_key: &[u8],
        now: u64,
    ) -> PendingPairing {
        pc_link
            .begin_pairing_at(&vault.state, phone_public_key, "Fictional phone", now)
            .expect("pending")
    }

    fn approve(
        pc_link: &PcLinkState,
        vault: &TestVault,
        now: u64,
    ) -> (String, Vec<u8>, ApprovedPeer) {
        let presence = presence(vault);
        let pending = begin(pc_link, vault, &phone_public_key(), now);
        let commit = pc_link
            .confirm_pairing_at(&vault.state, &presence, pending.request_id(), now)
            .expect("confirmed");
        let approved = pc_link
            .commit_pairing_at(
                &vault.state,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                now,
            )
            .expect("committed");
        (
            commit.link_id().to_string(),
            commit.leaf_certificate_der().to_vec(),
            approved,
        )
    }

    fn collect(mut lease: SnapshotLease, state: &VaultState) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(chunk) = lease.next_chunk_at(state, NOW).expect("chunk") {
            bytes.extend(chunk);
        }
        bytes
    }

    #[test]
    fn capture_returns_the_committed_ciphertext_and_leaves_the_source_untouched() {
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = link("source");
        let (link_id, leaf, approved) = approve(&pc_link, &vault, NOW);
        let path = vault
            .state
            .session
            .lock()
            .expect("session")
            .as_ref()
            .expect("unlocked")
            .path
            .clone();
        let before = std::fs::read(&path).expect("source");
        let revision = vault
            .state
            .session
            .lock()
            .expect("session")
            .as_ref()
            .expect("unlocked")
            .snapshot()
            .revision;

        let lease = pc_link
            .capture_snapshot_at(&vault.state, &link_id, &leaf, NOW)
            .expect("lease");
        assert_eq!(lease.revision(), revision);
        assert_eq!(lease.vault_id(), approved.vault_id());
        assert_eq!(lease.link_id(), approved.link_id());
        assert_eq!(lease.content_length(), before.len());
        let captured = collect(lease, &vault.state);
        assert_eq!(captured, before);
        assert_eq!(std::fs::read(&path).expect("source after"), before);
        assert!(!captured
            .windows(b"fictional-stored-secret".len())
            .any(|window| window == b"fictional-stored-secret"));
    }

    #[test]
    fn pending_confirmed_and_unknown_links_cannot_capture() {
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = link("pending");
        let phone_public_key = phone_public_key();
        let pending = begin(&pc_link, &vault, &phone_public_key, NOW);
        assert!(pc_link
            .capture_snapshot_at(&vault.state, pending.request_id(), &[1, 2, 3], NOW)
            .is_err());
        let presence = presence(&vault);
        let commit = pc_link
            .confirm_pairing_at(&vault.state, &presence, pending.request_id(), NOW)
            .expect("confirmed");
        assert!(pc_link
            .capture_snapshot_at(
                &vault.state,
                commit.link_id(),
                commit.leaf_certificate_der(),
                NOW
            )
            .is_err());
        let approved = pc_link
            .commit_pairing_at(
                &vault.state,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                NOW,
            )
            .expect("committed");
        assert!(pc_link
            .capture_snapshot_at(
                &vault.state,
                approved.link_id(),
                approved.leaf_certificate_der(),
                NOW
            )
            .is_ok());
        assert!(pc_link
            .capture_snapshot_at(&vault.state, approved.link_id(), &[9, 9, 9], NOW)
            .is_err());
    }

    #[test]
    fn a_grant_for_another_vault_cannot_capture() {
        let first = TestVault::with_login("fictional-login", "https://example.test");
        let second = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = link("wrong-vault");
        let (link_id, leaf, _) = approve(&pc_link, &first, NOW);
        assert!(pc_link
            .capture_snapshot_at(&second.state, &link_id, &leaf, NOW)
            .is_err());
    }

    #[test]
    fn lease_stops_after_revoke_lock_cancel_and_expiry() {
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = link("lease");
        let (link_id, leaf, approved) = approve(&pc_link, &vault, NOW);

        let mut revoked = pc_link
            .capture_snapshot_at(&vault.state, &link_id, &leaf, NOW)
            .expect("lease");
        assert!(revoked
            .next_chunk_at(&vault.state, NOW)
            .expect("chunk")
            .is_some());
        assert!(pc_link
            .revoke_peer(approved.vault_id(), &link_id)
            .expect("revoked"));
        assert_eq!(
            revoked.next_chunk_at(&vault.state, NOW).err(),
            Some(TRANSFER_REVOKED.to_string())
        );

        let (new_link_id, new_leaf, _) = approve(&pc_link, &vault, NOW + 1);
        let mut cancelled = pc_link
            .capture_snapshot_at(&vault.state, &new_link_id, &new_leaf, NOW + 1)
            .expect("lease");
        cancelled.cancel();
        assert_eq!(
            cancelled.next_chunk_at(&vault.state, NOW + 1).err(),
            Some(TRANSFER_CANCELLED.to_string())
        );

        let mut expired = pc_link
            .capture_snapshot_at(&vault.state, &new_link_id, &new_leaf, NOW + 1)
            .expect("lease");
        assert_eq!(
            expired
                .next_chunk_at(&vault.state, NOW + SNAPSHOT_LEASE_SECONDS + 2)
                .err(),
            Some(TRANSFER_EXPIRED.to_string())
        );

        let mut locked = pc_link
            .capture_snapshot_at(&vault.state, &new_link_id, &new_leaf, NOW + 1)
            .expect("lease");
        assert!(locked
            .next_chunk_at(&vault.state, NOW + 1)
            .expect("chunk")
            .is_some());
        vault.state.lock_for_lifecycle().expect("locked");
        assert_eq!(
            locked.next_chunk_at(&vault.state, NOW + 1).err(),
            Some(TRANSFER_LOCKED.to_string())
        );
        assert!(pc_link
            .capture_snapshot_at(&vault.state, &new_link_id, &new_leaf, NOW + 1)
            .is_err());
    }

    #[test]
    fn dropping_a_lease_mid_transfer_leaves_the_source_unchanged() {
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = link("dropped");
        let (link_id, leaf, _) = approve(&pc_link, &vault, NOW);
        let path = vault
            .state
            .session
            .lock()
            .expect("session")
            .as_ref()
            .expect("unlocked")
            .path
            .clone();
        let before = std::fs::read(&path).expect("source");
        let mut lease = pc_link
            .capture_snapshot_at(&vault.state, &link_id, &leaf, NOW)
            .expect("lease");
        assert!(lease
            .next_chunk_at(&vault.state, NOW)
            .expect("chunk")
            .is_some());
        drop(lease);
        assert_eq!(std::fs::read(&path).expect("source after"), before);
    }

    #[test]
    fn capture_rejects_an_oversized_committed_file() {
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = link("oversized");
        let (link_id, leaf, _) = approve(&pc_link, &vault, NOW);
        let path = vault
            .state
            .session
            .lock()
            .expect("session")
            .as_ref()
            .expect("unlocked")
            .path
            .clone();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("source");
        file.set_len(MAX_VAULT_FILE_BYTES + 1).expect("oversized");
        drop(file);
        assert!(pc_link
            .capture_snapshot_at(&vault.state, &link_id, &leaf, NOW)
            .is_err());
    }

    #[test]
    fn capture_waits_for_the_save_lock() {
        use std::sync::mpsc;
        use std::time::Duration;

        let vault = Arc::new(TestVault::with_login(
            "fictional-login",
            "https://example.test",
        ));
        let pc_link = Arc::new(link("lock-wait"));
        let (link_id, leaf, _) = approve(&pc_link, &vault, NOW);

        let guard = vault.state.session.lock().expect("session");
        let (sender, receiver) = mpsc::channel();
        let handle = {
            let vault = Arc::clone(&vault);
            let pc_link = Arc::clone(&pc_link);
            std::thread::spawn(move || {
                let result = pc_link
                    .capture_snapshot_at(&vault.state, &link_id, &leaf, NOW)
                    .is_ok();
                let _ = sender.send(result);
            })
        };
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        drop(guard);
        assert!(receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("capture completed"));
        handle.join().expect("capture thread");
    }

    #[test]
    fn concurrent_saves_yield_one_committed_revision_per_capture() {
        let vault = Arc::new(TestVault::with_login(
            "fictional-login",
            "https://example.test",
        ));
        let pc_link = Arc::new(link("concurrent"));
        let (link_id, leaf, _) = approve(&pc_link, &vault, NOW);

        let writer = {
            let vault = Arc::clone(&vault);
            std::thread::spawn(move || {
                for index in 0..10 {
                    vault.seed(|payload| {
                        payload.vault_name = format!("Fictional vault {index}");
                    });
                }
            })
        };

        let mut previous = 0;
        for _ in 0..10 {
            let lease = pc_link
                .capture_snapshot_at(&vault.state, &link_id, &leaf, NOW)
                .expect("lease");
            assert!(lease.revision() >= previous);
            previous = lease.revision();
            let revision = lease.revision();
            let captured = collect(lease, &vault.state);
            let file: VaultFile = serde_json::from_slice(&captured).expect("vault file");
            let key = Zeroizing::new(
                vault
                    .state
                    .session
                    .lock()
                    .expect("session")
                    .as_ref()
                    .expect("unlocked")
                    .expose_vault_key(|key| Ok(*key))
                    .expect("vault key"),
            );
            let opened = api::open_vault_with_key(&file, *key).expect("opened snapshot");
            assert_eq!(opened.payload.revision, revision);
        }
        writer.join().expect("writer");
    }
}
