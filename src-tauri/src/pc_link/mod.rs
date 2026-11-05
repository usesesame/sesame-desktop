mod authority;
mod discovery;
mod enrollment;
mod envelope;
mod fingerprint;
mod identity;
mod pairing;
mod protocol;
pub(crate) mod service;
mod snapshot;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::SysRng;
use rand::TryRng;

pub use authority::{ApprovedPeer, PendingCommit, PendingPairing};
pub use fingerprint::{CertificateFingerprint, PhonePublicKeyFingerprint, Sha256Fingerprint};
pub use identity::DesktopCertificate;
pub use snapshot::SnapshotLease;

use authority::{
    validate_link_id, validate_phone_label, validate_phone_public_key, validate_vault_id,
    AuthorityStore,
};
use envelope::{DeviceProtection, NativeProtection};
use identity::{create_identity, load_identity, DesktopIdentity};
use pairing::issue_client_certificate;

use crate::release::ReleasePresence;
use crate::vault::{unix_timestamp, VaultResult, VaultState};

pub const PC_LINK_SERVICE_NAME: &str = "sesame-pc.local";
pub const MAX_APPROVED_PEERS: usize = 32;
pub const MAX_APPROVED_PEERS_PER_VAULT: usize = 8;
pub const MAX_PENDING_PAIRINGS: usize = 8;
pub const PENDING_PAIRING_TTL_SECONDS: u64 = 120;
pub const PAIRING_RATE_WINDOW_SECONDS: u64 = 60;
pub const MAX_PAIRING_REQUESTS_PER_WINDOW: u32 = 5;
pub const SNAPSHOT_LEASE_SECONDS: u64 = 300;
pub const SNAPSHOT_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_PHONE_PUBLIC_KEY_BYTES: usize = 65;
pub const MAX_LINK_CERTIFICATE_BYTES: usize = 16 * 1024;
pub const MAX_PHONE_LABEL_CHARS: usize = 64;

pub(crate) const MAX_PEER_VAULT_ID_CHARS: usize = 128;

const PC_LINK_DIRECTORY: &str = "pc-link";
const IDENTITY_FILE_NAME: &str = "identity.sesame";
const AUTHORITY_FILE_NAME: &str = "authority.sesame";

const PAIRING_RATE_LIMITED: &str =
    "Pairing requests are arriving too quickly. Wait a minute and try again.";
const PAIRING_EXPIRED: &str = "This pairing request has expired. Start pairing again.";
const PAIRING_UNKNOWN: &str = "This pairing request is no longer available. Start pairing again.";
const TOO_MANY_PENDING: &str = "Too many pairing requests are waiting. Wait for them to expire.";
const PENDING_UNAVAILABLE: &str = "Sesame could not read the pending pairing requests.";
const AUTHORITY_UNAVAILABLE: &str = "Sesame could not read the PC link authority.";
const AUTHORITY_REVISION_EXHAUSTED: &str = "The PC link authority reached its revision limit.";
const IDENTITY_MISSING: &str =
    "The PC link identity is missing while phones are still linked. Clear the PC link setup and pair again.";
const NOT_APPROVED: &str = "The desktop has not approved this phone for this vault.";
const UNLOCK_REQUIRED: &str = "Unlock your vault before linking a phone.";
const SETUP_REQUIRED: &str = "Finish setting up this vault before linking a phone.";
const SESSION_CHANGED: &str = "The vault session changed. Start pairing again.";
const VAULT_CHANGED: &str = "The selected vault changed. Start pairing again.";
const NOT_CONFIRMED: &str = "This pairing request has not been confirmed.";
const ISSUED_CERTIFICATE_MISMATCH: &str =
    "The phone did not present the certificate issued for this link.";
const LINK_CERTIFICATE_EXPIRED: &str = "This PC link certificate has expired. Pair again.";
const IDENTIFIER_UNAVAILABLE: &str = "Sesame could not generate a PC link identifier.";

struct PcLinkPaths {
    identity: PathBuf,
    authority: PathBuf,
}

impl PcLinkPaths {
    fn new(app_local_data_dir: &Path) -> Self {
        let directory = app_local_data_dir.join(PC_LINK_DIRECTORY);
        Self {
            identity: directory.join(IDENTITY_FILE_NAME),
            authority: directory.join(AUTHORITY_FILE_NAME),
        }
    }
}

pub(crate) fn authority_path(app_local_data_dir: &Path) -> PathBuf {
    PcLinkPaths::new(app_local_data_dir).authority
}

pub(crate) fn has_authority_file(app_local_data_dir: &Path) -> bool {
    authority_path(app_local_data_dir).is_file()
}

#[derive(Default)]
struct PairingRate {
    window_started_at: u64,
    attempts: u32,
}

impl PairingRate {
    fn admit(&mut self, now: u64) -> VaultResult<()> {
        if now < self.window_started_at
            || now.saturating_sub(self.window_started_at) >= PAIRING_RATE_WINDOW_SECONDS
        {
            self.window_started_at = now;
            self.attempts = 0;
        }
        if self.attempts >= MAX_PAIRING_REQUESTS_PER_WINDOW {
            return Err(PAIRING_RATE_LIMITED.to_string());
        }
        self.attempts = self.attempts.saturating_add(1);
        Ok(())
    }
}

pub struct PcLinkState {
    paths: PcLinkPaths,
    identity: DesktopIdentity,
    authority: Arc<Mutex<AuthorityStore>>,
    pending: Mutex<BTreeMap<String, PendingPairing>>,
    pending_commits: Mutex<BTreeMap<String, PendingCommit>>,
    rate: Mutex<PairingRate>,
    protection: Box<dyn DeviceProtection>,
}

impl PcLinkState {
    pub fn open(app_local_data_dir: &Path) -> VaultResult<Self> {
        crate::vault::platform::ensure_device_protection()?;
        Self::open_with_protection(app_local_data_dir, Box::new(NativeProtection))
    }

    fn open_with_protection(
        app_local_data_dir: &Path,
        protection: Box<dyn DeviceProtection>,
    ) -> VaultResult<Self> {
        let paths = PcLinkPaths::new(app_local_data_dir);
        let authority = AuthorityStore::load(&paths.authority, protection.as_ref())?;
        let identity = match load_identity(&paths.identity, protection.as_ref())? {
            Some(identity) => identity,
            None if authority.grants.is_empty() => {
                create_identity(&paths.identity, protection.as_ref())?
            }
            None => return Err(IDENTITY_MISSING.to_string()),
        };
        Ok(Self {
            paths,
            identity,
            authority: Arc::new(Mutex::new(authority)),
            pending: Mutex::new(BTreeMap::new()),
            pending_commits: Mutex::new(BTreeMap::new()),
            rate: Mutex::new(PairingRate::default()),
            protection,
        })
    }

    pub fn desktop_certificate(&self) -> &DesktopCertificate {
        self.identity.certificate()
    }

    pub(crate) fn private_key_der(&self) -> &[u8] {
        self.identity.private_key_der()
    }

    pub(crate) fn selected_vault(state: &VaultState) -> VaultResult<(String, String, u64)> {
        let session = state
            .session
            .lock()
            .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
        let session = session
            .as_ref()
            .ok_or_else(|| UNLOCK_REQUIRED.to_string())?;
        if !session.setup_complete {
            return Err(SETUP_REQUIRED.to_string());
        }
        let snapshot = session.snapshot();
        let vault_id = snapshot
            .vault_id
            .filter(|vault_id| !vault_id.is_empty())
            .ok_or_else(|| "This vault does not have a valid identity for PC link.".to_string())?;
        Ok((vault_id, snapshot.vault_name, state.session_epoch()))
    }

    pub fn all_active_link_authorities(&self) -> VaultResult<Vec<Vec<u8>>> {
        let authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        Ok(authority.all_active_authorities(unix_timestamp()))
    }

    pub fn pairing_trust_authorities(&self) -> VaultResult<Vec<Vec<u8>>> {
        let mut authorities = self.all_active_link_authorities()?;
        let now = unix_timestamp();
        if let Ok(commits) = self.pending_commits.lock() {
            for commit in commits.values() {
                if commit.expires_at > now
                    && !authorities
                        .iter()
                        .any(|der| der == &commit.certificate_authority_der)
                {
                    authorities.push(commit.certificate_authority_der.clone());
                }
            }
        }
        Ok(authorities)
    }

    pub fn begin_pairing(
        &self,
        state: &VaultState,
        phone_public_key: &[u8],
        label: &str,
    ) -> VaultResult<PendingPairing> {
        self.begin_pairing_at(state, phone_public_key, label, unix_timestamp())
    }

    pub(crate) fn begin_pairing_at(
        &self,
        state: &VaultState,
        phone_public_key: &[u8],
        label: &str,
        now: u64,
    ) -> VaultResult<PendingPairing> {
        self.begin_pairing_inner(state, phone_public_key, label, None, now)
    }

    pub(crate) fn begin_pairing_with_id_at(
        &self,
        state: &VaultState,
        phone_public_key: &[u8],
        label: &str,
        request_id: String,
        now: u64,
    ) -> VaultResult<PendingPairing> {
        self.begin_pairing_inner(state, phone_public_key, label, Some(request_id), now)
    }

    fn begin_pairing_inner(
        &self,
        state: &VaultState,
        phone_public_key: &[u8],
        label: &str,
        requested_id: Option<String>,
        now: u64,
    ) -> VaultResult<PendingPairing> {
        validate_phone_public_key(phone_public_key)?;
        validate_phone_label(label)?;
        let phone_public_key_fingerprint =
            PhonePublicKeyFingerprint::from_phone_public_key(phone_public_key);
        let (vault_id, session_epoch) = {
            let session = state
                .session
                .lock()
                .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
            let session = session
                .as_ref()
                .ok_or_else(|| UNLOCK_REQUIRED.to_string())?;
            if !session.setup_complete {
                return Err(SETUP_REQUIRED.to_string());
            }
            let snapshot = session.snapshot();
            let vault_id = snapshot
                .vault_id
                .filter(|vault_id| !vault_id.is_empty())
                .ok_or_else(|| {
                    "This vault does not have a valid identity for PC link.".to_string()
                })?;
            (vault_id, state.session_epoch())
        };

        if requested_id.is_none() {
            let existing = {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
                pending.retain(|_, request| request.expires_at > now);
                pending
                    .values()
                    .find(|request| {
                        request.vault_id == vault_id
                            && request.phone_public_key_fingerprint == phone_public_key_fingerprint
                    })
                    .cloned()
            };
            if let Some(existing) = existing {
                return Ok(existing);
            }
        }

        {
            let mut rate = self
                .rate
                .lock()
                .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
            rate.admit(now)?;
        }

        let mut pending = self
            .pending
            .lock()
            .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
        pending.retain(|_, request| request.expires_at > now);
        if requested_id.is_none() {
            if let Some(existing) = pending.values().find(|request| {
                request.vault_id == vault_id
                    && request.phone_public_key_fingerprint == phone_public_key_fingerprint
            }) {
                return Ok(existing.clone());
            }
        }
        if pending.len() >= MAX_PENDING_PAIRINGS {
            return Err(TOO_MANY_PENDING.to_string());
        }
        let request_id = match requested_id {
            Some(request_id) => {
                validate_link_id(&request_id)?;
                if pending.contains_key(&request_id) {
                    return Err("This pairing request already exists.".to_string());
                }
                request_id
            }
            None => loop {
                let candidate = random_identifier()?;
                if !pending.contains_key(&candidate) {
                    break candidate;
                }
            },
        };
        let request = PendingPairing::new(
            request_id.clone(),
            vault_id,
            session_epoch,
            label.to_string(),
            phone_public_key.to_vec(),
            now,
            now.saturating_add(PENDING_PAIRING_TTL_SECONDS),
        )?;
        pending.insert(request_id, request.clone());
        Ok(request)
    }

    pub fn confirm_pairing(
        &self,
        state: &VaultState,
        presence: &ReleasePresence,
        request_id: &str,
    ) -> VaultResult<PendingCommit> {
        self.confirm_pairing_at(state, presence, request_id, unix_timestamp())
    }

    pub(crate) fn confirm_pairing_at(
        &self,
        state: &VaultState,
        presence: &ReleasePresence,
        request_id: &str,
        now: u64,
    ) -> VaultResult<PendingCommit> {
        let session_epoch = state.session_epoch();
        presence.require(session_epoch)?;
        let session = state
            .session
            .lock()
            .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
        let session = session
            .as_ref()
            .ok_or_else(|| UNLOCK_REQUIRED.to_string())?;
        if !session.setup_complete {
            return Err(SETUP_REQUIRED.to_string());
        }
        presence.require(session_epoch)?;
        let vault_id = session
            .snapshot()
            .vault_id
            .filter(|vault_id| !vault_id.is_empty())
            .ok_or_else(|| "This vault does not have a valid identity for PC link.".to_string())?;
        let pending = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
            let Some(request) = pending.get(request_id).cloned() else {
                return Err(PAIRING_UNKNOWN.to_string());
            };
            if request.expires_at <= now {
                pending.remove(request_id);
                return Err(PAIRING_EXPIRED.to_string());
            }
            if request.session_epoch != session_epoch {
                pending.remove(request_id);
                return Err(SESSION_CHANGED.to_string());
            }
            if request.vault_id != vault_id {
                pending.remove(request_id);
                return Err(VAULT_CHANGED.to_string());
            }
            request
        };
        let issued = issue_client_certificate(&pending.phone_public_key)?;
        let link_id = loop {
            let candidate = random_identifier()?;
            let collision = self
                .pending_commits
                .lock()
                .map_err(|_| PENDING_UNAVAILABLE.to_string())?
                .contains_key(&candidate);
            if !collision {
                break candidate;
            }
        };
        let commit = PendingCommit::new(
            &pending,
            link_id,
            issued.certificate_authority_der,
            issued.leaf_certificate_der,
            issued.not_after_unix,
        )?;
        self.remove_pending(request_id);
        let mut pending_commits = self
            .pending_commits
            .lock()
            .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
        pending_commits.retain(|_, commit| commit.expires_at > now);
        if pending_commits.len() >= MAX_PENDING_PAIRINGS {
            return Err(TOO_MANY_PENDING.to_string());
        }
        pending_commits.insert(commit.link_id.clone(), commit.clone());
        Ok(commit)
    }

    pub fn pending_commit(&self, link_id: &str) -> Option<PendingCommit> {
        self.pending_commits
            .lock()
            .ok()
            .and_then(|commits| commits.get(link_id).cloned())
    }

    pub fn pending_commit_for_request(&self, request_id: &str) -> Option<PendingCommit> {
        self.pending_commits.lock().ok().and_then(|commits| {
            commits
                .values()
                .find(|commit| commit.request_id == request_id)
                .cloned()
        })
    }

    pub fn commit_pairing(
        &self,
        state: &VaultState,
        presence: &ReleasePresence,
        link_id: &str,
        verified_leaf_certificate_der: &[u8],
    ) -> VaultResult<ApprovedPeer> {
        self.commit_pairing_at(
            state,
            presence,
            link_id,
            verified_leaf_certificate_der,
            unix_timestamp(),
        )
    }

    pub(crate) fn commit_pairing_at(
        &self,
        state: &VaultState,
        presence: &ReleasePresence,
        link_id: &str,
        verified_leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<ApprovedPeer> {
        validate_link_id(link_id)?;
        let session_epoch = state.session_epoch();
        presence.require(session_epoch)?;
        let session = state
            .session
            .lock()
            .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
        let session = session
            .as_ref()
            .ok_or_else(|| UNLOCK_REQUIRED.to_string())?;
        if !session.setup_complete {
            return Err(SETUP_REQUIRED.to_string());
        }
        presence.require(session_epoch)?;
        let vault_id = session
            .snapshot()
            .vault_id
            .filter(|vault_id| !vault_id.is_empty())
            .ok_or_else(|| "This vault does not have a valid identity for PC link.".to_string())?;
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        if let Some(existing) = authority.find_by_link(link_id) {
            if existing.vault_id() == vault_id
                && existing.leaf_certificate_der() == verified_leaf_certificate_der
                && !existing.is_expired(now)
            {
                return Ok(existing);
            }
            return Err(ISSUED_CERTIFICATE_MISMATCH.to_string());
        }
        let commit = {
            let mut commits = self
                .pending_commits
                .lock()
                .map_err(|_| PENDING_UNAVAILABLE.to_string())?;
            let Some(commit) = commits.get(link_id).cloned() else {
                return Err(NOT_CONFIRMED.to_string());
            };
            if commit.expires_at <= now {
                commits.remove(link_id);
                return Err(PAIRING_EXPIRED.to_string());
            }
            if commit.session_epoch != session_epoch {
                commits.remove(link_id);
                return Err(SESSION_CHANGED.to_string());
            }
            if commit.vault_id != vault_id {
                commits.remove(link_id);
                return Err(VAULT_CHANGED.to_string());
            }
            if commit.leaf_certificate_der != verified_leaf_certificate_der {
                return Err(ISSUED_CERTIFICATE_MISMATCH.to_string());
            }
            let now_unix = i64::try_from(now).map_err(|_| LINK_CERTIFICATE_EXPIRED.to_string())?;
            if commit.not_after_unix <= now_unix {
                commits.remove(link_id);
                return Err(LINK_CERTIFICATE_EXPIRED.to_string());
            }
            commit
        };
        let grant = ApprovedPeer::from_pending_commit(&commit, now)?;
        let mut next_grants = authority.grants.clone();
        next_grants.retain(|existing| {
            existing.link_id() != grant.link_id()
                && !(existing.vault_id() == grant.vault_id()
                    && existing.phone_public_key_fingerprint()
                        == grant.phone_public_key_fingerprint())
        });
        next_grants.push(grant.clone());
        authority::validate_grants(&next_grants)?;
        let next_revision = authority
            .revision
            .checked_add(1)
            .ok_or_else(|| AUTHORITY_REVISION_EXHAUSTED.to_string())?;
        authority.persist(
            &self.paths.authority,
            self.protection.as_ref(),
            &next_grants,
        )?;
        authority.grants = next_grants;
        authority.revision = next_revision;
        drop(authority);
        if let Ok(mut commits) = self.pending_commits.lock() {
            commits.remove(link_id);
        }
        Ok(grant)
    }

    pub fn cancel_pairing(&self, request_id: &str) -> bool {
        let removed_pending = self.remove_pending(request_id);
        let removed_commit = self
            .pending_commits
            .lock()
            .map(|mut commits| {
                let links = commits
                    .values()
                    .filter(|commit| commit.request_id == request_id)
                    .map(|commit| commit.link_id.clone())
                    .collect::<Vec<_>>();
                let removed = !links.is_empty();
                for link_id in links {
                    commits.remove(&link_id);
                }
                removed
            })
            .unwrap_or(false);
        removed_pending || removed_commit
    }

    pub fn discard_pending_pairings(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
        if let Ok(mut commits) = self.pending_commits.lock() {
            commits.clear();
        }
    }

    pub fn approved_peers(&self, vault_id: &str) -> VaultResult<Vec<ApprovedPeer>> {
        validate_vault_id(vault_id)?;
        let authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        Ok(authority
            .grants
            .iter()
            .filter(|grant| grant.vault_id() == vault_id)
            .cloned()
            .collect())
    }

    pub fn authorize_peer(
        &self,
        vault_id: &str,
        link_id: &str,
        verified_leaf_certificate_der: &[u8],
    ) -> VaultResult<ApprovedPeer> {
        self.authorize_peer_at(
            vault_id,
            link_id,
            verified_leaf_certificate_der,
            unix_timestamp(),
        )
    }

    pub(crate) fn authorize_peer_at(
        &self,
        vault_id: &str,
        link_id: &str,
        verified_leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<ApprovedPeer> {
        validate_vault_id(vault_id)?;
        validate_link_id(link_id)?;
        let authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        authority
            .find_approved(vault_id, link_id, verified_leaf_certificate_der, now)
            .ok_or_else(|| NOT_APPROVED.to_string())
    }

    pub fn active_link_authorities(&self, vault_id: &str) -> VaultResult<Vec<Vec<u8>>> {
        validate_vault_id(vault_id)?;
        let authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        Ok(authority.active_authorities(vault_id, unix_timestamp()))
    }

    pub fn revoke_peer(&self, vault_id: &str, link_id: &str) -> VaultResult<bool> {
        validate_vault_id(vault_id)?;
        validate_link_id(link_id)?;
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        let mut next_grants = authority.grants.clone();
        next_grants.retain(|grant| !(grant.vault_id() == vault_id && grant.link_id() == link_id));
        if next_grants.len() == authority.grants.len() {
            return Ok(false);
        }
        let next_revision = authority
            .revision
            .checked_add(1)
            .ok_or_else(|| AUTHORITY_REVISION_EXHAUSTED.to_string())?;
        authority.persist(
            &self.paths.authority,
            self.protection.as_ref(),
            &next_grants,
        )?;
        authority.grants = next_grants;
        authority.revision = next_revision;
        Ok(true)
    }

    pub(crate) fn remove_authority_if_no_active(&self, now: u64) -> VaultResult<()> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| AUTHORITY_UNAVAILABLE.to_string())?;
        if authority.grants.iter().any(|grant| !grant.is_expired(now)) {
            return Ok(());
        }
        authority.grants.clear();
        match std::fs::remove_file(&self.paths.authority) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Sesame could not remove the PC link authority.".to_string()),
        }
    }

    fn remove_pending(&self, request_id: &str) -> bool {
        self.pending
            .lock()
            .map(|mut pending| pending.remove(request_id).is_some())
            .unwrap_or(false)
    }
}

fn random_identifier() -> VaultResult<String> {
    let mut bytes = [0_u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| IDENTIFIER_UNAVAILABLE.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::TestVault;
    use crate::pc_link::envelope::TestProtection;
    use rcgen::PublicKeyData;
    use std::time::{Duration, Instant};

    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sesame-pc-link-state-{name}-{}",
            random_identifier().expect("name")
        ));
        std::fs::create_dir_all(&path).expect("test directory");
        path
    }

    fn state(root: &Path) -> PcLinkState {
        PcLinkState::open_with_protection(root, Box::new(TestProtection { fail: false }))
            .expect("state")
    }

    fn phone_public_key() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("phone key");
        key.der_bytes().to_vec()
    }

    fn vault_id(vault: &TestVault) -> String {
        vault
            .state
            .session
            .lock()
            .expect("session")
            .as_ref()
            .expect("unlocked")
            .snapshot()
            .vault_id
            .expect("vault id")
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
        state: &PcLinkState,
        vault: &TestVault,
        phone_public_key: &[u8],
        now: u64,
    ) -> PendingPairing {
        state
            .begin_pairing_at(&vault.state, phone_public_key, "Fictional phone", now)
            .expect("pending")
    }

    fn confirm_attempt(
        state: &PcLinkState,
        vault: &TestVault,
        presence: &ReleasePresence,
        request_id: &str,
        now: u64,
    ) -> PendingCommit {
        state
            .confirm_pairing_at(&vault.state, presence, request_id, now)
            .expect("confirmed")
    }

    fn commit_attempt(
        state: &PcLinkState,
        vault: &TestVault,
        presence: &ReleasePresence,
        commit: &PendingCommit,
        now: u64,
    ) -> ApprovedPeer {
        state
            .commit_pairing_at(
                &vault.state,
                presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                now,
            )
            .expect("committed")
    }

    fn active(state: &PcLinkState, vault: &TestVault, now: u64) -> (PendingCommit, ApprovedPeer) {
        let phone_public_key = phone_public_key();
        let presence = presence(vault);
        let pending = begin(state, vault, &phone_public_key, now);
        let commit = confirm_attempt(state, vault, &presence, pending.request_id(), now);
        let approved = commit_attempt(state, vault, &presence, &commit, now);
        (commit, approved)
    }

    #[test]
    fn reopening_restores_the_certificate_and_active_grants() {
        let root = directory("restore");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let first = state(&root);
        let certificate = first.desktop_certificate().clone();
        let (commit, approved) = active(&first, &vault, 1_000);
        drop(first);

        let reopened = state(&root);
        assert_eq!(reopened.desktop_certificate(), &certificate);
        assert_eq!(
            reopened
                .approved_peers(approved.vault_id())
                .expect("approved peers"),
            vec![approved.clone()]
        );
        assert_eq!(
            reopened
                .authorize_peer_at(
                    approved.vault_id(),
                    approved.link_id(),
                    approved.leaf_certificate_der(),
                    1_000,
                )
                .expect("authorized"),
            approved
        );
        assert_eq!(
            reopened
                .active_link_authorities(approved.vault_id())
                .expect("authorities"),
            vec![commit.certificate_authority_der().to_vec()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn incomplete_pairing_creates_no_authority() {
        let root = directory("incomplete");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let first = state(&root);
        let phone_public_key = phone_public_key();
        let pending = begin(&first, &vault, &phone_public_key, 1_000);
        let id = vault_id(&vault);
        assert!(first
            .authorize_peer_at(&id, pending.request_id(), &[1, 2, 3], 1_000)
            .is_err());
        drop(first);

        let reopened = state(&root);
        assert!(reopened
            .approved_peers(&id)
            .expect("approved peers")
            .is_empty());
        assert!(!reopened.cancel_pairing(pending.request_id()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn confirmation_issues_public_certificates_without_snapshot_authority() {
        let root = directory("confirm");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let presence = presence(&vault);
        let phone_public_key = phone_public_key();
        let pending = begin(&pc_link, &vault, &phone_public_key, 1_000);
        let commit = confirm_attempt(&pc_link, &vault, &presence, pending.request_id(), 1_000);
        assert_eq!(commit.vault_id(), vault_id(&vault));
        assert_eq!(
            PcLinkState::selected_vault(&vault.state)
                .expect("selected vault")
                .0,
            commit.vault_id()
        );
        assert!(!commit.certificate_authority_der().is_empty());
        assert!(!commit.leaf_certificate_der().is_empty());
        assert_eq!(
            commit.phone_public_key_fingerprint(),
            &PhonePublicKeyFingerprint::from_phone_public_key(&phone_public_key)
        );
        assert!(pc_link
            .active_link_authorities(commit.vault_id())
            .expect("authorities")
            .is_empty());
        assert!(pc_link
            .authorize_peer_at(
                commit.vault_id(),
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .is_err());
        assert_eq!(
            pc_link.pending_commit(commit.link_id()),
            Some(commit.clone())
        );
        assert_eq!(
            pc_link.pending_commit_for_request(commit.request_id()),
            Some(commit.clone())
        );
        let approved = commit_attempt(&pc_link, &vault, &presence, &commit, 1_000);
        assert_eq!(approved.link_id(), commit.link_id());
        assert_eq!(pc_link.pending_commit(commit.link_id()), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pending_pairings_expire_and_are_rate_limited() {
        let root = directory("pending");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let presence = presence(&vault);
        let request = begin(&pc_link, &vault, &phone_public_key(), 1_000);
        assert_eq!(
            pc_link
                .confirm_pairing_at(
                    &vault.state,
                    &presence,
                    request.request_id(),
                    1_000 + PENDING_PAIRING_TTL_SECONDS,
                )
                .err(),
            Some(PAIRING_EXPIRED.to_string())
        );

        for index in 0..MAX_PAIRING_REQUESTS_PER_WINDOW {
            let request = pc_link
                .begin_pairing_at(
                    &vault.state,
                    &phone_public_key(),
                    &format!("Fictional phone {index}"),
                    2_000,
                )
                .expect("pending");
            pc_link.cancel_pairing(request.request_id());
        }
        assert_eq!(
            pc_link
                .begin_pairing_at(&vault.state, &phone_public_key(), "Fictional phone", 2_000,)
                .err(),
            Some(PAIRING_RATE_LIMITED.to_string())
        );
        assert!(pc_link
            .begin_pairing_at(
                &vault.state,
                &phone_public_key(),
                "Fictional phone",
                2_000 + PAIRING_RATE_WINDOW_SECONDS,
            )
            .is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn confirmation_and_commit_require_current_release_presence() {
        let root = directory("presence");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let phone_public_key = phone_public_key();
        let pending = begin(&pc_link, &vault, &phone_public_key, 1_000);
        let no_presence = ReleasePresence::default();
        assert!(pc_link
            .confirm_pairing_at(&vault.state, &no_presence, pending.request_id(), 1_000)
            .is_err());
        let presence = presence(&vault);
        let commit = confirm_attempt(&pc_link, &vault, &presence, pending.request_id(), 1_000);
        assert!(pc_link
            .commit_pairing_at(
                &vault.state,
                &no_presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .is_err());
        assert!(pc_link
            .commit_pairing_at(
                &vault.state,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_requires_the_exact_issued_leaf_and_is_idempotent() {
        let root = directory("commit");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let presence = presence(&vault);
        let pending = begin(&pc_link, &vault, &phone_public_key(), 1_000);
        let commit = confirm_attempt(&pc_link, &vault, &presence, pending.request_id(), 1_000);
        assert!(pc_link
            .commit_pairing_at(&vault.state, &presence, commit.link_id(), &[1, 2, 3], 1_000,)
            .is_err());
        let approved = commit_attempt(&pc_link, &vault, &presence, &commit, 1_000);
        assert_eq!(
            pc_link
                .commit_pairing_at(
                    &vault.state,
                    &presence,
                    commit.link_id(),
                    commit.leaf_certificate_der(),
                    1_000,
                )
                .expect("idempotent"),
            approved
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repairing_the_same_phone_replaces_the_old_link() {
        let root = directory("replace");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let phone_public_key = phone_public_key();
        let presence = presence(&vault);
        let first_pending = begin(&pc_link, &vault, &phone_public_key, 1_000);
        let first_commit = confirm_attempt(
            &pc_link,
            &vault,
            &presence,
            first_pending.request_id(),
            1_000,
        );
        let first = commit_attempt(&pc_link, &vault, &presence, &first_commit, 1_000);
        let second_pending = begin(&pc_link, &vault, &phone_public_key, 2_000);
        let second_commit = confirm_attempt(
            &pc_link,
            &vault,
            &presence,
            second_pending.request_id(),
            2_000,
        );
        let second = commit_attempt(&pc_link, &vault, &presence, &second_commit, 2_000);
        let peers = pc_link
            .approved_peers(first.vault_id())
            .expect("approved peers");
        assert_eq!(peers, vec![second.clone()]);
        assert_ne!(first.link_id(), second.link_id());
        assert!(pc_link
            .authorize_peer_at(
                first.vault_id(),
                first.link_id(),
                first.leaf_certificate_der(),
                2_000,
            )
            .is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn revoke_is_vault_and_link_scoped_and_invalidates_access() {
        let root = directory("revoke");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let presence = presence(&vault);
        let first_pending = begin(&pc_link, &vault, &phone_public_key(), 1_000);
        let first_commit = confirm_attempt(
            &pc_link,
            &vault,
            &presence,
            first_pending.request_id(),
            1_000,
        );
        let first = commit_attempt(&pc_link, &vault, &presence, &first_commit, 1_000);
        let second_pending = begin(&pc_link, &vault, &phone_public_key(), 1_000);
        let second_commit = confirm_attempt(
            &pc_link,
            &vault,
            &presence,
            second_pending.request_id(),
            1_000,
        );
        let second = commit_attempt(&pc_link, &vault, &presence, &second_commit, 1_000);
        assert!(!pc_link
            .revoke_peer("vault-other", first.link_id())
            .expect("unrelated revoke"));
        assert!(pc_link
            .revoke_peer(first.vault_id(), first.link_id())
            .expect("revoked"));
        assert!(pc_link
            .authorize_peer_at(
                first.vault_id(),
                first.link_id(),
                first.leaf_certificate_der(),
                1_000,
            )
            .is_err());
        assert!(pc_link
            .authorize_peer_at(
                second.vault_id(),
                second.link_id(),
                second.leaf_certificate_der(),
                1_000,
            )
            .is_ok());
        assert!(!pc_link
            .revoke_peer(first.vault_id(), first.link_id())
            .expect("idempotent revoke"));
        drop(pc_link);

        let reopened = state(&root);
        assert!(reopened
            .authorize_peer_at(
                second.vault_id(),
                second.link_id(),
                second.leaf_certificate_der(),
                1_000,
            )
            .is_ok());
        assert!(reopened
            .authorize_peer_at(
                first.vault_id(),
                first.link_id(),
                first.leaf_certificate_der(),
                1_000,
            )
            .is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn locking_invalidates_pending_and_confirmed_attempts() {
        let root = directory("lock");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        let presence = presence(&vault);
        let pending = begin(&pc_link, &vault, &phone_public_key(), 1_000);
        let commit = confirm_attempt(&pc_link, &vault, &presence, pending.request_id(), 1_000);
        let epoch = vault.state.session_epoch();
        vault.state.lock_for_lifecycle().expect("locked");
        assert_ne!(vault.state.session_epoch(), epoch);
        assert!(pc_link
            .begin_pairing_at(&vault.state, &phone_public_key(), "Fictional phone", 1_000,)
            .is_err());
        assert!(pc_link
            .commit_pairing_at(
                &vault.state,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .is_err());
        pc_link.discard_pending_pairings();
        assert_eq!(pc_link.pending_commit(commit.link_id()), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn state_is_send_and_sync_for_tauri_glue() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PcLinkState>();
    }

    #[test]
    fn pending_and_confirmed_attempts_do_not_survive_reopen() {
        let root = directory("restart");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let first = state(&root);
        let presence = presence(&vault);
        let pending = begin(&first, &vault, &phone_public_key(), 1_000);
        let commit = confirm_attempt(&first, &vault, &presence, pending.request_id(), 1_000);
        drop(first);

        let reopened = state(&root);
        assert_eq!(reopened.pending_commit(commit.link_id()), None);
        assert!(reopened
            .approved_peers(&vault_id(&vault))
            .expect("approved peers")
            .is_empty());
        assert!(reopened
            .authorize_peer_at(
                &vault_id(&vault),
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_identity_with_active_links_fails_closed() {
        let root = directory("identity-loss");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let first = state(&root);
        let _ = active(&first, &vault, 1_000);
        drop(first);
        std::fs::remove_file(root.join("pc-link").join("identity.sesame"))
            .expect("identity removed");
        assert!(
            PcLinkState::open_with_protection(&root, Box::new(TestProtection { fail: false }))
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_phone_inputs_are_rejected() {
        let root = directory("inputs");
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let pc_link = state(&root);
        assert!(pc_link
            .begin_pairing_at(&vault.state, &[4; 64], "Fictional phone", 1_000)
            .is_err());
        assert!(pc_link
            .begin_pairing_at(&vault.state, &[5; 65], "Fictional phone", 1_000)
            .is_err());
        assert!(pc_link
            .begin_pairing_at(
                &vault.state,
                &phone_public_key(),
                &"a".repeat(MAX_PHONE_LABEL_CHARS + 1),
                1_000,
            )
            .is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
