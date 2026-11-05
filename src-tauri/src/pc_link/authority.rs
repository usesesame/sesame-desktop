use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::envelope::{
    invalid_state, newer_state, open, read_optional, seal, write_failed, write_private,
    DeviceProtection,
};
use super::fingerprint::{CertificateFingerprint, PhonePublicKeyFingerprint};
use super::{
    MAX_APPROVED_PEERS, MAX_APPROVED_PEERS_PER_VAULT, MAX_LINK_CERTIFICATE_BYTES,
    MAX_PEER_VAULT_ID_CHARS, MAX_PHONE_LABEL_CHARS, MAX_PHONE_PUBLIC_KEY_BYTES,
};
use crate::vault::VaultResult;

const AUTHORITY_VERSION: u8 = 1;
const AUTHORITY_TAG_LABEL: &[u8] = b"sesame-pc-link-authority-v1";
const AUTHORITY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const LINK_ID_BYTES: usize = 22;
const MAX_CERTIFICATE_VALIDITY_SECONDS: i64 = 100 * 365 * 24 * 60 * 60;

const TOO_MANY_PEERS: &str = "Too many phones are already linked. Revoke one first.";
const TOO_MANY_PEERS_FOR_VAULT: &str =
    "Too many phones are linked to this vault. Revoke one first.";
const INVALID_PHONE_PUBLIC_KEY: &str = "The phone public key is not a valid P-256 public key.";
const INVALID_LINK_CERTIFICATE: &str = "The PC link certificate is not valid.";
const INVALID_VAULT_ID: &str = "The vault identifier is not valid for PC link.";
const INVALID_LINK_ID: &str = "The link identifier is not valid.";
const INVALID_LABEL: &str = "The phone label is not valid.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPairing {
    pub(crate) request_id: String,
    pub(crate) vault_id: String,
    pub(crate) session_epoch: u64,
    pub(crate) label: String,
    pub(crate) phone_public_key: Vec<u8>,
    pub(crate) phone_public_key_fingerprint: PhonePublicKeyFingerprint,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
}

impl PendingPairing {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn phone_public_key(&self) -> &[u8] {
        &self.phone_public_key
    }

    pub fn phone_public_key_fingerprint(&self) -> &PhonePublicKeyFingerprint {
        &self.phone_public_key_fingerprint
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn new(
        request_id: String,
        vault_id: String,
        session_epoch: u64,
        label: String,
        phone_public_key: Vec<u8>,
        created_at: u64,
        expires_at: u64,
    ) -> VaultResult<Self> {
        validate_vault_id(&vault_id)?;
        validate_phone_label(&label)?;
        validate_phone_public_key(&phone_public_key)?;
        if expires_at <= created_at {
            return Err("The pairing request does not have a valid lifetime.".to_string());
        }
        let phone_public_key_fingerprint =
            PhonePublicKeyFingerprint::from_phone_public_key(&phone_public_key);
        Ok(Self {
            request_id,
            vault_id,
            session_epoch,
            label,
            phone_public_key,
            phone_public_key_fingerprint,
            created_at,
            expires_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommit {
    pub(crate) request_id: String,
    pub(crate) link_id: String,
    pub(crate) vault_id: String,
    pub(crate) session_epoch: u64,
    pub(crate) label: String,
    pub(crate) phone_public_key: Vec<u8>,
    pub(crate) phone_public_key_fingerprint: PhonePublicKeyFingerprint,
    pub(crate) certificate_authority_der: Vec<u8>,
    pub(crate) leaf_certificate_der: Vec<u8>,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) not_after_unix: i64,
}

impl PendingCommit {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn link_id(&self) -> &str {
        &self.link_id
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn phone_public_key(&self) -> &[u8] {
        &self.phone_public_key
    }

    pub fn phone_public_key_fingerprint(&self) -> &PhonePublicKeyFingerprint {
        &self.phone_public_key_fingerprint
    }

    pub fn certificate_authority_der(&self) -> &[u8] {
        &self.certificate_authority_der
    }

    pub fn leaf_certificate_der(&self) -> &[u8] {
        &self.leaf_certificate_der
    }

    pub fn leaf_certificate_fingerprint(&self) -> CertificateFingerprint {
        CertificateFingerprint::from_der(&self.leaf_certificate_der)
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }

    pub(crate) fn new(
        pending: &PendingPairing,
        link_id: String,
        certificate_authority_der: Vec<u8>,
        leaf_certificate_der: Vec<u8>,
        not_after_unix: i64,
    ) -> VaultResult<Self> {
        validate_link_id(&link_id)?;
        validate_link_certificate(&certificate_authority_der)?;
        validate_link_certificate(&leaf_certificate_der)?;
        let created_at =
            i64::try_from(pending.created_at).map_err(|_| INVALID_LINK_CERTIFICATE.to_string())?;
        if not_after_unix <= created_at {
            return Err(INVALID_LINK_CERTIFICATE.to_string());
        }
        Ok(Self {
            request_id: pending.request_id.clone(),
            link_id,
            vault_id: pending.vault_id.clone(),
            session_epoch: pending.session_epoch,
            label: pending.label.clone(),
            phone_public_key: pending.phone_public_key.clone(),
            phone_public_key_fingerprint: pending.phone_public_key_fingerprint,
            certificate_authority_der,
            leaf_certificate_der,
            created_at: pending.created_at,
            expires_at: pending.expires_at,
            not_after_unix,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedPeer {
    link_id: String,
    vault_id: String,
    label: String,
    certificate_authority_der: Vec<u8>,
    leaf_certificate_der: Vec<u8>,
    phone_public_key_fingerprint: PhonePublicKeyFingerprint,
    approved_at: u64,
    not_after_unix: i64,
}

impl ApprovedPeer {
    pub fn link_id(&self) -> &str {
        &self.link_id
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn certificate_authority_der(&self) -> &[u8] {
        &self.certificate_authority_der
    }

    pub fn leaf_certificate_der(&self) -> &[u8] {
        &self.leaf_certificate_der
    }

    pub fn phone_public_key_fingerprint(&self) -> &PhonePublicKeyFingerprint {
        &self.phone_public_key_fingerprint
    }

    pub fn leaf_certificate_fingerprint(&self) -> CertificateFingerprint {
        CertificateFingerprint::from_der(&self.leaf_certificate_der)
    }

    pub fn approved_at(&self) -> u64 {
        self.approved_at
    }

    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.not_after_unix <= 0 || (self.not_after_unix as u64) <= now
    }

    pub(crate) fn from_pending_commit(
        pending: &PendingCommit,
        approved_at: u64,
    ) -> VaultResult<Self> {
        validate_link_id(&pending.link_id)?;
        validate_vault_id(&pending.vault_id)?;
        validate_phone_label(&pending.label)?;
        validate_link_certificate(&pending.certificate_authority_der)?;
        validate_link_certificate(&pending.leaf_certificate_der)?;
        Ok(Self {
            link_id: pending.link_id.clone(),
            vault_id: pending.vault_id.clone(),
            label: pending.label.clone(),
            certificate_authority_der: pending.certificate_authority_der.clone(),
            leaf_certificate_der: pending.leaf_certificate_der.clone(),
            phone_public_key_fingerprint: pending.phone_public_key_fingerprint,
            approved_at,
            not_after_unix: pending.not_after_unix,
        })
    }

    pub(crate) fn matches(
        &self,
        vault_id: &str,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> bool {
        self.vault_id == vault_id
            && self.link_id == link_id
            && self.leaf_certificate_der == leaf_certificate_der
            && !self.is_expired(now)
    }
}

pub(crate) struct AuthorityStore {
    pub(crate) grants: Vec<ApprovedPeer>,
    pub(crate) revision: u64,
}

impl AuthorityStore {
    pub(crate) fn empty() -> Self {
        Self {
            grants: Vec::new(),
            revision: 0,
        }
    }

    pub(crate) fn load(path: &Path, protection: &dyn DeviceProtection) -> VaultResult<Self> {
        let Some(bytes) = read_optional(path, AUTHORITY_MAX_BYTES)? else {
            return Ok(Self::empty());
        };
        let body = open(protection, AUTHORITY_TAG_LABEL, &bytes)?;
        let stored: StoredAuthority = serde_json::from_slice(&body).map_err(|_| invalid_state())?;
        if stored.version != AUTHORITY_VERSION {
            return Err(newer_state());
        }
        let grants = stored
            .grants
            .into_iter()
            .map(ApprovedPeer::try_from)
            .collect::<VaultResult<Vec<_>>>()?;
        validate_grants(&grants)?;
        Ok(Self {
            grants,
            revision: 0,
        })
    }

    pub(crate) fn persist(
        &self,
        path: &Path,
        protection: &dyn DeviceProtection,
        grants: &[ApprovedPeer],
    ) -> VaultResult<()> {
        validate_grants(grants)?;
        let stored = StoredAuthority {
            version: AUTHORITY_VERSION,
            grants: grants.iter().map(StoredGrant::from).collect(),
        };
        let body = serde_json::to_vec(&stored).map_err(|_| write_failed())?;
        let sealed = seal(protection, AUTHORITY_TAG_LABEL, &body)?;
        write_private(path, &sealed)
    }

    pub(crate) fn find_approved(
        &self,
        vault_id: &str,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> Option<ApprovedPeer> {
        self.grants
            .iter()
            .find(|grant| grant.matches(vault_id, link_id, leaf_certificate_der, now))
            .cloned()
    }

    pub(crate) fn is_approved(
        &self,
        vault_id: &str,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.matches(vault_id, link_id, leaf_certificate_der, now))
    }

    pub(crate) fn find_by_link(&self, link_id: &str) -> Option<ApprovedPeer> {
        self.grants
            .iter()
            .find(|grant| grant.link_id == link_id)
            .cloned()
    }

    pub(crate) fn active_authorities(&self, vault_id: &str, now: u64) -> Vec<Vec<u8>> {
        let mut authorities = Vec::new();
        for grant in &self.grants {
            if grant.vault_id == vault_id
                && !grant.is_expired(now)
                && !authorities
                    .iter()
                    .any(|der: &Vec<u8>| der == &grant.certificate_authority_der)
            {
                authorities.push(grant.certificate_authority_der.clone());
            }
        }
        authorities
    }

    pub(crate) fn all_active_authorities(&self, now: u64) -> Vec<Vec<u8>> {
        let mut authorities = Vec::new();
        for grant in &self.grants {
            if !grant.is_expired(now)
                && !authorities
                    .iter()
                    .any(|der: &Vec<u8>| der == &grant.certificate_authority_der)
            {
                authorities.push(grant.certificate_authority_der.clone());
            }
        }
        authorities
    }
}

pub(crate) fn validate_vault_id(vault_id: &str) -> VaultResult<()> {
    if vault_id.is_empty()
        || vault_id.chars().count() > MAX_PEER_VAULT_ID_CHARS
        || vault_id.chars().any(char::is_control)
    {
        return Err(INVALID_VAULT_ID.to_string());
    }
    Ok(())
}

pub(crate) fn validate_phone_label(label: &str) -> VaultResult<()> {
    if label.chars().count() > MAX_PHONE_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(INVALID_LABEL.to_string());
    }
    Ok(())
}

pub(crate) fn validate_phone_public_key(phone_public_key: &[u8]) -> VaultResult<()> {
    if phone_public_key.len() != MAX_PHONE_PUBLIC_KEY_BYTES || phone_public_key[0] != 0x04 {
        return Err(INVALID_PHONE_PUBLIC_KEY.to_string());
    }
    Ok(())
}

pub(crate) fn validate_link_id(link_id: &str) -> VaultResult<()> {
    if link_id.len() != LINK_ID_BYTES
        || !link_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(INVALID_LINK_ID.to_string());
    }
    Ok(())
}

pub(crate) fn validate_link_certificate(certificate_der: &[u8]) -> VaultResult<()> {
    if certificate_der.is_empty() || certificate_der.len() > MAX_LINK_CERTIFICATE_BYTES {
        return Err(INVALID_LINK_CERTIFICATE.to_string());
    }
    Ok(())
}

pub(crate) fn validate_grants(grants: &[ApprovedPeer]) -> VaultResult<()> {
    if grants.len() > MAX_APPROVED_PEERS {
        return Err(TOO_MANY_PEERS.to_string());
    }
    for (index, grant) in grants.iter().enumerate() {
        let same_vault = grants[..index]
            .iter()
            .filter(|other| other.vault_id == grant.vault_id)
            .count();
        if same_vault >= MAX_APPROVED_PEERS_PER_VAULT {
            return Err(TOO_MANY_PEERS_FOR_VAULT.to_string());
        }
        if grants[..index]
            .iter()
            .any(|other| other.link_id == grant.link_id)
        {
            return Err("This link identifier is already active.".to_string());
        }
        if grants[..index].iter().any(|other| {
            other.vault_id == grant.vault_id
                && other.phone_public_key_fingerprint == grant.phone_public_key_fingerprint
        }) {
            return Err("This phone is already linked to this vault.".to_string());
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAuthority {
    version: u8,
    grants: Vec<StoredGrant>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredGrant {
    link_id: String,
    vault_id: String,
    label: String,
    certificate_authority_der: String,
    leaf_certificate_der: String,
    phone_public_key_fingerprint_sha256: String,
    approved_at: u64,
    not_after_unix: i64,
}

impl From<&ApprovedPeer> for StoredGrant {
    fn from(peer: &ApprovedPeer) -> Self {
        Self {
            link_id: peer.link_id.clone(),
            vault_id: peer.vault_id.clone(),
            label: peer.label.clone(),
            certificate_authority_der: URL_SAFE_NO_PAD.encode(&peer.certificate_authority_der),
            leaf_certificate_der: URL_SAFE_NO_PAD.encode(&peer.leaf_certificate_der),
            phone_public_key_fingerprint_sha256: peer.phone_public_key_fingerprint.to_hex(),
            approved_at: peer.approved_at,
            not_after_unix: peer.not_after_unix,
        }
    }
}

impl TryFrom<StoredGrant> for ApprovedPeer {
    type Error = String;

    fn try_from(stored: StoredGrant) -> VaultResult<Self> {
        validate_link_id(&stored.link_id)?;
        validate_vault_id(&stored.vault_id)?;
        validate_phone_label(&stored.label)?;
        let certificate_authority_der = URL_SAFE_NO_PAD
            .decode(stored.certificate_authority_der.as_bytes())
            .map_err(|_| invalid_state())?;
        let leaf_certificate_der = URL_SAFE_NO_PAD
            .decode(stored.leaf_certificate_der.as_bytes())
            .map_err(|_| invalid_state())?;
        validate_link_certificate(&certificate_authority_der)?;
        validate_link_certificate(&leaf_certificate_der)?;
        let phone_public_key_fingerprint =
            PhonePublicKeyFingerprint::from_hex(&stored.phone_public_key_fingerprint_sha256)?;
        let approved_at = i64::try_from(stored.approved_at).map_err(|_| invalid_state())?;
        let validity = stored
            .not_after_unix
            .checked_sub(approved_at)
            .ok_or_else(|| INVALID_LINK_CERTIFICATE.to_string())?;
        if validity <= 0 || validity > MAX_CERTIFICATE_VALIDITY_SECONDS {
            return Err(INVALID_LINK_CERTIFICATE.to_string());
        }
        Ok(Self {
            link_id: stored.link_id,
            vault_id: stored.vault_id,
            label: stored.label,
            certificate_authority_der,
            leaf_certificate_der,
            phone_public_key_fingerprint,
            approved_at: stored.approved_at,
            not_after_unix: stored.not_after_unix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pc_link::envelope::{ForeignProtection, TestProtection};

    fn directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sesame-pc-link-authority-{name}-{}",
            crate::vault::random_id()
        ));
        std::fs::create_dir_all(&path).expect("test directory");
        path
    }

    fn link_id() -> String {
        let mut bytes = [0_u8; 16];
        crate::vault::fill_random(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn grant(vault_id: &str, _link_seed: &str, seed: u8, not_after: i64) -> ApprovedPeer {
        ApprovedPeer {
            link_id: link_id(),
            vault_id: vault_id.to_string(),
            label: format!("Fictional phone {seed}"),
            certificate_authority_der: vec![seed, 1, 2],
            leaf_certificate_der: vec![seed, 3, 4],
            phone_public_key_fingerprint: PhonePublicKeyFingerprint::from_bytes(&[seed, 5, 6]),
            approved_at: 100,
            not_after_unix: not_after,
        }
    }

    fn pending_commit() -> PendingCommit {
        PendingCommit {
            request_id: crate::vault::random_id(),
            link_id: link_id(),
            vault_id: "vault-fictional".to_string(),
            session_epoch: 7,
            label: "Fictional phone".to_string(),
            phone_public_key: vec![4; 65],
            phone_public_key_fingerprint: PhonePublicKeyFingerprint::from_bytes(&[4; 65]),
            certificate_authority_der: vec![1, 2, 3],
            leaf_certificate_der: vec![4, 5, 6],
            created_at: 100,
            expires_at: 200,
            not_after_unix: 1_000,
        }
    }

    #[test]
    fn approved_grants_round_trip_and_match_exact_links() {
        let dir = directory("roundtrip");
        let path = dir.join("authority.sesame");
        let protection = TestProtection { fail: false };
        let grant = grant("vault-fictional", "one", 1, 10_000);
        let authority = AuthorityStore::empty();
        authority
            .persist(&path, &protection, std::slice::from_ref(&grant))
            .expect("persisted");

        let loaded = AuthorityStore::load(&path, &protection).expect("loaded");
        assert_eq!(loaded.grants, vec![grant.clone()]);
        assert!(loaded.is_approved(
            "vault-fictional",
            grant.link_id(),
            grant.leaf_certificate_der(),
            1_000
        ));
        assert!(!loaded.is_approved(
            "vault-fictional",
            &link_id(),
            grant.leaf_certificate_der(),
            1_000
        ));
        assert!(!loaded.is_approved(
            "vault-other",
            grant.link_id(),
            grant.leaf_certificate_der(),
            1_000
        ));
        assert!(grant.is_expired(20_000));
        assert!(!loaded.is_approved(
            "vault-fictional",
            grant.link_id(),
            grant.leaf_certificate_der(),
            20_000
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn altered_public_certificate_values_fail_authentication() {
        let dir = directory("altered-certificate");
        let path = dir.join("authority.sesame");
        let protection = TestProtection { fail: false };
        let grant = grant("vault-fictional", "altered", 3, 10_000);
        let mut stored = StoredGrant::from(&grant);
        stored.leaf_certificate_der = URL_SAFE_NO_PAD.encode([9_u8, 9, 9]);
        let body = serde_json::to_vec(&StoredAuthority {
            version: AUTHORITY_VERSION,
            grants: vec![stored],
        })
        .expect("body");
        let sealed = seal(&ForeignProtection, AUTHORITY_TAG_LABEL, &body).expect("sealed");
        write_private(&path, &sealed).expect("written");
        assert_eq!(
            AuthorityStore::load(&path, &protection).err(),
            Some(crate::pc_link::envelope::INVALID_STATE.to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_and_unknown_versions_fail_closed() {
        let dir = directory("tampered");
        let path = dir.join("authority.sesame");
        let protection = TestProtection { fail: false };
        let grant = grant("vault-fictional", "tampered", 5, 10_000);
        let authority = AuthorityStore::empty();
        authority
            .persist(&path, &protection, std::slice::from_ref(&grant))
            .expect("persisted");

        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).expect("tampered");
        assert_eq!(
            AuthorityStore::load(&path, &protection).err(),
            Some(crate::pc_link::envelope::INVALID_STATE.to_string())
        );

        let stored = StoredAuthority {
            version: AUTHORITY_VERSION + 1,
            grants: vec![StoredGrant::from(&grant)],
        };
        let body = serde_json::to_vec(&stored).expect("body");
        let sealed = seal(&protection, AUTHORITY_TAG_LABEL, &body).expect("sealed");
        write_private(&path, &sealed).expect("written");
        assert_eq!(
            AuthorityStore::load(&path, &protection).err(),
            Some(crate::pc_link::envelope::NEWER_STATE.to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_authority_reads_as_an_error_not_an_empty_grant() {
        let dir = directory("malformed");
        let path = dir.join("authority.sesame");
        let protection = TestProtection { fail: false };
        std::fs::write(&path, b"not-json").expect("written");
        assert!(AuthorityStore::load(&path, &protection).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn grant_counts_are_bounded_per_vault_and_in_total() {
        let one_vault = (0..=MAX_APPROVED_PEERS_PER_VAULT)
            .map(|index| grant("vault-fictional", "one-vault", index as u8, 10_000))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_grants(&one_vault).err(),
            Some(TOO_MANY_PEERS_FOR_VAULT.to_string())
        );

        let total = (0..=MAX_APPROVED_PEERS)
            .map(|index| {
                grant(
                    &format!("vault-{}", index / MAX_APPROVED_PEERS_PER_VAULT),
                    "total",
                    index as u8,
                    10_000,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            validate_grants(&total).err(),
            Some(TOO_MANY_PEERS.to_string())
        );
    }

    #[test]
    fn existing_core_vault_ids_are_accepted_and_preserved() {
        let vault_id = "629onBLQlMmpPc4H";
        assert_eq!(vault_id.len(), 16);
        assert!(validate_vault_id(vault_id).is_ok());
        assert!(validate_vault_id(&"a".repeat(MAX_PEER_VAULT_ID_CHARS)).is_ok());
        assert!(validate_vault_id(&"a".repeat(MAX_PEER_VAULT_ID_CHARS + 1)).is_err());
        assert!(validate_vault_id("fictional\u{0007}").is_err());

        let dir = directory("opaque-vault-id");
        let path = dir.join("authority.sesame");
        let protection = TestProtection { fail: false };
        let grant = grant(vault_id, "opaque", 1, 10_000);
        let authority = AuthorityStore::empty();
        authority
            .persist(&path, &protection, std::slice::from_ref(&grant))
            .expect("persisted");
        let loaded = AuthorityStore::load(&path, &protection).expect("loaded");
        assert_eq!(loaded.grants[0].vault_id(), vault_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_link_ids_and_phone_keys_are_rejected() {
        let grant = grant("vault-fictional", "duplicate", 7, 10_000);
        let duplicate_link = grant.clone();
        assert_eq!(
            validate_grants(&[grant.clone(), duplicate_link]).err(),
            Some("This link identifier is already active.".to_string())
        );
        let mut duplicate_phone = grant.clone();
        duplicate_phone.link_id = link_id();
        assert_eq!(
            validate_grants(&[grant, duplicate_phone]).err(),
            Some("This phone is already linked to this vault.".to_string())
        );
    }

    #[test]
    fn pending_commit_requires_bounded_public_values() {
        let mut pending = pending_commit();
        pending.link_id = "short".to_string();
        assert!(validate_link_id(&pending.link_id).is_err());
        assert!(validate_phone_public_key(&[4; 64]).is_err());
        assert!(validate_phone_public_key(&[5; 65]).is_err());
        assert!(validate_phone_label(&"a".repeat(MAX_PHONE_LABEL_CHARS + 1)).is_err());
        pending.link_id = link_id();
        assert!(PendingCommit::new(
            &PendingPairing::new(
                crate::vault::random_id(),
                pending.vault_id.clone(),
                7,
                pending.label.clone(),
                pending.phone_public_key.clone(),
                100,
                200
            )
            .expect("pending"),
            pending.link_id.clone(),
            pending.certificate_authority_der.clone(),
            pending.leaf_certificate_der.clone(),
            pending.not_after_unix
        )
        .is_ok());
    }
}
