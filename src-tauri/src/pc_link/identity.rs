use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Datelike, TimeDelta};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::envelope::{
    invalid_state, newer_state, open, read_optional, seal, write_failed, write_private,
    DeviceProtection,
};
use super::fingerprint::CertificateFingerprint;
use super::PC_LINK_SERVICE_NAME;
use crate::vault::{unix_timestamp, VaultResult};

const IDENTITY_VERSION: u8 = 1;
const IDENTITY_TAG_LABEL: &[u8] = b"sesame-pc-link-identity-v1";
const IDENTITY_MAX_BYTES: u64 = 256 * 1024;
const MAX_DESKTOP_CERTIFICATE_BYTES: usize = 16 * 1024;
const DESKTOP_CERTIFICATE_VALIDITY_DAYS: i64 = 3650;
const MAX_DESKTOP_IDENTITY_VALIDITY_SECONDS: i64 = 100 * 365 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: u64 = 24 * 60 * 60;

const IDENTITY_EXPIRED: &str = "The PC link identity has expired. Pair again.";
const IDENTITY_NOT_YET_VALID: &str = "The PC link identity is not valid yet.";
const IDENTITY_GENERATE_FAILED: &str = "Sesame could not create the PC link identity.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopCertificate {
    service_name: String,
    certificate_der: Vec<u8>,
    fingerprint: CertificateFingerprint,
    not_before_unix: i64,
    not_after_unix: i64,
}

impl DesktopCertificate {
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn fingerprint(&self) -> &CertificateFingerprint {
        &self.fingerprint
    }

    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint.to_hex()
    }

    pub fn not_before_unix(&self) -> i64 {
        self.not_before_unix
    }

    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }
}

pub(crate) struct DesktopIdentity {
    certificate: DesktopCertificate,
    #[allow(dead_code)]
    private_key_der: Zeroizing<Vec<u8>>,
}

impl DesktopIdentity {
    pub(crate) fn certificate(&self) -> &DesktopCertificate {
        &self.certificate
    }

    #[allow(dead_code)]
    pub(crate) fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }
}

pub(crate) fn load_identity(
    path: &Path,
    protection: &dyn DeviceProtection,
) -> VaultResult<Option<DesktopIdentity>> {
    let Some(bytes) = read_optional(path, IDENTITY_MAX_BYTES)? else {
        return Ok(None);
    };
    let body = open(protection, IDENTITY_TAG_LABEL, &bytes)?;
    let stored: StoredIdentity = serde_json::from_slice(&body).map_err(|_| invalid_state())?;
    if stored.version != IDENTITY_VERSION {
        return Err(newer_state());
    }
    if stored.service_name != PC_LINK_SERVICE_NAME {
        return Err(invalid_state());
    }
    let certificate_der = URL_SAFE_NO_PAD
        .decode(stored.certificate_der.as_bytes())
        .map_err(|_| invalid_state())?;
    if certificate_der.is_empty() || certificate_der.len() > MAX_DESKTOP_CERTIFICATE_BYTES {
        return Err(invalid_state());
    }
    let fingerprint = CertificateFingerprint::from_hex(&stored.fingerprint_sha256)?;
    if CertificateFingerprint::from_der(&certificate_der) != fingerprint {
        return Err(invalid_state());
    }
    validate_validity(stored.not_before_unix, stored.not_after_unix)?;

    let protected_key = URL_SAFE_NO_PAD
        .decode(stored.protected_private_key.as_bytes())
        .map_err(|_| invalid_state())?;
    let private_key_der = Zeroizing::new(
        protection
            .unprotect(&protected_key)
            .map_err(|_| invalid_state())?,
    );
    validate_private_key(&private_key_der)?;

    Ok(Some(DesktopIdentity {
        certificate: DesktopCertificate {
            service_name: stored.service_name,
            certificate_der,
            fingerprint,
            not_before_unix: stored.not_before_unix,
            not_after_unix: stored.not_after_unix,
        },
        private_key_der,
    }))
}

pub(crate) fn create_identity(
    path: &Path,
    protection: &dyn DeviceProtection,
) -> VaultResult<DesktopIdentity> {
    let mut key = KeyPair::generate().map_err(|_| IDENTITY_GENERATE_FAILED.to_string())?;
    let key_der = Zeroizing::new(key.serialize_der());
    let now = chrono::Utc::now();
    let not_before_time = now
        .checked_sub_signed(
            TimeDelta::try_days(1).ok_or_else(|| IDENTITY_GENERATE_FAILED.to_string())?,
        )
        .ok_or_else(|| IDENTITY_GENERATE_FAILED.to_string())?;
    let not_after_time = now
        .checked_add_signed(
            TimeDelta::try_days(DESKTOP_CERTIFICATE_VALIDITY_DAYS)
                .ok_or_else(|| IDENTITY_GENERATE_FAILED.to_string())?,
        )
        .ok_or_else(|| IDENTITY_GENERATE_FAILED.to_string())?;
    let not_before = rcgen::date_time_ymd(
        not_before_time.year(),
        not_before_time.month() as u8,
        not_before_time.day() as u8,
    );
    let not_after = rcgen::date_time_ymd(
        not_after_time.year(),
        not_after_time.month() as u8,
        not_after_time.day() as u8,
    );

    let mut params = CertificateParams::new(vec![PC_LINK_SERVICE_NAME.to_string()])
        .map_err(|_| IDENTITY_GENERATE_FAILED.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, PC_LINK_SERVICE_NAME);
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let certificate = params
        .self_signed(&key)
        .map_err(|_| IDENTITY_GENERATE_FAILED.to_string())?;
    let certificate_der = certificate.der().to_vec();
    key.zeroize();

    let not_before_unix = not_before.unix_timestamp();
    let not_after_unix = not_after.unix_timestamp();
    validate_validity(not_before_unix, not_after_unix)?;
    let fingerprint = CertificateFingerprint::from_der(&certificate_der);
    let protected_private_key = protection.protect(&key_der)?;
    let stored = StoredIdentity {
        version: IDENTITY_VERSION,
        service_name: PC_LINK_SERVICE_NAME.to_string(),
        certificate_der: URL_SAFE_NO_PAD.encode(&certificate_der),
        fingerprint_sha256: fingerprint.to_hex(),
        not_before_unix,
        not_after_unix,
        protected_private_key: URL_SAFE_NO_PAD.encode(protected_private_key),
    };
    let body = serde_json::to_vec(&stored).map_err(|_| write_failed())?;
    let sealed = seal(protection, IDENTITY_TAG_LABEL, &body)?;
    write_private(path, &sealed)?;

    Ok(DesktopIdentity {
        certificate: DesktopCertificate {
            service_name: PC_LINK_SERVICE_NAME.to_string(),
            certificate_der,
            fingerprint,
            not_before_unix,
            not_after_unix,
        },
        private_key_der: key_der,
    })
}

fn validate_validity(not_before_unix: i64, not_after_unix: i64) -> VaultResult<()> {
    let validity = not_after_unix
        .checked_sub(not_before_unix)
        .ok_or_else(invalid_state)?;
    if validity <= 0 || validity > MAX_DESKTOP_IDENTITY_VALIDITY_SECONDS {
        return Err(invalid_state());
    }
    let now = unix_timestamp();
    if not_after_unix <= 0 || (not_after_unix as u64) <= now {
        return Err(IDENTITY_EXPIRED.to_string());
    }
    if not_before_unix > 0 && (not_before_unix as u64) > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(IDENTITY_NOT_YET_VALID.to_string());
    }
    Ok(())
}

fn validate_private_key(private_key_der: &[u8]) -> VaultResult<()> {
    let mut key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(private_key_der),
        &PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|_| invalid_state())?;
    if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        key.zeroize();
        return Err(invalid_state());
    }
    key.zeroize();
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredIdentity {
    version: u8,
    service_name: String,
    certificate_der: String,
    fingerprint_sha256: String,
    not_before_unix: i64,
    not_after_unix: i64,
    protected_private_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pc_link::envelope::TestProtection;

    fn directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sesame-pc-link-identity-{name}-{}",
            crate::vault::random_id()
        ));
        std::fs::create_dir_all(&path).expect("test directory");
        path
    }

    fn identity(path: &Path, protection: &TestProtection) -> DesktopIdentity {
        create_identity(path, protection).expect("identity")
    }

    #[test]
    fn identity_round_trips_with_stable_certificate() {
        let dir = directory("roundtrip");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let created = identity(&path, &protection);
        let certificate = created.certificate().clone();
        assert_eq!(certificate.service_name(), PC_LINK_SERVICE_NAME);
        assert_eq!(
            certificate.fingerprint(),
            &CertificateFingerprint::from_der(certificate.certificate_der())
        );
        assert!(certificate.not_after_unix() > certificate.not_before_unix());
        let validity_days =
            (certificate.not_after_unix() - certificate.not_before_unix()) / (24 * 60 * 60);
        assert!((3650..=3651).contains(&validity_days));
        assert!(certificate
            .certificate_der()
            .windows(PC_LINK_SERVICE_NAME.len())
            .any(|window| window == PC_LINK_SERVICE_NAME.as_bytes()));
        drop(created);

        let reopened = load_identity(&path, &protection)
            .expect("loaded")
            .expect("identity");
        assert_eq!(reopened.certificate(), &certificate);
        assert_eq!(
            reopened.private_key_der(),
            created_key_bytes(&path, &protection)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn created_key_bytes(path: &Path, protection: &TestProtection) -> Vec<u8> {
        let sealed = std::fs::read(path).expect("identity file");
        let body = open(protection, IDENTITY_TAG_LABEL, &sealed).expect("body");
        let stored: StoredIdentity = serde_json::from_slice(&body).expect("stored");
        URL_SAFE_NO_PAD
            .decode(stored.protected_private_key.as_bytes())
            .expect("protected key")
    }

    #[test]
    fn identity_is_accepted_by_a_standard_rustls_server_config() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let dir = directory("rustls-server");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let created = identity(&path, &protection);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = CertificateDer::from(created.certificate().certificate_der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(created.private_key_der().to_vec()));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key);
        assert!(config.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_private_key_is_p256() {
        let dir = directory("algorithm");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let identity = identity(&path, &protection);
        let mut key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(identity.private_key_der()),
            &PKCS_ECDSA_P256_SHA256,
        )
        .expect("parsed key");
        assert_eq!(key.algorithm(), &PKCS_ECDSA_P256_SHA256);
        key.zeroize();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_identity_fails_closed() {
        let dir = directory("tampered");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let _ = identity(&path, &protection);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).expect("written");
        assert!(load_identity(&path, &protection).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_rejects_unknown_version_and_fingerprint_mismatch() {
        let dir = directory("versions");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let _ = identity(&path, &protection);
        let sealed = std::fs::read(&path).expect("read");
        let body = open(&protection, IDENTITY_TAG_LABEL, &sealed).expect("body");
        let mut stored: StoredIdentity = serde_json::from_slice(&body).expect("stored");
        stored.version = IDENTITY_VERSION + 1;
        let newer_body = serde_json::to_vec(&stored).expect("newer");
        let newer = seal(&protection, IDENTITY_TAG_LABEL, &newer_body).expect("sealed");
        write_private(&path, &newer).expect("written");
        assert_eq!(load_identity(&path, &protection).err(), Some(newer_state()));

        stored.version = IDENTITY_VERSION;
        stored.fingerprint_sha256 = "0".repeat(64);
        let mismatched_body = serde_json::to_vec(&stored).expect("mismatched");
        let mismatched = seal(&protection, IDENTITY_TAG_LABEL, &mismatched_body).expect("sealed");
        write_private(&path, &mismatched).expect("written");
        assert!(load_identity(&path, &protection).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_identity_fails_closed() {
        let dir = directory("expired");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let _ = identity(&path, &protection);
        let sealed = std::fs::read(&path).expect("read");
        let body = open(&protection, IDENTITY_TAG_LABEL, &sealed).expect("body");
        let mut stored: StoredIdentity = serde_json::from_slice(&body).expect("stored");
        stored.not_before_unix = 1;
        stored.not_after_unix = 2;
        let expired_body = serde_json::to_vec(&stored).expect("expired");
        let expired = seal(&protection, IDENTITY_TAG_LABEL, &expired_body).expect("sealed");
        write_private(&path, &expired).expect("written");
        assert_eq!(
            load_identity(&path, &protection).err(),
            Some(IDENTITY_EXPIRED.to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_is_not_written_when_device_protection_fails() {
        let dir = directory("no-protection");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: true };
        assert!(create_identity(&path, &protection).is_err());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = directory("private");
        let path = dir.join("identity.sesame");
        let protection = TestProtection { fail: false };
        let _ = identity(&path, &protection);
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
