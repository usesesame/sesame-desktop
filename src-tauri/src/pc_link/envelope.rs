use std::io::ErrorKind;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::storage::atomic_replace;
use crate::vault::util::read_file_with_limit;
use crate::vault::{bytes_match, create_private_dir, VaultResult};

const ENVELOPE_VERSION: u8 = 1;

pub(crate) const INVALID_STATE: &str =
    "The PC link state is not valid. Clear the PC link setup and pair again.";
pub(crate) const NEWER_STATE: &str = "The PC link state was written by a newer Sesame.";
pub(crate) const READ_FAILED: &str = "Sesame could not read the PC link state.";
pub(crate) const WRITE_FAILED: &str = "Sesame could not save the PC link state.";
pub(crate) const UNEXPECTED_SIZE: &str = "The PC link state has an unexpected size.";

pub(crate) fn invalid_state() -> String {
    INVALID_STATE.to_string()
}

pub(crate) fn newer_state() -> String {
    NEWER_STATE.to_string()
}

pub(crate) fn read_failed() -> String {
    READ_FAILED.to_string()
}

pub(crate) fn write_failed() -> String {
    WRITE_FAILED.to_string()
}

pub(crate) trait DeviceProtection: Send + Sync {
    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>>;
    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>>;
}

pub(crate) struct NativeProtection;

impl DeviceProtection for NativeProtection {
    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        crate::vault::platform::protect_for_device(plaintext)
    }

    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>> {
        crate::vault::platform::unprotect_for_device(protected)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    version: u8,
    body: String,
    tag: String,
}

fn tag_for(label: &[u8], body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}

pub(crate) fn seal(
    protection: &dyn DeviceProtection,
    label: &[u8],
    body: &[u8],
) -> VaultResult<Vec<u8>> {
    let protected_tag = protection.protect(&tag_for(label, body))?;
    let envelope = Envelope {
        version: ENVELOPE_VERSION,
        body: URL_SAFE_NO_PAD.encode(body),
        tag: URL_SAFE_NO_PAD.encode(protected_tag),
    };
    serde_json::to_vec(&envelope).map_err(|_| write_failed())
}

pub(crate) fn open(
    protection: &dyn DeviceProtection,
    label: &[u8],
    bytes: &[u8],
) -> VaultResult<Vec<u8>> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| invalid_state())?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(newer_state());
    }
    let body = URL_SAFE_NO_PAD
        .decode(envelope.body.as_bytes())
        .map_err(|_| invalid_state())?;
    let protected_tag = URL_SAFE_NO_PAD
        .decode(envelope.tag.as_bytes())
        .map_err(|_| invalid_state())?;
    let tag = protection.unprotect(&protected_tag)?;
    if !bytes_match(&tag, &tag_for(label, &body)) {
        return Err(invalid_state());
    }
    Ok(body)
}

pub(crate) fn read_optional(path: &Path, max_bytes: u64) -> VaultResult<Option<Vec<u8>>> {
    match read_file_with_limit(path, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) if error.kind() == ErrorKind::InvalidData => Err(UNEXPECTED_SIZE.to_string()),
        Err(_) => Err(read_failed()),
    }
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    atomic_replace(path, bytes)
}

#[cfg(test)]
pub(crate) struct TestProtection {
    pub(crate) fail: bool,
}

#[cfg(test)]
impl DeviceProtection for TestProtection {
    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        if self.fail {
            return Err("test protection unavailable".to_string());
        }
        Ok(plaintext.to_vec())
    }

    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>> {
        if self.fail {
            return Err("test protection unavailable".to_string());
        }
        Ok(protected.to_vec())
    }
}

#[cfg(test)]
pub(crate) struct ForeignProtection;

#[cfg(test)]
impl DeviceProtection for ForeignProtection {
    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        let mut protected = Vec::with_capacity(plaintext.len() + 1);
        protected.push(0xa5);
        protected.extend_from_slice(plaintext);
        Ok(protected)
    }

    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>> {
        protected
            .strip_prefix(&[0xa5])
            .map(|plaintext| plaintext.to_vec())
            .ok_or_else(|| "foreign protection".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_body_round_trips_and_rejects_edits() {
        let protection = TestProtection { fail: false };
        let sealed = seal(&protection, b"label", b"fictional body").expect("sealed");
        assert_eq!(
            open(&protection, b"label", &sealed).expect("opened"),
            b"fictional body"
        );

        let other_label = open(&protection, b"other", &sealed);
        assert_eq!(other_label, Err(INVALID_STATE.to_string()));

        let mut envelope: Envelope = serde_json::from_slice(&sealed).expect("envelope");
        envelope.body = URL_SAFE_NO_PAD.encode(b"altered body");
        let altered = serde_json::to_vec(&envelope).expect("altered");
        assert_eq!(
            open(&protection, b"label", &altered),
            Err(INVALID_STATE.to_string())
        );
    }

    #[test]
    fn envelope_version_and_protection_fail_closed() {
        let protection = TestProtection { fail: false };
        let sealed = seal(&protection, b"label", b"fictional body").expect("sealed");
        let mut envelope: Envelope = serde_json::from_slice(&sealed).expect("envelope");
        envelope.version = ENVELOPE_VERSION + 1;
        let newer = serde_json::to_vec(&envelope).expect("newer");
        assert_eq!(
            open(&protection, b"label", &newer),
            Err(NEWER_STATE.to_string())
        );

        let failing = TestProtection { fail: true };
        assert!(open(&failing, b"label", &sealed).is_err());
        assert!(seal(&failing, b"label", b"fictional body").is_err());
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let protection = TestProtection { fail: false };
        assert!(open(&protection, b"label", b"not-json").is_err());
        assert!(open(&protection, b"label", b"{}").is_err());
        assert!(open(&protection, b"label", b"").is_err());
    }
}
