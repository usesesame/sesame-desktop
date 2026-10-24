use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

pub const VERSION_V3: u32 = 3;
pub const LABEL_DEVICE_LIST: &str = "sesame-sync-v3-devicelist";
pub const LABEL_DEVICE_LIST_DIGEST: &str = "sesame-sync-v3-devicelist-digest";
pub const LABEL_HEADER: &str = "sesame-sync-v3-header";
pub const LABEL_HEADER_DIGEST: &str = "sesame-sync-v3-header-digest";
pub const LABEL_REQUEST: &str = "sesame-sync-v3-request";
pub const LABEL_RECEIPT: &str = "sesame-sync-v3-receipt";
pub const LABEL_AAD: &str = "sesame-sync-v3-aad";
pub const LABEL_CHECKPOINT: &str = "sesame-sync-v3-checkpoint";

pub const DIGEST_BYTES: usize = 32;
pub const KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const NONCE_BYTES: usize = 24;
pub const REQUEST_NONCE_BYTES: usize = 16;
pub const MIN_SEALED_LABEL_BYTES: usize = 40;
pub const MAX_SEALED_LABEL_BYTES: usize = 256;
pub const MAX_CIPHERTEXT_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_DEVICES: usize = 10;
pub const REQUEST_TIMESTAMP_SKEW: u64 = 5 * 60;

pub struct Canonical(Vec<u8>);

impl Canonical {
    pub fn new(label: &str) -> Self {
        let mut canonical = Self(Vec::new());
        canonical.text(label);
        canonical
    }

    pub fn add(&mut self, part: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(part.len() as u64).to_be_bytes());
        self.0.extend_from_slice(part);
        self
    }

    pub fn text(&mut self, value: &str) -> &mut Self {
        self.add(value.as_bytes())
    }

    pub fn number(&mut self, value: u64) -> &mut Self {
        self.text(&value.to_string())
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn digest(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(&self.0))
    }
}

pub fn decode_exact(value: &str, length: usize) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    if decoded.len() != length || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return None;
    }
    Some(decoded)
}

pub fn decode_range(value: &str, minimum: usize, maximum: usize) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    if decoded.len() < minimum
        || decoded.len() > maximum
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return None;
    }
    Some(decoded)
}

pub fn valid_digest(value: &str) -> bool {
    decode_exact(value, DIGEST_BYTES).is_some()
}

pub fn opaque_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    Invalid,
    DeviceList,
    History,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError {
    pub kind: ProofKind,
    pub detail: &'static str,
}

impl ProofError {
    pub fn invalid(detail: &'static str) -> Self {
        Self {
            kind: ProofKind::Invalid,
            detail,
        }
    }

    pub fn device_list(detail: &'static str) -> Self {
        Self {
            kind: ProofKind::DeviceList,
            detail,
        }
    }

    pub fn history(detail: &'static str) -> Self {
        Self {
            kind: ProofKind::History,
            detail,
        }
    }
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lead = match self.kind {
            ProofKind::Invalid => "The service sent a Sync record this device cannot read",
            ProofKind::DeviceList => "Your devices disagree about the device list",
            ProofKind::History => "Your devices disagree about history",
        };
        write!(formatter, "{lead}: {}.", self.detail)
    }
}

impl From<ProofError> for String {
    fn from(error: ProofError) -> Self {
        error.to_string()
    }
}

pub type ProofResult<T> = Result<T, ProofError>;
