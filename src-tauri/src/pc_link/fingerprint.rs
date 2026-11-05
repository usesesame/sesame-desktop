use std::fmt;

use sha2::{Digest, Sha256};

use crate::vault::VaultResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sha256Fingerprint([u8; 32]);

pub type CertificateFingerprint = Sha256Fingerprint;
pub type PhonePublicKeyFingerprint = Sha256Fingerprint;

impl Sha256Fingerprint {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&digest);
        Self(fingerprint)
    }

    pub fn from_der(certificate_der: &[u8]) -> Self {
        Self::from_bytes(certificate_der)
    }

    pub fn from_phone_public_key(public_key: &[u8]) -> Self {
        Self::from_bytes(public_key)
    }

    pub fn from_hex(value: &str) -> VaultResult<Self> {
        if value.len() != 64 {
            return Err("The fingerprint is not valid.".to_string());
        }
        let mut fingerprint = [0_u8; 32];
        let (pairs, _) = value.as_bytes().as_chunks::<2>();
        for (index, pair) in pairs.iter().enumerate() {
            let high = hex_nibble(pair[0]).ok_or_else(fingerprint_invalid)?;
            let low = hex_nibble(pair[1]).ok_or_else(fingerprint_invalid)?;
            fingerprint[index] = (high << 4) | low;
        }
        Ok(Self(fingerprint))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(64);
        for byte in self.0 {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        value
    }
}

impl fmt::Display for Sha256Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

fn fingerprint_invalid() -> String {
    "The fingerprint is not valid.".to_string()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hex_round_trips() {
        let fingerprint = Sha256Fingerprint::from_bytes(b"fictional certificate");
        let hex = fingerprint.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Sha256Fingerprint::from_hex(&hex), Ok(fingerprint));
        assert_eq!(
            Sha256Fingerprint::from_hex(&hex.to_uppercase()),
            Ok(fingerprint)
        );
    }

    #[test]
    fn malformed_fingerprints_are_rejected() {
        assert!(Sha256Fingerprint::from_hex("").is_err());
        assert!(Sha256Fingerprint::from_hex("00").is_err());
        assert!(Sha256Fingerprint::from_hex(&"g".repeat(64)).is_err());
    }
}
