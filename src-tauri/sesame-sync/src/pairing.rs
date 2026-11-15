use super::pake::MAX_AD_BYTES;

pub const MAX_FIELD_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDeviceIdentity {
    pub device_id: String,
    pub signing_key: String,
    pub package_key: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApproverIdentity {
    pub device_id: String,
    pub signing_key: String,
    pub vault_id: String,
    pub head_digest: String,
}

fn encode_fields(fields: &[&str]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for field in fields {
        let bytes = field.as_bytes();
        if bytes.len() > MAX_FIELD_BYTES {
            return None;
        }
        out.push(u8::try_from(bytes.len()).ok()?);
        out.extend_from_slice(bytes);
    }
    (out.len() <= MAX_AD_BYTES).then_some(out)
}

fn decode_fields(bytes: &[u8], count: usize) -> Option<Vec<String>> {
    let mut fields = Vec::with_capacity(count);
    let mut rest = bytes;
    for _ in 0..count {
        let (&length, tail) = rest.split_first()?;
        let length = usize::from(length);
        if length > MAX_FIELD_BYTES || tail.len() < length {
            return None;
        }
        let (field, remaining) = tail.split_at(length);
        fields.push(String::from_utf8(field.to_vec()).ok()?);
        rest = remaining;
    }
    rest.is_empty().then_some(fields)
}

pub fn package_key_commitment(package_key: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    match URL_SAFE_NO_PAD.decode(package_key) {
        Ok(bytes) if bytes.len() == super::canonical::HYBRID_KEY_BYTES => {
            format!("sha256:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)))
        }
        _ => package_key.to_string(),
    }
}

impl NewDeviceIdentity {
    pub fn encode(&self) -> Option<Vec<u8>> {
        encode_fields(&[
            &self.device_id,
            &self.signing_key,
            &self.package_key,
            &self.label,
        ])
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut fields = decode_fields(bytes, 4)?.into_iter();
        Some(Self {
            device_id: fields.next()?,
            signing_key: fields.next()?,
            package_key: fields.next()?,
            label: fields.next()?,
        })
    }
}

impl ApproverIdentity {
    pub fn encode(&self) -> Option<Vec<u8>> {
        encode_fields(&[
            &self.device_id,
            &self.signing_key,
            &self.vault_id,
            &self.head_digest,
        ])
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut fields = decode_fields(bytes, 4)?.into_iter();
        Some(Self {
            device_id: fields.next()?,
            signing_key: fields.next()?,
            vault_id: fields.next()?,
            head_digest: fields.next()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_key(length: usize, byte: u8) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(vec![byte; length])
    }

    #[test]
    fn a_classical_package_key_is_advertised_as_it_is() {
        let key = encoded_key(32, 7);
        assert_eq!(package_key_commitment(&key), key);
    }

    #[test]
    fn a_hybrid_package_key_is_advertised_by_a_digest_that_fits_a_field() {
        let first = package_key_commitment(&encoded_key(1216, 5));
        let second = package_key_commitment(&encoded_key(1216, 6));
        assert!(first.starts_with("sha256:"));
        assert!(first.len() <= MAX_FIELD_BYTES);
        assert_ne!(first, second);
        assert_eq!(first, package_key_commitment(&encoded_key(1216, 5)));
    }

    #[test]
    fn an_advertisement_that_commits_to_a_hybrid_key_encodes_and_decodes() {
        let mut device = device();
        device.package_key = package_key_commitment(&encoded_key(1216, 5));
        let encoded = device.encode().expect("fits the advertisement limit");
        assert!(encoded.len() <= MAX_AD_BYTES);
        assert_eq!(NewDeviceIdentity::decode(&encoded), Some(device));
    }

    #[test]
    fn the_full_hybrid_key_never_fits_an_advertisement() {
        let mut device = device();
        device.package_key = encoded_key(1216, 5);
        assert!(device.encode().is_none());
    }

    fn device() -> NewDeviceIdentity {
        NewDeviceIdentity {
            device_id: "deviceAAAAAAAAAAAAAA01".to_string(),
            signing_key: "k".repeat(43),
            package_key: "p".repeat(43),
            label: "Kitchen laptop".to_string(),
        }
    }

    #[test]
    fn identities_round_trip_and_reject_damage() {
        let encoded = device().encode().expect("fits");
        assert_eq!(NewDeviceIdentity::decode(&encoded), Some(device()));
        assert_eq!(
            NewDeviceIdentity::decode(&encoded[..encoded.len() - 1]),
            None
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(NewDeviceIdentity::decode(&trailing), None);
        assert_eq!(NewDeviceIdentity::decode(&[]), None);
    }

    #[test]
    fn an_oversized_field_is_refused_instead_of_truncated() {
        let mut long = device();
        long.label = "x".repeat(MAX_FIELD_BYTES + 1);
        assert_eq!(long.encode(), None);
        assert_eq!(NewDeviceIdentity::decode(&[200, 1, 2, 3]), None);
    }

    #[test]
    fn the_approver_identity_fits_the_pairing_message() {
        let approver = ApproverIdentity {
            device_id: "deviceBBBBBBBBBBBBBB01".to_string(),
            signing_key: "k".repeat(43),
            vault_id: "v".repeat(36),
            head_digest: "h".repeat(43),
        };
        let encoded = approver.encode().expect("fits");
        assert!(encoded.len() <= MAX_AD_BYTES);
        assert_eq!(ApproverIdentity::decode(&encoded), Some(approver));
    }
}
