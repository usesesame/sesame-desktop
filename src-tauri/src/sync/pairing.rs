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
