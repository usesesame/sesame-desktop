use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde_json;
use std::io::{self, Read, Write};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    types::*, util::fill_random, VaultResult, MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB,
    MAX_KDF_PARALLELISM, MAX_KDF_TOTAL_WORK, MAX_VAULT_FILE_BYTES, MIN_KDF_ITERATIONS,
    MIN_KDF_MEMORY_KIB, VAULT_SIZE_LIMIT_MESSAGE,
};

pub fn default_kdf_params() -> KdfParams {
    let mut salt = [0_u8; 32];
    fill_random(&mut salt);
    KdfParams {
        algorithm: "argon2id".into(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        memory_kib: MIN_KDF_MEMORY_KIB,
        iterations: MIN_KDF_ITERATIONS,
        parallelism: 4,
    }
}

pub fn derive_key(password: &str, params: &KdfParams) -> VaultResult<[u8; 32]> {
    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    derive_key_from_exact(&normalized, params)
}

pub fn password_forms(password: &str) -> Vec<Zeroizing<String>> {
    let mut forms: Vec<Zeroizing<String>> = Vec::with_capacity(3);
    for form in [
        Zeroizing::new(password.nfc().collect::<String>()),
        Zeroizing::new(password.nfd().collect::<String>()),
        Zeroizing::new(password.to_string()),
    ] {
        if !forms.iter().any(|seen| seen.as_str() == form.as_str()) {
            forms.push(form);
        }
    }
    forms
}

pub fn unwrap_with_password(
    password: &str,
    params: &KdfParams,
    blob: &CipherBlob,
    aad: &[u8],
) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
    for form in password_forms(password) {
        let wrapping_key = Zeroizing::new(derive_key_from_exact(&form, params)?);
        if let Ok(bytes) = decrypt_bytes(&wrapping_key, blob, aad) {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn derive_key_from_exact(password: &str, params: &KdfParams) -> VaultResult<[u8; 32]> {
    validate_kdf_params(params)?;
    let salt = URL_SAFE_NO_PAD
        .decode(&params.salt)
        .map_err(|_| "The vault KDF settings are invalid.".to_string())?;
    let config = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| "The vault KDF settings are invalid.".to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, config);
    let mut output = [0_u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|_| "Sesame could not derive a local vault key.".to_string())?;
    Ok(output)
}

pub fn validate_kdf_params(params: &KdfParams) -> VaultResult<()> {
    if params.algorithm != "argon2id"
        || params.memory_kib < MIN_KDF_MEMORY_KIB
        || params.memory_kib > MAX_KDF_MEMORY_KIB
        || params.iterations < MIN_KDF_ITERATIONS
        || params.iterations > MAX_KDF_ITERATIONS
        || params.parallelism == 0
        || params.parallelism > MAX_KDF_PARALLELISM
    {
        return Err("The vault KDF settings are outside Sesame's safe limits.".into());
    }
    if u64::from(params.memory_kib) * u64::from(params.iterations) > MAX_KDF_TOTAL_WORK {
        return Err("The vault KDF settings are outside Sesame's safe limits.".into());
    }
    let salt = URL_SAFE_NO_PAD
        .decode(&params.salt)
        .map_err(|_| "The vault KDF settings are invalid.".to_string())?;
    if !(16..=64).contains(&salt.len()) {
        return Err("The vault KDF settings are invalid.".into());
    }
    Ok(())
}

pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> VaultResult<CipherBlob> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Sesame could not initialise local encryption.".to_string())?;
    let mut nonce = [0_u8; 24];
    fill_random(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Sesame could not encrypt the local vault.".to_string())?;
    Ok(CipherBlob {
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_bytes(
    key: &[u8; 32],
    blob: &CipherBlob,
    aad: &[u8],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Sesame could not initialise local encryption.".to_string())?;
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&blob.nonce)
        .map_err(|_| "The encrypted vault nonce is invalid.".to_string())?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| "The encrypted vault nonce is invalid.".to_string())?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&blob.ciphertext)
        .map_err(|_| "The encrypted vault data is invalid.".to_string())?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "The encrypted vault could not be authenticated.".to_string())
}

const CAPPED_BUFFER_FIRST_BYTES: usize = 4096;

struct CappedBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: u64,
}

impl CappedBuffer {
    fn new(limit: u64) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            limit,
        }
    }

    fn grow_to_fit(&mut self, needed: usize) -> Option<Zeroizing<Vec<u8>>> {
        let current = self.bytes.capacity();
        if needed <= current {
            return None;
        }
        let ceiling = usize::try_from(self.limit).unwrap_or(usize::MAX);
        let target = needed
            .max(current.saturating_mul(2))
            .max(CAPPED_BUFFER_FIRST_BYTES)
            .min(ceiling.max(needed));
        let mut grown = Zeroizing::new(Vec::with_capacity(target));
        grown.extend_from_slice(&self.bytes);
        let mut retired = std::mem::replace(&mut self.bytes, grown);
        Zeroize::zeroize(&mut *retired);
        Some(retired)
    }
}

impl Write for CappedBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.bytes.len() as u64 + data.len() as u64 > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the encoded vault would exceed its size limit",
            ));
        }
        self.grow_to_fit(self.bytes.len() + data.len());
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn serialize_payload(payload: &VaultPayload) -> VaultResult<Zeroizing<Vec<u8>>> {
    serialize_payload_capped(payload, MAX_VAULT_FILE_BYTES)
}

fn serialize_payload_capped(payload: &VaultPayload, limit: u64) -> VaultResult<Zeroizing<Vec<u8>>> {
    let mut buffer = CappedBuffer::new(limit);
    serde_json::to_writer(&mut buffer, payload).map_err(|error| {
        if error.is_io() {
            VAULT_SIZE_LIMIT_MESSAGE.to_string()
        } else {
            "Sesame could not prepare the local vault.".to_string()
        }
    })?;
    let written = buffer.bytes.len();
    let padding = padded_length(written, limit) - written;
    io::copy(&mut io::repeat(b' ').take(padding as u64), &mut buffer)
        .map_err(|_| "Sesame could not prepare the local vault.".to_string())?;
    Ok(buffer.bytes)
}

const PADDING_FLOOR_BYTES: usize = 16 * 1024;
const FILE_ENVELOPE_RESERVE_DIVISOR: u64 = 64;

fn padded_length(length: usize, limit: u64) -> usize {
    let file_budget = limit - limit / FILE_ENVELOPE_RESERVE_DIVISOR;
    let ceiling = usize::try_from(file_budget / 4 * 3).unwrap_or(usize::MAX);
    if length >= ceiling {
        return length;
    }
    padme_length(length).min(ceiling)
}

fn padme_length(length: usize) -> usize {
    let length = length.max(PADDING_FLOOR_BYTES);
    let exponent = usize::BITS - 1 - length.leading_zeros();
    let significant_bits = u32::BITS - exponent.leading_zeros();
    let mask = (1_usize << (exponent - significant_bits)) - 1;
    (length + mask) & !mask
}

pub fn bytes_match(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (index, byte) in left.iter().enumerate() {
        difference |= byte ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Attachment, DocumentMetadata};
    use crate::WRAP_AAD;

    const COMPOSED: &str = "fictional caf\u{e9} na\u{ef}ve password";
    const DECOMPOSED: &str = "fictional cafe\u{301} nai\u{308}ve password";

    fn wrap_with_exact(password: &str, params: &KdfParams, secret: &[u8]) -> CipherBlob {
        let key = derive_key_from_exact(password, params).expect("legacy key");
        encrypt_bytes(&key, secret, WRAP_AAD).expect("legacy wrap")
    }

    #[test]
    fn an_ascii_password_derives_the_same_key_as_before_normalization() {
        let params = default_kdf_params();
        let password = "fictional ascii password 42";
        assert_eq!(
            derive_key(password, &params).expect("normalized"),
            derive_key_from_exact(password, &params).expect("exact")
        );
        assert_eq!(password_forms(password).len(), 1);
    }

    #[test]
    fn composed_and_decomposed_forms_derive_one_key() {
        assert_ne!(COMPOSED, DECOMPOSED);
        let params = default_kdf_params();
        assert_eq!(
            derive_key(COMPOSED, &params).expect("composed"),
            derive_key(DECOMPOSED, &params).expect("decomposed")
        );
    }

    #[test]
    fn a_wrap_written_from_the_decomposed_form_opens_with_the_composed_form() {
        let params = default_kdf_params();
        let wrap = wrap_with_exact(DECOMPOSED, &params, &[5_u8; 32]);
        let opened = unwrap_with_password(COMPOSED, &params, &wrap, WRAP_AAD)
            .expect("derivation")
            .expect("opened");
        assert_eq!(opened.as_slice(), &[5_u8; 32]);
    }

    #[test]
    fn a_wrap_written_from_the_composed_form_opens_with_the_decomposed_form() {
        let params = default_kdf_params();
        let wrap = wrap_with_exact(COMPOSED, &params, &[6_u8; 32]);
        let opened = unwrap_with_password(DECOMPOSED, &params, &wrap, WRAP_AAD)
            .expect("derivation")
            .expect("opened");
        assert_eq!(opened.as_slice(), &[6_u8; 32]);
    }

    #[test]
    fn a_wrong_password_opens_nothing_in_any_form() {
        let params = default_kdf_params();
        let wrap = wrap_with_exact(COMPOSED, &params, &[7_u8; 32]);
        assert!(unwrap_with_password(
            "fictional caf\u{e9} other password",
            &params,
            &wrap,
            WRAP_AAD
        )
        .expect("derivation")
        .is_none());
    }

    #[test]
    fn invalid_kdf_settings_are_an_error_not_a_wrong_password() {
        let mut params = default_kdf_params();
        let wrap = wrap_with_exact(COMPOSED, &params, &[8_u8; 32]);
        params.memory_kib = 0;
        assert!(unwrap_with_password(COMPOSED, &params, &wrap, WRAP_AAD).is_err());
    }

    #[test]
    fn capped_buffer_keeps_only_bytes_under_the_limit() {
        let mut buffer = CappedBuffer::new(4);
        buffer.write_all(b"abc").expect("under the limit");
        assert!(buffer.write_all(b"de").is_err());
        assert_eq!(&*buffer.bytes, b"abc");
    }

    #[test]
    fn capped_buffer_wipes_each_buffer_it_replaces() {
        let mut buffer = CappedBuffer::new(1024 * 1024);
        let marker = b"fictional plaintext marker ";
        let mut replaced = 0;
        let mut written = 0;
        while written < 40_000 {
            let retired = buffer.grow_to_fit(buffer.bytes.len() + marker.len());
            buffer.write_all(marker).expect("under the limit");
            written += marker.len();
            if let Some(retired) = retired {
                replaced += 1;
                assert!(retired.is_empty());
                let capacity = retired.capacity();
                let residue = unsafe { std::slice::from_raw_parts(retired.as_ptr(), capacity) };
                assert!(residue.iter().all(|byte| *byte == 0));
            }
        }
        assert!(replaced >= 3);
        assert_eq!(buffer.bytes.len(), written);
        assert!(buffer
            .bytes
            .chunks(marker.len())
            .all(|chunk| chunk == marker));
    }

    #[test]
    fn capped_buffer_never_grows_past_its_limit() {
        let mut buffer = CappedBuffer::new(10_000);
        buffer.write_all(&[1_u8; 6_000]).expect("first write");
        buffer.write_all(&[2_u8; 4_000]).expect("second write");
        assert!(buffer.bytes.capacity() <= 10_000);
        assert!(buffer.write_all(&[3_u8]).is_err());
        assert_eq!(buffer.bytes.len(), 10_000);
    }

    #[test]
    fn payload_serialization_rejects_an_oversized_change_early() {
        let mut document = DocumentMetadata::default();
        document.id = "fictional-document".into();
        document.title = "Fictional document".into();
        document.attachments = vec![Attachment {
            id: "fictional-attachment".into(),
            filename: "fictional.bin".into(),
            content_type: "application/octet-stream".into(),
            size: 4096,
            data: vec![7; 4096],
        }];
        let mut payload = VaultPayload::default();
        payload.vault_name = "fictional oversized vault".into();
        payload.documents = vec![document];
        let encoded = serialize_payload_capped(&payload, 256);
        assert_eq!(encoded.err().as_deref(), Some(VAULT_SIZE_LIMIT_MESSAGE));
        let accepted = serialize_payload_capped(&payload, 64 * 1024).expect("small limit passes");
        assert!(serde_json::from_slice::<serde_json::Value>(&accepted).is_ok());
    }

    fn payload_with_note(note_length: usize) -> VaultPayload {
        let mut payload = VaultPayload::default();
        payload.vault_name = "Fictional padded vault".into();
        let mut note = SecureNote::default();
        note.id = "fictional-note".into();
        note.title = "Fictional note".into();
        note.content = "n".repeat(note_length);
        payload.secure_notes = vec![note];
        payload
    }

    fn compact_length(payload: &VaultPayload) -> usize {
        serde_json::to_vec(payload).expect("compact json").len()
    }

    #[test]
    fn padme_lengths_match_known_values_and_the_floor() {
        assert_eq!(padme_length(0), PADDING_FLOOR_BYTES);
        assert_eq!(padme_length(1), PADDING_FLOOR_BYTES);
        assert_eq!(padme_length(PADDING_FLOOR_BYTES), PADDING_FLOOR_BYTES);
        assert_eq!(padme_length(PADDING_FLOOR_BYTES + 1), 17 * 1024);
        assert_eq!(padme_length(100_000), 100_352);
        assert_eq!(padme_length(1_000_000), 1_015_808);
        assert_eq!(padme_length(2_340_682), 2_359_296);
    }

    #[test]
    fn padme_overhead_stays_under_seven_percent_above_the_floor() {
        let mut length = PADDING_FLOOR_BYTES;
        while length < 80 * 1024 * 1024 {
            let padded = padme_length(length);
            assert!(padded >= length);
            assert!(padded - length <= length / 16, "{length} -> {padded}");
            assert_eq!(padme_length(padded), padded);
            length += length / 97 + 1;
        }
    }

    #[test]
    fn padded_serialization_is_the_compact_json_followed_by_spaces() {
        let payload = payload_with_note(40);
        let compact = serde_json::to_vec(&payload).expect("compact json");
        let padded = serialize_payload_capped(&payload, MAX_VAULT_FILE_BYTES).expect("padded");
        assert_eq!(padded.len(), PADDING_FLOOR_BYTES);
        assert_eq!(&padded[..compact.len()], compact.as_slice());
        assert!(padded[compact.len()..].iter().all(|byte| *byte == b' '));
        let reread: VaultPayload = serde_json::from_slice(&padded).expect("padded json");
        assert_eq!(serde_json::to_vec(&reread).expect("reserialized"), compact);
    }

    #[test]
    fn edits_inside_one_bucket_keep_one_length_and_other_buckets_differ() {
        let lengths: Vec<usize> = [0, 1, 40, 400, 4000, 12000]
            .into_iter()
            .map(|size| {
                serialize_payload_capped(&payload_with_note(size), MAX_VAULT_FILE_BYTES)
                    .expect("padded")
                    .len()
            })
            .collect();
        assert!(lengths.iter().all(|length| *length == PADDING_FLOOR_BYTES));
        let larger = serialize_payload_capped(&payload_with_note(40_000), MAX_VAULT_FILE_BYTES)
            .expect("larger padded");
        assert!(larger.len() > PADDING_FLOOR_BYTES);
        assert!(larger.len() <= compact_length(&payload_with_note(40_000)) * 17 / 16);
    }

    #[test]
    fn padding_never_exceeds_the_limit() {
        for limit in [512_u64, 20_000, 64 * 1024, 1024 * 1024] {
            for size in [0, 10, 100, 1_000, 10_000, 40_000, 400_000] {
                let payload = payload_with_note(size);
                let compact = compact_length(&payload);
                match serialize_payload_capped(&payload, limit) {
                    Ok(padded) => {
                        assert!(padded.len() as u64 <= limit, "{limit} {size}");
                        assert!(padded.len() >= compact);
                    }
                    Err(message) => {
                        assert!(compact as u64 > limit, "{limit} {size}");
                        assert_eq!(message, VAULT_SIZE_LIMIT_MESSAGE);
                    }
                }
            }
        }
    }

    #[test]
    fn padding_leaves_room_for_the_encoded_file_inside_the_file_limit() {
        let limit = MAX_VAULT_FILE_BYTES;
        let (opened, _) = crate::api::create_vault("fictional padding password", "Fictional")
            .expect("create vault");
        let mut file = opened.file.clone();
        file.payload.ciphertext = String::new();
        let envelope = serde_json::to_vec(&file).expect("encode envelope").len() as u64;
        let ceiling = (limit - limit / FILE_ENVELOPE_RESERVE_DIVISOR) as usize / 4 * 3;
        let mut lengths: Vec<usize> = (0..=limit as usize).step_by(1_048_573).collect();
        lengths.extend([ceiling - 1, ceiling, ceiling + 1, limit as usize]);
        let mut padded_count = 0;
        for length in lengths {
            let padded = padded_length(length, limit);
            assert!(padded >= length);
            assert!(padded as u64 <= limit);
            if padded > length {
                padded_count += 1;
                let encoded = envelope + ((padded as u64 + 16).div_ceil(3) * 4);
                assert!(encoded <= limit, "{length} -> {padded} -> {encoded}");
            }
        }
        assert!(padded_count > 40);
    }

    #[test]
    fn a_payload_at_the_limit_is_kept_unpadded_and_one_byte_over_is_refused() {
        let payload = payload_with_note(3_000);
        let exact = compact_length(&payload) as u64;
        let at_limit = serialize_payload_capped(&payload, exact).expect("at the limit");
        assert_eq!(at_limit.len() as u64, exact);
        assert_eq!(
            serialize_payload_capped(&payload, exact - 1)
                .err()
                .as_deref(),
            Some(VAULT_SIZE_LIMIT_MESSAGE)
        );
    }

    #[test]
    fn a_payload_near_the_ceiling_is_not_padded_past_the_file_budget() {
        let limit = 64 * 1024_u64;
        let ceiling = (limit - limit / FILE_ENVELOPE_RESERVE_DIVISOR) / 4 * 3;
        let payload = payload_with_note(ceiling as usize - 400);
        let compact = compact_length(&payload) as u64;
        assert!(compact < ceiling);
        let padded = serialize_payload_capped(&payload, limit).expect("padded");
        assert_eq!(padded.len() as u64, ceiling);
        let beyond = payload_with_note(ceiling as usize + 100);
        let kept = serialize_payload_capped(&beyond, limit).expect("kept");
        assert_eq!(kept.len(), compact_length(&beyond));
    }

    #[test]
    fn padded_ciphertext_fails_authentication_when_any_padding_byte_changes() {
        let key = [9_u8; 32];
        let payload = payload_with_note(40);
        let padded = serialize_payload_capped(&payload, MAX_VAULT_FILE_BYTES).expect("padded");
        let compact = compact_length(&payload);
        let blob = encrypt_bytes(&key, &padded, b"fictional padding aad").expect("sealed");
        let opened = decrypt_bytes(&key, &blob, b"fictional padding aad").expect("opened");
        assert_eq!(opened.as_slice(), padded.as_slice());
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&blob.ciphertext)
            .expect("ciphertext");
        for index in (compact..padded.len()).step_by(97) {
            let mut tampered = ciphertext.clone();
            tampered[index] ^= 0x01;
            let changed = CipherBlob {
                nonce: blob.nonce.clone(),
                ciphertext: URL_SAFE_NO_PAD.encode(tampered),
            };
            assert!(decrypt_bytes(&key, &changed, b"fictional padding aad").is_err());
        }
    }
}
