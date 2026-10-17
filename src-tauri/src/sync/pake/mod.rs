use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hkdf::Hkdf;
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub const SID_BYTES: usize = 16;
pub const POINT_BYTES: usize = 32;
pub const TAG_BYTES: usize = 32;
pub const MAX_AD_BYTES: usize = 256;
const DSI: &[u8] = b"CPaceRistretto255";
const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
const SHA512_BLOCK_BYTES: usize = 128;
pub const PAIRING_CI: &[u8] = b"sesame-sync-v3-pairing";
const ROLE_NEW_DEVICE: &[u8] = b"sesame-sync-v3-pairing-new-device";
const ROLE_APPROVER: &[u8] = b"sesame-sync-v3-pairing-approver";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PakeError {
    Malformed,
    BadPoint,
    ConfirmationFailed,
    Entropy,
}

impl std::fmt::Display for PakeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "The pairing message could not be read.",
            Self::BadPoint => "The pairing message holds an invalid value.",
            Self::ConfirmationFailed => {
                "The pairing codes did not match. Start again with a new code."
            }
            Self::Entropy => "Sesame could not gather randomness for pairing.",
        })
    }
}

impl From<PakeError> for String {
    fn from(error: PakeError) -> Self {
        error.to_string()
    }
}

fn leb128(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn prepend_len(value: &[u8]) -> Vec<u8> {
    let mut out = leb128(value.len());
    out.extend_from_slice(value);
    out
}

fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|part| prepend_len(part)).collect()
}

fn generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let padding = SHA512_BLOCK_BYTES
        .saturating_sub(prepend_len(prs).len())
        .saturating_sub(prepend_len(DSI).len())
        .saturating_sub(1);
    let zeros = vec![0u8; padding];
    let generator_string = lv_cat(&[DSI, prs, &zeros, ci, sid]);
    let hash: [u8; 64] = Sha512::digest(&generator_string).into();
    RistrettoPoint::from_uniform_bytes(&hash)
}

fn random_scalar() -> Result<Scalar, PakeError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    SysRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| PakeError::Entropy)?;
    bytes[31] &= 0x0f;
    Ok(Scalar::from_bytes_mod_order(*bytes))
}

fn decode(bytes: &[u8]) -> Result<RistrettoPoint, PakeError> {
    let compressed = CompressedRistretto::from_slice(bytes).map_err(|_| PakeError::BadPoint)?;
    let point = compressed.decompress().ok_or(PakeError::BadPoint)?;
    if point.is_identity() {
        return Err(PakeError::BadPoint);
    }
    Ok(point)
}

struct Shared {
    isk: Zeroizing<[u8; 64]>,
    transcript: Vec<u8>,
}

fn shared_secret(
    scalar: &Scalar,
    peer: &RistrettoPoint,
    sid: &[u8],
    transcript: Vec<u8>,
) -> Result<Shared, PakeError> {
    let shared_point = scalar * peer;
    if shared_point.is_identity() {
        return Err(PakeError::BadPoint);
    }
    let mut k = shared_point.compress().to_bytes();
    let mut input = lv_cat(&[DSI_ISK, sid, &k]);
    input.extend_from_slice(&transcript);
    k.zeroize();
    let isk: [u8; 64] = Sha512::digest(&input).into();
    input.zeroize();
    Ok(Shared {
        isk: Zeroizing::new(isk),
        transcript,
    })
}

fn tag(shared: &Shared, role: &[u8]) -> Result<[u8; TAG_BYTES], PakeError> {
    let transcript_hash = Sha256::digest(&shared.transcript);
    let hkdf = Hkdf::<Sha256>::new(None, &shared.isk[..]);
    let mut out = [0u8; TAG_BYTES];
    let mut info = role.to_vec();
    info.extend_from_slice(&transcript_hash);
    hkdf.expand(&info, &mut out)
        .map_err(|_| PakeError::Malformed)?;
    Ok(out)
}

fn tags_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

pub fn normalize_code(code: &str) -> Vec<u8> {
    code.chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .flat_map(char::to_uppercase)
        .map(|character| match character {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect::<String>()
        .into_bytes()
}

pub const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const CODE_LENGTH: usize = 10;

pub fn generate_code() -> Result<String, PakeError> {
    let mut bytes = Zeroizing::new([0u8; CODE_LENGTH]);
    SysRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| PakeError::Entropy)?;
    Ok(bytes
        .iter()
        .map(|byte| char::from(CODE_ALPHABET[usize::from(byte & 31)]))
        .collect())
}

pub struct Offer {
    pub message: Vec<u8>,
    sid: [u8; SID_BYTES],
    scalar: Scalar,
    point: [u8; POINT_BYTES],
    prs: Vec<u8>,
    ad: Vec<u8>,
}

impl Drop for Offer {
    fn drop(&mut self) {
        self.prs.zeroize();
        self.scalar.zeroize();
    }
}

pub struct Answered {
    pub message: Vec<u8>,
    new_device_tag: [u8; TAG_BYTES],
    isk: Zeroizing<[u8; 64]>,
}

pub struct Completed {
    pub confirmation: Vec<u8>,
    pub approver_ad: Vec<u8>,
}

fn encode_message(first: &[u8], point: &[u8; POINT_BYTES], ad: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(first);
    out.extend_from_slice(point);
    out.extend_from_slice(&(ad.len() as u16).to_be_bytes());
    out.extend_from_slice(ad);
    out.extend_from_slice(tail);
    out
}

struct Parsed<'a> {
    point: &'a [u8],
    ad: &'a [u8],
    tail: &'a [u8],
}

fn parse<'a>(message: &'a [u8], leading: usize) -> Result<Parsed<'a>, PakeError> {
    let body = message.get(leading..).ok_or(PakeError::Malformed)?;
    let point = body.get(..POINT_BYTES).ok_or(PakeError::Malformed)?;
    let length_bytes = body
        .get(POINT_BYTES..POINT_BYTES + 2)
        .ok_or(PakeError::Malformed)?;
    let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    if length > MAX_AD_BYTES {
        return Err(PakeError::Malformed);
    }
    let start = POINT_BYTES + 2;
    let ad = body
        .get(start..start + length)
        .ok_or(PakeError::Malformed)?;
    Ok(Parsed {
        point,
        ad,
        tail: &body[start + length..],
    })
}

fn transcript(point_a: &[u8], ad_a: &[u8], point_b: &[u8], ad_b: &[u8]) -> Vec<u8> {
    let mut out = lv_cat(&[point_a, ad_a]);
    out.extend_from_slice(&lv_cat(&[point_b, ad_b]));
    out
}

impl Offer {
    pub fn begin(code: &str, ad: &[u8]) -> Result<Self, PakeError> {
        let mut sid = [0u8; SID_BYTES];
        SysRng
            .try_fill_bytes(&mut sid)
            .map_err(|_| PakeError::Entropy)?;
        Self::begin_with(code, ad, sid, random_scalar()?)
    }

    fn begin_with(
        code: &str,
        ad: &[u8],
        sid: [u8; SID_BYTES],
        scalar: Scalar,
    ) -> Result<Self, PakeError> {
        if ad.len() > MAX_AD_BYTES {
            return Err(PakeError::Malformed);
        }
        let prs = normalize_code(code);
        let point = (scalar * generator(&prs, PAIRING_CI, &sid))
            .compress()
            .to_bytes();
        Ok(Self {
            message: encode_message(&sid, &point, ad, &[]),
            sid,
            scalar,
            point,
            prs,
            ad: ad.to_vec(),
        })
    }

    pub fn finish(self, answer: &[u8]) -> Result<Completed, PakeError> {
        let parsed = parse(answer, 0)?;
        if parsed.tail.len() != TAG_BYTES {
            return Err(PakeError::Malformed);
        }
        let peer = decode(parsed.point)?;
        let shared = shared_secret(
            &self.scalar,
            &peer,
            &self.sid,
            transcript(&self.point, &self.ad, parsed.point, parsed.ad),
        )?;
        if !tags_equal(&tag(&shared, ROLE_APPROVER)?, parsed.tail) {
            return Err(PakeError::ConfirmationFailed);
        }
        Ok(Completed {
            confirmation: tag(&shared, ROLE_NEW_DEVICE)?.to_vec(),
            approver_ad: parsed.ad.to_vec(),
        })
    }
}

pub fn answer(code: &str, offer: &[u8], ad: &[u8]) -> Result<(Answered, Vec<u8>), PakeError> {
    answer_with(code, offer, ad, random_scalar()?)
}

fn answer_with(
    code: &str,
    offer: &[u8],
    ad: &[u8],
    scalar: Scalar,
) -> Result<(Answered, Vec<u8>), PakeError> {
    if ad.len() > MAX_AD_BYTES {
        return Err(PakeError::Malformed);
    }
    let sid = offer.get(..SID_BYTES).ok_or(PakeError::Malformed)?;
    let parsed = parse(offer, SID_BYTES)?;
    if !parsed.tail.is_empty() {
        return Err(PakeError::Malformed);
    }
    let peer = decode(parsed.point)?;
    let prs = Zeroizing::new(normalize_code(code));
    let point = (scalar * generator(&prs, PAIRING_CI, sid))
        .compress()
        .to_bytes();
    let shared = shared_secret(
        &scalar,
        &peer,
        sid,
        transcript(parsed.point, parsed.ad, &point, ad),
    )?;
    let approver_tag = tag(&shared, ROLE_APPROVER)?;
    let answered = Answered {
        message: encode_message(&[], &point, ad, &approver_tag),
        new_device_tag: tag(&shared, ROLE_NEW_DEVICE)?,
        isk: shared.isk,
    };
    Ok((answered, parsed.ad.to_vec()))
}

impl Answered {
    pub fn verify_confirmation(
        self,
        confirmation: &[u8],
    ) -> Result<Zeroizing<[u8; 64]>, PakeError> {
        if !tags_equal(&self.new_device_tag, confirmation) {
            return Err(PakeError::ConfirmationFailed);
        }
        Ok(self.isk)
    }
}

#[cfg(test)]
mod tests;
