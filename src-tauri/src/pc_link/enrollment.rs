use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

use super::authority::{validate_phone_label, validate_phone_public_key};
use super::fingerprint::PhonePublicKeyFingerprint;
use super::protocol::PairingState;
use super::PENDING_PAIRING_TTL_SECONDS;
use crate::vault::{bytes_match, VaultResult};

const MAX_CODE_FAILURES: u8 = 5;
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub(crate) struct PairingWindow {
    pub(crate) code: Zeroizing<String>,
    pub(crate) expires_at: u64,
    deadline: Instant,
    pub(crate) enrollments: BTreeMap<String, Enrollment>,
    pub(crate) enrolled_id: Option<String>,
    pub(crate) failed_attempts: u8,
}

pub(crate) struct Enrollment {
    pub(crate) enrollment_id: String,
    pub(crate) label: String,
    pub(crate) phone_public_key_fingerprint: PhonePublicKeyFingerprint,
    pub(crate) state: PairingState,
    pub(crate) link_id: Option<String>,
}

impl PairingWindow {
    pub(crate) fn new(now: u64) -> VaultResult<Self> {
        Ok(Self {
            code: generate_pairing_code()?,
            expires_at: now.saturating_add(PENDING_PAIRING_TTL_SECONDS),
            deadline: Instant::now() + Duration::from_secs(PENDING_PAIRING_TTL_SECONDS),
            enrollments: BTreeMap::new(),
            enrolled_id: None,
            failed_attempts: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_code(now: u64, code: String) -> VaultResult<Self> {
        let mut window = Self::new(now)?;
        window.code = Zeroizing::new(code);
        Ok(window)
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    #[cfg(test)]
    pub(crate) fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }

    fn is_expired_at(&self, now: Instant) -> bool {
        self.deadline <= now || self.failed_attempts >= MAX_CODE_FAILURES
    }

    pub(crate) fn verify_code(&mut self, code: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        if bytes_match(code.as_bytes(), self.code.as_bytes()) {
            return true;
        }
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        false
    }

    pub(crate) fn enroll(
        &mut self,
        enrollment_id: String,
        label: String,
        phone_public_key: Vec<u8>,
    ) -> VaultResult<&Enrollment> {
        validate_phone_label(&label)?;
        validate_phone_public_key(&phone_public_key)?;
        if self.enrolled_id.is_some() {
            return Err("This pairing code has already enrolled a phone.".to_string());
        }
        let phone_public_key_fingerprint =
            PhonePublicKeyFingerprint::from_phone_public_key(&phone_public_key);
        let enrollment = Enrollment {
            enrollment_id: enrollment_id.clone(),
            label,
            phone_public_key_fingerprint,
            state: PairingState::PendingConfirmation,
            link_id: None,
        };
        self.enrollments.insert(enrollment_id.clone(), enrollment);
        self.enrolled_id = Some(enrollment_id.clone());
        self.enrollments
            .get(&enrollment_id)
            .ok_or_else(|| "Sesame could not read the pairing request.".to_string())
    }

    pub(crate) fn enrollment(&self, enrollment_id: &str) -> Option<&Enrollment> {
        self.enrollments.get(enrollment_id)
    }

    pub(crate) fn enrollment_mut(&mut self, enrollment_id: &str) -> Option<&mut Enrollment> {
        self.enrollments.get_mut(enrollment_id)
    }

    pub(crate) fn expire_all(&mut self) {
        for enrollment in self.enrollments.values_mut() {
            if enrollment.state != PairingState::Active {
                enrollment.state = PairingState::Expired;
            }
        }
        self.enrolled_id = None;
    }
}

pub(crate) fn generate_pairing_code() -> VaultResult<Zeroizing<String>> {
    let mut bytes = [0_u8; 10];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "Sesame could not create a pairing code.".to_string())?;
    let mut code = Zeroizing::new(String::with_capacity(10));
    for byte in bytes {
        code.push(CODE_ALPHABET[(byte & 31) as usize] as char);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pc_link::protocol::is_pairing_code;

    fn phone_public_key() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("phone key");
        use rcgen::PublicKeyData;
        key.der_bytes().to_vec()
    }

    #[test]
    fn pairing_codes_fit_the_wire_alphabet_and_length() {
        let code = generate_pairing_code().expect("code");
        assert!(is_pairing_code(&code));
    }

    #[test]
    fn code_failures_close_the_window() {
        let mut window = PairingWindow::new(1_000).expect("window");
        let expected = window.code.clone();
        for _ in 0..MAX_CODE_FAILURES {
            assert!(!window.verify_code("AAAAAAAAAA"));
        }
        assert!(window.is_expired());
        assert_eq!(window.failed_attempts, MAX_CODE_FAILURES);
        assert!(!window.verify_code(&expected));
        assert_eq!(window.failed_attempts, MAX_CODE_FAILURES);
    }

    #[test]
    fn the_correct_code_cannot_reopen_an_expired_window() {
        let mut window = PairingWindow::new(u64::MAX).expect("window");
        let expected = window.code.clone();
        window.set_deadline(Instant::now() - Duration::from_secs(1));
        assert!(!window.verify_code(&expected));
        assert_eq!(window.failed_attempts, 0);
    }

    #[test]
    fn pairing_deadline_ignores_changes_to_the_wall_clock_display() {
        let mut window = PairingWindow::new(1_000).expect("window");
        let deadline = window.deadline();
        window.expires_at = 0;
        assert!(!window.is_expired_at(deadline - Duration::from_nanos(1)));
        window.expires_at = u64::MAX;
        assert!(window.is_expired_at(deadline));
        assert!(window.is_expired_at(deadline + Duration::from_secs(5)));
    }

    #[test]
    fn one_phone_can_enroll_per_code() {
        let mut window = PairingWindow::new(1_000).expect("window");
        let code = window.code.to_string();
        assert!(window.verify_code(&code));
        window
            .enroll(
                "ABCDEFGHIJKLMNOPQRSTUV".to_string(),
                "Fictional phone".to_string(),
                phone_public_key(),
            )
            .expect("enrolled");
        assert!(window
            .enroll(
                "ABCDEFGHIJKLMNOPQRSTUW".to_string(),
                "Fictional phone".to_string(),
                phone_public_key(),
            )
            .is_err());
        assert_eq!(
            window
                .enrollment("ABCDEFGHIJKLMNOPQRSTUV")
                .expect("enrollment")
                .state,
            PairingState::PendingConfirmation
        );
    }
}
