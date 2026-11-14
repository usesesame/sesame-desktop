use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault::types::{CipherBlob, KdfParams};
use crate::vault::VaultResult;

pub const STAGED_LIFETIME: Duration = Duration::from_secs(10 * 60);
const NOT_READY: &str = "Show and save the new recovery kit first.";
const EXPIRED: &str =
    "The new recovery kit was shown too long ago. Show it again before you continue.";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedRecovery {
    pub wrap: CipherBlob,
    pub kdf: KdfParams,
}

struct Staged {
    key: Zeroizing<[u8; 32]>,
    recovery: PreparedRecovery,
    at: Instant,
}

#[derive(Default)]
pub struct PreparedKeyChange {
    staged: Mutex<Option<Staged>>,
}

impl PreparedKeyChange {
    pub fn stage(&self, key: &[u8; 32], recovery: PreparedRecovery, now: Instant) {
        if let Ok(mut guard) = self.staged.lock() {
            *guard = Some(Staged {
                key: Zeroizing::new(*key),
                recovery,
                at: now,
            });
        }
    }

    pub fn take(&self, now: Instant) -> VaultResult<([u8; 32], PreparedRecovery)> {
        let staged = self
            .staged
            .lock()
            .map_err(|_| NOT_READY.to_string())?
            .take()
            .ok_or_else(|| NOT_READY.to_string())?;
        if now.saturating_duration_since(staged.at) > STAGED_LIFETIME {
            return Err(EXPIRED.to_string());
        }
        Ok((*staged.key, staged.recovery.clone()))
    }

    pub fn discard(&self) {
        if let Ok(mut guard) = self.staged.lock() {
            *guard = None;
        }
    }

    #[cfg(test)]
    pub fn is_staged(&self) -> bool {
        self.staged.lock().is_ok_and(|guard| guard.is_some())
    }
}

impl Drop for PreparedKeyChange {
    fn drop(&mut self) {
        self.discard();
    }
}

#[cfg(test)]
pub fn fictional_recovery() -> PreparedRecovery {
    PreparedRecovery {
        wrap: CipherBlob {
            nonce: "fictional-nonce".to_string(),
            ciphertext: "fictional-ciphertext".to_string(),
        },
        kdf: KdfParams {
            algorithm: "argon2id".to_string(),
            salt: "fictional-salt".to_string(),
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_staged_key_is_handed_over_once_and_never_twice() {
        let staged = PreparedKeyChange::default();
        let now = Instant::now();
        assert!(staged.take(now).is_err());
        staged.stage(&[4u8; 32], fictional_recovery(), now);
        assert!(staged.is_staged());
        let (key, recovery) = staged.take(now).expect("taken");
        assert_eq!(key, [4u8; 32]);
        assert_eq!(recovery.wrap.nonce, "fictional-nonce");
        assert!(!staged.is_staged());
        assert_eq!(staged.take(now).err().expect("refused"), NOT_READY);
    }

    #[test]
    fn a_staged_key_expires_and_is_gone_after_the_refusal() {
        let staged = PreparedKeyChange::default();
        let now = Instant::now();
        staged.stage(&[4u8; 32], fictional_recovery(), now);
        let late = now + STAGED_LIFETIME + Duration::from_secs(1);
        assert_eq!(staged.take(late).err().expect("refused"), EXPIRED);
        assert!(!staged.is_staged());
        assert!(staged.take(late).is_err());
    }

    #[test]
    fn a_new_kit_replaces_the_one_before_and_cancel_forgets_it() {
        let staged = PreparedKeyChange::default();
        let now = Instant::now();
        staged.stage(&[1u8; 32], fictional_recovery(), now);
        staged.stage(&[2u8; 32], fictional_recovery(), now);
        assert_eq!(staged.take(now).expect("taken").0, [2u8; 32]);
        staged.stage(&[3u8; 32], fictional_recovery(), now);
        staged.discard();
        assert!(staged.take(now).is_err());
    }

    #[test]
    fn a_staged_key_is_taken_right_at_the_end_of_its_lifetime() {
        let staged = PreparedKeyChange::default();
        let now = Instant::now();
        staged.stage(&[5u8; 32], fictional_recovery(), now);
        assert!(staged.take(now + STAGED_LIFETIME).is_ok());
    }
}
