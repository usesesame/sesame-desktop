use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::vault::{bytes_match, decrypt_bytes, derive_key, UnlockedVault, VaultResult, WRAP_AAD};

pub const PRESENCE_TTL: Duration = Duration::from_secs(120);
pub const PRESENCE_REQUIRED: &str = "presenceRequired";
const MAX_ATTEMPTS_BEFORE_COOLDOWN: u32 = 3;
const COOLDOWN_BASE: Duration = Duration::from_secs(5);
const COOLDOWN_MAX: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct ReleasePresence {
    grant: Mutex<Option<Grant>>,
    failures: Mutex<u32>,
    cooldown_until: Mutex<Option<Instant>>,
}

struct Grant {
    epoch: u64,
    expires_at: Instant,
}

impl ReleasePresence {
    pub fn require(&self, epoch: u64) -> VaultResult<()> {
        let grant = self.grant.lock().map_err(|_| LOCK_ERROR.to_string())?;
        match grant.as_ref() {
            Some(grant) if grant.epoch == epoch && grant.expires_at > Instant::now() => Ok(()),
            _ => Err(PRESENCE_REQUIRED.into()),
        }
    }

    pub fn grant_with_password(
        &self,
        session: &UnlockedVault,
        epoch: u64,
        secret: &str,
    ) -> VaultResult<()> {
        self.await_cooldown()?;
        let verified = verify_master_password(session, secret);
        if verified.is_ok() {
            let mut grant = self.grant.lock().map_err(|_| LOCK_ERROR.to_string())?;
            *grant = Some(Grant {
                epoch,
                expires_at: Instant::now() + PRESENCE_TTL,
            });
            let mut failures = self.failures.lock().map_err(|_| LOCK_ERROR.to_string())?;
            *failures = 0;
        } else {
            self.record_failure()?;
        }
        verified
    }

    pub fn revoke(&self) {
        if let Ok(mut grant) = self.grant.lock() {
            *grant = None;
        }
    }

    fn await_cooldown(&self) -> VaultResult<()> {
        let until = *self
            .cooldown_until
            .lock()
            .map_err(|_| LOCK_ERROR.to_string())?;
        match until {
            Some(until) if until > Instant::now() => {
                Err("Too many attempts. Wait a moment and try again.".into())
            }
            _ => Ok(()),
        }
    }

    fn record_failure(&self) -> VaultResult<()> {
        let mut failures = self.failures.lock().map_err(|_| LOCK_ERROR.to_string())?;
        *failures = failures.saturating_add(1);
        if *failures >= MAX_ATTEMPTS_BEFORE_COOLDOWN {
            let over = (*failures - MAX_ATTEMPTS_BEFORE_COOLDOWN).min(6);
            let cooldown = COOLDOWN_BASE * (1_u32 << over);
            let mut until = self
                .cooldown_until
                .lock()
                .map_err(|_| LOCK_ERROR.to_string())?;
            *until = Some(Instant::now() + cooldown.min(COOLDOWN_MAX));
        }
        Ok(())
    }
}

fn verify_master_password(session: &UnlockedVault, secret: &str) -> VaultResult<()> {
    let wrapping_key = Zeroizing::new(derive_key(secret, &session.kdf)?);
    let mut candidate = decrypt_bytes(&wrapping_key, &session.key_wrap, WRAP_AAD)
        .map_err(|_| "That master password does not open this vault.".to_string())?;
    let matched = bytes_match(&candidate, session.key.as_ref());
    candidate.zeroize();
    if matched {
        Ok(())
    } else {
        Err("That master password does not open this vault.".into())
    }
}

const LOCK_ERROR: &str = "Sesame could not read the vault session.";

#[cfg(test)]
mod tests {
    use super::*;
    use sesame_core::api::create_vault;

    fn session() -> UnlockedVault {
        let (opened, _) =
            create_vault("fictional master password", "Fictional vault").expect("created vault");
        let path =
            std::env::temp_dir().join(format!("sesame-release-{}", crate::vault::random_id()));
        UnlockedVault::from_opened(path, &opened).expect("unlocked vault")
    }

    #[test]
    fn without_a_grant_presence_is_required() {
        let presence = ReleasePresence::default();
        assert_eq!(presence.require(7), Err(PRESENCE_REQUIRED.to_string()));
    }

    #[test]
    fn an_expired_grant_presence_is_required() {
        let presence = ReleasePresence::default();
        *presence.grant.lock().expect("grant lock") = Some(Grant {
            epoch: 7,
            expires_at: Instant::now() - Duration::from_secs(1),
        });
        assert_eq!(presence.require(7), Err(PRESENCE_REQUIRED.to_string()));
    }

    #[test]
    fn a_grant_covers_its_epoch_only() {
        let presence = ReleasePresence::default();
        let vault = session();
        presence
            .grant_with_password(&vault, 7, "fictional master password")
            .expect("granted");
        assert!(presence.require(7).is_ok());
        assert_eq!(presence.require(8), Err(PRESENCE_REQUIRED.to_string()));
    }

    #[test]
    fn a_wrong_password_grants_nothing_and_earns_a_cooldown() {
        let presence = ReleasePresence::default();
        let vault = session();
        for _ in 0..MAX_ATTEMPTS_BEFORE_COOLDOWN {
            assert!(presence
                .grant_with_password(&vault, 7, "fictional wrong password")
                .is_err());
        }
        assert_eq!(
            presence.grant_with_password(&vault, 7, "fictional master password"),
            Err("Too many attempts. Wait a moment and try again.".to_string())
        );
        assert_eq!(presence.require(7), Err(PRESENCE_REQUIRED.to_string()));
    }

    #[test]
    fn a_correct_password_after_failures_resets_the_cooldown() {
        let presence = ReleasePresence::default();
        let vault = session();
        for _ in 0..MAX_ATTEMPTS_BEFORE_COOLDOWN - 1 {
            assert!(presence
                .grant_with_password(&vault, 7, "fictional wrong password")
                .is_err());
        }
        assert!(presence
            .grant_with_password(&vault, 7, "fictional master password")
            .is_ok());
        assert!(presence.require(7).is_ok());
    }

    #[test]
    fn revoking_drops_the_grant() {
        let presence = ReleasePresence::default();
        let vault = session();
        presence
            .grant_with_password(&vault, 7, "fictional master password")
            .expect("granted");
        presence.revoke();
        assert_eq!(presence.require(7), Err(PRESENCE_REQUIRED.to_string()));
    }
}
