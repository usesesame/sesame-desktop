use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use crate::crypto::{
    bytes_match, decrypt_bytes, default_kdf_params, derive_key, encrypt_bytes,
    master_password_kdf_params, unwrap_with_password,
};
use crate::platform::{ensure_device_protection, protect_for_device};
use crate::types::{CipherBlob, KdfParams, PinWrap};
use crate::util::{fill_secret, generate_recovery_kit};
use crate::{UnlockedVault, VaultResult, PIN_WRAP_AAD, RECOVERY_WRAP_AAD, WRAP_AAD};

pub const VAULT_CHANGED_DURING_CHECK: &str =
    "Sesame locked or changed the vault while it checked your secret. Try again.";

fn same_json<T: serde::Serialize>(left: &T, right: &T) -> bool {
    match (serde_json::to_vec(left), serde_json::to_vec(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[derive(Clone)]
pub struct KeySettings {
    session: u64,
    kdf: KdfParams,
    key_wrap: CipherBlob,
    recovery: Option<(KdfParams, CipherBlob)>,
}

impl KeySettings {
    pub fn of(session: &UnlockedVault) -> Self {
        Self {
            session: session.opened_in_lock_generation(),
            kdf: session.kdf.clone(),
            key_wrap: session.key_wrap.clone(),
            recovery: session
                .recovery_kdf
                .clone()
                .zip(session.recovery_wrap.clone()),
        }
    }

    pub fn has_recovery(&self) -> bool {
        self.recovery.is_some()
    }

    pub fn same_session(&self, session: &UnlockedVault) -> bool {
        self.session == session.opened_in_lock_generation()
    }

    pub fn still_match(&self, session: &UnlockedVault) -> bool {
        let recovery_matches = match (
            &self.recovery,
            &session.recovery_kdf,
            &session.recovery_wrap,
        ) {
            (Some((kdf, wrap)), Some(current_kdf), Some(current_wrap)) => {
                same_json(kdf, current_kdf) && same_json(wrap, current_wrap)
            }
            (None, None, None) => true,
            _ => false,
        };
        recovery_matches
            && same_json(&self.kdf, &session.kdf)
            && same_json(&self.key_wrap, &session.key_wrap)
    }
}

pub struct SecretProof {
    settings: KeySettings,
    candidate: Option<Zeroizing<Vec<u8>>>,
}

impl SecretProof {
    pub fn master_password(settings: &KeySettings, password: &str) -> VaultResult<Self> {
        let candidate =
            unwrap_with_password(password, &settings.kdf, &settings.key_wrap, WRAP_AAD)?;
        Ok(Self {
            settings: settings.clone(),
            candidate,
        })
    }

    pub fn recovery_kit(settings: &KeySettings, recovery_kit: &str) -> VaultResult<Self> {
        let (kdf, wrap) = settings
            .recovery
            .as_ref()
            .ok_or("This vault does not have a recovery wrapper.")?;
        let normalized = Zeroizing::new(recovery_kit.trim().to_ascii_uppercase());
        let wrapping_key = Zeroizing::new(derive_key(&normalized, kdf)?);
        let candidate = decrypt_bytes(&wrapping_key, wrap, RECOVERY_WRAP_AAD).ok();
        Ok(Self {
            settings: settings.clone(),
            candidate,
        })
    }

    pub fn opens(&self, session: &UnlockedVault) -> VaultResult<bool> {
        if !self.settings.still_match(session) {
            return Err(VAULT_CHANGED_DURING_CHECK.into());
        }
        let opens = match self.candidate.as_ref() {
            Some(candidate) => {
                session.expose_vault_key(|key| Ok(bytes_match(candidate.as_slice(), key)))?
            }
            None => false,
        };
        if opens && !self.settings.same_session(session) {
            return Err(VAULT_CHANGED_DURING_CHECK.into());
        }
        Ok(opens)
    }

    pub fn require(&self, session: &UnlockedVault, wrong: &str) -> VaultResult<()> {
        if self.opens(session)? {
            Ok(())
        } else {
            Err(wrong.to_string())
        }
    }
}

pub struct NewMasterWrap {
    kdf: KdfParams,
    wrapping_key: Zeroizing<[u8; 32]>,
}

impl NewMasterWrap {
    pub fn derive(password: &str) -> VaultResult<Self> {
        let kdf = master_password_kdf_params();
        let wrapping_key = Zeroizing::new(derive_key(password, &kdf)?);
        Ok(Self { kdf, wrapping_key })
    }

    pub fn seal(&self, vault_key: &[u8; 32]) -> VaultResult<(KdfParams, CipherBlob)> {
        let wrap = encrypt_bytes(&self.wrapping_key, vault_key, WRAP_AAD)?;
        Ok((self.kdf.clone(), wrap))
    }
}

pub struct NewRecoveryKit {
    kit: Zeroizing<String>,
    kdf: KdfParams,
    wrapping_key: Zeroizing<[u8; 32]>,
}

impl NewRecoveryKit {
    pub fn generate() -> VaultResult<Self> {
        let kit = Zeroizing::new(generate_recovery_kit()?);
        let kdf = default_kdf_params();
        let wrapping_key = Zeroizing::new(derive_key(&kit, &kdf)?);
        Ok(Self {
            kit,
            kdf,
            wrapping_key,
        })
    }

    pub fn seal(&self, vault_key: &[u8; 32]) -> VaultResult<(KdfParams, CipherBlob)> {
        let wrap = encrypt_bytes(&self.wrapping_key, vault_key, RECOVERY_WRAP_AAD)?;
        Ok((self.kdf.clone(), wrap))
    }

    pub fn kit_for_display(&self) -> String {
        self.kit.to_string()
    }
}

pub struct NewPinWrap {
    kdf: KdfParams,
    protected_pepper: String,
    wrapping_key: Zeroizing<[u8; 32]>,
}

impl NewPinWrap {
    pub fn prepare(pin: &str) -> VaultResult<Self> {
        crate::storage::validate_new_unlock_pin(pin)?;
        let mut pepper = Zeroizing::new([0_u8; 32]);
        fill_secret(&mut *pepper)?;
        ensure_device_protection()?;
        let protected_pepper = URL_SAFE_NO_PAD.encode(protect_for_device(&*pepper)?);
        let kdf = default_kdf_params();
        let secret = crate::storage::pin_secret(pin, &*pepper);
        let wrapping_key = Zeroizing::new(derive_key(secret.as_str(), &kdf)?);
        Ok(Self {
            kdf,
            protected_pepper,
            wrapping_key,
        })
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn for_tests(wrapping_key: [u8; 32]) -> Self {
        Self {
            kdf: default_kdf_params(),
            protected_pepper: "fictional-protected-pepper".to_string(),
            wrapping_key: Zeroizing::new(wrapping_key),
        }
    }

    pub fn seal(&self, vault_key: &[u8; 32]) -> VaultResult<PinWrap> {
        Ok(PinWrap {
            kdf: self.kdf.clone(),
            protected_pepper: self.protected_pepper.clone(),
            key_wrap: encrypt_bytes(&self.wrapping_key, vault_key, PIN_WRAP_AAD)?,
        })
    }
}

pub struct NewKeyWraps {
    master: NewMasterWrap,
    recovery: NewRecoveryKit,
}

impl NewKeyWraps {
    pub fn derive(new_password: &str) -> VaultResult<Self> {
        Ok(Self {
            master: NewMasterWrap::derive(new_password)?,
            recovery: NewRecoveryKit::generate()?,
        })
    }

    pub fn master(&self) -> &NewMasterWrap {
        &self.master
    }

    pub fn recovery(&self) -> &NewRecoveryKit {
        &self.recovery
    }
}
