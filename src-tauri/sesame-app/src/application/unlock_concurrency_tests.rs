use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use crate::release::ReleasePresence;
use crate::test_support::TestVault;
use crate::vault::crypto::{default_kdf_params, derive_key, encrypt_bytes};
use crate::vault::key_proof::{KeySettings, SecretProof, VAULT_CHANGED_DURING_CHECK};
use crate::vault::storage::{persist_session, write_vault_file};
use crate::vault::throttle::{PersistedPinThrottle, PinAttemptGuard};
use crate::vault::{PinWrap, PIN_WRAP_AAD};

use super::lifecycle::{
    begin_unlock, confirm_unlock_survived, lock_and_notify, unlock_vault_in_state,
    unlock_with_derived_key, LOCKED_DURING_UNLOCK,
};
use super::tests::FakeEffects;
use super::unlock::unlock_pin_vault_in_state;

const MASTER_PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional mistaken password";
const PIN: &str = "135790";
const WRONG_PIN: &str = "246801";
const STEP: Duration = Duration::from_secs(60);

fn locked_vault() -> TestVault {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    *vault.state.session.lock().expect("session lock") = None;
    vault
}

fn locked_vault_with_pin() -> TestVault {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    {
        let mut session = vault.state.session.lock().expect("session lock");
        let session = session.as_mut().expect("session");
        let kdf = default_kdf_params();
        let protected_pepper = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let secret = format!("{PIN}:{protected_pepper}");
        let wrapping_key = Zeroizing::new(derive_key(&secret, &kdf).expect("derived key"));
        let key_wrap = session
            .expose_vault_key(|key| encrypt_bytes(&wrapping_key, key, PIN_WRAP_AAD))
            .expect("wrapped key");
        session.pin_wrap = Some(PinWrap {
            kdf,
            protected_pepper,
            key_wrap,
        });
        persist_session(session).expect("persisted pin wrap");
    }
    *vault.state.session.lock().expect("session lock") = None;
    vault
}

fn password_key(file: &crate::vault::VaultFile) -> crate::vault::VaultResult<[u8; 32]> {
    sesame_core::api::unwrap_key_with_password(file, MASTER_PASSWORD)
}

fn unlocked(vault: &TestVault) -> bool {
    vault.state.session.lock().expect("session lock").is_some()
}

#[test]
fn two_unlocks_started_together_derive_one_at_a_time() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let deriving = AtomicUsize::new(0);
    let most = AtomicUsize::new(0);

    let results: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let turn = begin_unlock(&vault.state);
                    unlock_with_derived_key(&vault.state, &effects, &turn, |file| {
                        let now = deriving.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(150));
                        let key = password_key(file);
                        deriving.fetch_sub(1, Ordering::SeqCst);
                        key
                    })
                    .map(|_| ())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("unlock thread"))
            .collect()
    });

    assert_eq!(most.load(Ordering::SeqCst), 1);
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert!(unlocked(&vault));
}

#[test]
fn a_wrong_and_a_right_password_started_together_each_get_their_own_answer() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let presence = ReleasePresence::default();

    let (wrong, right) = std::thread::scope(|scope| {
        let wrong = scope.spawn(|| {
            unlock_vault_in_state(
                &vault.state,
                &presence,
                &effects,
                Zeroizing::new(WRONG_PASSWORD.to_string()),
            )
        });
        let right = scope.spawn(|| {
            unlock_vault_in_state(
                &vault.state,
                &presence,
                &effects,
                Zeroizing::new(MASTER_PASSWORD.to_string()),
            )
        });
        (
            wrong.join().expect("wrong thread"),
            right.join().expect("right thread"),
        )
    });

    assert!(wrong.is_err());
    assert!(right.is_ok());
    assert!(unlocked(&vault));
}

#[test]
fn a_lock_during_the_key_derivation_wins_and_does_not_wait_for_it() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (started, deriving) = mpsc::channel();
    let (release, locked) = mpsc::channel::<()>();
    let (vault, effects) = (&vault, &effects);

    let unlock = std::thread::scope(|scope| {
        let unlock = scope.spawn(move || {
            let turn = begin_unlock(&vault.state);
            unlock_with_derived_key(&vault.state, effects, &turn, |file| {
                started.send(()).expect("started");
                locked.recv_timeout(STEP).expect("lock finished first");
                password_key(file)
            })
        });
        deriving.recv_timeout(STEP).expect("derivation started");
        lock_and_notify(&vault.state, effects).expect("locked during the derivation");
        release.send(()).expect("released");
        unlock.join().expect("unlock thread")
    });

    assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
    assert!(!unlocked(vault));
    assert_eq!(
        confirm_unlock_survived(&vault.state).err().as_deref(),
        Some(LOCKED_DURING_UNLOCK)
    );
}

#[test]
fn an_unlock_that_races_a_restore_never_opens_the_replaced_file() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (replacement, _) =
        sesame_core::api::create_vault("fictional restored password", "Fictional restored vault")
            .expect("replacement vault");
    let (started, deriving) = mpsc::channel();
    let (release, replaced) = mpsc::channel::<()>();
    let (vault, effects) = (&vault, &effects);

    let unlock = std::thread::scope(|scope| {
        let unlock = scope.spawn(move || {
            let turn = begin_unlock(&vault.state);
            unlock_with_derived_key(&vault.state, effects, &turn, |file| {
                started.send(()).expect("started");
                replaced.recv_timeout(STEP).expect("restore finished first");
                password_key(file)
            })
        });
        deriving.recv_timeout(STEP).expect("derivation started");
        vault
            .state
            .apply_lifecycle_replacement(|| write_vault_file(vault.path(), &replacement.file))
            .expect("restored during the derivation");
        release.send(()).expect("released");
        unlock.join().expect("unlock thread")
    });

    assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
    assert!(!unlocked(vault));
}

#[test]
fn an_unlock_refuses_a_file_whose_key_changed_behind_it() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (replacement, _) =
        sesame_core::api::create_vault("fictional other password", "Fictional other vault")
            .expect("replacement vault");

    let turn = begin_unlock(&vault.state);
    let unlock = unlock_with_derived_key(&vault.state, &effects, &turn, |file| {
        let key = password_key(file);
        write_vault_file(vault.path(), &replacement.file).expect("replaced outside Sesame");
        key
    });

    assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
    assert!(!unlocked(&vault));
}

#[test]
fn a_panic_during_the_derivation_does_not_block_the_next_unlock() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    let panicked = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let turn = begin_unlock(&vault.state);
                unlock_with_derived_key(&vault.state, &effects, &turn, |_| {
                    panic!("fictional failure during the derivation")
                })
            })
            .join()
    });

    assert!(panicked.is_err());
    assert!(!unlocked(&vault));
    unlock_vault_in_state(
        &vault.state,
        &ReleasePresence::default(),
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked after the panic");
    assert!(unlocked(&vault));
}

#[test]
fn pin_attempts_started_together_cannot_slip_past_the_lockout() {
    let vault = locked_vault_with_pin();
    let effects = FakeEffects::with_pin_throttle(
        vault.path().to_path_buf(),
        PersistedPinThrottle {
            failures: 8,
            locked_until_unix_ms: None,
        },
    );
    *vault.state.pin_guard.lock().expect("PIN guard") =
        PinAttemptGuard::from_persisted(PersistedPinThrottle {
            failures: 8,
            locked_until_unix_ms: None,
        });

    let errors: Vec<String> = std::thread::scope(|scope| {
        let attempts: Vec<_> = (0..3)
            .map(|_| {
                scope.spawn(|| {
                    unlock_pin_vault_in_state(&vault.state, &effects, WRONG_PIN.to_string())
                        .err()
                        .expect("a wrong PIN was refused")
                })
            })
            .collect();
        attempts
            .into_iter()
            .map(|attempt| attempt.join().expect("PIN thread"))
            .collect()
    });

    let refused = errors
        .iter()
        .filter(|error| error.starts_with("Too many incorrect PIN attempts."))
        .count();
    assert_eq!(refused, 2, "{errors:?}");
    let throttle = effects.pin_throttle().expect("persisted throttle");
    assert_eq!(throttle.failures, 9);
    assert!(throttle.locked_until_unix_ms.is_some());
    assert!(!unlocked(&vault));
    let locked_out = unlock_pin_vault_in_state(&vault.state, &effects, PIN.to_string())
        .err()
        .expect("the right PIN waits out the lockout");
    assert!(
        locked_out.starts_with("Too many incorrect PIN attempts."),
        "{locked_out}"
    );
}

#[test]
fn two_wrong_pins_started_together_are_both_charged() {
    let vault = locked_vault_with_pin();
    let effects =
        FakeEffects::with_pin_throttle(vault.path().to_path_buf(), PersistedPinThrottle::default());

    std::thread::scope(|scope| {
        let attempts: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    unlock_pin_vault_in_state(&vault.state, &effects, WRONG_PIN.to_string())
                })
            })
            .collect();
        for attempt in attempts {
            assert!(attempt.join().expect("PIN thread").is_err());
        }
    });

    assert_eq!(effects.pin_throttle().map(|state| state.failures), Some(2));
    assert!(!unlocked(&vault));
}

#[test]
fn a_password_check_against_a_rotated_key_reports_the_change() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let settings = {
        let session = vault.state.session.lock().expect("session lock");
        KeySettings::of(session.as_ref().expect("session"))
    };
    let right = SecretProof::master_password(&settings, MASTER_PASSWORD).expect("derived");
    let wrong = SecretProof::master_password(&settings, WRONG_PASSWORD).expect("derived");
    {
        let session = vault.state.session.lock().expect("session lock");
        let session = session.as_ref().expect("session");
        assert_eq!(right.opens(session), Ok(true));
        assert_eq!(wrong.opens(session), Ok(false));
    }
    {
        let mut session = vault.state.session.lock().expect("session lock");
        let session = session.as_mut().expect("session");
        session.kdf = default_kdf_params();
    }
    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");
    assert_eq!(
        right.opens(session),
        Err(VAULT_CHANGED_DURING_CHECK.to_string())
    );
}

#[test]
fn a_wrong_proof_for_the_presence_check_counts_toward_the_cooldown() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let epoch = vault.state.session_epoch();
    let settings = {
        let session = vault.state.session.lock().expect("session lock");
        KeySettings::of(session.as_ref().expect("session"))
    };
    let wrong = SecretProof::master_password(&settings, WRONG_PASSWORD).expect("derived");
    let right = SecretProof::master_password(&settings, MASTER_PASSWORD).expect("derived");
    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");

    for _ in 0..3 {
        assert!(presence.grant_with_proof(session, epoch, &wrong).is_err());
    }

    assert_eq!(
        presence.grant_with_proof(session, epoch, &right),
        Err("Too many attempts. Wait a moment and try again.".to_string())
    );
    assert_eq!(
        presence.ready_for_password(),
        Err("Too many attempts. Wait a moment and try again.".to_string())
    );
}
