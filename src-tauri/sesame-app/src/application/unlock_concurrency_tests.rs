use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use crate::release::ReleasePresence;
use crate::test_support::TestVault;
use crate::vault::crypto::{default_kdf_params, derive_key, encrypt_bytes};
use crate::vault::key_proof::{KeySettings, SecretProof, VAULT_CHANGED_DURING_CHECK};
use crate::vault::storage::{persist_session, write_vault_file};
use crate::vault::throttle::{PersistedPinThrottle, PinAttemptGuard};
use crate::vault::{PinWrap, VaultResult, PIN_WRAP_AAD};

use super::lifecycle::{
    begin_unlock, confirm_unlock_survived, lock_and_notify, lock_if_unlocked,
    unlock_vault_in_state, unlock_with_derived_key, LOCKED_DURING_UNLOCK,
};
use super::tests::FakeEffects;
use super::unlock::unlock_pin_vault_in_state;
use super::DesktopEffects;

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
                    let turn = begin_unlock(&vault.state).expect("unlock turn");
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

fn unlock_while(
    vault: &TestVault,
    lock: impl FnOnce(&TestVault, &FakeEffects<'_>),
) -> VaultResult<()> {
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (started, deriving) = mpsc::channel();
    let (release, locked) = mpsc::channel::<()>();
    let effects = &effects;
    std::thread::scope(|scope| {
        let unlock = scope.spawn(move || {
            let turn = begin_unlock(&vault.state).expect("unlock turn");
            unlock_with_derived_key(&vault.state, effects, &turn, |file| {
                started.send(()).expect("started");
                locked.recv_timeout(STEP).expect("lock finished first");
                password_key(file)
            })
            .and_then(|_| confirm_unlock_survived(&vault.state, &turn))
        });
        deriving.recv_timeout(STEP).expect("derivation started");
        lock(vault, effects);
        release.send(()).expect("released");
        unlock.join().expect("unlock thread")
    })
}

#[test]
fn every_way_of_locking_wins_over_an_unlock_in_progress() {
    let ways: [(&str, fn(&TestVault, &FakeEffects<'_>)); 4] = [
        (
            "the tray, the lock command and the window",
            |vault, effects| {
                lock_and_notify(&vault.state, effects).expect("locked");
            },
        ),
        (
            "screen lock, sleep, idle, a webview crash, exit and the updater",
            |vault, effects| {
                assert_eq!(lock_if_unlocked(&vault.state, effects), Ok(false));
            },
        ),
        ("deleting the vault", |vault, _| {
            drop(
                vault
                    .state
                    .begin_destructive_lifecycle_change(|_| Ok(()))
                    .expect("deleting"),
            );
        }),
        ("restoring a backup", |vault, _| {
            vault
                .state
                .apply_lifecycle_replacement(|_| Ok(()))
                .expect("restored");
        }),
    ];
    for (way, lock) in ways {
        let vault = locked_vault();
        let unlock = unlock_while(&vault, lock);
        assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK), "{way}");
        assert!(!unlocked(&vault), "{way}");
    }
}

#[test]
fn a_conditional_lock_does_not_wait_for_the_derivation() {
    let vault = locked_vault();
    let locked = AtomicUsize::new(0);
    let unlock = unlock_while(&vault, |vault, effects| {
        lock_if_unlocked(&vault.state, effects).expect("asked to lock");
        locked.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(locked.load(Ordering::SeqCst), 1);
    assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
}

fn lock_and_unlock_again(state: &crate::vault::VaultState) {
    let unlocked = state
        .session
        .lock()
        .expect("session lock")
        .take()
        .expect("an unlocked session");
    assert_eq!(state.lock_if_unlocked(), Ok(false));
    state.install_session(&mut state.session.lock().expect("session lock"), unlocked);
    state.advance_session_epoch();
}

fn set_pause(
    vault: &TestVault,
    pause: impl Fn(&crate::vault::VaultState, &str) + Send + Sync + 'static,
) {
    *vault.state.test_pause.lock().expect("pause") = Some(std::sync::Arc::new(pause));
}

fn clear_pause(vault: &TestVault) {
    *vault.state.test_pause.lock().expect("pause") = None;
}

#[test]
fn a_lock_while_an_unlock_waits_for_its_turn_wins() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (queued_tx, queued_rx) = mpsc::channel::<()>();
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let pause_side = Mutex::new((queued_tx, locked_rx));
    set_pause(&vault, move |_, point| {
        if point == "unlockQueued" {
            let side = pause_side.lock().expect("pause side");
            let _ = side.0.send(());
            let _ = side.1.recv_timeout(STEP);
        }
    });
    let derived = AtomicUsize::new(0);
    let (vault_ref, effects_ref, derived_ref) = (&vault, &effects, &derived);
    let unlock = std::thread::scope(|scope| {
        let unlock = scope.spawn(move || {
            let turn = begin_unlock(&vault_ref.state)?;
            unlock_with_derived_key(&vault_ref.state, effects_ref, &turn, |file| {
                derived_ref.fetch_add(1, Ordering::SeqCst);
                password_key(file)
            })
            .and_then(|_| confirm_unlock_survived(&vault_ref.state, &turn))
        });
        queued_rx.recv_timeout(STEP).expect("the unlock was queued");
        assert_eq!(lock_if_unlocked(&vault_ref.state, effects_ref), Ok(false));
        locked_tx.send(()).expect("locked");
        unlock.join().expect("unlock thread")
    });
    clear_pause(&vault);

    assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
    assert_eq!(derived.load(Ordering::SeqCst), 0);
    assert!(!unlocked(&vault));
}

#[test]
fn a_lock_right_after_the_unlock_check_never_replaces_a_newer_presence_grant() {
    let vault = locked_vault();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::with_presence(vault.path().to_path_buf(), &presence);
    let (committing_tx, committing_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let pause_side = Mutex::new((committing_tx, done_rx));
    set_pause(&vault, move |_, point| {
        if point == "unlockCommitting" {
            let side = pause_side.lock().expect("pause side");
            let _ = side.0.send(());
            let _ = side.1.recv_timeout(Duration::from_millis(500));
        }
    });
    let (vault_ref, effects_ref, presence_ref) = (&vault, &effects, &presence);
    std::thread::scope(|scope| {
        let unlock = scope.spawn(move || {
            unlock_vault_in_state(
                &vault_ref.state,
                presence_ref,
                effects_ref,
                Zeroizing::new(MASTER_PASSWORD.to_string()),
            )
        });
        committing_rx
            .recv_timeout(STEP)
            .expect("the unlock passed its check");
        lock_and_notify(&vault_ref.state, effects_ref).expect("locked");
        presence_ref.grant_after_unlock(vault_ref.state.session_epoch());
        let _ = done_tx.send(());
        let _ = unlock.join().expect("unlock thread");
    });
    clear_pause(&vault);

    assert!(!unlocked(&vault));
    assert_eq!(presence.require(vault.state.session_epoch()), Ok(()));
}

#[test]
fn a_pin_checked_against_one_session_is_not_saved_into_the_next() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let checked = {
        let session = vault.state.session.lock().expect("session lock");
        KeySettings::of(session.as_ref().expect("session"))
    };
    lock_and_unlock_again(&vault.state);
    let before = std::fs::read(vault.path()).expect("vault bytes");

    let saved = super::unlock::apply_unlock_pin_in_state(
        &vault.state,
        &FakeEffects::new(vault.path().to_path_buf()),
        &checked,
        &crate::vault::key_proof::NewPinWrap::for_tests([4_u8; 32]),
    );

    assert_eq!(saved, Err(VAULT_CHANGED_DURING_CHECK.to_string()));
    assert!(vault
        .state
        .session
        .lock()
        .expect("session lock")
        .as_ref()
        .expect("session")
        .pin_wrap
        .is_none());
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_ne!(vault.state.cached_pin_unlock(), Some(true));
}

#[test]
fn a_recovery_kit_prepared_for_one_session_is_not_sealed_into_the_next() {
    let (opened, _) =
        sesame_core::api::create_vault(MASTER_PASSWORD, "Fictional vault").expect("vault");
    let directory =
        std::env::temp_dir().join(format!("sesame-resume-{}", crate::vault::random_id()));
    std::fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("vault.sesame");
    write_vault_file(&path, &opened.file).expect("written");
    let state = crate::vault::VaultState::default();
    state.install_session(
        &mut state.session.lock().expect("session lock"),
        crate::vault::UnlockedVault::from_opened(path.clone(), &opened).expect("session"),
    );
    *state.test_pause.lock().expect("pause") = Some(std::sync::Arc::new(|state, point| {
        if point == "recoverySetupPrepared" {
            lock_and_unlock_again(state);
        }
    }));
    let before = std::fs::read(&path).expect("vault bytes");

    let resumed = super::unlock::resume_recovery_setup_in_state(&state);
    *state.test_pause.lock().expect("pause") = None;
    let after = std::fs::read(&path).expect("vault bytes");
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(resumed.err().as_deref(), Some(VAULT_CHANGED_DURING_CHECK));
    assert_eq!(after, before);
}

#[test]
fn a_new_vault_derived_while_a_lock_came_is_not_created() {
    let directory =
        std::env::temp_dir().join(format!("sesame-create-{}", crate::vault::random_id()));
    std::fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("vault.sesame");
    let state = crate::vault::VaultState::default();
    *state.test_pause.lock().expect("pause") = Some(std::sync::Arc::new(|state, point| {
        if point == "vaultDerived" {
            assert_eq!(state.lock_if_unlocked(), Ok(false));
        }
    }));

    let created = super::unlock::create_vault_in_state(
        &state,
        &FakeEffects::new(path.clone()),
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    );
    *state.test_pause.lock().expect("pause") = None;
    let exists = path.exists();
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(created.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
    assert!(!exists);
    assert!(state.session.lock().expect("session lock").is_none());
}

#[test]
fn a_lock_that_cleared_the_session_wins_over_an_unlock_waiting_for_it() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (derived_tx, derived_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let done_rx = Mutex::new(done_rx);
    *vault.state.test_pause.lock().expect("pause") = Some(std::sync::Arc::new(move |_, point| {
        if point == "lock" {
            let _ = go_tx.send(());
            let _ = done_rx
                .lock()
                .expect("done")
                .recv_timeout(Duration::from_millis(300));
        }
    }));
    let (vault_ref, effects) = (&vault, &effects);
    let unlock = std::thread::scope(|scope| {
        let unlock = scope.spawn(move || {
            let turn = begin_unlock(&vault_ref.state).expect("unlock turn");
            let result = unlock_with_derived_key(&vault_ref.state, effects, &turn, |file| {
                let key = password_key(file);
                derived_tx.send(()).expect("derived");
                go_rx
                    .recv_timeout(STEP)
                    .expect("the lock cleared the session");
                key
            })
            .and_then(|_| confirm_unlock_survived(&vault_ref.state, &turn));
            let _ = done_tx.send(());
            result
        });
        derived_rx.recv_timeout(STEP).expect("derivation finished");
        lock_and_notify(&vault_ref.state, effects).expect("locked");
        unlock.join().expect("unlock thread")
    });
    *vault.state.test_pause.lock().expect("pause") = None;

    assert_eq!(unlock.err().as_deref(), Some(LOCKED_DURING_UNLOCK));
    assert!(!unlocked(&vault));
}

#[test]
fn an_unlock_reports_a_lock_that_came_after_the_install() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let turn = begin_unlock(&vault.state).expect("unlock turn");
    unlock_with_derived_key(&vault.state, &effects, &turn, password_key).expect("installed");
    assert_eq!(confirm_unlock_survived(&vault.state, &turn), Ok(()));
    assert_eq!(lock_if_unlocked(&vault.state, &effects), Ok(true));

    assert_eq!(
        confirm_unlock_survived(&vault.state, &turn)
            .err()
            .as_deref(),
        Some(LOCKED_DURING_UNLOCK)
    );
    assert!(!unlocked(&vault));
}

#[test]
fn an_unlock_reports_a_lock_even_when_a_session_is_back() {
    let vault = locked_vault();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let turn = begin_unlock(&vault.state).expect("unlock turn");
    unlock_with_derived_key(&vault.state, &effects, &turn, password_key).expect("installed");
    lock_and_notify(&vault.state, &effects).expect("locked");
    vault.reopen();

    assert!(unlocked(&vault));
    assert_eq!(
        confirm_unlock_survived(&vault.state, &turn)
            .err()
            .as_deref(),
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
            let turn = begin_unlock(&vault.state).expect("unlock turn");
            unlock_with_derived_key(&vault.state, effects, &turn, |file| {
                started.send(()).expect("started");
                replaced.recv_timeout(STEP).expect("restore finished first");
                password_key(file)
            })
        });
        deriving.recv_timeout(STEP).expect("derivation started");
        vault
            .state
            .apply_lifecycle_replacement(|_| write_vault_file(vault.path(), &replacement.file))
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

    let turn = begin_unlock(&vault.state).expect("unlock turn");
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
                let turn = begin_unlock(&vault.state).expect("unlock turn");
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

fn without_recovery_wrap(vault: &TestVault) {
    let mut session = vault.state.session.lock().expect("session lock");
    let session = session.as_mut().expect("session");
    session.recovery_wrap = None;
    session.recovery_kdf = None;
    persist_session(session).expect("persisted vault without a recovery wrap");
}

fn change_password(state: &crate::vault::VaultState, path: &std::path::Path, to: &str) {
    super::unlock::change_master_password_in_state(
        state,
        &FakeEffects::new(path.to_path_buf()),
        crate::vault::ChangeMasterPasswordRequest {
            current_password: Some(MASTER_PASSWORD.to_string()),
            recovery_kit: None,
            new_password: to.to_string(),
        },
    )
    .expect("changed the master password");
}

const NEW_PASSWORD: &str = "fictional replacement passphrase 9031";

fn checked_settings(vault: &TestVault) -> KeySettings {
    let session = vault.state.session.lock().expect("session lock");
    KeySettings::of(session.as_ref().expect("session"))
}

#[test]
fn a_pin_saved_while_the_master_password_changes_never_leaves_a_stale_pin_flag() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    without_recovery_wrap(&vault);
    let wrap = crate::vault::key_proof::NewPinWrap::for_tests([4_u8; 32]);
    let checked = checked_settings(&vault);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let (derived_tx, derived_rx) = mpsc::channel::<()>();
    let (saved_tx, saved_rx) = mpsc::channel::<()>();
    let (changed_tx, changed_rx) = mpsc::channel::<()>();
    let change_side = Mutex::new((derived_tx, saved_rx));
    let pin_side = Mutex::new((saved_tx, changed_rx));
    *vault.state.test_pause.lock().expect("pause") =
        Some(std::sync::Arc::new(move |_, point| match point {
            "passwordChangeDerived" => {
                let side = change_side.lock().expect("change side");
                let _ = side.0.send(());
                let _ = side.1.recv_timeout(STEP);
            }
            "pinSaved" => {
                let _ = pin_side.lock().expect("pin side").0.send(());
            }
            "pinSessionReleased" => {
                pin_side
                    .lock()
                    .expect("pin side")
                    .1
                    .recv_timeout(STEP)
                    .expect("the key change finished first");
            }
            _ => {}
        }));
    let vault_ref = &vault;
    std::thread::scope(|scope| {
        let change = scope.spawn(move || {
            change_password(&vault_ref.state, vault_ref.path(), NEW_PASSWORD);
            let _ = changed_tx.send(());
        });
        derived_rx
            .recv_timeout(STEP)
            .expect("the new password was derived");
        super::unlock::apply_unlock_pin_in_state(&vault_ref.state, &effects, &checked, &wrap)
            .expect("PIN saved");
        change.join().expect("change thread");
    });
    *vault.state.test_pause.lock().expect("pause") = None;

    let has_wrap = vault
        .state
        .session
        .lock()
        .expect("session lock")
        .as_ref()
        .expect("session")
        .pin_wrap
        .is_some();
    assert!(!has_wrap);
    assert_eq!(vault.state.cached_pin_unlock(), Some(has_wrap));
}

#[test]
fn a_pin_prepared_before_a_key_change_wraps_the_new_key() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    without_recovery_wrap(&vault);
    let wrapping_key = [4_u8; 32];
    let wrap = crate::vault::key_proof::NewPinWrap::for_tests(wrapping_key);
    let checked = checked_settings(&vault);
    change_password(&vault.state, vault.path(), NEW_PASSWORD);
    super::unlock::apply_unlock_pin_in_state(
        &vault.state,
        &FakeEffects::new(vault.path().to_path_buf()),
        &checked,
        &wrap,
    )
    .expect("PIN saved");

    let session = vault.state.session.lock().expect("session lock");
    let session = session.as_ref().expect("session");
    let pin_wrap = session.pin_wrap.as_ref().expect("a PIN wrap");
    let opened =
        crate::vault::crypto::decrypt_bytes(&wrapping_key, &pin_wrap.key_wrap, PIN_WRAP_AAD)
            .expect("the PIN wrap opens");
    assert!(session
        .expose_vault_key(|key| Ok(opened.as_slice() == key))
        .expect("key"));
    assert_eq!(vault.state.cached_pin_unlock(), Some(true));
}

#[test]
fn a_recovery_kit_checked_before_the_kit_was_replaced_cannot_finish_setup() {
    let (opened, kit) =
        sesame_core::api::create_vault(MASTER_PASSWORD, "Fictional vault").expect("vault");
    let directory =
        std::env::temp_dir().join(format!("sesame-drift-{}", crate::vault::random_id()));
    std::fs::create_dir_all(&directory).expect("directory");
    let mut session =
        crate::vault::UnlockedVault::from_opened(directory.join("vault.sesame"), &opened)
            .expect("session");
    write_vault_file(&session.path, &opened.file).expect("written");
    let proof = SecretProof::recovery_kit(&KeySettings::of(&session), &kit).expect("derived");
    crate::vault::storage::resume_recovery_setup_for_session(&mut session).expect("new kit");

    let finished = crate::vault::storage::complete_recovery_setup_with(&mut session, &proof);
    let _ = std::fs::remove_dir_all(&directory);
    assert_eq!(finished, Err(VAULT_CHANGED_DURING_CHECK.to_string()));
    assert!(!session.setup_complete);
}

#[test]
fn a_key_change_after_the_replacement_password_check_stops_the_replacement() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    crate::test_support::grant(&vault, &presence);
    let effects = FakeEffects::with_presence(vault.path().to_path_buf(), &presence);
    let request = written_replacement_request(&vault, &effects);
    *vault.state.test_pause.lock().expect("pause") = Some(std::sync::Arc::new(|state, point| {
        if point == "replacementDerived" {
            let mut session = state.session.lock().expect("session lock");
            session.as_mut().expect("session").kdf = default_kdf_params();
        }
    }));
    let before = std::fs::read(vault.path()).expect("vault bytes");

    let replaced = super::recovery_replacement::complete_recovery_replacement_in_state(
        &vault.state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
        1_800_000_000 + crate::vault::storage::RECOVERY_REPLACEMENT_DELAY_SECS,
        false,
    );
    *vault.state.test_pause.lock().expect("pause") = None;

    assert_eq!(replaced.err().as_deref(), Some(VAULT_CHANGED_DURING_CHECK));
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(request.exists());
}

#[cfg(unix)]
#[test]
fn a_stale_replacement_password_check_never_takes_the_request_away() {
    use std::os::unix::fs::MetadataExt;

    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    crate::test_support::grant(&vault, &presence);
    let effects = FakeEffects::with_presence(vault.path().to_path_buf(), &presence);
    let request = written_replacement_request(&vault, &effects);
    let request_file = std::fs::metadata(&request).expect("request").ino();
    set_pause(&vault, |state, point| {
        if point == "replacementDerived" {
            let mut session = state.session.lock().expect("session lock");
            session.as_mut().expect("session").kdf = default_kdf_params();
        }
    });

    let replaced = super::recovery_replacement::complete_recovery_replacement_in_state(
        &vault.state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
        1_800_000_000 + crate::vault::storage::RECOVERY_REPLACEMENT_DELAY_SECS,
        false,
    );
    clear_pause(&vault);

    assert_eq!(replaced.err().as_deref(), Some(VAULT_CHANGED_DURING_CHECK));
    assert_eq!(
        std::fs::metadata(&request).expect("request").ino(),
        request_file
    );
}

fn written_replacement_request(vault: &TestVault, effects: &FakeEffects<'_>) -> PathBuf {
    let request = effects.recovery_replacement_path().expect("request path");
    let session = vault.state.session.lock().expect("session lock");
    super::recovery_replacement::write_request(
        &request,
        session.as_ref().expect("session"),
        1_800_000_000,
    )
    .expect("written request");
    request
}

#[test]
fn a_replacement_password_checked_before_a_lock_and_unlock_grants_nothing_and_replaces_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = std::sync::Arc::new(ReleasePresence::default());
    crate::test_support::grant(&vault, &presence);
    let effects = FakeEffects::with_presence(vault.path().to_path_buf(), &presence);
    let request = written_replacement_request(&vault, &effects);
    let reopened = std::sync::Arc::clone(&presence);
    set_pause(&vault, move |state, point| {
        if point == "replacementProofDerived" {
            lock_and_unlock_again(state);
            reopened.grant_after_unlock(state.session_epoch());
        }
    });
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let stored = std::fs::read(&request).expect("request bytes");

    let replaced = super::recovery_replacement::complete_recovery_replacement_in_state(
        &vault.state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
        1_800_000_000 + crate::vault::storage::RECOVERY_REPLACEMENT_DELAY_SECS,
        false,
    );
    clear_pause(&vault);

    assert_eq!(replaced.err().as_deref(), Some(VAULT_CHANGED_DURING_CHECK));
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_eq!(std::fs::read(&request).expect("request bytes"), stored);
    assert_eq!(presence.require(vault.state.session_epoch()), Ok(()));
}

#[test]
fn a_join_whose_password_was_checked_before_a_lock_and_unlock_stops_the_adoption() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    without_recovery_wrap(&vault);
    let store_dir = std::env::temp_dir().join(format!("sesame-join-{}", crate::vault::random_id()));
    let store = super::sync::SyncStore::new(store_dir.clone());
    let payload = {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("session")
            .open_payload()
            .expect("payload")
            .clone()
    };
    let vault_id = payload.vault_id.clone().unwrap_or_default();
    set_pause(&vault, |state, point| {
        if point == "adoptionSealed" {
            lock_and_unlock_again(state);
        }
    });
    let before = std::fs::read(vault.path()).expect("vault bytes");

    let joined = super::sync_adopt::finish_adoption_in_state(
        &vault.state,
        &store,
        &FakeEffects::new(PathBuf::new()),
        [5_u8; 32],
        payload,
        MASTER_PASSWORD,
        &vault_id,
    );
    clear_pause(&vault);
    let _ = std::fs::remove_dir_all(&store_dir);

    assert_eq!(joined.err().as_deref(), Some(VAULT_CHANGED_DURING_CHECK));
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
}

#[test]
fn a_master_password_change_while_joining_stops_the_adoption() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    without_recovery_wrap(&vault);
    let path = vault.path().to_path_buf();
    let store_dir = std::env::temp_dir().join(format!("sesame-join-{}", crate::vault::random_id()));
    let store = super::sync::SyncStore::new(store_dir.clone());
    let payload = {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("session")
            .open_payload()
            .expect("payload")
            .clone()
    };
    let vault_id = payload.vault_id.clone().unwrap_or_default();
    let changed_path = path.clone();
    *vault.state.test_pause.lock().expect("pause") =
        Some(std::sync::Arc::new(move |state, point| {
            if point == "adoptionSealed" {
                change_password(state, &changed_path, NEW_PASSWORD);
            }
        }));

    let joined = super::sync_adopt::finish_adoption_in_state(
        &vault.state,
        &store,
        &FakeEffects::new(PathBuf::new()),
        [5_u8; 32],
        payload,
        MASTER_PASSWORD,
        &vault_id,
    );
    *vault.state.test_pause.lock().expect("pause") = None;
    let _ = std::fs::remove_dir_all(&store_dir);

    assert_eq!(joined.err().as_deref(), Some(VAULT_CHANGED_DURING_CHECK));
    let file = sesame_core::loader::VaultLoader::read(&path).expect("vault file");
    assert!(sesame_core::api::open_vault_with_password(&file, NEW_PASSWORD).is_ok());
    assert!(sesame_core::api::open_vault_with_password(&file, MASTER_PASSWORD).is_err());
}
