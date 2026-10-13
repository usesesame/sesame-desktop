use std::fs;
use std::path::{Path, PathBuf};

use sesame_core::api::{
    create_vault, open_vault_with_key, open_vault_with_password, open_vault_with_recovery_kit,
    unwrap_key_with_password, unwrap_key_with_recovery_kit,
};
use sesame_core::crypto::{decrypt_bytes, default_kdf_params, derive_key, encrypt_bytes};
use sesame_core::storage::{
    commit_payload_change, persist_session, replace_recovery_kit_for_session,
    RECOVERY_REPLACEMENT_DELAY_SECS,
};
use sesame_core::{
    random_id, HelloWrap, PinWrap, UnlockedVault, VaultEntry, VaultFile, MAX_VAULT_FILE_BYTES,
    PIN_WRAP_AAD,
};

const PASSWORD: &str = "fictional master password";
const PIN: &str = "472913";
const PEPPER: &str = "ZmljdGlvbmFscGVwcGVy";
const REQUESTED_AT: u64 = 1_800_000_000;
const READY_AT: u64 = REQUESTED_AT + RECOVERY_REPLACEMENT_DELAY_SECS;

fn replace_kit(session: &mut UnlockedVault, password: &str) -> Result<String, String> {
    replace_recovery_kit_for_session(session, password, REQUESTED_AT, READY_AT, false)
        .map(|replacement| replacement.recovery_kit)
}

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    session: UnlockedVault,
    kit: String,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("sesame-kit-replacement-{}", random_id()));
        fs::create_dir_all(&directory).expect("test directory");
        let path = directory.join("vault.sesame");
        let (opened, kit) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
        let mut session = UnlockedVault::from_opened(path.clone(), &opened).expect("session");
        session.setup_complete = true;
        persist_session(&mut session).expect("initial save");
        Self {
            directory,
            path,
            session,
            kit,
        }
    }

    fn previous_copy(&self) -> PathBuf {
        self.path.with_extension("sesame.prev")
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(&self.path).expect("vault bytes")
    }

    fn file(&self) -> VaultFile {
        file_from(&self.bytes())
    }

    fn save_login(&mut self, id: &str, password: &str) {
        let mut payload = self.session.open_payload().expect("payload").clone();
        let mut entry = VaultEntry::default();
        entry.id = id.to_string();
        entry.title = "Northwind".to_string();
        entry.password = password.to_string();
        payload.entries.push(entry);
        commit_payload_change(&mut self.session, payload).expect("saved login");
    }

    fn assert_old_state_is_intact(&self, before: &[u8]) {
        assert_eq!(self.bytes(), before);
        let file = self.file();
        assert!(open_vault_with_password(&file, PASSWORD).is_ok());
        assert!(open_vault_with_recovery_kit(&file, &self.kit).is_ok());
        let leftovers: Vec<_> = fs::read_dir(&self.directory)
            .expect("directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temporary files: {leftovers:?}");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn file_from(bytes: &[u8]) -> VaultFile {
    serde_json::from_slice(bytes).expect("vault file")
}

fn pin_wrap_for(session: &UnlockedVault) -> PinWrap {
    let kdf = default_kdf_params();
    let wrapping_key = derive_key(&format!("{PIN}:{PEPPER}"), &kdf).expect("pin key");
    let key_wrap = session
        .expose_vault_key(|key| encrypt_bytes(&wrapping_key, key, PIN_WRAP_AAD))
        .expect("pin wrap");
    PinWrap {
        kdf,
        protected_pepper: "ZmljdGlvbmFs".to_string(),
        key_wrap,
    }
}

fn vault_key_from_pin_wrap(wrap: &PinWrap) -> [u8; 32] {
    let wrapping_key = derive_key(&format!("{PIN}:{PEPPER}"), &wrap.kdf).expect("pin key");
    decrypt_bytes(&wrapping_key, &wrap.key_wrap, PIN_WRAP_AAD)
        .expect("unwrapped vault key")
        .as_slice()
        .try_into()
        .expect("vault key length")
}

fn fictional_hello_wrap() -> HelloWrap {
    HelloWrap {
        key_name: "sesame-vault-hello-fictional".to_string(),
        ciphertext: "ZmljdGlvbmFsIGhlbGxvIGNpcGhlcnRleHQ".to_string(),
    }
}

fn write_backup(vault: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let folder = vault.parent().expect("vault folder").join("backups");
    fs::create_dir_all(&folder).expect("backup folder");
    let backup = folder.join(name);
    fs::write(&backup, bytes).expect("backup copy");
    backup
}

#[test]
fn a_replaced_kit_cannot_open_versions_written_after_replacement() {
    let mut fixture = Fixture::new();
    fixture.save_login("before", "fictional-secret-before");
    let old_copy = fixture.bytes();
    let old_kit = fixture.kit.clone();

    let new_kit = replace_kit(&mut fixture.session, PASSWORD).expect("replaced kit");
    fixture.save_login("after", "fictional-secret-AAAA");
    fixture.save_login("later", "fictional-secret-BBBB");
    let current = fixture.file();

    assert!(open_vault_with_recovery_kit(&current, &old_kit).is_err());
    let key_from_old_copy =
        unwrap_key_with_recovery_kit(&file_from(&old_copy), &old_kit).expect("old copy opens");
    assert!(open_vault_with_key(&current, key_from_old_copy).is_err());

    let opened = open_vault_with_recovery_kit(&current, &new_kit).expect("new kit opens");
    assert!(opened
        .payload
        .entries
        .iter()
        .any(|entry| entry.password == "fictional-secret-AAAA"));
    assert!(open_vault_with_password(&current, PASSWORD).is_ok());
}

#[test]
fn replacing_the_kit_rotates_the_vault_key_and_every_wrap() {
    let mut fixture = Fixture::new();
    fixture.session.pin_wrap = Some(pin_wrap_for(&fixture.session));
    fixture.session.hello_wrap = Some(fictional_hello_wrap());
    persist_session(&mut fixture.session).expect("save with unlock wraps");
    persist_session(&mut fixture.session).expect("create a previous copy");
    assert!(fixture.previous_copy().exists());
    let before = fixture.file();
    assert!(before.pin_wrap.is_some() && before.hello_wrap.is_some());
    let old_key = unwrap_key_with_password(&before, PASSWORD).expect("old key");

    let new_kit = replace_kit(&mut fixture.session, PASSWORD).expect("replaced kit");

    let after = fixture.file();
    let new_key = unwrap_key_with_password(&after, PASSWORD).expect("new key");
    assert_ne!(old_key, new_key);
    assert_eq!(
        unwrap_key_with_recovery_kit(&after, &new_kit).expect("kit key"),
        new_key
    );
    assert_ne!(after.kdf.salt, before.kdf.salt);
    assert_ne!(
        after.recovery_kdf.as_ref().expect("kit kdf").salt,
        before.recovery_kdf.as_ref().expect("old kit kdf").salt
    );
    assert!(after.pin_wrap.is_none());
    assert!(after.hello_wrap.is_none());
    assert!(fixture.session.pin_wrap.is_none());
    assert!(fixture.session.hello_wrap.is_none());
    assert!(!fixture.previous_copy().exists());
    assert!(open_vault_with_recovery_kit(&after, &fixture.kit).is_err());
}

#[test]
fn a_pin_set_before_replacement_cannot_open_later_versions() {
    let mut fixture = Fixture::new();
    fixture.session.pin_wrap = Some(pin_wrap_for(&fixture.session));
    persist_session(&mut fixture.session).expect("save with a PIN");
    let old_copy = file_from(&fixture.bytes());
    let old_pin_wrap = old_copy.pin_wrap.as_ref().expect("saved PIN wrap");
    assert!(open_vault_with_key(&old_copy, vault_key_from_pin_wrap(old_pin_wrap)).is_ok());

    replace_kit(&mut fixture.session, PASSWORD).expect("replaced kit");
    fixture.save_login("after", "fictional-secret-AAAA");

    let current = fixture.file();
    assert!(current.pin_wrap.is_none());
    assert!(open_vault_with_key(&current, vault_key_from_pin_wrap(old_pin_wrap)).is_err());
}

#[test]
fn a_wrong_master_password_replaces_nothing() {
    let mut fixture = Fixture::new();
    fixture.session.pin_wrap = Some(pin_wrap_for(&fixture.session));
    fixture.session.hello_wrap = Some(fictional_hello_wrap());
    persist_session(&mut fixture.session).expect("save with unlock wraps");
    let before = fixture.bytes();

    for wrong in ["fictional wrong password", ""] {
        let error = replace_kit(&mut fixture.session, wrong).expect_err("refused");
        assert!(error.contains("master password is not correct"), "{error}");
        fixture.assert_old_state_is_intact(&before);
        assert!(fixture.session.pin_wrap.is_some());
        assert!(fixture.session.hello_wrap.is_some());
    }

    fixture.save_login("after", "fictional-secret-AAAA");
    assert!(open_vault_with_recovery_kit(&fixture.file(), &fixture.kit).is_ok());
}

#[test]
fn a_replacement_waits_for_the_delay_and_an_unfinished_setup() {
    let mut fixture = Fixture::new();
    let before = fixture.bytes();

    for now in [READY_AT - 1, REQUESTED_AT - 1] {
        assert!(replace_recovery_kit_for_session(
            &mut fixture.session,
            PASSWORD,
            REQUESTED_AT,
            now,
            false
        )
        .is_err());
    }
    fixture.session.setup_complete = false;
    assert!(replace_kit(&mut fixture.session, PASSWORD).is_err());
    fixture.session.setup_complete = true;

    fixture.assert_old_state_is_intact(&before);
}

#[test]
fn a_second_replacement_retires_the_first_new_kit_and_its_copies() {
    let mut fixture = Fixture::new();
    let first_kit = replace_kit(&mut fixture.session, PASSWORD).expect("first replacement");
    fixture.save_login("between", "fictional-secret-AAAA");
    let copy_after_first = fixture.bytes();

    let second_kit = replace_kit(&mut fixture.session, PASSWORD).expect("second replacement");
    fixture.save_login("after", "fictional-secret-BBBB");

    assert_ne!(first_kit, second_kit);
    let current = fixture.file();
    assert!(open_vault_with_recovery_kit(&current, &first_kit).is_err());
    assert!(open_vault_with_recovery_kit(&current, &fixture.kit).is_err());
    assert!(open_vault_with_recovery_kit(&current, &second_kit).is_ok());
    let key_from_first_copy =
        unwrap_key_with_recovery_kit(&file_from(&copy_after_first), &first_kit)
            .expect("copy made after the first replacement opens with the first kit");
    assert!(open_vault_with_key(&current, key_from_first_copy).is_err());
}

#[test]
fn backups_made_before_replacement_still_open_with_the_old_kit_unless_pruned() {
    let mut fixture = Fixture::new();
    fixture.save_login("before", "fictional-secret-before");
    let old_copy = fixture.bytes();
    let backup = write_backup(&fixture.path, "sesame-backup-fictional.sesame", &old_copy);
    let revision = write_backup(
        &fixture.path,
        "sesame-before-import-fictional.sesame",
        &old_copy,
    );

    let kept = replace_recovery_kit_for_session(
        &mut fixture.session,
        PASSWORD,
        REQUESTED_AT,
        READY_AT,
        false,
    )
    .expect("replaced without pruning");
    assert_eq!(kept.backups_remaining, None);
    let kept_file = file_from(&fs::read(&backup).expect("backup survives"));
    assert!(open_vault_with_recovery_kit(&kept_file, &fixture.kit).is_ok());
    assert!(open_vault_with_password(&kept_file, PASSWORD).is_ok());
    assert!(revision.exists());

    let pruned = replace_recovery_kit_for_session(
        &mut fixture.session,
        PASSWORD,
        REQUESTED_AT,
        READY_AT,
        true,
    )
    .expect("replaced with pruning");
    assert_eq!(pruned.backups_remaining, Some(0));
    assert!(!backup.exists());
    assert!(!revision.exists());
}

#[test]
fn a_save_over_the_size_limit_replaces_nothing_and_can_be_retried() {
    let mut fixture = Fixture::new();
    fixture.session.pin_wrap = Some(pin_wrap_for(&fixture.session));
    fixture.session.hello_wrap = Some(fictional_hello_wrap());
    persist_session(&mut fixture.session).expect("save with unlock wraps");
    let before = fixture.bytes();
    let old_wrap = fixture.session.key_wrap.ciphertext.clone();
    fixture.session.legacy_device_wrap = Some("a".repeat(MAX_VAULT_FILE_BYTES as usize));

    assert!(replace_kit(&mut fixture.session, PASSWORD).is_err());

    fixture.assert_old_state_is_intact(&before);
    assert_eq!(fixture.session.key_wrap.ciphertext, old_wrap);
    assert!(fixture.session.pin_wrap.is_some());
    assert!(fixture.session.hello_wrap.is_some());

    fixture.session.legacy_device_wrap = None;
    let new_kit = replace_kit(&mut fixture.session, PASSWORD).expect("retried replacement");
    let current = fixture.file();
    assert!(open_vault_with_recovery_kit(&current, &new_kit).is_ok());
    assert!(open_vault_with_recovery_kit(&current, &fixture.kit).is_err());
}

#[test]
fn a_previous_copy_that_cannot_be_removed_replaces_nothing_and_can_be_retried() {
    let mut fixture = Fixture::new();
    fixture.session.pin_wrap = Some(pin_wrap_for(&fixture.session));
    persist_session(&mut fixture.session).expect("save with a PIN");
    let before = fixture.bytes();
    let blocker = fixture.previous_copy();
    let _ = fs::remove_file(&blocker);
    fs::create_dir(&blocker).expect("blocking directory");
    fs::write(blocker.join("keep"), b"fictional").expect("blocking contents");

    assert!(replace_kit(&mut fixture.session, PASSWORD).is_err());

    fixture.assert_old_state_is_intact(&before);
    assert!(fixture.session.pin_wrap.is_some());

    fs::remove_dir_all(&blocker).expect("cleared blocker");
    let new_kit = replace_kit(&mut fixture.session, PASSWORD).expect("retried replacement");
    let current = fixture.file();
    assert!(open_vault_with_recovery_kit(&current, &new_kit).is_ok());
    assert!(open_vault_with_recovery_kit(&current, &fixture.kit).is_err());
    assert!(current.pin_wrap.is_none());
}

#[test]
fn a_failed_final_replace_keeps_the_session_and_leaves_no_temporary_file() {
    let mut fixture = Fixture::new();
    fixture.session.hello_wrap = Some(fictional_hello_wrap());
    persist_session(&mut fixture.session).expect("save with a Hello wrap");
    let before = fixture.bytes();
    fs::remove_file(&fixture.path).expect("removed vault file");
    fs::create_dir(&fixture.path).expect("directory in the vault place");
    fs::write(fixture.path.join("keep"), b"fictional").expect("directory contents");

    assert!(replace_kit(&mut fixture.session, PASSWORD).is_err());

    assert!(fixture.path.is_dir());
    assert!(fixture.session.hello_wrap.is_some());
    let leftovers = fs::read_dir(&fixture.directory)
        .expect("directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .count();
    assert_eq!(leftovers, 0);

    fs::remove_dir_all(&fixture.path).expect("cleared blocker");
    fs::write(&fixture.path, &before).expect("restored vault file");
    let new_kit = replace_kit(&mut fixture.session, PASSWORD).expect("retried replacement");
    assert!(open_vault_with_recovery_kit(&fixture.file(), &new_kit).is_ok());
}

#[test]
fn a_vault_folder_that_cannot_be_created_replaces_nothing() {
    let mut fixture = Fixture::new();
    let outer = fixture.directory.join("outer");
    fs::create_dir(&outer).expect("outer folder");
    fixture.session = {
        let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
        let mut session =
            UnlockedVault::from_opened(outer.join("blocked").join("vault.sesame"), &opened)
                .expect("session");
        session.setup_complete = true;
        session
    };
    fs::write(outer.join("blocked"), b"not a directory").expect("blocking file");
    let key_wrap = fixture.session.key_wrap.ciphertext.clone();

    assert!(replace_kit(&mut fixture.session, PASSWORD).is_err());

    assert_eq!(fixture.session.key_wrap.ciphertext, key_wrap);
    assert!(outer.join("blocked").is_file());
}
