use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sesame_core::{
    api,
    backup::{apply_restored_vault_file, prepare_backup_for_restore, verify_backup_file},
    loader::{Credential, LoadFailure, VaultLoader},
    random_id,
    storage::{commit_payload_change, persist_session},
    UnlockedVault, VaultEntry, VaultFile, VaultPayload,
};

const PASSWORD: &str = "fictional review password";
const FLOOR_BYTES: usize = 16 * 1024;
const COMPATIBILITY_FIXTURE: &[u8] = include_bytes!("fixtures/compatibility/v0.2.2.sesame");
const COMPATIBILITY_PASSWORD: &str = "fictional master password 01";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-padding-{}", random_id()));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("vault.sesame")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn login(index: usize, password: &str) -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = format!("fictional-login-{index:06}");
    entry.title = format!("Fictional service {index}");
    entry.url = format!("https://service{index}.example.test/login");
    entry.username = format!("fictional.user{index}");
    entry.password = password.into();
    entry.created_at = 1_700_000_000;
    entry.updated_at = 1_700_000_000;
    entry.password_updated_at = 1_700_000_000;
    entry.revision = 1;
    entry
}

fn session_in(directory: &TestDirectory) -> UnlockedVault {
    let (opened, _) = api::create_vault(PASSWORD, "Fictional vault").expect("create vault");
    let mut session = UnlockedVault::from_opened(directory.path(), &opened).expect("session");
    session.setup_complete = true;
    persist_session(&mut session).expect("initial save");
    session
}

fn vault_with_logins(session: &mut UnlockedVault, count: usize) -> VaultPayload {
    let mut payload = session.open_payload().expect("payload").clone();
    payload.entries = (0..count)
        .map(|index| login(index, "fictional-start"))
        .collect();
    commit_payload_change(session, payload.clone()).expect("save logins");
    session.open_payload().expect("saved payload").clone()
}

fn saved_size(directory: &TestDirectory) -> usize {
    fs::metadata(directory.path()).expect("vault file").len() as usize
}

fn decrypted_payload(directory: &TestDirectory) -> Vec<u8> {
    let file = VaultLoader::read(&directory.path()).expect("read vault");
    VaultLoader::authenticate(&file, Credential::MasterPassword(PASSWORD))
        .expect("authenticate vault")
        .bytes()
        .to_vec()
}

#[test]
fn file_size_is_identical_across_password_edits_inside_one_bucket() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    let base = vault_with_logins(&mut session, 10);
    let mut sizes = Vec::new();
    for length in [1_usize, 8, 9, 16, 24, 64, 200] {
        let mut edited = base.clone();
        edited.entries[3].password = "p".repeat(length);
        commit_payload_change(&mut session, edited).expect("save edit");
        sizes.push(saved_size(&directory));
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]), "{sizes:?}");
}

#[test]
fn file_size_is_identical_across_added_logins_inside_one_bucket() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    let mut sizes = Vec::new();
    for count in [1_usize, 5, 10, 20] {
        vault_with_logins(&mut session, count);
        sizes.push(saved_size(&directory));
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]), "{sizes:?}");
}

#[test]
fn file_size_differs_across_buckets() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    vault_with_logins(&mut session, 10);
    let small = saved_size(&directory);
    vault_with_logins(&mut session, 200);
    let medium = saved_size(&directory);
    vault_with_logins(&mut session, 1000);
    let large = saved_size(&directory);
    assert!(small < medium && medium < large, "{small} {medium} {large}");
}

#[test]
fn the_decrypted_payload_is_json_followed_only_by_spaces() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    vault_with_logins(&mut session, 10);
    let bytes = decrypted_payload(&directory);
    assert_eq!(bytes.len(), FLOOR_BYTES);
    let compact = bytes.trim_ascii_end();
    assert!(compact.len() < bytes.len());
    assert_eq!(compact.last(), Some(&b'}'));
    assert!(bytes[compact.len()..].iter().all(|byte| *byte == b' '));
    serde_json::from_slice::<serde_json::Value>(compact).expect("compact json");
}

#[test]
fn a_padded_vault_opens_through_the_loader_with_every_credential_path() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    let saved = vault_with_logins(&mut session, 10);
    assert_eq!(decrypted_payload(&directory).len(), FLOOR_BYTES);
    let bytes = fs::read(directory.path()).expect("vault bytes");
    let opened = api::open_vault_bytes(&bytes, PASSWORD).expect("open padded vault");
    assert_eq!(opened.payload.entries.len(), 10);
    assert_eq!(opened.payload.revision, saved.revision);
    assert_eq!(opened.payload.entries[7].password, "fictional-start");
    assert!(!opened.migrated);
    let file = VaultLoader::read(&directory.path()).expect("read vault");
    VaultLoader::open(&file, Credential::VaultKey(&opened.key)).expect("open with the vault key");
    let reopened =
        VaultLoader::open(&file, Credential::MasterPassword(PASSWORD)).expect("password");
    assert_eq!(reopened.payload.vault_id, saved.vault_id);
}

#[test]
fn a_padded_vault_passes_backup_verification_and_restore() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    let saved = vault_with_logins(&mut session, 10);
    let backup = directory.0.join("export.sesame");
    fs::copy(directory.path(), &backup).expect("backup copy");
    let verified = verify_backup_file(&backup, PASSWORD).expect("verify padded backup");
    assert_eq!(verified.entry_count, 10);
    assert_eq!(verified.revision, saved.revision);

    let destination = directory.0.join("restored.sesame");
    let prepared =
        prepare_backup_for_restore(&backup, &destination, PASSWORD).expect("prepare restore");
    apply_restored_vault_file(&destination, &prepared).expect("install restore");
    let restored = fs::read(&destination).expect("restored bytes");
    let opened = api::open_vault_bytes(&restored, PASSWORD).expect("open restored vault");
    assert_eq!(opened.payload.entries.len(), 10);
    let file = VaultLoader::parse(&restored).expect("restored envelope");
    let authenticated = VaultLoader::authenticate(&file, Credential::MasterPassword(PASSWORD))
        .expect("authenticate restored vault");
    assert_eq!(authenticated.bytes().len(), FLOOR_BYTES);
}

#[test]
fn restoring_an_older_backup_writes_a_padded_payload() {
    let directory = TestDirectory::new();
    let source = directory.0.join("old.sesame");
    let destination = directory.0.join("restored.sesame");
    fs::write(&source, COMPATIBILITY_FIXTURE).expect("fixture copy");
    let before = VaultLoader::parse(COMPATIBILITY_FIXTURE).expect("fixture envelope");
    let before_bytes =
        VaultLoader::authenticate(&before, Credential::MasterPassword(COMPATIBILITY_PASSWORD))
            .expect("authenticate fixture")
            .bytes()
            .len();
    assert!(before_bytes < FLOOR_BYTES);
    let prepared = prepare_backup_for_restore(&source, &destination, COMPATIBILITY_PASSWORD)
        .expect("prepare restore");
    apply_restored_vault_file(&destination, &prepared).expect("install restore");
    assert_eq!(
        fs::read(&source).expect("source preserved"),
        COMPATIBILITY_FIXTURE
    );
    let restored = fs::read(&destination).expect("restored bytes");
    let file = VaultLoader::parse(&restored).expect("restored envelope");
    let authenticated =
        VaultLoader::authenticate(&file, Credential::MasterPassword(COMPATIBILITY_PASSWORD))
            .expect("authenticate restored vault");
    assert_eq!(authenticated.bytes().len(), FLOOR_BYTES);
}

fn ciphertext_of(file: &VaultFile) -> Vec<u8> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&file.payload.ciphertext)
        .expect("ciphertext");
    assert_eq!(ciphertext.len(), FLOOR_BYTES + 16);
    ciphertext
}

fn with_ciphertext(file: &VaultFile, ciphertext: &[u8]) -> Vec<u8> {
    let mut tampered = file.clone();
    tampered.payload.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    serde_json::to_vec(&tampered).expect("encode tampered file")
}

#[test]
fn tampering_with_the_padding_is_detected() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    vault_with_logins(&mut session, 10);
    let compact_length = decrypted_payload(&directory).trim_ascii_end().len();
    let file = VaultLoader::read(&directory.path()).expect("read vault");
    let ciphertext = ciphertext_of(&file);
    let plaintext_length = FLOOR_BYTES;
    assert!(compact_length < plaintext_length);

    let mut attempts = 0;
    for index in (compact_length..plaintext_length).step_by(61) {
        let mut flipped = ciphertext.clone();
        flipped[index] ^= 0x01;
        let bytes = with_ciphertext(&file, &flipped);
        assert_eq!(
            VaultLoader::load(&bytes, Credential::MasterPassword(PASSWORD)).err(),
            Some(LoadFailure::Authentication)
        );
        attempts += 1;
    }
    assert!(attempts > 100);

    let mut last_padding_byte = ciphertext.clone();
    last_padding_byte[plaintext_length - 1] ^= 0x20;
    let mut first_padding_byte = ciphertext.clone();
    first_padding_byte[compact_length] ^= 0x20;
    let mut tag = ciphertext.clone();
    tag[plaintext_length + 3] ^= 0x01;
    for tampered in [last_padding_byte, first_padding_byte, tag] {
        assert_eq!(
            VaultLoader::load(
                &with_ciphertext(&file, &tampered),
                Credential::MasterPassword(PASSWORD)
            )
            .err(),
            Some(LoadFailure::Authentication)
        );
    }
}

#[test]
fn removing_or_adding_padding_bytes_is_detected() {
    let directory = TestDirectory::new();
    let mut session = session_in(&directory);
    vault_with_logins(&mut session, 10);
    let file = VaultLoader::read(&directory.path()).expect("read vault");
    let ciphertext = ciphertext_of(&file);
    let plaintext_length = FLOOR_BYTES;

    let mut shortened = ciphertext[..plaintext_length - 1].to_vec();
    shortened.extend_from_slice(&ciphertext[plaintext_length..]);
    let mut lengthened = ciphertext[..plaintext_length].to_vec();
    lengthened.push(0x20);
    lengthened.extend_from_slice(&ciphertext[plaintext_length..]);
    let mut without_tag = ciphertext.clone();
    without_tag.truncate(plaintext_length);
    for tampered in [shortened, lengthened, without_tag] {
        assert!(matches!(
            VaultLoader::load(
                &with_ciphertext(&file, &tampered),
                Credential::MasterPassword(PASSWORD)
            )
            .err(),
            Some(LoadFailure::Authentication | LoadFailure::InvalidStructure)
        ));
    }
}
