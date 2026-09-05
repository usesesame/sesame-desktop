use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sesame_core::{
    api, backup, encrypt_bytes,
    loader::{Credential, FormatState, LoadFailure, VaultLoader},
    payload_aad_for_file, random_id, CipherBlob, VaultFile, MAX_VAULT_FILE_BYTES,
};

const PASSWORD: &str = "fictional master password 01";
const FIXTURE: &[u8] = include_bytes!("fixtures/compatibility/v0.2.2.sesame");

fn fixture() -> VaultFile {
    VaultLoader::parse(FIXTURE).expect("fixture envelope")
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-loader-{}", random_id()));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn format_one_is_rejected_consistently_before_credentials_or_replacement() {
    let mut file = fixture();
    file.format_version = 1;
    let bytes = serde_json::to_vec(&file).expect("envelope");
    let expected = LoadFailure::UnsupportedFormat { format: 1 };
    assert_eq!(VaultLoader::inspect(&bytes), Err(expected));
    assert_eq!(VaultLoader::parse(&bytes).err(), Some(expected));
    assert_eq!(
        VaultLoader::open(&file, Credential::MasterPassword("wrong")).err(),
        Some(expected)
    );
    assert_eq!(
        VaultLoader::open(&file, Credential::RecoveryKit("wrong")).err(),
        Some(expected)
    );
    assert_eq!(
        VaultLoader::open(&file, Credential::VaultKey(&[0; 32])).err(),
        Some(expected)
    );

    let directory = TestDirectory::new();
    let source = directory.0.join("source.sesame");
    let destination = directory.0.join("active.sesame");
    fs::write(&source, &bytes).expect("source");
    fs::write(&destination, FIXTURE).expect("active");
    assert_eq!(
        backup::read_backup_file(&source).err(),
        Some(expected.to_string())
    );
    assert_eq!(
        backup::verify_backup_file(&source, PASSWORD).err(),
        Some(expected.to_string())
    );
    assert_eq!(
        backup::prepare_backup_for_restore(&source, &destination, PASSWORD).err(),
        Some(expected.to_string())
    );
    assert_eq!(
        api::open_vault_bytes(&bytes, PASSWORD).err(),
        Some(expected.to_string())
    );
    assert_eq!(fs::read(source).expect("source preserved"), bytes);
    assert_eq!(fs::read(destination).expect("active preserved"), FIXTURE);
    assert_eq!(fs::read_dir(&directory.0).expect("directory").count(), 2);
}

#[test]
fn inspection_reports_migration_without_authenticating_or_guessing_labels() {
    let current = VaultLoader::inspect(FIXTURE).expect("inspection");
    assert_eq!(current.state, FormatState::Current);
    for format in 2..=9 {
        let mut file = fixture();
        file.format_version = format;
        let bytes = serde_json::to_vec(&file).expect("relabelled envelope");
        let inspected = VaultLoader::inspect(&bytes).expect("recognized envelope only");
        assert_eq!(inspected.format, format);
        assert_eq!(inspected.state, FormatState::NeedsMigration);
        assert_eq!(
            VaultLoader::open(&file, Credential::MasterPassword(PASSWORD)).err(),
            Some(LoadFailure::Authentication)
        );
    }
    let mut file = fixture();
    file.setup_complete = false;
    assert_eq!(
        VaultLoader::open(&file, Credential::MasterPassword(PASSWORD)).err(),
        Some(LoadFailure::Authentication)
    );
}

#[test]
fn failures_distinguish_credentials_ciphertext_and_authenticated_schema() {
    let mut file = fixture();
    assert_eq!(
        VaultLoader::open(&file, Credential::MasterPassword("wrong")).err(),
        Some(LoadFailure::WrongPassword)
    );
    assert_eq!(
        VaultLoader::open(&file, Credential::RecoveryKit("wrong")).err(),
        Some(LoadFailure::WrongRecoveryKit)
    );
    let key = VaultLoader::unwrap_key(&file, Credential::MasterPassword(PASSWORD)).expect("key");
    let aad = payload_aad_for_file(file.format_version, file.setup_complete).expect("label");
    file.payload = encrypt_bytes(&key, br#"{"items":[{"kind":"future-record"}]}"#, aad)
        .expect("authenticated schema");
    assert_eq!(
        VaultLoader::open(&file, Credential::VaultKey(&key)).err(),
        Some(LoadFailure::RecoveryRequired { format: 10 })
    );
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(&file.payload.ciphertext)
        .expect("ciphertext");
    ciphertext[0] ^= 1;
    file.payload.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    assert_eq!(
        VaultLoader::open(&file, Credential::VaultKey(&key)).err(),
        Some(LoadFailure::Authentication)
    );
}

#[test]
fn envelope_failures_are_bounded_and_do_not_become_wrong_password() {
    let mut file = fixture();
    file.format_version = 11;
    assert_eq!(
        VaultLoader::validate(&file),
        Err(LoadFailure::NewerFormat { format: 11 })
    );
    file = fixture();
    file.kdf.memory_kib = u32::MAX;
    assert_eq!(
        VaultLoader::open(&file, Credential::MasterPassword("wrong")).err(),
        Some(LoadFailure::UnsafeKdf)
    );
    file = fixture();
    file.kdf.memory_kib = 1;
    assert_eq!(VaultLoader::validate(&file), Err(LoadFailure::UnsafeKdf));
    file = fixture();
    file.recovery_wrap = None;
    assert_eq!(
        VaultLoader::validate(&file),
        Err(LoadFailure::InvalidStructure)
    );
    file = fixture();
    file.payload.nonce = "!".into();
    assert_eq!(
        VaultLoader::validate(&file),
        Err(LoadFailure::InvalidStructure)
    );
    assert_eq!(
        VaultLoader::inspect(b"{"),
        Err(LoadFailure::InvalidStructure)
    );
    assert_eq!(
        VaultLoader::inspect(&vec![b' '; MAX_VAULT_FILE_BYTES as usize + 1]),
        Err(LoadFailure::SizeLimit)
    );
    let directory = TestDirectory::new();
    assert_eq!(
        VaultLoader::read(&directory.0.join("missing.sesame")).err(),
        Some(LoadFailure::LocalIo)
    );
    let path = directory.0.join("oversized.sesame");
    fs::File::create(&path)
        .expect("sparse file")
        .set_len(MAX_VAULT_FILE_BYTES + 1)
        .expect("sparse length");
    assert_eq!(VaultLoader::read(&path).err(), Some(LoadFailure::SizeLimit));
}

#[test]
fn named_password_path_does_not_accept_a_recovery_kit() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/compatibility/manifest.json"))
            .expect("manifest");
    let kit = manifest["fixtures"][4]["secrets"]["recoveryKit"]
        .as_str()
        .expect("fictional kit");
    assert_eq!(
        VaultLoader::load(FIXTURE, Credential::MasterPassword(kit)).err(),
        Some(LoadFailure::WrongPassword)
    );
    assert!(VaultLoader::load(FIXTURE, Credential::RecoveryKit(kit)).is_ok());
}

#[test]
fn migration_is_in_memory_and_resealed_result_is_idempotent() {
    let opened = VaultLoader::load(FIXTURE, Credential::MasterPassword(PASSWORD)).expect("open");
    assert!(opened.migration.payload_changed);
    assert!(!opened.migration.envelope_changed);
    assert_eq!(opened.migration.source_format, 10);
    let sealed = api::seal_vault(&opened).expect("seal");
    let reopened =
        VaultLoader::open(&sealed, Credential::MasterPassword(PASSWORD)).expect("reopen");
    assert!(!reopened.migration.required());
    assert_eq!(opened.payload.entries.len(), reopened.payload.entries.len());
    assert_eq!(
        serde_json::to_vec(&fixture()).expect("unchanged envelope"),
        serde_json::to_vec(&opened.file).expect("read-only open")
    );
}

#[test]
fn snapshots_use_only_the_supplied_protocol_context_and_preserve_authenticated_bytes() {
    let authenticated = VaultLoader::authenticate(&fixture(), Credential::MasterPassword(PASSWORD))
        .expect("fixture");
    let key = [17; 32];
    let aad = b"fictional signed snapshot context";
    let blob = encrypt_bytes(&key, authenticated.bytes(), aad).expect("snapshot");
    let snapshot = VaultLoader::open_snapshot(2, &key, &blob, aad).expect("snapshot");
    assert_eq!(snapshot.bytes(), authenticated.bytes());
    assert_eq!(
        snapshot.payload().vault_id,
        authenticated.payload().vault_id
    );
    assert_eq!(
        VaultLoader::open_snapshot(2, &key, &blob, b"stale context").err(),
        Some(LoadFailure::Authentication)
    );
    assert_eq!(
        VaultLoader::open_snapshot(3, &key, &blob, aad).err(),
        Some(LoadFailure::InvalidStructure)
    );
    let malformed = CipherBlob {
        nonce: "?".into(),
        ciphertext: blob.ciphertext,
    };
    assert_eq!(
        VaultLoader::open_snapshot(2, &key, &malformed, aad).err(),
        Some(LoadFailure::InvalidStructure)
    );
}
