use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sesame_core::{
    backup::{inspect_backup_file, verify_backup_file},
    encrypt_bytes,
    loader::{Credential, VaultLoader},
    payload_aad_for_file, random_id,
    types::{BackupCompatibility, CipherBlob, KdfParams, VaultFile},
    VAULT_FORMAT_VERSION,
};

const PASSWORD: &str = "fictional master password 01";
const FIXTURE: &[u8] = include_bytes!("fixtures/compatibility/v0.1.0.sesame");

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-inspection-{}", random_id()));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).expect("fixture");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn kdf() -> KdfParams {
    KdfParams {
        algorithm: "argon2id".into(),
        salt: URL_SAFE_NO_PAD.encode([7_u8; 16]),
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    }
}

fn blob() -> CipherBlob {
    CipherBlob {
        nonce: URL_SAFE_NO_PAD.encode([1_u8; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([2_u8; 48]),
    }
}

fn envelope(format_version: u8) -> VaultFile {
    VaultFile {
        format_version,
        kdf: kdf(),
        key_wrap: blob(),
        legacy_device_wrap: None,
        recovery_kdf: None,
        recovery_wrap: None,
        pin_wrap: None,
        hello_wrap: None,
        setup_complete: true,
        payload: blob(),
    }
}

/// Re-encrypts the fixture's authenticated payload under another format's label.
fn authenticated_old_format(format: u8) -> Vec<u8> {
    let mut file = VaultLoader::parse(FIXTURE).expect("fixture envelope");
    let authenticated =
        VaultLoader::authenticate(&file, Credential::MasterPassword(PASSWORD)).expect("payload");
    let key = VaultLoader::unwrap_key(&file, Credential::MasterPassword(PASSWORD)).expect("key");
    let aad = payload_aad_for_file(format, true).expect("historical label");
    file.payload = encrypt_bytes(&key, authenticated.bytes(), aad).expect("historical payload");
    file.format_version = format;
    serde_json::to_vec(&file).expect("historical envelope")
}

#[test]
fn inspection_classifies_current_older_newer_and_unsupported_formats() {
    let directory = TestDirectory::new();

    let current = directory.write(
        "current.sesame",
        &serde_json::to_vec(&envelope(VAULT_FORMAT_VERSION)).expect("current"),
    );
    let inspected = inspect_backup_file(&current).expect("current inspection");
    assert_eq!(inspected.compatibility, BackupCompatibility::Current);
    assert_eq!(inspected.format_version, VAULT_FORMAT_VERSION);
    assert!(inspected.setup_complete);

    for format in 2..VAULT_FORMAT_VERSION {
        let path = directory.write(
            &format!("format-{format}.sesame"),
            &serde_json::to_vec(&envelope(format)).expect("older"),
        );
        let inspected = inspect_backup_file(&path).expect("older inspection");
        assert_eq!(
            inspected.compatibility,
            BackupCompatibility::Upgrade,
            "format {format}"
        );
        assert_eq!(inspected.format_version, format);
    }

    let newer = directory.write(
        "newer.sesame",
        &serde_json::to_vec(&envelope(VAULT_FORMAT_VERSION + 1)).expect("newer"),
    );
    let inspected = inspect_backup_file(&newer).expect("newer inspection");
    assert_eq!(inspected.compatibility, BackupCompatibility::Newer);
    assert_eq!(inspected.format_version, VAULT_FORMAT_VERSION + 1);

    let unsupported = directory.write(
        "unsupported.sesame",
        &serde_json::to_vec(&envelope(1)).expect("unsupported"),
    );
    let inspected = inspect_backup_file(&unsupported).expect("unsupported inspection");
    assert_eq!(inspected.compatibility, BackupCompatibility::Unsupported);
    assert_eq!(inspected.format_version, 1);
}

#[test]
fn inspection_names_a_newer_format_without_parsing_the_rest_of_the_envelope() {
    let directory = TestDirectory::new();
    let path = directory.write("future.sesame", br#"{"formatVersion":12}"#);
    let inspected = inspect_backup_file(&path).expect("newer header");
    assert_eq!(inspected.compatibility, BackupCompatibility::Newer);
    assert_eq!(inspected.format_version, 12);
}

#[test]
fn inspection_still_rejects_unreadable_and_unsafe_recognized_files() {
    let directory = TestDirectory::new();

    let malformed = directory.write("malformed.sesame", b"{");
    assert!(inspect_backup_file(&malformed).is_err());

    let mut unsafe_kdf = envelope(VAULT_FORMAT_VERSION);
    unsafe_kdf.kdf.memory_kib = u32::MAX;
    let unsafe_path = directory.write(
        "unsafe.sesame",
        &serde_json::to_vec(&unsafe_kdf).expect("unsafe"),
    );
    assert!(inspect_backup_file(&unsafe_path).is_err());

    let no_extension = directory.write("backup.txt", FIXTURE);
    assert!(inspect_backup_file(&no_extension).is_err());
}

#[test]
fn verification_reports_whether_a_restore_upgrades_the_backup() {
    let directory = TestDirectory::new();

    let current = directory.write("current.sesame", FIXTURE);
    let verified = verify_backup_file(&current, PASSWORD).expect("current verification");
    assert_eq!(verified.format_version, VAULT_FORMAT_VERSION);
    assert_eq!(verified.compatibility, BackupCompatibility::Current);

    let old = directory.write("format-9.sesame", &authenticated_old_format(9));
    let verified = verify_backup_file(&old, PASSWORD).expect("older verification");
    assert_eq!(verified.format_version, 9);
    assert_eq!(verified.compatibility, BackupCompatibility::Upgrade);
}
