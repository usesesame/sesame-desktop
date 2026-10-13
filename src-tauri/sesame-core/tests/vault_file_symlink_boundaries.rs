use std::fs;
use std::path::PathBuf;

use sesame_core::api::{create_vault, open_vault_with_password};
use sesame_core::loader::VaultLoader;
use sesame_core::platform::{open_private_append, open_private_file, securely_delete};
use sesame_core::storage::{commit_payload_change, persist_session};
use sesame_core::{random_id, UnlockedVault};

const PASSWORD: &str = "fictional master password";

fn test_directory(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("sesame-symlink-{name}-{}", random_id()));
    fs::create_dir_all(&directory).expect("test directory");
    directory
}

fn unlocked_session(path: &PathBuf) -> UnlockedVault {
    let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
    let mut session = UnlockedVault::from_opened(path.clone(), &opened).expect("session");
    session.setup_complete = true;
    session
}

#[cfg(unix)]
#[test]
fn saving_a_vault_does_not_follow_a_symlink_at_the_legacy_temp_path() {
    use std::os::unix::fs::symlink;

    let directory = test_directory("legacy-temp");
    let vault_path = directory.join("vault.sesame");
    let canary_path = directory.join("canary.txt");
    fs::write(&canary_path, b"fictional canary before save").expect("canary");
    symlink(&canary_path, vault_path.with_extension("sesame.tmp")).expect("planted symlink");

    let mut session = unlocked_session(&vault_path);
    persist_session(&mut session).expect("save");

    assert_eq!(
        fs::read(&canary_path).expect("canary after"),
        b"fictional canary before save"
    );
    let metadata = fs::symlink_metadata(&vault_path).expect("vault metadata");
    assert!(metadata.file_type().is_file());
    let file = VaultLoader::read(&vault_path).expect("read saved vault");
    assert!(open_vault_with_password(&file, PASSWORD).is_ok());
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn the_previous_copy_does_not_follow_a_symlink() {
    use std::os::unix::fs::symlink;

    let directory = test_directory("previous-copy");
    let vault_path = directory.join("vault.sesame");
    let mut session = unlocked_session(&vault_path);
    persist_session(&mut session).expect("first save");
    let first = fs::read(&vault_path).expect("first bytes");

    let canary_path = directory.join("canary-prev.txt");
    fs::write(&canary_path, b"fictional previous canary").expect("canary");
    symlink(&canary_path, vault_path.with_extension("sesame.prev")).expect("planted symlink");

    let mut payload = session.open_payload().expect("payload").clone();
    payload.vault_name = "Changed fictional vault".to_string();
    commit_payload_change(&mut session, payload).expect("second save");

    assert_eq!(
        fs::read(&canary_path).expect("canary after"),
        b"fictional previous canary"
    );
    assert_eq!(
        fs::read(vault_path.with_extension("sesame.prev")).expect("previous copy"),
        first
    );
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn saving_over_a_planted_symlink_replaces_the_link_and_not_its_target() {
    use std::os::unix::fs::symlink;

    let directory = test_directory("vault-link");
    let vault_path = directory.join("vault.sesame");
    let canary_path = directory.join("canary.txt");
    fs::write(&canary_path, b"fictional canary at the vault path").expect("canary");
    symlink(&canary_path, &vault_path).expect("planted symlink");

    let mut session = unlocked_session(&vault_path);
    persist_session(&mut session).expect("save");

    assert_eq!(
        fs::read(&canary_path).expect("canary after"),
        b"fictional canary at the vault path"
    );
    let metadata = fs::symlink_metadata(&vault_path).expect("vault metadata");
    assert!(metadata.file_type().is_file());
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn private_file_creation_refuses_an_existing_path() {
    use std::os::unix::fs::symlink;

    let directory = test_directory("open-private");
    let canary_path = directory.join("canary.txt");
    fs::write(&canary_path, b"fictional canary protected").expect("canary");
    let link_path = directory.join("linked.bin");
    symlink(&canary_path, &link_path).expect("planted symlink");

    assert!(open_private_file(&link_path).is_err());
    assert!(open_private_file(&canary_path).is_err());
    assert_eq!(
        fs::read(&canary_path).expect("canary after"),
        b"fictional canary protected"
    );
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn private_append_creates_a_0600_file_and_keeps_earlier_lines() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let directory = test_directory("append-create");
    let log_path = directory.join("events.jsonl");

    writeln!(open_private_append(&log_path).expect("first open"), "first").expect("first line");
    writeln!(
        open_private_append(&log_path).expect("second open"),
        "second"
    )
    .expect("second line");

    let mode = fs::metadata(&log_path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(fs::read(&log_path).expect("content"), b"first\nsecond\n");
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn private_append_tightens_a_file_that_was_created_with_wider_modes() {
    use std::os::unix::fs::PermissionsExt;

    let directory = test_directory("append-tighten");
    let log_path = directory.join("events.jsonl");
    fs::write(&log_path, b"fictional earlier line\n").expect("existing log");
    fs::set_permissions(&log_path, fs::Permissions::from_mode(0o644)).expect("wide mode");

    open_private_append(&log_path).expect("open");

    let mode = fs::metadata(&log_path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(target_os = "linux")]
#[test]
fn private_append_refuses_a_symlink_and_leaves_its_target_alone() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = test_directory("append-symlink");
    let canary_path = directory.join("canary.txt");
    fs::write(&canary_path, b"fictional canary protected\n").expect("canary");
    fs::set_permissions(&canary_path, fs::Permissions::from_mode(0o644)).expect("canary mode");
    let link_path = directory.join("events.jsonl");
    symlink(&canary_path, &link_path).expect("planted symlink");

    assert!(open_private_append(&link_path).is_err());

    assert_eq!(
        fs::read(&canary_path).expect("canary after"),
        b"fictional canary protected\n"
    );
    let mode = fs::metadata(&canary_path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(target_os = "linux")]
#[test]
fn private_append_refuses_a_dangling_symlink_without_creating_its_target() {
    use std::os::unix::fs::symlink;

    let directory = test_directory("append-dangling");
    let missing_path = directory.join("created-through-link.txt");
    let link_path = directory.join("events.jsonl");
    symlink(&missing_path, &link_path).expect("planted symlink");

    assert!(open_private_append(&link_path).is_err());

    assert!(!missing_path.exists());
    fs::remove_dir_all(&directory).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn secure_deletion_removes_a_link_without_overwriting_its_target() {
    use std::os::unix::fs::symlink;

    let directory = test_directory("secure-delete");
    let canary_path = directory.join("canary.txt");
    fs::write(&canary_path, b"fictional canary for deletion").expect("canary");
    let link_path = directory.join("staged.bin");
    symlink(&canary_path, &link_path).expect("planted symlink");

    securely_delete(&link_path).expect("deleted link");

    assert!(!link_path.exists());
    assert_eq!(
        fs::read(&canary_path).expect("canary after"),
        b"fictional canary for deletion"
    );
    fs::remove_dir_all(&directory).expect("cleanup");
}
