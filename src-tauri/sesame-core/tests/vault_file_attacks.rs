use std::fs;
use std::path::PathBuf;

use sesame_core::api::{
    create_vault, open_vault_bytes, open_vault_with_key, open_vault_with_password,
    open_vault_with_recovery_kit,
};
use sesame_core::{
    default_kdf_params, derive_key, encrypt_bytes, random_id, serialize_payload,
    verify_backup_file, CipherBlob, KdfParams, VaultEntry, VaultFile, VaultPayload,
    MAX_BACKUP_BYTES, MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM, PAYLOAD_AAD,
    PENDING_SETUP_PAYLOAD_AAD, WRAP_AAD,
};

const PASSWORD_A: &str = "fictional master password one";
const PASSWORD_B: &str = "fictional master password beta";
const CANARY_PASSWORD: &str = "fictional-secret-canary";

fn login(id: &str) -> VaultEntry {
    VaultEntry {
        id: id.to_string(),
        title: "Northwind".to_string(),
        username: "casey".to_string(),
        password: CANARY_PASSWORD.to_string(),
        url: "https://northwind.test".to_string(),
        ..VaultEntry::default()
    }
}

fn complete_vault(password: &str, name: &str) -> (VaultFile, [u8; 32], String) {
    let (mut opened, kit) = create_vault(password, name).expect("created vault");
    opened.payload.entries.push(login("fictional-login"));
    let key: [u8; 32] = opened
        .key
        .as_ref()
        .to_owned()
        .try_into()
        .expect("vault key length");
    opened.file.setup_complete = true;
    opened.file.payload = encrypt_bytes(
        &opened.key,
        &serialize_payload(&opened.payload).expect("serialized payload"),
        PAYLOAD_AAD,
    )
    .expect("sealed payload");
    (opened.file.clone(), key, kit)
}

fn wrap(plaintext: &[u8], secret: &str, kdf: &KdfParams, aad: &[u8]) -> CipherBlob {
    let wrapping_key = derive_key(secret, kdf).expect("derived wrapping key");
    encrypt_bytes(&wrapping_key, plaintext, aad).expect("sealed wrap")
}

fn flip_char(value: &str, index: usize) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    chars[index] = if chars[index] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

fn backup_file(name: &str, file: &VaultFile) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("sesame-vault-attack-{}", random_id()));
    fs::create_dir_all(&directory).expect("created temp directory");
    let path = directory.join(format!("{name}.sesame"));
    fs::write(
        &path,
        serde_json::to_vec(file).expect("serialized vault file"),
    )
    .expect("wrote backup");
    path
}

fn remove_backup(path: &PathBuf) {
    fs::remove_dir_all(path.parent().expect("backup directory")).expect("removed temp directory");
}

#[test]
fn a_vault_file_cannot_be_relabelled_into_another_format() {
    let (file, key, _) = complete_vault(PASSWORD_A, "Vault A");
    for version in [0_u8, 2, 8, 9, 11, 255] {
        let mut relabelled = file.clone();
        relabelled.format_version = version;
        assert!(
            open_vault_with_key(&relabelled, key).is_err(),
            "format {version} still authenticated the payload"
        );
    }
    assert!(open_vault_with_key(&file, key).is_ok());
}

#[test]
fn the_setup_flag_is_bound_into_the_payload_label() {
    let (file, key, _) = complete_vault(PASSWORD_A, "Vault A");

    let mut claimed_pending = file.clone();
    claimed_pending.setup_complete = false;
    assert!(open_vault_with_key(&claimed_pending, key).is_err());

    let pending_payload = VaultPayload {
        vault_name: "Vault A".to_string(),
        ..VaultPayload::default()
    };
    let mut honestly_pending = file.clone();
    honestly_pending.setup_complete = false;
    honestly_pending.payload = encrypt_bytes(
        &key,
        &serialize_payload(&pending_payload).expect("serialized payload"),
        PENDING_SETUP_PAYLOAD_AAD,
    )
    .expect("sealed payload");
    assert!(open_vault_with_key(&honestly_pending, key).is_ok());

    let mut relabelled_complete = honestly_pending;
    relabelled_complete.setup_complete = true;
    assert!(open_vault_with_key(&relabelled_complete, key).is_err());
}

#[test]
fn a_key_wrap_from_another_vault_cannot_unlock_either_vault() {
    let (file_a, _, _) = complete_vault(PASSWORD_A, "Vault A");
    let (file_b, _, _) = complete_vault(PASSWORD_B, "Vault B");

    let mut stolen = file_a.clone();
    stolen.key_wrap = file_b.key_wrap.clone();

    assert!(open_vault_with_password(&stolen, PASSWORD_A).is_err());
    assert!(open_vault_with_password(&stolen, PASSWORD_B).is_err());
    assert!(open_vault_with_password(&file_a, PASSWORD_A).is_ok());
    assert!(open_vault_with_password(&file_b, PASSWORD_B).is_ok());
}

#[test]
fn a_recovery_wrap_in_the_master_slot_opens_nothing() {
    let (file, _, kit) = complete_vault(PASSWORD_A, "Vault A");

    let mut swapped = file.clone();
    swapped.key_wrap = swapped.recovery_wrap.take().expect("recovery wrap");
    swapped.recovery_kdf = None;

    assert!(open_vault_with_password(&swapped, PASSWORD_A).is_err());
    assert!(open_vault_with_recovery_kit(&swapped, &kit).is_err());
    assert!(open_vault_with_password(&file, PASSWORD_A).is_ok());
    assert!(open_vault_with_recovery_kit(&file, &kit).is_ok());
}

#[test]
fn a_master_wrap_in_the_recovery_slot_opens_nothing_with_the_kit() {
    let (file, _, kit) = complete_vault(PASSWORD_A, "Vault A");

    let mut swapped = file.clone();
    swapped.recovery_wrap = Some(swapped.key_wrap.clone());
    swapped.key_wrap = wrap(&[9_u8; 32], PASSWORD_A, &file.kdf, WRAP_AAD);

    assert!(open_vault_with_password(&swapped, PASSWORD_A).is_err());
    assert!(open_vault_with_recovery_kit(&swapped, &kit).is_err());
}

#[test]
fn a_wrap_sealed_under_the_payload_label_never_unwraps() {
    let (file, real_key, _) = complete_vault(PASSWORD_A, "Vault A");

    let mut confused = file.clone();
    confused.key_wrap = wrap(&[7_u8; 32], PASSWORD_A, &file.kdf, PAYLOAD_AAD);

    assert!(open_vault_with_password(&confused, PASSWORD_A).is_err());
    assert!(open_vault_with_key(&confused, [7_u8; 32]).is_err());
    assert!(open_vault_with_key(&file, real_key).is_ok());
}

#[test]
fn flipped_payload_and_nonce_bytes_never_authenticate() {
    let (file, key, _) = complete_vault(PASSWORD_A, "Vault A");

    let length = file.payload.ciphertext.len();
    let step = (length / 8).max(1);
    let positions: Vec<usize> = (0..length)
        .step_by(step)
        .chain(std::iter::once(length - 1))
        .collect();
    for index in positions {
        let mut tampered = file.clone();
        tampered.payload.ciphertext = flip_char(&file.payload.ciphertext, index);
        assert!(
            open_vault_with_key(&tampered, key).is_err(),
            "a ciphertext flip at byte {index} still authenticated"
        );
    }

    for index in [
        0,
        file.payload.nonce.len() / 2,
        file.payload.nonce.len() - 1,
    ] {
        let mut tampered = file.clone();
        tampered.payload.nonce = flip_char(&file.payload.nonce, index);
        assert!(
            open_vault_with_key(&tampered, key).is_err(),
            "a nonce flip at byte {index} still authenticated"
        );
    }
}

#[test]
fn a_truncated_payload_is_rejected() {
    let (file, key, _) = complete_vault(PASSWORD_A, "Vault A");

    for cut in [1_usize, 4, file.payload.ciphertext.len() / 2] {
        let mut truncated = file.clone();
        truncated.payload.ciphertext =
            file.payload.ciphertext[..file.payload.ciphertext.len() - cut].to_string();
        assert!(
            open_vault_with_key(&truncated, key).is_err(),
            "a cut of {cut} still authenticated"
        );
    }

    let mut emptied = file.clone();
    emptied.payload.ciphertext = String::new();
    assert!(open_vault_with_key(&emptied, key).is_err());
}

#[test]
fn a_payload_nonce_reused_from_another_blob_is_rejected() {
    let (file, key, _) = complete_vault(PASSWORD_A, "Vault A");

    let mut reused = file.clone();
    reused.payload.nonce = file.key_wrap.nonce.clone();
    assert!(open_vault_with_key(&reused, key).is_err());
}

#[test]
fn near_miss_passwords_never_open_the_vault() {
    let (file, _, _) = complete_vault(PASSWORD_A, "Vault A");

    for guess in [
        "fictional master password one ",
        "fictional master password one  ",
        "fictional master password on",
        "FICTIONAL MASTER PASSWORD ONE",
        "fictional master password onE",
        "fictional master password one1",
        "",
    ] {
        assert!(
            open_vault_with_password(&file, guess).is_err(),
            "the guess {:?} opened the vault",
            guess
        );
    }

    assert!(open_vault_with_password(&file, PASSWORD_A).is_ok());
}

#[test]
fn kdf_parameters_outside_the_limits_are_refused_before_any_work() {
    let mut hostile_params: Vec<KdfParams> = Vec::new();
    let mut memory_below = default_kdf_params();
    memory_below.memory_kib = 0;
    hostile_params.push(memory_below);
    let mut memory_over = default_kdf_params();
    memory_over.memory_kib = MAX_KDF_MEMORY_KIB + 1;
    hostile_params.push(memory_over);
    let mut iterations_below = default_kdf_params();
    iterations_below.iterations = 0;
    hostile_params.push(iterations_below);
    let mut iterations_over = default_kdf_params();
    iterations_over.iterations = MAX_KDF_ITERATIONS + 1;
    hostile_params.push(iterations_over);
    let mut parallelism_below = default_kdf_params();
    parallelism_below.parallelism = 0;
    hostile_params.push(parallelism_below);
    let mut parallelism_over = default_kdf_params();
    parallelism_over.parallelism = MAX_KDF_PARALLELISM + 1;
    hostile_params.push(parallelism_over);
    let mut wrong_algorithm = default_kdf_params();
    wrong_algorithm.algorithm = "argon2i".to_string();
    hostile_params.push(wrong_algorithm);

    for params in &hostile_params {
        assert!(derive_key(PASSWORD_A, params).is_err());
    }

    let (file, _, _) = complete_vault(PASSWORD_A, "Vault A");
    let mut hostile_file = file.clone();
    hostile_file.kdf.memory_kib = MAX_KDF_MEMORY_KIB + 1;
    assert!(open_vault_with_password(&hostile_file, PASSWORD_A).is_err());
}

#[test]
fn a_vault_key_of_the_wrong_length_is_refused() {
    let (file, _, _) = complete_vault(PASSWORD_A, "Vault A");

    let mut forged = file.clone();
    forged.key_wrap = wrap(&[0_u8; 16], PASSWORD_A, &file.kdf, WRAP_AAD);

    assert!(open_vault_with_password(&forged, PASSWORD_A).is_err());
}

#[test]
fn a_tampered_or_foreign_backup_never_verifies_and_leaks_nothing() {
    let (file, _, kit_b) = complete_vault(PASSWORD_B, "Vault B");
    let path = backup_file("fictional-backup", &file);

    let verification = verify_backup_file(&path, PASSWORD_B).expect("healthy backup verified");
    assert_eq!(verification.vault_name, "Vault B");
    assert_eq!(verification.entry_count, 1);
    let wire = serde_json::to_string(&verification).expect("serialized verification");
    assert!(!wire.contains(CANARY_PASSWORD));
    assert!(verify_backup_file(&path, &kit_b).is_ok());
    assert!(verify_backup_file(&path, PASSWORD_A).is_err());

    let bytes = fs::read(&path).expect("backup bytes");
    let mut tampered: VaultFile = serde_json::from_slice(&bytes).expect("parsed backup");
    tampered.payload.ciphertext = flip_char(&tampered.payload.ciphertext, 0);
    let tampered_path = backup_file("fictional-backup-tampered", &tampered);
    assert!(verify_backup_file(&tampered_path, PASSWORD_B).is_err());

    remove_backup(&path);
    remove_backup(&tampered_path);
}

#[test]
fn a_backup_file_that_uses_the_wrong_label_is_refused() {
    let (file, key, _) = complete_vault(PASSWORD_A, "Vault A");
    let path = backup_file("fictional-backup-relabelled", &file);

    let bytes = fs::read(&path).expect("backup bytes");
    let mut relabelled: VaultFile = serde_json::from_slice(&bytes).expect("parsed backup");
    relabelled.format_version = 9;
    let relabelled_path = backup_file("fictional-backup-relabelled-2", &relabelled);

    assert!(open_vault_bytes(
        &fs::read(&relabelled_path).expect("relabelled bytes"),
        PASSWORD_A
    )
    .is_err());
    assert!(open_vault_with_key(&relabelled, key).is_err());

    remove_backup(&path);
    remove_backup(&relabelled_path);
}

#[test]
fn a_backup_over_the_size_limit_is_refused_before_parsing() {
    let directory = std::env::temp_dir().join(format!("sesame-vault-attack-{}", random_id()));
    fs::create_dir_all(&directory).expect("created temp directory");
    let path = directory.join("oversized.sesame");
    fs::write(&path, vec![0_u8; (MAX_BACKUP_BYTES + 1) as usize]).expect("wrote oversized backup");

    assert!(sesame_core::read_backup_file(&path).is_err());

    fs::remove_dir_all(&directory).expect("removed temp directory");
}
