use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sesame_core::backup::validate_backup_file;
use sesame_core::types::{CipherBlob, KdfParams, PinWrap, VaultFile};
use sesame_core::VAULT_FORMAT_VERSION;

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

fn backup() -> VaultFile {
    VaultFile {
        format_version: VAULT_FORMAT_VERSION,
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

#[test]
fn a_well_formed_backup_is_accepted() {
    assert!(validate_backup_file(&backup()).is_ok());
}

#[test]
fn a_format_from_the_future_is_refused_rather_than_guessed_at() {
    let mut file = backup();
    file.format_version = VAULT_FORMAT_VERSION + 1;
    assert!(validate_backup_file(&file).is_err());

    file.format_version = 0;
    assert!(validate_backup_file(&file).is_err());
}

#[test]
fn key_derivation_settings_outside_the_safe_range_are_refused() {
    let mut file = backup();
    file.kdf.memory_kib = u32::MAX;
    assert!(validate_backup_file(&file).is_err());

    let mut file = backup();
    file.kdf.algorithm = "scrypt".into();
    assert!(validate_backup_file(&file).is_err());

    let mut file = backup();
    file.kdf.salt = URL_SAFE_NO_PAD.encode([1_u8; 4]);
    assert!(validate_backup_file(&file).is_err());
}

#[test]
fn a_nonce_or_ciphertext_of_the_wrong_size_is_refused() {
    let mut file = backup();
    file.payload.nonce = URL_SAFE_NO_PAD.encode([1_u8; 12]);
    assert!(validate_backup_file(&file).is_err());

    let mut file = backup();
    file.payload.ciphertext = URL_SAFE_NO_PAD.encode([2_u8; 8]);
    assert!(validate_backup_file(&file).is_err());

    let mut file = backup();
    file.key_wrap.nonce = "not base64!".into();
    assert!(validate_backup_file(&file).is_err());
}

#[test]
fn pin_unlock_material_is_checked_like_every_other_wrapped_key() {
    let mut file = backup();
    file.pin_wrap = Some(PinWrap {
        kdf: kdf(),
        protected_pepper: URL_SAFE_NO_PAD.encode([3_u8; 32]),
        key_wrap: blob(),
    });
    assert!(validate_backup_file(&file).is_ok());

    let mut unbounded_kdf = kdf();
    unbounded_kdf.memory_kib = u32::MAX;
    let mut hostile = file.clone();
    hostile.pin_wrap = Some(PinWrap {
        kdf: unbounded_kdf,
        protected_pepper: URL_SAFE_NO_PAD.encode([3_u8; 32]),
        key_wrap: blob(),
    });
    assert!(
        validate_backup_file(&hostile).is_err(),
        "an unbounded PIN KDF was accepted"
    );

    let mut short_nonce = blob();
    short_nonce.nonce = URL_SAFE_NO_PAD.encode([1_u8; 8]);
    let mut hostile = file.clone();
    hostile.pin_wrap = Some(PinWrap {
        kdf: kdf(),
        protected_pepper: URL_SAFE_NO_PAD.encode([3_u8; 32]),
        key_wrap: short_nonce,
    });
    assert!(
        validate_backup_file(&hostile).is_err(),
        "a malformed PIN key wrap was accepted"
    );
}
