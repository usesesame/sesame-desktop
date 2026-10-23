use sesame_core::api::create_vault;
use sesame_core::crypto::{default_kdf_params, master_password_kdf_params};
use sesame_core::{MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_TOTAL_WORK, MIN_KDF_MEMORY_KIB};

#[test]
fn the_master_password_cost_is_above_the_minimum_and_inside_the_accepted_range() {
    let params = master_password_kdf_params();
    assert_eq!(params.algorithm, "argon2id");
    assert_eq!(params.memory_kib, 131_072);
    assert_eq!(params.iterations, 3);
    assert!(params.memory_kib > MIN_KDF_MEMORY_KIB);
    assert!(params.memory_kib <= MAX_KDF_MEMORY_KIB);
    assert!(params.iterations <= MAX_KDF_ITERATIONS);
    assert!(u64::from(params.memory_kib) * u64::from(params.iterations) <= MAX_KDF_TOTAL_WORK);
}

#[test]
fn a_new_vault_uses_the_stronger_cost_for_the_password_and_the_minimum_for_the_random_recovery_kit()
{
    let (opened, _) = create_vault("fictional master password", "Fictional vault").expect("vault");
    assert_eq!(opened.file.kdf.memory_kib, 131_072);
    let recovery = opened.file.recovery_kdf.clone().expect("recovery kdf");
    assert_eq!(recovery.memory_kib, default_kdf_params().memory_kib);
    assert_eq!(recovery.memory_kib, MIN_KDF_MEMORY_KIB);
}

#[test]
fn a_vault_with_the_older_minimum_cost_still_opens() {
    let (opened, _) = create_vault("fictional master password", "Fictional vault").expect("vault");
    let mut file = opened.file.clone();
    let old = default_kdf_params();
    let key = sesame_core::crypto::derive_key("fictional master password", &old).expect("key");
    file.kdf = old;
    file.key_wrap = sesame_core::crypto::encrypt_bytes(&key, &*opened.key, sesame_core::WRAP_AAD)
        .expect("wrap");
    let bytes = serde_json::to_vec(&file).expect("encoded");
    assert!(sesame_core::api::open_vault_bytes(&bytes, "fictional master password").is_ok());
}
