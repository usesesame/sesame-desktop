use std::{fs, path::PathBuf};

use sesame_core::{
    backup::{apply_restored_vault_file, prepare_backup_for_restore},
    crypto::serialize_payload,
    loader::{Credential, VaultLoader},
    random_id, VAULT_FORMAT_VERSION,
};

const MANIFEST: &str = include_str!("fixtures/compatibility/manifest.json");
const ACTIVE: &[u8] = include_bytes!("fixtures/compatibility/v0.2.2.sesame");

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-transaction-{}", random_id()));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn restore_fixture(file_name: &str) {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).expect("manifest");
    let fixtures = manifest["fixtures"].as_array().expect("fixtures");
    let entry = fixtures
        .iter()
        .find(|entry| entry["fileName"].as_str() == Some(file_name))
        .expect("fixture entry");
    let password = entry["secrets"]["masterPassword"]
        .as_str()
        .expect("master password");
    let recovery_kit = entry["secrets"]["recoveryKit"]
        .as_str()
        .expect("recovery kit");
    let source_bytes = fixture_bytes(file_name);
    let directory = TestDirectory::new();
    let source = directory.0.join(file_name);
    let destination = directory.0.join("active.sesame");
    fs::write(&source, source_bytes).expect("source fixture");
    fs::write(&destination, ACTIVE).expect("active vault");

    let source_file = VaultLoader::parse(source_bytes).expect("source envelope");
    let source_payload =
        VaultLoader::authenticate(&source_file, Credential::MasterPassword(password))
            .expect("source authentication");
    let source_value: serde_json::Value =
        serde_json::from_slice(source_payload.bytes()).expect("source payload");
    let prepared =
        prepare_backup_for_restore(&source, &destination, password).expect("prepared transaction");
    assert_eq!(fs::read(&source).expect("source preserved"), source_bytes);
    let installed = apply_restored_vault_file(&destination, &prepared).expect("installed restore");
    assert_eq!(
        fs::read(&source).expect("source still preserved"),
        source_bytes
    );
    let safety = directory
        .0
        .join("backups")
        .join(installed.safety_backup_name.expect("safety backup"));
    assert_eq!(fs::read(safety).expect("safety bytes"), ACTIVE);

    let restarted_file = VaultLoader::read(&destination).expect("restart read");
    assert_eq!(restarted_file.format_version, VAULT_FORMAT_VERSION);
    let restarted = VaultLoader::open(&restarted_file, Credential::MasterPassword(password))
        .expect("restart password open");
    assert!(!restarted.migration.required());
    let restarted_payload = serialize_payload(&restarted.payload).expect("restarted payload");
    assert_manifest_payload(entry, &restarted.payload);
    assert_original_fields_preserved(entry, &source_value, &restarted_payload);
    let recovered = VaultLoader::open(&restarted_file, Credential::RecoveryKit(recovery_kit))
        .expect("restart recovery open");
    assert_eq!(
        serialize_payload(&recovered.payload).expect("recovery payload"),
        restarted_payload
    );

    let new_backup = directory.0.join("new-backup.sesame");
    fs::copy(&destination, &new_backup).expect("new backup");
    let backup_file = VaultLoader::read(&new_backup).expect("backup read");
    let backup =
        VaultLoader::open(&backup_file, Credential::MasterPassword(password)).expect("backup open");
    assert!(!backup.migration.required());
    assert_eq!(
        serialize_payload(&backup.payload).expect("backup payload"),
        restarted_payload
    );

    let second_destination = directory.0.join("restored-again.sesame");
    let prepared_again = prepare_backup_for_restore(&new_backup, &second_destination, password)
        .expect("idempotent preparation");
    apply_restored_vault_file(&second_destination, &prepared_again).expect("idempotent install");
    let opened_again = VaultLoader::open(
        &VaultLoader::read(&second_destination).expect("second read"),
        Credential::RecoveryKit(recovery_kit),
    )
    .expect("second recovery open");
    assert!(!opened_again.migration.required());
    assert_eq!(
        serialize_payload(&opened_again.payload).expect("second payload"),
        restarted_payload
    );
    let replayed = prepare_backup_for_restore(&new_backup, &second_destination, password)
        .expect("replayed preparation");
    apply_restored_vault_file(&second_destination, &replayed).expect("replayed install");
    let replayed = VaultLoader::open(
        &VaultLoader::read(&second_destination).expect("replayed read"),
        Credential::MasterPassword(password),
    )
    .expect("replayed open");
    assert_eq!(
        serialize_payload(&replayed.payload).expect("replayed payload"),
        restarted_payload
    );
}

macro_rules! restore_test {
    ($name:ident, $fixture:literal) => {
        #[test]
        fn $name() {
            restore_fixture($fixture);
        }
    };
}

restore_test!(fixture_v0_1_0_restores_transactionally, "v0.1.0.sesame");
restore_test!(fixture_v0_1_1_restores_transactionally, "v0.1.1.sesame");
restore_test!(fixture_v0_2_0_restores_transactionally, "v0.2.0.sesame");
restore_test!(fixture_v0_2_1_restores_transactionally, "v0.2.1.sesame");
restore_test!(fixture_v0_2_2_restores_transactionally, "v0.2.2.sesame");

fn assert_original_fields_preserved(
    entry: &serde_json::Value,
    source: &serde_json::Value,
    restored: &[u8],
) {
    let mut source = source.clone();
    let mut restored: serde_json::Value = serde_json::from_slice(restored).expect("restored value");
    assert_stored_timestamps(&source, &restored);
    for (id, fields) in entry["expectedMigration"]["backfilled"]
        .as_object()
        .expect("backfilled records")
    {
        let fields: Vec<&str> = fields
            .as_array()
            .expect("backfilled field list")
            .iter()
            .map(|field| field.as_str().expect("backfilled field"))
            .collect();
        remove_fields_for_id(&mut source, id, &fields);
        remove_fields_for_id(&mut restored, id, &fields);
    }
    retain_source_shape(&source, &mut restored);
    assert_eq!(restored, source);
}

fn remove_fields_for_id(value: &mut serde_json::Value, id: &str, fields: &[&str]) {
    match value {
        serde_json::Value::Object(object) => {
            if object.get("id").and_then(serde_json::Value::as_str) == Some(id) {
                for field in fields {
                    object.remove(*field);
                }
            }
            for value in object.values_mut() {
                remove_fields_for_id(value, id, fields);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                remove_fields_for_id(value, id, fields);
            }
        }
        _ => {}
    }
}

fn assert_stored_timestamps(source: &serde_json::Value, restored: &serde_json::Value) {
    match (source, restored) {
        (serde_json::Value::Object(source), serde_json::Value::Object(restored)) => {
            for key in [
                "createdAt",
                "updatedAt",
                "passwordUpdatedAt",
                "deletedAt",
                "capturedAt",
            ] {
                if let Some(value) = source.get(key).filter(|value| value.as_u64() != Some(0)) {
                    assert_eq!(restored.get(key), Some(value));
                }
            }
            for (key, value) in source {
                if let Some(restored) = restored.get(key) {
                    assert_stored_timestamps(value, restored);
                }
            }
        }
        (serde_json::Value::Array(source), serde_json::Value::Array(restored)) => {
            assert_eq!(source.len(), restored.len());
            for (source, restored) in source.iter().zip(restored) {
                assert_stored_timestamps(source, restored);
            }
        }
        _ => {}
    }
}

fn retain_source_shape(source: &serde_json::Value, migrated: &mut serde_json::Value) {
    match (source, migrated) {
        (serde_json::Value::Object(source), serde_json::Value::Object(migrated)) => {
            migrated.retain(|key, _| source.contains_key(key));
            for (key, value) in source {
                if let Some(migrated) = migrated.get_mut(key) {
                    retain_source_shape(value, migrated);
                }
            }
        }
        (serde_json::Value::Array(source), serde_json::Value::Array(migrated)) => {
            assert_eq!(source.len(), migrated.len());
            for (source, migrated) in source.iter().zip(migrated) {
                retain_source_shape(source, migrated);
            }
        }
        _ => {}
    }
}

fn assert_manifest_payload(entry: &serde_json::Value, payload: &sesame_core::VaultPayload) {
    assert_eq!(
        payload.vault_name,
        entry["vault"]["name"].as_str().expect("vault name")
    );
    assert_eq!(
        payload.vault_id.as_deref(),
        entry["vault"]["vaultId"].as_str()
    );
    assert_eq!(
        payload.revision,
        entry["vault"]["revision"].as_u64().expect("vault revision")
    );
    for (name, actual) in [
        ("entries", payload.entries.len()),
        ("identities", payload.identities.len()),
        ("secureNotes", payload.secure_notes.len()),
        ("cards", payload.cards.len()),
        ("wifiNetworks", payload.wifi_networks.len()),
        ("sshKeys", payload.ssh_keys.len()),
        ("softwareLicenses", payload.software_licenses.len()),
        ("documents", payload.documents.len()),
        ("customRecords", payload.custom_records.len()),
        ("folders", payload.folders.len()),
        ("trash", payload.trash.len()),
        ("history", payload.history.len()),
    ] {
        assert_eq!(
            actual,
            entry["expectedMigration"]["afterOpenCounts"][name]
                .as_u64()
                .expect("expected count") as usize,
            "{name} count"
        );
    }
    let items = payload.item_views();
    let present_ids: Vec<&str> = items
        .iter()
        .map(|item| item.id())
        .chain(payload.folders.iter().map(|folder| folder.id.as_str()))
        .chain(payload.history.iter().map(|history| history.id.as_str()))
        .chain(payload.trash.iter().map(|trash| trash.item.id()))
        .collect();
    for expected in entry["stableIds"].as_array().expect("stable ids") {
        let expected = expected.as_str().expect("stable id");
        assert!(
            present_ids.contains(&expected),
            "missing stable id {expected}"
        );
    }
    let preserved = &entry["expectedMigration"]["preservedTimestamps"]["login-alpha"];
    let preserved_login = payload
        .entries
        .iter()
        .find(|item| item.id == "login-alpha")
        .expect("preserved login");
    assert_eq!(
        preserved_login.created_at,
        preserved["createdAt"].as_u64().expect("created time")
    );
    assert_eq!(
        preserved_login.updated_at,
        preserved["updatedAt"].as_u64().expect("updated time")
    );
    assert_eq!(
        preserved_login.password_updated_at,
        preserved["passwordUpdatedAt"]
            .as_u64()
            .expect("password time")
    );
    let backfilled = payload
        .entries
        .iter()
        .find(|item| item.id == "login-empty")
        .expect("backfilled login");
    let fields = entry["expectedMigration"]["backfilled"]["login-empty"]
        .as_array()
        .expect("backfilled fields");
    assert!(fields.iter().any(|field| field == "createdAt"));
    assert!(fields.iter().any(|field| field == "updatedAt"));
    assert!(fields.iter().any(|field| field == "passwordUpdatedAt"));
    assert!(fields.iter().any(|field| field == "revision"));
    assert!(backfilled.created_at > 0);
    assert_eq!(backfilled.updated_at, backfilled.created_at);
    assert_eq!(backfilled.password_updated_at, backfilled.updated_at);
    assert_eq!(backfilled.revision, 1);
}

fn fixture_bytes(file_name: &str) -> &'static [u8] {
    match file_name {
        "v0.1.0.sesame" => include_bytes!("fixtures/compatibility/v0.1.0.sesame"),
        "v0.1.1.sesame" => include_bytes!("fixtures/compatibility/v0.1.1.sesame"),
        "v0.2.0.sesame" => include_bytes!("fixtures/compatibility/v0.2.0.sesame"),
        "v0.2.1.sesame" => include_bytes!("fixtures/compatibility/v0.2.1.sesame"),
        "v0.2.2.sesame" => include_bytes!("fixtures/compatibility/v0.2.2.sesame"),
        _ => panic!("unknown fixture"),
    }
}
