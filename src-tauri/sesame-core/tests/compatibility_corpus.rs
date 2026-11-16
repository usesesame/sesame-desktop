use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::Value;
use sesame_core::loader::{Credential, VaultLoader};
use sesame_core::storage::persist_session;
use sesame_core::{
    encrypt_bytes, payload_aad_for_file, random_id, UnlockedVault, VAULT_FORMAT_VERSION,
};
use sha2::{Digest, Sha256};

const PUBLISHED_RELEASES: [&str; 6] = ["v0.1.0", "v0.1.1", "v0.2.0", "v0.2.1", "v0.2.2", "v0.5.3"];

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compatibility")
}

fn manifest() -> &'static Value {
    static MANIFEST: OnceLock<Value> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let bytes = fs::read(corpus_dir().join("manifest.json")).expect("read corpus manifest");
        serde_json::from_slice(&bytes).expect("parsed corpus manifest")
    })
}

fn fixture_entry(tag: &str) -> Value {
    manifest()["fixtures"]
        .as_array()
        .expect("manifest fixture list")
        .iter()
        .find(|fixture| fixture["id"].as_str() == Some(tag))
        .expect("fixture entry in manifest")
        .clone()
}

fn digest_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn directory_listing(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).expect("read corpus directory") {
        let entry = entry.expect("corpus directory entry");
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if path.is_dir() {
            for nested in directory_listing(&path) {
                names.push(format!("{name}/{nested}"));
            }
            names.push(format!("{name}/"));
        } else {
            names.push(name);
        }
    }
    names.sort();
    names
}

fn counts_of(payload: &sesame_core::VaultPayload) -> Vec<(&'static str, usize)> {
    vec![
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
    ]
}

fn all_stable_ids(payload: &sesame_core::VaultPayload) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    ids.extend(payload.entries.iter().map(|entry| entry.id.clone()));
    ids.extend(
        payload
            .identities
            .iter()
            .map(|identity| identity.id.clone()),
    );
    ids.extend(payload.secure_notes.iter().map(|note| note.id.clone()));
    ids.extend(payload.cards.iter().map(|card| card.id.clone()));
    ids.extend(payload.wifi_networks.iter().map(|wifi| wifi.id.clone()));
    ids.extend(payload.ssh_keys.iter().map(|key| key.id.clone()));
    ids.extend(
        payload
            .software_licenses
            .iter()
            .map(|license| license.id.clone()),
    );
    ids.extend(payload.documents.iter().map(|document| document.id.clone()));
    ids.extend(
        payload
            .custom_records
            .iter()
            .map(|record| record.id.clone()),
    );
    ids.extend(payload.folders.iter().map(|folder| folder.id.clone()));
    ids.extend(payload.history.iter().map(|entry| entry.id.clone()));
    ids.extend(payload.trash.iter().map(|trashed| match &trashed.item {
        sesame_core::TaggedItem::Login(entry) => entry.id.clone(),
        _ => String::new(),
    }));
    ids
}

fn open_fixture(tag: &str) {
    let entry = fixture_entry(tag);
    let path = corpus_dir().join(entry["fileName"].as_str().expect("fixture file name"));
    let before_listing = directory_listing(&corpus_dir());

    let bytes = fs::read(&path).expect("read fixture bytes");
    assert_eq!(
        digest_of(&bytes),
        entry["digestSha256"].as_str().expect("recorded digest"),
        "{tag} no longer matches its recorded digest"
    );

    let file = VaultLoader::read(&path).expect("the current reader accepts the fixture");
    assert_eq!(
        u64::from(file.format_version),
        entry["formatVersion"].as_u64().expect("recorded format")
    );
    assert!(file.setup_complete);

    let master_password = entry["secrets"]["masterPassword"]
        .as_str()
        .expect("master password");
    let recovery_kit = entry["secrets"]["recoveryKit"]
        .as_str()
        .expect("recovery kit");
    let authenticated =
        VaultLoader::authenticate(&file, Credential::MasterPassword(master_password))
            .expect("master password authenticates the fixture");
    let payload_bytes = authenticated.bytes();
    let raw_payload: Value =
        serde_json::from_slice(&payload_bytes).expect("parsed the decrypted payload");
    let items = raw_payload["items"].as_array().expect("tagged items shape");
    let identity = items
        .iter()
        .find(|item| item["kind"] == "identity")
        .expect("identity item");
    assert_eq!(
        identity.get("favourite").is_some(),
        entry["payloadShape"]["identityHasFavourite"]
            .as_bool()
            .expect("identityHasFavourite"),
        "{tag} identity favourite key presence did not match its recorded payload shape"
    );
    assert_eq!(
        identity.get("tags").is_some(),
        entry["payloadShape"]["identityHasTags"]
            .as_bool()
            .expect("identityHasTags"),
        "{tag} identity tags key presence did not match its recorded payload shape"
    );

    let opened = VaultLoader::open(&file, Credential::MasterPassword(master_password))
        .expect("opened the fixture");
    assert_eq!(
        opened.migration.envelope_changed,
        entry["expectedMigration"]["fileChanged"]
            .as_bool()
            .expect("fileChanged")
            || file.format_version < VAULT_FORMAT_VERSION
    );
    assert_eq!(
        opened.migration.payload_changed,
        entry["expectedMigration"]["payloadChanged"]
            .as_bool()
            .expect("payloadChanged")
    );
    assert!(
        opened.migrated,
        "{tag} authenticated payload must report its migration state"
    );
    assert_eq!(opened.file.format_version, VAULT_FORMAT_VERSION);
    assert_eq!(
        opened.payload.vault_name,
        entry["vault"]["name"].as_str().expect("vault name")
    );
    assert_eq!(
        opened.payload.vault_id.clone().unwrap_or_default(),
        entry["vault"]["vaultId"].as_str().expect("vault id")
    );
    assert_eq!(
        opened.payload.revision,
        entry["vault"]["revision"].as_u64().expect("revision")
    );
    for (field, expected) in counts_of(&opened.payload) {
        let recorded = entry["counts"][field].as_u64().expect("recorded count") as usize;
        assert_eq!(expected, recorded, "{tag} {field} count changed");
    }
    let recorded_ids = entry["stableIds"].as_array().expect("recorded stable ids");
    let present_ids = all_stable_ids(&opened.payload);
    for id in recorded_ids {
        let id = id.as_str().expect("stable id");
        assert!(
            present_ids.iter().any(|present| present == id),
            "{tag} lost stable id {id}"
        );
    }

    let preserved = &entry["expectedMigration"]["preservedTimestamps"]["login-alpha"];
    let login_alpha = opened
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == "login-alpha")
        .expect("login-alpha entry");
    assert_eq!(
        login_alpha.created_at,
        preserved["createdAt"].as_u64().expect("createdAt")
    );
    assert_eq!(
        login_alpha.updated_at,
        preserved["updatedAt"].as_u64().expect("updatedAt")
    );
    assert_eq!(
        login_alpha.password_updated_at,
        preserved["passwordUpdatedAt"]
            .as_u64()
            .expect("passwordUpdatedAt")
    );

    let backfilled = opened
        .payload
        .entries
        .iter()
        .find(|entry| entry.id == "login-empty")
        .expect("login-empty entry");
    assert!(
        backfilled.created_at > 0,
        "{tag} empty entry kept a zero creation time"
    );
    assert_eq!(backfilled.updated_at, backfilled.created_at);
    assert_eq!(backfilled.password_updated_at, backfilled.updated_at);
    assert_eq!(backfilled.revision, 1);

    let reparsed = VaultLoader::parse(&bytes).expect("reparsed the fixture bytes");
    let with_kit = VaultLoader::open(&reparsed, Credential::RecoveryKit(recovery_kit))
        .expect("recovery kit opens the fixture");
    assert_eq!(with_kit.payload.vault_id, opened.payload.vault_id);

    let after_bytes = fs::read(&path).expect("re-read fixture bytes");
    assert_eq!(
        digest_of(&after_bytes),
        digest_of(&bytes),
        "{tag} was rewritten during a read"
    );
    assert_eq!(
        directory_listing(&corpus_dir()),
        before_listing,
        "{tag} read left new files in the corpus"
    );
}

#[test]
fn corpus_covers_every_published_release_and_records_unproven_formats() {
    let manifest = manifest();
    assert_eq!(
        manifest["corpusSchema"].as_str(),
        Some("sesame.compatibility-corpus/1")
    );
    assert_eq!(manifest["digestAlgorithm"].as_str(), Some("sha256"));

    let fixture_ids: Vec<&str> = manifest["fixtures"]
        .as_array()
        .expect("fixture list")
        .iter()
        .map(|fixture| fixture["id"].as_str().expect("fixture id"))
        .collect();
    assert_eq!(fixture_ids, PUBLISHED_RELEASES);

    let proven = manifest["provenFormats"]
        .as_array()
        .expect("proven formats");
    assert_eq!(proven.len(), 1);
    assert_eq!(proven[0]["format"].as_u64(), Some(10));
    assert_eq!(
        proven[0]["fixtures"]
            .as_array()
            .expect("proven fixtures")
            .len(),
        PUBLISHED_RELEASES.len()
    );

    let unproven = manifest["unprovenFormats"]
        .as_array()
        .expect("unproven formats");
    assert_eq!(unproven.len(), 1);
    let formats: Vec<u64> = unproven[0]["formats"]
        .as_array()
        .expect("unproven format list")
        .iter()
        .map(|format| format.as_u64().expect("format number"))
        .collect();
    assert_eq!(formats, (2..=9).collect::<Vec<u64>>());
    assert!(!unproven[0]["reason"]
        .as_str()
        .expect("unproven reason")
        .is_empty());
    assert_eq!(
        unproven[0]["decision"]["status"].as_str(),
        Some("excludedFromCompatibilityPromise"),
        "unproven formats must remain outside the compatibility promise"
    );
    assert_eq!(
        unproven[0]["decision"]["readersRetained"].as_bool(),
        Some(true)
    );
    assert_eq!(
        unproven[0]["recoveryPath"]["status"].as_str(),
        Some("approvedUnprovenRecovery")
    );
    assert!(!unproven[0]["decision"]["note"]
        .as_str()
        .expect("decision note")
        .is_empty());

    let generations = manifest["writerGenerations"]
        .as_array()
        .expect("writer generations");
    for fixture in manifest["fixtures"].as_array().expect("fixture list") {
        let generation_id = fixture["writerGeneration"].as_str().expect("generation id");
        let generation = generations
            .iter()
            .find(|generation| generation["id"].as_str() == Some(generation_id))
            .unwrap_or_else(|| panic!("{generation_id} is not a declared writer generation"));
        let generator = generation["generator"].as_str().expect("generator path");
        assert!(
            corpus_dir().join(generator).is_file(),
            "{generator} is missing from the corpus"
        );
        let versions: Vec<&str> = generation["versions"]
            .as_array()
            .expect("generation versions")
            .iter()
            .map(|version| version.as_str().expect("version"))
            .collect();
        assert!(
            versions.contains(&fixture["writerTag"].as_str().expect("writer tag")),
            "fixture writer tag is not part of its declared generation"
        );
    }

    let listing = directory_listing(&corpus_dir());
    let mut expected: Vec<String> = vec!["generator/".to_string(), "manifest.json".to_string()];
    for fixture in manifest["fixtures"].as_array().expect("fixture list") {
        expected.push(
            fixture["fileName"]
                .as_str()
                .expect("fixture file name")
                .to_string(),
        );
    }
    for generation in generations {
        expected.push(
            generation["generator"]
                .as_str()
                .expect("generator path")
                .to_string(),
        );
    }
    expected.sort();
    assert_eq!(
        listing, expected,
        "the corpus directory holds files the manifest does not record"
    );

    for fixture in manifest["fixtures"].as_array().expect("fixture list") {
        let counts = fixture["counts"].as_object().expect("recorded counts");
        for (field, count) in counts {
            assert!(
                count.as_u64().expect("count value") >= 1,
                "{} records an empty {field}",
                fixture["id"].as_str().expect("fixture id")
            );
        }
    }
}

#[test]
fn fixture_v0_1_0_opens_and_matches_its_recorded_evidence() {
    open_fixture("v0.1.0");
}

#[test]
fn fixture_v0_1_1_opens_and_matches_its_recorded_evidence() {
    open_fixture("v0.1.1");
}

#[test]
fn fixture_v0_2_0_opens_and_matches_its_recorded_evidence() {
    open_fixture("v0.2.0");
}

#[test]
fn fixture_v0_2_1_opens_and_matches_its_recorded_evidence() {
    open_fixture("v0.2.1");
}

#[test]
fn fixture_v0_2_2_opens_and_matches_its_recorded_evidence() {
    open_fixture("v0.2.2");
}

#[test]
fn fixture_v0_5_3_opens_and_matches_its_recorded_evidence() {
    open_fixture("v0.5.3");
}

const PADDED_PAYLOAD_BYTES: usize = 24 * 1024;

fn reseal_with_padding(file: &sesame_core::VaultFile, password: &str) -> Vec<u8> {
    let key = VaultLoader::unwrap_key(file, Credential::MasterPassword(password))
        .expect("unwrapped vault key");
    let authenticated =
        VaultLoader::authenticate(file, Credential::VaultKey(&key)).expect("authenticated payload");
    let mut padded = authenticated.bytes().to_vec();
    assert!(padded.len() < PADDED_PAYLOAD_BYTES);
    padded.resize(PADDED_PAYLOAD_BYTES, b' ');
    let aad = payload_aad_for_file(file.format_version, file.setup_complete).expect("payload aad");
    let mut resealed = file.clone();
    resealed.payload = encrypt_bytes(&key, &padded, aad).expect("resealed payload");
    serde_json::to_vec(&resealed).expect("resealed file")
}

#[test]
fn every_fixture_opens_after_its_payload_is_padded_with_spaces() {
    for tag in PUBLISHED_RELEASES {
        let entry = fixture_entry(tag);
        let bytes = fs::read(corpus_dir().join(entry["fileName"].as_str().expect("file name")))
            .expect("fixture bytes");
        let password = entry["secrets"]["masterPassword"]
            .as_str()
            .expect("password");
        let recovery_kit = entry["secrets"]["recoveryKit"]
            .as_str()
            .expect("recovery kit");
        let file = VaultLoader::parse(&bytes).expect("fixture envelope");
        let original =
            VaultLoader::open(&file, Credential::MasterPassword(password)).expect("opened fixture");

        let padded_bytes = reseal_with_padding(&file, password);
        assert_ne!(padded_bytes, bytes);
        for credential in [
            Credential::MasterPassword(password),
            Credential::RecoveryKit(recovery_kit),
        ] {
            let opened = VaultLoader::load(&padded_bytes, credential)
                .unwrap_or_else(|error| panic!("{tag} padded fixture did not open: {error:?}"));
            assert_eq!(opened.payload.vault_id, original.payload.vault_id, "{tag}");
            assert_eq!(opened.payload.revision, original.payload.revision, "{tag}");
            assert_eq!(
                counts_of(&opened.payload),
                counts_of(&original.payload),
                "{tag}"
            );
            assert_eq!(
                all_stable_ids(&opened.payload),
                all_stable_ids(&original.payload),
                "{tag}"
            );
            assert_eq!(
                opened.migration.payload_changed,
                original.migration.payload_changed
            );
            assert_eq!(
                opened.migration.envelope_changed,
                original.migration.envelope_changed
            );
        }
        let padded_file = VaultLoader::parse(&padded_bytes).expect("padded envelope");
        let authenticated =
            VaultLoader::authenticate(&padded_file, Credential::MasterPassword(password))
                .expect("authenticated padded payload");
        assert_eq!(authenticated.bytes().len(), PADDED_PAYLOAD_BYTES);
    }
}

#[test]
fn every_format_10_fixture_upgrades_on_save_and_keeps_its_original_copy() {
    for tag in PUBLISHED_RELEASES {
        let entry = fixture_entry(tag);
        let source = corpus_dir().join(entry["fileName"].as_str().expect("file name"));
        let original = fs::read(&source).expect("fixture bytes");
        let password = entry["secrets"]["masterPassword"]
            .as_str()
            .expect("password");
        let recovery_kit = entry["secrets"]["recoveryKit"]
            .as_str()
            .expect("recovery kit");
        let directory = std::env::temp_dir().join(format!("sesame-corpus-upgrade-{}", random_id()));
        fs::create_dir_all(&directory).expect("test directory");
        let vault = directory.join("vault.sesame");
        fs::write(&vault, &original).expect("copied fixture");

        let file = VaultLoader::read(&vault).expect("fixture envelope");
        let opened = VaultLoader::open(&file, Credential::MasterPassword(password))
            .expect("opened the fixture");
        let mut session = UnlockedVault::from_opened(vault.clone(), &opened).expect("session");
        persist_session(&mut session).expect("saved the upgrade");

        let backups = fs::read_dir(directory.join("backups"))
            .expect("backup folder")
            .flatten()
            .map(|backup| backup.path())
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1, "{tag}");
        assert_eq!(
            fs::read(&backups[0]).expect("backup bytes"),
            original,
            "{tag}"
        );

        let upgraded = VaultLoader::read(&vault).expect("upgraded envelope");
        assert_eq!(upgraded.format_version, VAULT_FORMAT_VERSION, "{tag}");
        assert!(upgraded.setup_complete, "{tag}");
        for credential in [
            Credential::MasterPassword(password),
            Credential::RecoveryKit(recovery_kit),
        ] {
            let reopened = VaultLoader::open(&upgraded, credential)
                .unwrap_or_else(|error| panic!("{tag} upgrade did not reopen: {error:?}"));
            assert!(!reopened.migrated, "{tag}");
            assert_eq!(reopened.payload.vault_id, opened.payload.vault_id, "{tag}");
            assert_eq!(
                counts_of(&reopened.payload),
                counts_of(&opened.payload),
                "{tag}"
            );
            assert_eq!(
                all_stable_ids(&reopened.payload),
                all_stable_ids(&opened.payload),
                "{tag}"
            );
        }
        let _ = fs::remove_dir_all(&directory);
    }
}

type WrittenField = (String, String, bool);
type WrittenLogin = (String, Vec<WrittenField>);

fn raw_legacy_fields(item: &Value) -> Vec<WrittenField> {
    item["legacyFields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .map(|field| {
                    (
                        field["label"].as_str().expect("legacy label").to_string(),
                        field["value"].as_str().expect("legacy value").to_string(),
                        field["secret"].as_bool().unwrap_or(false),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn written_legacy_fields(payload: &Value) -> Vec<WrittenLogin> {
    let mut logins = Vec::new();
    for item in payload["items"].as_array().expect("tagged items") {
        if item["kind"] == "login" {
            logins.push((
                item["id"].as_str().expect("login id").to_string(),
                raw_legacy_fields(item),
            ));
        }
    }
    for trashed in payload["trash"].as_array().expect("trash") {
        let item = &trashed["item"];
        if item["kind"] == "login" {
            logins.push((
                item["id"].as_str().expect("trashed login id").to_string(),
                raw_legacy_fields(item),
            ));
        }
    }
    for entry in payload["history"].as_array().expect("history") {
        if entry["item"]["kind"] == "login" {
            logins.push((
                entry["id"].as_str().expect("history id").to_string(),
                raw_legacy_fields(&entry["item"]),
            ));
        }
    }
    logins
}

fn upgraded_login<'a>(
    payload: &'a sesame_core::VaultPayload,
    id: &str,
) -> &'a sesame_core::VaultEntry {
    let active = payload.entries.iter().find(|entry| entry.id == id);
    let trashed = payload
        .trash
        .iter()
        .find_map(|trashed| match &trashed.item {
            sesame_core::TaggedItem::Login(entry) if entry.id == id => Some(entry),
            _ => None,
        });
    let history = payload.history.iter().find_map(|entry| match &entry.item {
        sesame_core::TaggedItem::Login(login) if entry.id == id => Some(login),
        _ => None,
    });
    active
        .or(trashed)
        .or(history)
        .unwrap_or_else(|| panic!("upgraded vault lost login {id}"))
}

fn fixture_credential<'a>(use_kit: bool, password: &'a str, kit: &'a str) -> Credential<'a> {
    if use_kit {
        Credential::RecoveryKit(kit)
    } else {
        Credential::MasterPassword(password)
    }
}

#[test]
fn fixture_v0_5_3_upgrades_to_format_11_and_moves_login_legacy_fields() {
    let tag = "v0.5.3";
    let entry = fixture_entry(tag);
    let source = corpus_dir().join(entry["fileName"].as_str().expect("file name"));
    let original = fs::read(&source).expect("fixture bytes");
    assert_eq!(
        digest_of(&original),
        entry["digestSha256"].as_str().expect("recorded digest")
    );
    let password = entry["secrets"]["masterPassword"]
        .as_str()
        .expect("password");
    let recovery_kit = entry["secrets"]["recoveryKit"]
        .as_str()
        .expect("recovery kit");

    let fixture = VaultLoader::parse(&original).expect("fixture envelope");
    assert_eq!(fixture.format_version, 10);
    let written: Value = serde_json::from_slice(
        VaultLoader::authenticate(&fixture, Credential::MasterPassword(password))
            .expect("authenticated the fixture payload")
            .bytes(),
    )
    .expect("parsed the fixture payload");
    let written = written_legacy_fields(&written);
    let recorded = entry["legacyFields"]
        .as_object()
        .expect("recorded legacy fields");
    assert_eq!(
        written
            .iter()
            .filter(|(_, fields)| !fields.is_empty())
            .count(),
        recorded.len()
    );
    for (id, fields) in recorded {
        let (_, actual) = written
            .iter()
            .find(|(written_id, _)| written_id == id)
            .unwrap_or_else(|| panic!("{tag} has no login {id}"));
        let expected = fields
            .as_array()
            .expect("recorded fields")
            .iter()
            .map(|field| {
                (
                    field["label"].as_str().expect("label").to_string(),
                    field["secret"].as_bool().expect("secret flag"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual
                .iter()
                .map(|(label, _, secret)| (label.clone(), *secret))
                .collect::<Vec<_>>(),
            expected,
            "{tag} {id}"
        );
    }
    assert!(written
        .iter()
        .flat_map(|(_, fields)| fields)
        .any(|(_, _, secret)| *secret));
    assert!(written
        .iter()
        .flat_map(|(_, fields)| fields)
        .any(|(_, _, secret)| !*secret));

    for open_with_kit in [false, true] {
        let directory =
            std::env::temp_dir().join(format!("sesame-corpus-format-11-{}", random_id()));
        fs::create_dir_all(&directory).expect("test directory");
        let vault = directory.join("vault.sesame");
        fs::write(&vault, &original).expect("copied fixture");

        let file = VaultLoader::read(&vault).expect("fixture envelope");
        let opened = VaultLoader::open(
            &file,
            fixture_credential(open_with_kit, password, recovery_kit),
        )
        .expect("opened the fixture");
        assert!(opened.migrated);
        let mut session = UnlockedVault::from_opened(vault.clone(), &opened).expect("session");
        persist_session(&mut session).expect("saved the upgrade");
        drop(session);

        let backups = fs::read_dir(directory.join("backups"))
            .expect("backup folder")
            .flatten()
            .map(|backup| backup.path())
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert!(backups[0]
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("sesame-before-upgrade-")));
        assert_eq!(fs::read(&backups[0]).expect("backup bytes"), original);

        let upgraded = VaultLoader::read(&vault).expect("upgraded envelope");
        assert_eq!(upgraded.format_version, VAULT_FORMAT_VERSION);
        assert_eq!(upgraded.format_version, 11);
        assert!(upgraded.setup_complete);
        for reopen_with_kit in [false, true] {
            let raw: Value = serde_json::from_slice(
                VaultLoader::authenticate(
                    &upgraded,
                    fixture_credential(reopen_with_kit, password, recovery_kit),
                )
                .expect("authenticated the upgraded payload")
                .bytes(),
            )
            .expect("parsed the upgraded payload");
            for (id, fields) in written_legacy_fields(&raw) {
                assert!(fields.is_empty(), "{tag} {id} kept legacy fields on disk");
            }

            let reopened = VaultLoader::open(
                &upgraded,
                fixture_credential(reopen_with_kit, password, recovery_kit),
            )
            .unwrap_or_else(|error| panic!("{tag} upgrade did not reopen: {error:?}"));
            assert!(!reopened.migrated);
            assert_eq!(reopened.payload.vault_id, opened.payload.vault_id);
            assert_eq!(counts_of(&reopened.payload), counts_of(&opened.payload));
            assert_eq!(
                all_stable_ids(&reopened.payload),
                all_stable_ids(&opened.payload)
            );
            for (id, fields) in &written {
                let login = upgraded_login(&reopened.payload, id);
                assert!(login.legacy_fields.is_empty(), "{tag} {id}");
                let moved = login
                    .custom_fields
                    .iter()
                    .map(|field| {
                        let secret = match field.kind.as_str() {
                            "secret" => true,
                            "text" => false,
                            other => panic!("{tag} {id} moved a field as {other}"),
                        };
                        (field.label.clone(), field.value.clone(), secret)
                    })
                    .collect::<Vec<_>>();
                assert_eq!(&moved, fields, "{tag} {id}");
            }
        }
        let _ = fs::remove_dir_all(&directory);
    }
}
