use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::Value;
use sesame_core::loader::{Credential, VaultLoader};
use sesame_core::VAULT_FORMAT_VERSION;
use sha2::{Digest, Sha256};

const PUBLISHED_RELEASES: [&str; 5] = ["v0.1.0", "v0.1.1", "v0.2.0", "v0.2.1", "v0.2.2"];

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
    assert_eq!(file.format_version, VAULT_FORMAT_VERSION);
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
        Some("supportRetained"),
        "the recorded owner decision for formats 2 through 9 must keep the upgrade path"
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
