use std::env;
use std::fs;
use std::path::PathBuf;

use sesame_core::api::{
    create_vault, open_vault_bytes, open_vault_with_recovery_kit, parse_vault_file,
};
use sesame_core::storage::complete_recovery_setup_for_session;
use sesame_core::types::{
    Card, CustomFieldEntry, CustomRecord, DocumentMetadata, Folder, HistoryEntry, HistoryOperation,
    Identity, SecureNote, SshKey, SoftwareLicense, TaggedItem, TrashedItem, VaultEntry,
    VaultPayload, WifiNetwork,
};
use sesame_core::UnlockedVault;

const MASTER_PASSWORD: &str = "fictional master password 01";
const VAULT_NAME: &str = "Fictional Story Vault";
const BASE: u64 = 1_700_000_000;

fn out_dir() -> PathBuf {
    let dir = PathBuf::from(env::var("SESAME_FIXTURE_OUT").expect("fixture output directory"));
    fs::create_dir_all(&dir).expect("created fixture output directory");
    dir
}

fn login_alpha() -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = "login-alpha".to_string();
    entry.title = "Kaffeehaus Müllerstraße".to_string();
    entry.url = "https://login.example/mueller".to_string();
    entry.urls = vec!["https://alt.example/mueller".to_string()];
    entry.tags = vec!["fiction".to_string()];
    entry.username = "frida@example.test".to_string();
    entry.email = "frida@example.test".to_string();
    entry.password = "fictional-login-secret-01".to_string();
    entry.folder_id = Some("folder-arcs".to_string());
    entry.favourite = true;
    entry.last_used_at = Some(BASE + 500);
    entry.totp = Some(
        "otpauth://totp/Fictional:frida?secret=JBSWY3DPEHPK3PXP&issuer=FictionalCo".to_string(),
    );
    entry.backup_codes = vec!["FICTION-1111".to_string(), "FICTION-2222".to_string()];
    entry.recovery_email = Some("help@example.test".to_string());
    entry.recovery_not_applicable = false;
    entry.notes = Some("Fictional login note".to_string());
    entry.created_at = BASE;
    entry.updated_at = BASE + 100;
    entry.password_updated_at = BASE + 90;
    entry.revision = 3;
    entry
}

fn login_empty() -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = "login-empty".to_string();
    entry.title = "Empty optionals".to_string();
    entry
}

fn login_trashed() -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = "login-trashed".to_string();
    entry.title = "Trashed login".to_string();
    entry.username = "old@example.test".to_string();
    entry.password = "fictional-trashed-secret".to_string();
    entry.created_at = BASE + 10;
    entry.updated_at = BASE + 20;
    entry.password_updated_at = BASE + 20;
    entry.revision = 2;
    entry
}

fn login_historical() -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = "login-alpha".to_string();
    entry.title = "Kaffeehaus Müllerstraße".to_string();
    entry.password = "fictional-old-secret".to_string();
    entry.created_at = BASE;
    entry.updated_at = BASE + 50;
    entry.password_updated_at = BASE + 50;
    entry.revision = 2;
    entry
}

fn fictional_payload(vault_id: Option<String>) -> VaultPayload {
    VaultPayload {
        vault_name: VAULT_NAME.to_string(),
        folders: vec![
            Folder {
                id: "folder-arcs".to_string(),
                name: "Story arcs".to_string(),
            },
            Folder {
                id: "folder-drafts".to_string(),
                name: "Old drafts".to_string(),
            },
        ],
        entries: vec![login_alpha(), login_empty()],
        identities: vec![{
            let mut identity = Identity::default();
            identity.id = "identity-alpha".to_string();
            identity.label = "Frida Fictional".to_string();
            identity.full_name = "Frida Fictional".to_string();
            identity.email = "frida@example.test".to_string();
            identity.phone = "+1 555 0100".to_string();
            identity.address_line1 = "12 Fictional Lane".to_string();
            identity.city = "Springfield".to_string();
            identity.postal_code = "10001".to_string();
            identity.country = "Fictionland".to_string();
            identity.created_at = BASE;
            identity.updated_at = BASE + 30;
            identity.revision = 1;
            identity
        }],
        secure_notes: vec![{
            let mut note = SecureNote::default();
            note.id = "note-alpha".to_string();
            note.title = "Fictional note – café notes".to_string();
            note.content = "Fictional note content with unicode ✓".to_string();
            note.created_at = BASE;
            note.updated_at = BASE + 40;
            note.revision = 1;
            note
        }],
        cards: vec![{
            let mut card = Card::default();
            card.id = "card-alpha".to_string();
            card.title = "Fictional card".to_string();
            card.cardholder_name = "Frida Fictional".to_string();
            card.number = "1234 5678 9012 3456".to_string();
            card.expiry_month = "12".to_string();
            card.expiry_year = "2030".to_string();
            card.security_code = "123".to_string();
            card.brand = "Fictioncard".to_string();
            card.created_at = BASE;
            card.updated_at = BASE + 40;
            card.revision = 1;
            card
        }],
        wifi_networks: vec![{
            let mut network = WifiNetwork::default();
            network.id = "wifi-alpha".to_string();
            network.title = "Fictional guest network".to_string();
            network.ssid = "FictionalGuest".to_string();
            network.password = "fictional-wifi-pass".to_string();
            network.security_type = "wpa2".to_string();
            network.created_at = BASE;
            network.updated_at = BASE + 40;
            network.revision = 1;
            network
        }],
        ssh_keys: vec![{
            let mut key = SshKey::default();
            key.id = "ssh-alpha".to_string();
            key.title = "Fictional key".to_string();
            key.key_type = "ed25519".to_string();
            key.private_key = "fictional-private-key-not-real".to_string();
            key.public_key =
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE1AAAAIFictionalPlaceholderNotARealKey fictional@example.test"
                    .to_string();
            key.created_at = BASE;
            key.updated_at = BASE + 40;
            key.revision = 1;
            key
        }],
        software_licenses: vec![{
            let mut license = SoftwareLicense::default();
            license.id = "license-alpha".to_string();
            license.title = "Fictional license".to_string();
            license.license_key = "FICTION-AAAA-BBBB-CCCC-DDDD".to_string();
            license.product_name = "Fictional Editor".to_string();
            license.purchased_from = "Fictional Store".to_string();
            license.purchase_date = "2026-01-02".to_string();
            license.created_at = BASE;
            license.updated_at = BASE + 40;
            license.revision = 1;
            license
        }],
        documents: vec![{
            let mut document = DocumentMetadata::default();
            document.id = "document-alpha".to_string();
            document.title = "Fictional document".to_string();
            document.document_type = "pdf".to_string();
            document.document_number = "DOC-FICTION-001".to_string();
            document.issuing_authority = "Fictional Authority".to_string();
            document.created_at = BASE;
            document.updated_at = BASE + 40;
            document.revision = 1;
            document
        }],
        custom_records: vec![{
            let mut record = CustomRecord::default();
            record.id = "custom-alpha".to_string();
            record.title = "Fictional record".to_string();
            record.fields = vec![CustomFieldEntry {
                label: "Server".to_string(),
                value: "db.example.test".to_string(),
                kind: "text".to_string(),
            }];
            record.notes = "Fictional custom record".to_string();
            record.created_at = BASE;
            record.updated_at = BASE + 40;
            record.revision = 1;
            record
        }],
        trash: vec![TrashedItem {
            item: TaggedItem::Login(login_trashed()),
            deleted_at: BASE + 400,
        }],
        history: vec![HistoryEntry {
            id: "history-alpha".to_string(),
            item: TaggedItem::Login(login_historical()),
            captured_at: BASE + 60,
            operation: HistoryOperation::Edit,
        }],
        vault_id,
        revision: 1,
    }
}

fn expected_counts() -> Vec<(&'static str, usize)> {
    vec![
        ("entries", 2),
        ("identities", 1),
        ("secureNotes", 1),
        ("cards", 1),
        ("wifiNetworks", 1),
        ("sshKeys", 1),
        ("softwareLicenses", 1),
        ("documents", 1),
        ("customRecords", 1),
        ("folders", 2),
        ("trash", 1),
        ("history", 1),
    ]
}

fn verify_and_record(tag: &str, bytes: &[u8], recovery_kit: &str, out: &PathBuf) {
    let reopened = open_vault_bytes(bytes, MASTER_PASSWORD).expect("opened with master password");
    assert_eq!(reopened.file.format_version, 10);
    assert!(reopened.file.setup_complete);
    assert_eq!(reopened.payload.vault_name, VAULT_NAME);
    assert!(reopened.payload.vault_id.is_some());
    for (field, expected) in expected_counts() {
        let actual = match field {
            "entries" => reopened.payload.entries.len(),
            "identities" => reopened.payload.identities.len(),
            "secureNotes" => reopened.payload.secure_notes.len(),
            "cards" => reopened.payload.cards.len(),
            "wifiNetworks" => reopened.payload.wifi_networks.len(),
            "sshKeys" => reopened.payload.ssh_keys.len(),
            "softwareLicenses" => reopened.payload.software_licenses.len(),
            "documents" => reopened.payload.documents.len(),
            "customRecords" => reopened.payload.custom_records.len(),
            "folders" => reopened.payload.folders.len(),
            "trash" => reopened.payload.trash.len(),
            "history" => reopened.payload.history.len(),
            _ => unreachable!(),
        };
        assert_eq!(actual, expected, "count mismatch for {field}");
    }
    let parsed = parse_vault_file(bytes).expect("parsed fixture");
    let with_kit = open_vault_with_recovery_kit(&parsed, recovery_kit)
        .expect("opened with recovery kit");
    assert_eq!(with_kit.payload.vault_id, reopened.payload.vault_id);

    let file_name = format!("{tag}.sesame");
    fs::write(out.join(&file_name), bytes).expect("wrote fixture file");
    let meta = serde_json::json!({
        "writerTag": tag,
        "writerCommit": env::var("SESAME_WRITER_COMMIT").expect("writer commit"),
        "fileName": file_name,
        "formatVersion": reopened.file.format_version,
        "setupComplete": reopened.file.setup_complete,
        "kdf": {
            "algorithm": reopened.file.kdf.algorithm,
            "memoryKib": reopened.file.kdf.memory_kib,
            "iterations": reopened.file.kdf.iterations,
            "parallelism": reopened.file.kdf.parallelism,
        },
        "masterPassword": MASTER_PASSWORD,
        "recoveryKit": recovery_kit,
        "vaultName": reopened.payload.vault_name,
        "vaultId": reopened.payload.vault_id,
        "revision": reopened.payload.revision,
        "counts": serde_json::json!({
            "entries": reopened.payload.entries.len(),
            "identities": reopened.payload.identities.len(),
            "secureNotes": reopened.payload.secure_notes.len(),
            "cards": reopened.payload.cards.len(),
            "wifiNetworks": reopened.payload.wifi_networks.len(),
            "sshKeys": reopened.payload.ssh_keys.len(),
            "softwareLicenses": reopened.payload.software_licenses.len(),
            "documents": reopened.payload.documents.len(),
            "customRecords": reopened.payload.custom_records.len(),
            "folders": reopened.payload.folders.len(),
            "trash": reopened.payload.trash.len(),
            "history": reopened.payload.history.len(),
        }),
        "stableIds": [
            "login-alpha",
            "login-empty",
            "login-trashed",
            "identity-alpha",
            "note-alpha",
            "card-alpha",
            "wifi-alpha",
            "ssh-alpha",
            "license-alpha",
            "document-alpha",
            "custom-alpha",
            "folder-arcs",
            "folder-drafts",
            "history-alpha"
        ],
    });
    fs::write(
        out.join(format!("meta-{tag}.json")),
        serde_json::to_vec_pretty(&meta).expect("serialized meta"),
    )
    .expect("wrote meta");
}

#[test]
fn generate_fixture_with_this_releases_writer() {
    let tag = env::var("SESAME_WRITER_TAG").expect("writer tag");
    let out = out_dir();
    let directory = env::temp_dir().join(format!("sesame-fixture-{tag}-{}", sesame_core::fresh_vault_id()));
    let path = directory.join("vault.sesame");

    let (opened, recovery_kit) = create_vault(MASTER_PASSWORD, VAULT_NAME).expect("created vault");
    let vault_id = opened.payload.vault_id.clone();
    let mut session = UnlockedVault {
        path: path.clone(),
        key: opened.key.clone(),
        kdf: opened.file.kdf.clone(),
        key_wrap: opened.file.key_wrap.clone(),
        legacy_device_wrap: opened.file.legacy_device_wrap.clone(),
        recovery_kdf: opened.file.recovery_kdf.clone(),
        recovery_wrap: opened.file.recovery_wrap.clone(),
        pin_wrap: opened.file.pin_wrap.clone(),
        hello_wrap: opened.file.hello_wrap.clone(),
        setup_complete: opened.file.setup_complete,
        payload: opened.payload.clone(),
    };
    session.payload = fictional_payload(vault_id);

    complete_recovery_setup_for_session(&mut session, &recovery_kit).expect("completed setup");

    let bytes = fs::read(&path).expect("read generated vault");
    verify_and_record(&tag, &bytes, &recovery_kit, &out);

    drop(session);
    fs::remove_dir_all(&directory).expect("removed temporary vault directory");
}
