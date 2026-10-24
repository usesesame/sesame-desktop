use sesame_core::{
    json_export_bytes, Attachment, Card, CustomFieldEntry, CustomRecord, DocumentMetadata, Folder,
    Identity, LegacyField, SecureNote, SoftwareLicense, SshKey, TaggedItem, TrashedItem,
    VaultEntry, VaultPayload, WifiNetwork, READABLE_EXPORT_FORMAT, READABLE_EXPORT_VERSION,
};

const CANARY: &str = "fictional-export-canary";

fn fictional_payload() -> VaultPayload {
    let mut payload = VaultPayload::default();
    payload.vault_name = "Fictional vault".to_string();
    payload.folders = vec![Folder {
        id: "folder-1".to_string(),
        name: "Fictional folder".to_string(),
    }];

    let mut login = VaultEntry::default();
    login.id = "login-1".to_string();
    login.title = "Fictional login".to_string();
    login.password = format!("{CANARY}-login-password");
    login.totp = Some(format!("{CANARY}-totp"));
    login.import_source = Some(format!("{CANARY}-import-source"));
    login.legacy_fields = vec![LegacyField {
        label: "Old PIN".to_string(),
        value: format!("{CANARY}-legacy"),
        secret: true,
    }];
    payload.entries = vec![login];

    let mut identity = Identity::default();
    identity.id = "identity-1".to_string();
    identity.label = "Fictional identity".to_string();
    identity.full_name = format!("{CANARY}-full-name");
    payload.identities = vec![identity];

    let mut note = SecureNote::default();
    note.id = "note-1".to_string();
    note.title = "Fictional note".to_string();
    note.content = format!("{CANARY}-note-body");
    note.locked = true;
    payload.secure_notes = vec![note];

    let mut card = Card::default();
    card.id = "card-1".to_string();
    card.title = "Fictional card".to_string();
    card.number = format!("{CANARY}-card-number");
    card.security_code = format!("{CANARY}-card-code");
    payload.cards = vec![card];

    let mut wifi = WifiNetwork::default();
    wifi.id = "wifi-1".to_string();
    wifi.title = "Fictional network".to_string();
    wifi.password = format!("{CANARY}-wifi-password");
    payload.wifi_networks = vec![wifi];

    let mut ssh = SshKey::default();
    ssh.id = "ssh-1".to_string();
    ssh.title = "Fictional key".to_string();
    ssh.private_key = format!("{CANARY}-private-key");
    ssh.passphrase = format!("{CANARY}-passphrase");
    payload.ssh_keys = vec![ssh];

    let mut licence = SoftwareLicense::default();
    licence.id = "licence-1".to_string();
    licence.title = "Fictional licence".to_string();
    licence.license_key = format!("{CANARY}-licence-key");
    payload.software_licenses = vec![licence];

    let mut document = DocumentMetadata::default();
    document.id = "document-1".to_string();
    document.title = "Fictional document".to_string();
    document.document_number = format!("{CANARY}-document-number");
    document.attachments = vec![Attachment {
        id: "attachment-1".to_string(),
        filename: "scan.txt".to_string(),
        content_type: "text/plain".to_string(),
        size: 5,
        data: b"hello".to_vec(),
    }];
    payload.documents = vec![document];

    let mut record = CustomRecord::default();
    record.id = "record-1".to_string();
    record.title = "Fictional record".to_string();
    record.fields = vec![CustomFieldEntry {
        label: "Secret".to_string(),
        value: format!("{CANARY}-custom-secret"),
        kind: "secret".to_string(),
    }];
    payload.custom_records = vec![record];

    let mut trashed = SecureNote::default();
    trashed.id = "note-trashed".to_string();
    trashed.title = "Fictional trashed note".to_string();
    trashed.content = format!("{CANARY}-trashed-body");
    payload.trash = vec![TrashedItem {
        item: TaggedItem::SecureNote(trashed),
        deleted_at: 1_800_000_000,
    }];
    payload
}

fn exported() -> serde_json::Value {
    let bytes = json_export_bytes(&fictional_payload()).expect("export");
    serde_json::from_slice(&bytes).expect("valid json")
}

#[test]
fn the_export_names_its_format_and_version() {
    let document = exported();
    assert_eq!(document["format"], READABLE_EXPORT_FORMAT);
    assert_eq!(READABLE_EXPORT_FORMAT, "sesame-export");
    assert_eq!(document["version"], READABLE_EXPORT_VERSION);
    assert_eq!(READABLE_EXPORT_VERSION, 1);
    assert_eq!(document["vaultName"], "Fictional vault");
    assert!(document["exportedAt"].as_u64().is_some());
}

#[test]
fn the_export_holds_exactly_the_documented_top_level_fields_and_no_history() {
    let document = exported();
    let mut keys: Vec<&str> = document
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "cards",
            "customRecords",
            "documents",
            "exportedAt",
            "folders",
            "format",
            "identities",
            "logins",
            "secureNotes",
            "softwareLicenses",
            "sshKeys",
            "trash",
            "vaultName",
            "version",
            "wifiNetworks",
        ]
    );
}

#[test]
fn every_item_kind_is_exported_with_its_secrets() {
    let text = serde_json::to_string(&exported()).expect("text");
    for secret in [
        "login-password",
        "totp",
        "full-name",
        "note-body",
        "card-number",
        "card-code",
        "wifi-password",
        "private-key",
        "passphrase",
        "licence-key",
        "document-number",
        "custom-secret",
        "trashed-body",
        "legacy",
        "import-source",
    ] {
        assert!(
            text.contains(&format!("{CANARY}-{secret}")),
            "{secret} is missing from the export"
        );
    }
    let document = exported();
    for list in [
        "folders",
        "logins",
        "identities",
        "secureNotes",
        "cards",
        "wifiNetworks",
        "sshKeys",
        "softwareLicenses",
        "documents",
        "customRecords",
        "trash",
    ] {
        assert_eq!(document[list].as_array().expect(list).len(), 1, "{list}");
    }
}

#[test]
fn an_attachment_keeps_its_name_type_and_contents() {
    let document = exported();
    let attachment = &document["documents"][0]["attachments"][0];
    assert_eq!(attachment["filename"], "scan.txt");
    assert_eq!(attachment["contentType"], "text/plain");
    assert_eq!(attachment["size"], 5);
    assert_eq!(attachment["data"], "aGVsbG8");
}

#[test]
fn a_trashed_item_keeps_its_kind_and_deletion_time() {
    let document = exported();
    let trashed = &document["trash"][0];
    assert_eq!(trashed["deletedAt"], 1_800_000_000_u64);
    assert_eq!(trashed["item"]["kind"], "secure_note");
    assert_eq!(trashed["item"]["title"], "Fictional trashed note");
}

#[test]
fn an_empty_vault_exports_empty_lists() {
    let bytes = json_export_bytes(&VaultPayload::default()).expect("export");
    let document: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
    assert_eq!(document["logins"].as_array().expect("logins").len(), 0);
    assert_eq!(document["trash"].as_array().expect("trash").len(), 0);
}

const FORMAT_DOCUMENT: &str = include_str!("../../../EXPORT-FORMAT.md");

#[test]
fn the_format_document_names_every_field_the_export_writes() {
    let document = exported();
    let mut missing = Vec::new();
    for (key, value) in document.as_object().expect("object") {
        if !FORMAT_DOCUMENT.contains(&format!("`{key}`")) {
            missing.push(key.clone());
        }
        let Some(list) = value.as_array() else {
            continue;
        };
        for item in list {
            let item = item.get("item").unwrap_or(item);
            for field in item.as_object().expect("item object").keys() {
                if !FORMAT_DOCUMENT.contains(&format!("`{field}`")) {
                    missing.push(format!("{key}.{field}"));
                }
            }
        }
    }
    let attachment = &document["documents"][0]["attachments"][0];
    for field in attachment.as_object().expect("attachment").keys() {
        if !FORMAT_DOCUMENT.contains(&format!("`{field}`")) {
            missing.push(format!("attachment.{field}"));
        }
    }
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "EXPORT-FORMAT.md does not name {missing:?}"
    );
    assert!(FORMAT_DOCUMENT.contains("This page\ndescribes version 1."));
}
