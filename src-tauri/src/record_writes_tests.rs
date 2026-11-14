use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::application::records::record_view_in_state;
use crate::application::reveal::item_field_in_state;
use crate::commands::test_support::TestVault;
use crate::commands::{save_card_in_state, save_document_in_state, save_secure_note_in_state};
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::{
    Card, CardInput, DocumentMetadataInput, SecureNote, SecureNoteInput, TaggedItem, VaultPayload,
};

use crate::application::history::{
    preview_history_version_in_state, preview_trashed_item_in_state,
    restore_history_version_in_state, restore_trashed_item_in_state,
};
use crate::application::record_writes::{
    add_document_attachment_in_state, delete_record_in_state, remove_document_attachment_in_state,
    set_secure_note_lock_in_state, MAX_ATTACHMENTS_PER_DOCUMENT, MAX_ATTACHMENT_BYTES,
};
use sesame_app::test_support::grant;

const CANARY: &str = "fictional-note-body-canary";

fn vault() -> TestVault {
    TestVault::with_login("fictional-login", "https://northwind.example")
}

fn lock(vault: &TestVault) {
    *vault.state.session.lock().expect("session lock") = None;
}

fn bytes(vault: &TestVault) -> Vec<u8> {
    std::fs::read(vault.path()).expect("vault bytes")
}

fn payload(vault: &TestVault) -> VaultPayload {
    let session = vault.state.session.lock().expect("session lock");
    session
        .as_ref()
        .expect("session")
        .open_payload()
        .expect("opened payload")
        .clone()
}

fn card_input(id: Option<&str>, title: &str, number: &str, kept: &[&str]) -> CardInput {
    CardInput {
        id: id.map(str::to_string),
        title: title.to_string(),
        cardholder_name: "Fictional Holder".to_string(),
        number: number.to_string(),
        expiry_month: "01".to_string(),
        expiry_year: "2030".to_string(),
        security_code: "123".to_string(),
        brand: "Fictional".to_string(),
        notes: String::new(),
        tags: Vec::new(),
        kept_secrets: kept.iter().map(|key| key.to_string()).collect(),
    }
}

fn document_input(id: Option<&str>, title: &str) -> DocumentMetadataInput {
    DocumentMetadataInput {
        id: id.map(str::to_string),
        title: title.to_string(),
        document_type: "Fictional type".to_string(),
        document_number: "Fictional number".to_string(),
        issuing_authority: "Fictional authority".to_string(),
        issue_date: "2030-01-01".to_string(),
        expiry_date: "2040-01-01".to_string(),
        notes: String::new(),
        tags: Vec::new(),
        kept_secrets: Vec::new(),
    }
}

fn note_input(id: Option<&str>, content: &str, locked: bool, kept: &[&str]) -> SecureNoteInput {
    SecureNoteInput {
        id: id.map(str::to_string),
        title: "Fictional note".to_string(),
        content: content.to_string(),
        locked,
        tags: Vec::new(),
        kept_secrets: kept.iter().map(|key| key.to_string()).collect(),
    }
}

fn note_of(item: &TaggedItem) -> Option<&SecureNote> {
    match item {
        TaggedItem::SecureNote(note) => Some(note),
        _ => None,
    }
}

fn add_attachment(vault: &TestVault, document_id: &str, filename: &str) -> String {
    let data = URL_SAFE_NO_PAD.encode(b"fictional attachment");
    add_document_attachment_in_state(&vault.state, document_id, filename, "text/plain", &data)
        .expect("added attachment");
    payload(vault)
        .documents
        .iter()
        .find(|document| document.id == document_id)
        .expect("document")
        .attachments
        .last()
        .expect("attachment")
        .id
        .clone()
}

#[test]
fn saving_and_deleting_on_a_locked_vault_write_nothing() {
    let vault = vault();
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();
    lock(&vault);

    assert_eq!(
        save_card_in_state(card_input(None, "Fictional card", "", &[]), &vault.state).err(),
        Some("Unlock your vault before saving a card.".to_string())
    );
    assert_eq!(
        delete_record_in_state::<Card>(
            &vault.state,
            "fictional-login",
            "card",
            "Unlock your vault before deleting a card.",
            "Choose a saved card to delete.",
        )
        .err(),
        Some("Unlock your vault before deleting a card.".to_string())
    );

    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn an_invalid_record_leaves_the_vault_file_byte_identical() {
    let vault = vault();
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        save_card_in_state(card_input(None, "", "fictional-number", &[]), &vault.state).err(),
        Some("Give this card a name so you can find it again.".to_string())
    );
    assert_eq!(
        save_document_in_state(document_input(None, ""), &vault.state).err(),
        Some("Give this document a name so you can find it again.".to_string())
    );
    let untitled_note = SecureNoteInput {
        id: None,
        title: String::new(),
        content: CANARY.to_string(),
        locked: true,
        tags: Vec::new(),
        kept_secrets: Vec::new(),
    };
    assert_eq!(
        save_secure_note_in_state(untitled_note, &vault.state).err(),
        Some("Give this note a title so you can find it again.".to_string())
    );

    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
    let stored = payload(&vault);
    assert!(stored.cards.is_empty());
    assert!(stored.documents.is_empty());
    assert!(stored.secure_notes.is_empty());
    assert!(stored.history.is_empty());
}

#[test]
fn a_save_carries_metadata_history_and_secrets() {
    let vault = vault();
    let card_id = save_card_in_state(
        card_input(None, "Fictional card", "fictional-number-canary", &[]),
        &vault.state,
    )
    .expect("saved card")
    .id;
    vault.seed(|payload| {
        let card = payload
            .cards
            .iter_mut()
            .find(|card| card.id == card_id)
            .expect("card");
        card.created_at = 11;
        card.folder_id = Some("fictional-folder".to_string());
        card.favourite = true;
        card.last_used_at = Some(22);
    });
    let epoch = vault.state.session_epoch();

    let saved = save_card_in_state(
        card_input(Some(&card_id), "Fictional renamed card", "", &["number"]),
        &vault.state,
    )
    .expect("saved card");

    assert_eq!(saved.id, card_id);
    let stored_payload = payload(&vault);
    let stored = stored_payload
        .cards
        .iter()
        .find(|card| card.id == card_id)
        .expect("stored card");
    assert_eq!(stored.title, "Fictional renamed card");
    assert_eq!(stored.number, "fictional-number-canary");
    assert_eq!(stored.created_at, 11);
    assert_eq!(stored.revision, 2);
    assert_eq!(stored.folder_id.as_deref(), Some("fictional-folder"));
    assert!(stored.favourite);
    assert_eq!(stored.last_used_at, Some(22));
    assert_eq!(vault.state.session_epoch(), epoch + 1);

    let history = &stored_payload.history;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].item.id(), card_id);
    let TaggedItem::Card(previous) = &history[0].item else {
        panic!("history entry is not a card");
    };
    assert_eq!(previous.title, "Fictional card");
    assert_eq!(previous.number, "fictional-number-canary");
}

#[test]
fn a_document_save_keeps_its_attachments() {
    let vault = vault();
    let document_id =
        save_document_in_state(document_input(None, "Fictional document"), &vault.state)
            .expect("saved document")
            .id;
    let attachment_id = add_attachment(&vault, &document_id, "fictional.txt");
    let epoch = vault.state.session_epoch();

    save_document_in_state(
        document_input(Some(&document_id), "Fictional renamed document"),
        &vault.state,
    )
    .expect("saved document");

    let stored_payload = payload(&vault);
    let stored = stored_payload
        .documents
        .iter()
        .find(|document| document.id == document_id)
        .expect("stored document");
    assert_eq!(stored.title, "Fictional renamed document");
    assert_eq!(stored.revision, 3);
    assert_eq!(stored.attachments.len(), 1);
    assert_eq!(stored.attachments[0].id, attachment_id);
    assert_eq!(vault.state.session_epoch(), epoch + 1);

    let history = &stored_payload.history;
    assert_eq!(history.len(), 1);
    let TaggedItem::Document(previous) = &history[0].item else {
        panic!("history entry is not a document");
    };
    assert!(previous.attachments.is_empty());
}

#[test]
fn an_attachment_above_the_size_limit_is_refused_without_writing() {
    let vault = vault();
    let document_id =
        save_document_in_state(document_input(None, "Fictional document"), &vault.state)
            .expect("saved document")
            .id;
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();
    let data = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_ATTACHMENT_BYTES + 1]);

    assert_eq!(
        add_document_attachment_in_state(
            &vault.state,
            &document_id,
            "fictional.bin",
            "application/octet-stream",
            &data,
        )
        .err(),
        Some("Attachments are limited to 5 MB.".to_string())
    );

    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
    assert!(payload(&vault)
        .documents
        .iter()
        .find(|document| document.id == document_id)
        .expect("document")
        .attachments
        .is_empty());
}

#[test]
fn the_attachment_cap_and_removal_rules_hold() {
    let vault = vault();
    let document_id =
        save_document_in_state(document_input(None, "Fictional document"), &vault.state)
            .expect("saved document")
            .id;
    let first = add_attachment(&vault, &document_id, "fictional-1.txt");
    for index in 2..=MAX_ATTACHMENTS_PER_DOCUMENT {
        add_attachment(&vault, &document_id, &format!("fictional-{index}.txt"));
    }
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();
    let data = URL_SAFE_NO_PAD.encode(b"fictional attachment");

    assert_eq!(
        add_document_attachment_in_state(
            &vault.state,
            &document_id,
            "fictional-6.txt",
            "text/plain",
            &data,
        )
        .err(),
        Some("A document can hold up to 5 attachments.".to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);

    remove_document_attachment_in_state(&vault.state, &document_id, &first).expect("removed");
    assert_eq!(
        payload(&vault)
            .documents
            .iter()
            .find(|document| document.id == document_id)
            .expect("document")
            .attachments
            .len(),
        4
    );
    let after_remove = bytes(&vault);
    assert_eq!(
        remove_document_attachment_in_state(&vault.state, &document_id, &first).err(),
        Some("That attachment no longer exists.".to_string())
    );
    assert_eq!(bytes(&vault), after_remove);
    assert_eq!(
        add_document_attachment_in_state(
            &vault.state,
            "fictional-missing",
            "fictional.txt",
            "text/plain",
            &data,
        )
        .err(),
        Some("That saved document no longer exists.".to_string())
    );
}

#[test]
fn deleting_a_record_moves_it_to_trash_and_advances_the_epoch() {
    let vault = vault();
    let card_id = save_card_in_state(card_input(None, "Fictional card", "", &[]), &vault.state)
        .expect("saved card")
        .id;
    let epoch = vault.state.session_epoch();

    let deleted = delete_record_in_state::<Card>(
        &vault.state,
        &format!("  {card_id}  "),
        "card",
        "Unlock your vault before deleting a card.",
        "Choose a saved card to delete.",
    )
    .expect("deleted card");

    assert_eq!(deleted.id, card_id);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    let stored = payload(&vault);
    assert!(stored.cards.is_empty());
    assert_eq!(stored.trash.len(), 1);
    assert_eq!(stored.trash[0].item.id(), card_id);
}

#[test]
fn deleting_a_missing_or_different_record_writes_nothing() {
    let vault = vault();
    let card_id = save_card_in_state(card_input(None, "Fictional card", "", &[]), &vault.state)
        .expect("saved card")
        .id;
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        delete_record_in_state::<Card>(
            &vault.state,
            "",
            "card",
            "Unlock your vault before deleting a card.",
            "Choose a saved card to delete.",
        )
        .err(),
        Some("Choose a saved card to delete.".to_string())
    );
    assert_eq!(
        delete_record_in_state::<Card>(
            &vault.state,
            "fictional-missing",
            "card",
            "Unlock your vault before deleting a card.",
            "Choose a saved card to delete.",
        )
        .err(),
        Some("That saved card no longer exists.".to_string())
    );
    assert_eq!(
        delete_record_in_state::<Card>(
            &vault.state,
            "fictional-login",
            "card",
            "Unlock your vault before deleting a card.",
            "Choose a saved card to delete.",
        )
        .err(),
        Some("That item id belongs to a different kind of saved item.".to_string())
    );

    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
    let stored = payload(&vault);
    assert_eq!(stored.cards.len(), 1);
    assert_eq!(stored.cards[0].id, card_id);
    assert!(stored.trash.is_empty());
}

#[test]
fn previewing_or_restoring_a_missing_history_version_writes_nothing() {
    let vault = vault();
    let card_id = save_card_in_state(card_input(None, "Fictional card", "", &[]), &vault.state)
        .expect("saved card")
        .id;
    save_card_in_state(
        card_input(Some(&card_id), "Fictional renamed card", "", &[]),
        &vault.state,
    )
    .expect("saved card");
    let history_id = payload(&vault).history[0].id.clone();
    assert_eq!(payload(&vault).history.len(), 1);
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        preview_history_version_in_state(&vault.state, "fictional-missing").err(),
        Some("That version is no longer available.".to_string())
    );
    assert_eq!(
        restore_history_version_in_state(&vault.state, "fictional-missing").err(),
        Some("That version is no longer available.".to_string())
    );
    assert_eq!(
        preview_history_version_in_state(&vault.state, "").err(),
        Some("Choose a version to preview.".to_string())
    );
    assert_eq!(
        restore_history_version_in_state(&vault.state, "").err(),
        Some("Choose a version to restore.".to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);

    let restored = restore_history_version_in_state(&vault.state, &history_id).expect("restored");
    assert_eq!(restored.restored_id, card_id);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    let stored = payload(&vault);
    assert_eq!(
        stored
            .cards
            .iter()
            .find(|card| card.id == card_id)
            .expect("card")
            .title,
        "Fictional card"
    );
    assert!(stored.history.iter().any(|entry| entry.id == history_id));
}

#[test]
fn previewing_or_restoring_a_missing_history_version_needs_an_unlocked_vault() {
    let vault = vault();
    lock(&vault);
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        preview_history_version_in_state(&vault.state, "fictional-version").err(),
        Some("Unlock your vault first.".to_string())
    );
    assert_eq!(
        restore_history_version_in_state(&vault.state, "fictional-version").err(),
        Some("Unlock your vault before restoring a version.".to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn previewing_or_restoring_a_missing_trashed_item_writes_nothing() {
    let vault = vault();
    let card_id = save_card_in_state(card_input(None, "Fictional card", "", &[]), &vault.state)
        .expect("saved card")
        .id;
    delete_record_in_state::<Card>(
        &vault.state,
        &card_id,
        "card",
        "Unlock your vault before deleting a card.",
        "Choose a saved card to delete.",
    )
    .expect("deleted card");
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        preview_trashed_item_in_state(&vault.state, "fictional-missing").err(),
        Some("That deleted item is no longer in trash.".to_string())
    );
    assert_eq!(
        restore_trashed_item_in_state(&vault.state, "fictional-missing").err(),
        Some("That deleted item is no longer in trash.".to_string())
    );
    assert_eq!(
        preview_trashed_item_in_state(&vault.state, "").err(),
        Some("Choose a deleted item to preview.".to_string())
    );
    assert_eq!(
        restore_trashed_item_in_state(&vault.state, "").err(),
        Some("Choose a deleted item to restore.".to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);

    let restored = restore_trashed_item_in_state(&vault.state, &card_id).expect("restored");
    assert_eq!(restored.restored_id, card_id);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    let stored = payload(&vault);
    assert_eq!(stored.cards.len(), 1);
    assert_eq!(stored.cards[0].id, card_id);
    assert!(stored.trash.is_empty());
}

#[test]
fn restoring_a_trashed_item_needs_an_unlocked_vault() {
    let vault = vault();
    lock(&vault);
    let before = bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        preview_trashed_item_in_state(&vault.state, "fictional-item").err(),
        Some("Unlock your vault first.".to_string())
    );
    assert_eq!(
        restore_trashed_item_in_state(&vault.state, "fictional-item").err(),
        Some("Unlock your vault before restoring an item.".to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn a_locked_note_cannot_be_previewed_or_unlocked_without_presence() {
    let vault = vault();
    let presence = ReleasePresence::default();
    let note_id = save_secure_note_in_state(note_input(None, CANARY, true, &[]), &vault.state)
        .expect("saved note")
        .id;

    let view = record_view_in_state(&vault.state, &note_id, "note", note_of).expect("note view");
    assert!(view.record.content.is_empty());
    assert_eq!(view.secret_fields, vec!["content".to_string()]);
    assert!(!serde_json::to_string(&view)
        .expect("serialized note view")
        .contains(CANARY));

    assert_eq!(
        item_field_in_state(&vault.state, &presence, &note_id, "secure_note", "content")
            .map(|value| value.to_string()),
        Err(PRESENCE_REQUIRED.to_string())
    );

    let before = bytes(&vault);
    assert_eq!(
        set_secure_note_lock_in_state(&note_id, false, &vault.state, &presence).map(|_| ()),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert!(payload(&vault).secure_notes[0].locked);

    grant(&vault, &presence);
    vault.state.advance_session_epoch();
    assert_eq!(
        set_secure_note_lock_in_state(&note_id, false, &vault.state, &presence).map(|_| ()),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(bytes(&vault), before);
    assert!(payload(&vault).secure_notes[0].locked);

    grant(&vault, &presence);
    set_secure_note_lock_in_state(&note_id, false, &vault.state, &presence).expect("unlocked");
    assert!(!payload(&vault).secure_notes[0].locked);
    grant(&vault, &presence);
    let view = record_view_in_state(&vault.state, &note_id, "note", note_of).expect("note view");
    assert_eq!(view.record.content, CANARY);
    assert!(view.secret_fields.is_empty());
    assert_eq!(
        item_field_in_state(&vault.state, &presence, &note_id, "secure_note", "content")
            .map(|value| value.to_string()),
        Err("Nothing is saved in that field for this item.".to_string())
    );
}

#[test]
fn a_note_save_cannot_turn_the_lock_off() {
    let vault = vault();
    let note_id = save_secure_note_in_state(note_input(None, CANARY, true, &[]), &vault.state)
        .expect("saved note")
        .id;

    save_secure_note_in_state(
        note_input(Some(&note_id), "", false, &["content"]),
        &vault.state,
    )
    .expect("saved note");

    let stored_payload = payload(&vault);
    let stored = stored_payload.secure_notes.first().expect("note");
    assert!(stored.locked);
    assert_eq!(stored.content, CANARY);
    assert_eq!(stored.revision, 2);
}
