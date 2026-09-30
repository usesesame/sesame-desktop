use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use sesame_core::snapshot::password_counts;
use sesame_core::types::{
    Attachment, Card, CustomFieldEntry, CustomRecord, DocumentMetadata, Folder, HistoryEntry,
    HistoryOperation, Identity, LegacyField, SecureNote, SoftwareLicense, SshKey, TaggedItem,
    TrashedItem, VaultEntry, VaultPayload, WifiNetwork,
};

struct ZeroedBeforeFree;

const TRACKED_ALLOCATIONS: usize = 4;

static TRACKED_POINTERS: [AtomicUsize; TRACKED_ALLOCATIONS] =
    [const { AtomicUsize::new(0) }; TRACKED_ALLOCATIONS];
static TRACKED_LENGTHS: [AtomicUsize; TRACKED_ALLOCATIONS] =
    [const { AtomicUsize::new(0) }; TRACKED_ALLOCATIONS];
static SAW_ZEROED_DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static WATCHED_PLAINTEXT_POINTER: AtomicUsize = AtomicUsize::new(0);
static WATCHED_PLAINTEXT_LENGTH: AtomicUsize = AtomicUsize::new(0);
static SAW_UNWIPED_PLAINTEXT_DEALLOC: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for ZeroedBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        for (index, tracked_pointer) in TRACKED_POINTERS.iter().enumerate() {
            if pointer as usize == tracked_pointer.load(Ordering::SeqCst) {
                let length = TRACKED_LENGTHS[index].load(Ordering::SeqCst);
                if length <= layout.size() {
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
                    if bytes.iter().all(|byte| *byte == 0) {
                        SAW_ZEROED_DEALLOCS.fetch_or(1 << index, Ordering::SeqCst);
                    }
                }
            }
        }
        let plaintext_pointer = WATCHED_PLAINTEXT_POINTER.load(Ordering::SeqCst);
        if plaintext_pointer != 0 {
            let plaintext_length = WATCHED_PLAINTEXT_LENGTH.load(Ordering::SeqCst);
            if plaintext_length != 0 && plaintext_length <= layout.size() {
                let plaintext = unsafe {
                    std::slice::from_raw_parts(plaintext_pointer as *const u8, plaintext_length)
                };
                let bytes = unsafe { std::slice::from_raw_parts(pointer, plaintext_length) };
                if bytes == plaintext {
                    SAW_UNWIPED_PLAINTEXT_DEALLOC.store(true, Ordering::SeqCst);
                }
            }
        }
        let plaintext_pointer = WATCHED_PLAINTEXT_POINTER.load(Ordering::SeqCst);
        if plaintext_pointer != 0 {
            let plaintext_length = WATCHED_PLAINTEXT_LENGTH.load(Ordering::SeqCst);
            if plaintext_length != 0 && plaintext_length <= layout.size() {
                let plaintext = unsafe {
                    std::slice::from_raw_parts(plaintext_pointer as *const u8, plaintext_length)
                };
                let bytes = unsafe { std::slice::from_raw_parts(pointer, plaintext_length) };
                if bytes == plaintext {
                    SAW_UNWIPED_PLAINTEXT_DEALLOC.store(true, Ordering::SeqCst);
                }
            }
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ZeroedBeforeFree = ZeroedBeforeFree;

static TRACKING_GATE: Mutex<()> = Mutex::new(());

fn tracking_gate() -> MutexGuard<'static, ()> {
    TRACKING_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn drop_and_require_zeroed<T>(value: T, pointer: *const u8, length: usize) {
    drop_and_require_all_zeroed(value, &[(pointer, length)]);
}

fn drop_and_require_all_zeroed<T>(value: T, allocations: &[(*const u8, usize)]) {
    assert!(
        !allocations.is_empty() && allocations.len() <= TRACKED_ALLOCATIONS,
        "unsupported tracked allocation count"
    );
    let _gate = tracking_gate();
    for (index, (pointer, length)) in allocations.iter().enumerate() {
        TRACKED_POINTERS[index].store(*pointer as usize, Ordering::SeqCst);
        TRACKED_LENGTHS[index].store(*length, Ordering::SeqCst);
    }
    SAW_ZEROED_DEALLOCS.store(0, Ordering::SeqCst);
    drop(value);
    let zeroed = SAW_ZEROED_DEALLOCS.load(Ordering::SeqCst);
    for index in 0..allocations.len() {
        TRACKED_POINTERS[index].store(0, Ordering::SeqCst);
        TRACKED_LENGTHS[index].store(0, Ordering::SeqCst);
    }
    let expected = (1_usize << allocations.len()) - 1;
    assert_eq!(
        zeroed, expected,
        "plaintext reached the allocator before it was zeroed"
    );
}

fn login(password: &str) -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.id = "login-a".to_string();
    entry.password = password.to_string();
    entry
}

fn require_no_unwiped_plaintext<T>(plaintext: &'static [u8], action: impl FnOnce() -> T) -> T {
    let _gate = tracking_gate();
    WATCHED_PLAINTEXT_POINTER.store(plaintext.as_ptr() as usize, Ordering::SeqCst);
    WATCHED_PLAINTEXT_LENGTH.store(plaintext.len(), Ordering::SeqCst);
    SAW_UNWIPED_PLAINTEXT_DEALLOC.store(false, Ordering::SeqCst);
    let value = action();
    let unwiped = SAW_UNWIPED_PLAINTEXT_DEALLOC.load(Ordering::SeqCst);
    WATCHED_PLAINTEXT_POINTER.store(0, Ordering::SeqCst);
    WATCHED_PLAINTEXT_LENGTH.store(0, Ordering::SeqCst);
    assert!(
        !unwiped,
        "a plaintext copy reached the allocator before it was zeroed"
    );
    value
}

#[test]
fn a_dropped_payload_zeroes_the_login_password() {
    let mut payload = VaultPayload::default();
    payload.entries.push(login("fictional-vault-password"));
    let pointer = payload.entries[0].password.as_ptr();
    let length = payload.entries[0].password.len();

    drop_and_require_zeroed(payload, pointer, length);
}

#[test]
fn a_dropped_tagged_item_zeroes_the_login_password() {
    let item = TaggedItem::Login(login("fictional-tagged-password"));
    let TaggedItem::Login(entry) = &item else {
        panic!("expected a login item");
    };
    let pointer = entry.password.as_ptr();
    let length = entry.password.len();

    drop_and_require_zeroed(item, pointer, length);
}

#[test]
fn a_dropped_vault_entry_zeroes_the_login_password() {
    let entry = login("fictional-entry-password");
    let pointer = entry.password.as_ptr();
    let length = entry.password.len();

    drop_and_require_zeroed(entry, pointer, length);
}

#[test]
fn a_dropped_document_zeroes_attachment_bytes() {
    let mut document = DocumentMetadata::default();
    document.id = "doc-a".to_string();
    document.title = "Passport".to_string();
    document.attachments = vec![Attachment {
        id: "attachment-a".to_string(),
        filename: "scan.png".to_string(),
        content_type: "image/png".to_string(),
        size: 26,
        data: b"fictional-attachment-bytes".to_vec(),
    }];
    let pointer = document.attachments[0].data.as_ptr();
    let length = document.attachments[0].data.len();

    drop_and_require_zeroed(document, pointer, length);
}

const SHARED_PASSWORD: &str = "fictional-shared-password";

#[test]
fn dropped_password_counts_zero_their_keys() {
    let mut payload = VaultPayload::default();
    payload.entries = vec![login(SHARED_PASSWORD), login(SHARED_PASSWORD)];
    let counts =
        require_no_unwiped_plaintext(SHARED_PASSWORD.as_bytes(), || password_counts(&payload));
    assert_eq!(counts.len(), 1, "duplicate passwords share one count entry");
    assert_eq!(counts.get(SHARED_PASSWORD).copied(), Some(2));
    let key = counts.keys().next().expect("one counted password");
    let pointer = key.as_ptr();
    let length = key.len();

    drop_and_require_zeroed(counts, pointer, length);
}

#[test]
fn a_dropped_trashed_item_zeroes_the_nested_password() {
    let trashed = TrashedItem {
        item: TaggedItem::Login(login("fictional-trashed-password")),
        deleted_at: 1_700_000_000,
    };
    let TaggedItem::Login(entry) = &trashed.item else {
        panic!("expected a login item");
    };
    let pointer = entry.password.as_ptr();
    let length = entry.password.len();

    drop_and_require_zeroed(trashed, pointer, length);
}

#[test]
fn a_dropped_history_entry_zeroes_the_id_and_nested_password() {
    let history = HistoryEntry {
        id: "fictional-history-id".to_string(),
        item: TaggedItem::Login(login("fictional-history-password")),
        captured_at: 1_700_000_000,
        operation: HistoryOperation::Edit,
    };
    let TaggedItem::Login(entry) = &history.item else {
        panic!("expected a login item");
    };
    let password_pointer = entry.password.as_ptr();
    let password_length = entry.password.len();
    let id_pointer = history.id.as_ptr();
    let id_length = history.id.len();

    drop_and_require_all_zeroed(
        history,
        &[(id_pointer, id_length), (password_pointer, password_length)],
    );
}

#[test]
fn a_dropped_secure_note_zeroes_the_content() {
    let mut note = SecureNote::default();
    note.id = "note-a".to_string();
    note.title = "Recovery codes".to_string();
    note.content = "fictional-secure-note-content".to_string();
    let pointer = note.content.as_ptr();
    let length = note.content.len();

    drop_and_require_zeroed(note, pointer, length);
}

#[test]
fn a_dropped_card_zeroes_the_number() {
    let mut card = Card::default();
    card.id = "card-a".to_string();
    card.title = "Travel card".to_string();
    card.number = "4111111111111111".to_string();
    let pointer = card.number.as_ptr();
    let length = card.number.len();

    drop_and_require_zeroed(card, pointer, length);
}

#[test]
fn a_dropped_wifi_network_zeroes_the_password() {
    let mut network = WifiNetwork::default();
    network.id = "wifi-a".to_string();
    network.title = "Home network".to_string();
    network.ssid = "fictional-ssid".to_string();
    network.password = "fictional-wifi-password".to_string();
    let pointer = network.password.as_ptr();
    let length = network.password.len();

    drop_and_require_zeroed(network, pointer, length);
}

#[test]
fn a_dropped_ssh_key_zeroes_the_private_key() {
    let mut key = SshKey::default();
    key.id = "ssh-a".to_string();
    key.title = "Deploy key".to_string();
    key.key_type = "ed25519".to_string();
    key.private_key = "fictional-ssh-private-key".to_string();
    let pointer = key.private_key.as_ptr();
    let length = key.private_key.len();

    drop_and_require_zeroed(key, pointer, length);
}

#[test]
fn a_dropped_software_license_zeroes_the_license_key() {
    let mut license = SoftwareLicense::default();
    license.id = "license-a".to_string();
    license.title = "Editor license".to_string();
    license.license_key = "fictional-license-key".to_string();
    let pointer = license.license_key.as_ptr();
    let length = license.license_key.len();

    drop_and_require_zeroed(license, pointer, length);
}

#[test]
fn a_dropped_custom_field_entry_zeroes_the_value() {
    let field = CustomFieldEntry {
        label: "API token".to_string(),
        value: "fictional-custom-field-value".to_string(),
        kind: "text".to_string(),
    };
    let pointer = field.value.as_ptr();
    let length = field.value.len();

    drop_and_require_zeroed(field, pointer, length);
}

#[test]
fn a_dropped_custom_record_zeroes_the_notes() {
    let mut record = CustomRecord::default();
    record.id = "record-a".to_string();
    record.title = "Home router".to_string();
    record.fields = vec![CustomFieldEntry {
        label: "Admin password".to_string(),
        value: "fictional-record-field-value".to_string(),
        kind: "password".to_string(),
    }];
    record.notes = "fictional-custom-record-notes".to_string();
    let pointer = record.notes.as_ptr();
    let length = record.notes.len();

    drop_and_require_zeroed(record, pointer, length);
}

#[test]
fn a_dropped_identity_zeroes_the_full_name() {
    let mut identity = Identity::default();
    identity.id = "identity-a".to_string();
    identity.label = "Passport".to_string();
    identity.full_name = "Fictional Person".to_string();
    let pointer = identity.full_name.as_ptr();
    let length = identity.full_name.len();

    drop_and_require_zeroed(identity, pointer, length);
}

#[test]
fn a_dropped_folder_zeroes_the_name() {
    let folder = Folder {
        id: "folder-a".to_string(),
        name: "fictional-folder-name".to_string(),
    };
    let pointer = folder.name.as_ptr();
    let length = folder.name.len();

    drop_and_require_zeroed(folder, pointer, length);
}

#[test]
fn a_dropped_legacy_field_zeroes_the_value() {
    let field = LegacyField {
        label: "PIN".to_string(),
        value: "fictional-legacy-field-value".to_string(),
        secret: true,
    };
    let pointer = field.value.as_ptr();
    let length = field.value.len();

    drop_and_require_zeroed(field, pointer, length);
}
