use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use sesame_core::snapshot::password_counts;
use sesame_core::types::{Attachment, DocumentMetadata, VaultEntry, VaultPayload};

struct ZeroedBeforeFree;

static TRACKED_POINTER: AtomicUsize = AtomicUsize::new(0);
static TRACKED_LENGTH: AtomicUsize = AtomicUsize::new(0);
static SAW_ZEROED_DEALLOC: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for ZeroedBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if pointer as usize == TRACKED_POINTER.load(Ordering::SeqCst) {
            let length = TRACKED_LENGTH.load(Ordering::SeqCst);
            if length <= layout.size() {
                let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
                if bytes.iter().all(|byte| *byte == 0) {
                    SAW_ZEROED_DEALLOC.store(true, Ordering::SeqCst);
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
    let _gate = tracking_gate();
    TRACKED_POINTER.store(pointer as usize, Ordering::SeqCst);
    TRACKED_LENGTH.store(length, Ordering::SeqCst);
    SAW_ZEROED_DEALLOC.store(false, Ordering::SeqCst);
    drop(value);
    let zeroed = SAW_ZEROED_DEALLOC.load(Ordering::SeqCst);
    TRACKED_POINTER.store(0, Ordering::SeqCst);
    TRACKED_LENGTH.store(0, Ordering::SeqCst);
    assert!(
        zeroed,
        "plaintext reached the allocator before it was zeroed"
    );
}

#[test]
fn a_dropped_payload_zeroes_the_login_password() {
    let mut payload = VaultPayload::default();
    payload.entries.push(VaultEntry {
        id: "login-a".to_string(),
        password: "fictional-vault-password".to_string(),
        ..VaultEntry::default()
    });
    let pointer = payload.entries[0].password.as_ptr();
    let length = payload.entries[0].password.len();

    drop_and_require_zeroed(payload, pointer, length);
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

#[test]
fn dropped_password_counts_zero_their_keys() {
    let mut payload = VaultPayload::default();
    payload.entries = vec![VaultEntry {
        id: "login-a".to_string(),
        password: "fictional-shared-password".to_string(),
        ..VaultEntry::default()
    }];
    let counts = password_counts(&payload);
    let key = counts.keys().next().expect("one counted password");
    let pointer = key.as_ptr();
    let length = key.len();

    drop_and_require_zeroed(counts, pointer, length);
}
