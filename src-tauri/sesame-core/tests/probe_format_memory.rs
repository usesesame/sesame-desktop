use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use sesame_core::{loader::VaultLoader, random_id};

struct CountingAllocator;

static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED_BYTES.fetch_add(new_size, Ordering::SeqCst);
        System.realloc(pointer, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn probing_the_format_does_not_build_the_ignored_field() {
    let ignored_bytes = 20 * 1024 * 1024;
    let mut document = String::with_capacity(ignored_bytes + 64);
    document.push_str("{\"formatVersion\":10,\"ignored\":\"");
    document.push_str(&"x".repeat(ignored_bytes));
    document.push_str("\"}");
    let path = std::env::temp_dir().join(format!("sesame-probe-{}.json", random_id()));
    std::fs::write(&path, &document).expect("hostile document");
    let bytes = std::fs::read(&path).expect("hostile document bytes");
    std::fs::remove_file(&path).expect("hostile document cleanup");
    let before = ALLOCATED_BYTES.load(Ordering::SeqCst);
    let format = VaultLoader::probe_format(&bytes).expect("declared format");
    let allocated = ALLOCATED_BYTES.load(Ordering::SeqCst) - before;
    assert_eq!(format, 10);
    assert!(
        allocated < 1024 * 1024,
        "probing allocated {allocated} bytes for a document with a 20 MiB ignored field"
    );
}
