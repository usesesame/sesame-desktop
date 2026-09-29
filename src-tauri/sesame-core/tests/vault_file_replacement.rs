#![cfg(unix)]

use std::fs;

use sesame_core::platform::replace_file;
use sesame_core::random_id;

#[test]
fn replacing_a_file_succeeds_in_a_temporary_directory() {
    let directory = std::env::temp_dir().join(format!("sesame-replacement-{}", random_id()));
    fs::create_dir_all(&directory).expect("test directory");
    let source = directory.join("replacement.tmp");
    let destination = directory.join("vault.sesame");
    fs::write(&source, b"fictional replacement contents").expect("replacement source");
    fs::write(&destination, b"fictional destination contents").expect("destination before");

    replace_file(&source, &destination).expect("replacement");

    assert_eq!(
        fs::read(&destination).expect("destination after replacement"),
        b"fictional replacement contents"
    );
    assert!(!source.exists());
    fs::remove_dir_all(&directory).expect("cleanup");
}
