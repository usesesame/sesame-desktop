use std::{fs, path::PathBuf};

use sesame_core::{
    api,
    loader::{Credential, VaultLoader},
    random_id,
    storage::{
        commit_payload_change, persist_session, write_vault_file, write_vault_file_without_previous,
    },
    Attachment, DocumentMetadata, UnlockedVault, MAX_VAULT_FILE_BYTES,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("sesame-save-limit-{}", random_id())))
    }

    fn path(&self) -> PathBuf {
        self.0.join("vault.sesame")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn vault_writer_accepts_the_reader_limit_and_rejects_the_next_byte_without_writes() {
    let directory = TestDirectory::new();
    let path = directory.path();
    let (opened, _) = api::create_vault("fictional review password", "Fictional vault")
        .expect("create fictional vault");
    let mut file = opened.file.clone();
    file.legacy_device_wrap = Some(String::new());
    let overhead = serde_json::to_vec(&file).expect("encode fixture").len();
    file.legacy_device_wrap = Some("a".repeat(MAX_VAULT_FILE_BYTES as usize - overhead));
    write_vault_file(&path, &file).expect("save at the reader limit");
    let saved = fs::read(&path).expect("saved bytes");
    assert_eq!(saved.len() as u64, MAX_VAULT_FILE_BYTES);
    VaultLoader::load(
        &saved,
        Credential::MasterPassword("fictional review password"),
    )
    .expect("authenticate saved vault");
    let previous = path.with_extension("sesame.prev");
    write_vault_file(&path, &file).expect("create previous copy");
    assert_eq!(fs::read(&previous).expect("previous bytes"), saved);
    file.legacy_device_wrap.as_mut().expect("padding").push('a');
    for writer in [write_vault_file, write_vault_file_without_previous] {
        assert!(writer(&path, &file).is_err());
        assert_eq!(fs::read(&path).expect("active preserved"), saved);
        assert_eq!(fs::read(&previous).expect("previous preserved"), saved);
        assert!(!path.with_extension("sesame.tmp").exists());
    }
}

#[test]
fn oversized_initial_save_creates_no_directory_or_file() {
    let directory = TestDirectory::new();
    let (opened, _) = api::create_vault("fictional review password", "Fictional vault")
        .expect("create fictional vault");
    let mut file = opened.file.clone();
    file.payload.ciphertext = "a".repeat(MAX_VAULT_FILE_BYTES as usize);
    for writer in [write_vault_file, write_vault_file_without_previous] {
        assert!(writer(&directory.path(), &file).is_err());
        assert!(!directory.0.exists());
    }
}

#[test]
fn oversized_attachment_changes_preserve_both_files_and_session_then_allow_a_smaller_save() {
    let directory = TestDirectory::new();
    let path = directory.path();
    let (opened, _) = api::create_vault("fictional review password", "Fictional vault")
        .expect("create fictional vault");
    let mut session = UnlockedVault::from_opened(path.clone(), &opened).expect("session");
    session.setup_complete = true;
    persist_session(&mut session).expect("initial save");
    persist_session(&mut session).expect("create previous copy");
    let active = fs::read(&path).expect("active bytes");
    let previous = fs::read(path.with_extension("sesame.prev")).expect("previous bytes");
    let original = session.open_payload().expect("original payload");
    let revision = original.revision;
    let mut changed = original.clone();
    drop(original);
    for document_index in 0..2 {
        let mut document = DocumentMetadata {
            id: format!("fictional-document-{document_index}"),
            title: "Fictional document".into(),
            revision: 1,
            ..DocumentMetadata::default()
        };
        for index in 0..4 {
            let size = 5 * 1024 * 1024;
            document.attachments.push(Attachment {
                id: format!("fictional-attachment-{document_index}-{index}"),
                filename: "fictional.bin".into(),
                content_type: "application/octet-stream".into(),
                size: size as u64,
                data: vec![42; size],
            });
        }
        changed.documents.push(document);
    }
    assert!(commit_payload_change(&mut session, changed).is_err());
    assert_eq!(fs::read(&path).expect("active preserved"), active);
    assert_eq!(
        fs::read(path.with_extension("sesame.prev")).expect("previous preserved"),
        previous
    );
    assert!(!path.with_extension("sesame.tmp").exists());
    let current = session.open_payload().expect("unchanged session");
    assert_eq!(current.revision, revision);
    assert!(current.documents.is_empty());
    let mut smaller = current.clone();
    drop(current);
    smaller.vault_name = "Fictional renamed vault".into();
    commit_payload_change(&mut session, smaller).expect("smaller save");
    let file = VaultLoader::read(&path).expect("read saved vault");
    let reopened = VaultLoader::open(
        &file,
        Credential::MasterPassword("fictional review password"),
    )
    .expect("authenticate saved vault");
    assert_eq!(reopened.payload.vault_name, "Fictional renamed vault");
    assert_eq!(reopened.payload.revision, revision + 1);
}
