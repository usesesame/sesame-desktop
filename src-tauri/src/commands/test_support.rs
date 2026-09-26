use std::path::PathBuf;

use sesame_core::api::{create_vault, open_vault_with_password};

use crate::vault::storage::commit_payload_change;
use crate::vault::{random_id, LoginInput, UnlockedVault, VaultEntry, VaultFile, VaultState};

const TEST_PASSWORD: &str = "fictional master password";

pub(crate) struct TestVault {
    pub state: VaultState,
    path: PathBuf,
    directory: PathBuf,
}

impl TestVault {
    pub(crate) fn with_login(id: &str, url: &str) -> Self {
        let (opened, _) =
            create_vault(TEST_PASSWORD, "Fictional vault").expect("created test vault");
        let directory = std::env::temp_dir().join(format!("sesame-command-{}", random_id()));
        let path = directory.join("vault.sesame");
        let mut session =
            UnlockedVault::from_opened(path.clone(), &opened).expect("unlocked vault");
        session.setup_complete = true;
        let mut payload = session.open_payload().expect("opened payload").clone();
        payload.entries.push(VaultEntry {
            id: id.to_string(),
            title: "Northwind".to_string(),
            url: url.to_string(),
            username: "fictional-user".to_string(),
            password: "fictional-stored-secret".to_string(),
            updated_at: 41,
            password_updated_at: 42,
            revision: 7,
            ..VaultEntry::default()
        });
        commit_payload_change(&mut session, payload).expect("seeded payload");
        let state = VaultState::default();
        *state.session.lock().expect("session lock") = Some(session);
        Self {
            state,
            path,
            directory,
        }
    }

    pub(crate) fn stored_login(&self, id: &str) -> VaultEntry {
        let bytes = std::fs::read(&self.path).expect("vault bytes");
        let file: VaultFile = serde_json::from_slice(&bytes).expect("vault file");
        let opened = open_vault_with_password(&file, TEST_PASSWORD).expect("opened vault");
        opened
            .payload
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .expect("stored login")
            .clone()
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn login_input(id: Option<&str>, url: &str, password: &str) -> LoginInput {
    LoginInput {
        id: id.map(str::to_string),
        title: "Northwind".to_string(),
        url: url.to_string(),
        urls: Vec::new(),
        tags: Vec::new(),
        username: "fictional-user".to_string(),
        email: String::new(),
        password: password.to_string(),
        folder: String::new(),
        folder_id: None,
        totp: None,
        backup_codes: Vec::new(),
        recovery_email: String::new(),
        recovery_phone: String::new(),
        recovery_not_applicable: false,
        notes: String::new(),
    }
}
