use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::devicelist::{DeviceList, DeviceListEntry};
use super::identity::{ensure_device_protection, protect_for_device, unprotect_for_device};
use super::key_change::PreparedRecovery;
use crate::vault::VaultResult;

pub const JOURNAL_FILE_NAME: &str = "sync-rekey-journal.sesame";
const JOURNAL_VERSION: u8 = 1;
const UNREADABLE: &str = "Sesame could not read the saved vault key change.";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredJournal {
    version: u8,
    vault_id: String,
    entry_index: u64,
    entry_digest: String,
    base_head_digest: String,
    epoch_after: u64,
    created_at: u64,
    protected_key: String,
    #[serde(default)]
    recovery: Option<PreparedRecovery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Adopt,
    Discard,
}

pub struct Journal {
    pub vault_id: String,
    pub entry_index: u64,
    pub entry_digest: String,
    pub base_head_digest: String,
    pub epoch_after: u64,
    pub created_at: u64,
    pub recovery: Option<PreparedRecovery>,
    key: Zeroizing<[u8; 32]>,
}

pub fn journal_path(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(JOURNAL_FILE_NAME)
}

pub fn is_pending(path: &Path) -> bool {
    path.exists()
}

pub fn forget(path: &Path) -> VaultResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the saved vault key change.".to_string()),
    }
}

impl Journal {
    pub fn new(
        entry: &DeviceListEntry,
        base_head_digest: &str,
        key: &[u8; 32],
        recovery: PreparedRecovery,
        created_at: u64,
    ) -> Self {
        Self {
            vault_id: entry.vault_id.clone(),
            entry_index: entry.index,
            entry_digest: entry.digest(),
            base_head_digest: base_head_digest.to_string(),
            epoch_after: entry.epoch_after,
            created_at,
            recovery: Some(recovery),
            key: Zeroizing::new(*key),
        }
    }

    pub fn key(&self) -> [u8; 32] {
        *self.key
    }

    pub fn save(&self, path: &Path) -> VaultResult<()> {
        ensure_device_protection()?;
        let mut protected = protect_for_device(self.key.as_slice())?;
        let stored = StoredJournal {
            version: JOURNAL_VERSION,
            vault_id: self.vault_id.clone(),
            entry_index: self.entry_index,
            entry_digest: self.entry_digest.clone(),
            base_head_digest: self.base_head_digest.clone(),
            epoch_after: self.epoch_after,
            created_at: self.created_at,
            protected_key: URL_SAFE_NO_PAD.encode(&protected),
            recovery: self.recovery.clone(),
        };
        protected.zeroize();
        let body = serde_json::to_vec(&stored)
            .map_err(|_| "Sesame could not save the vault key change.".to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| "Sesame could not save the vault key change.".to_string())?;
        }
        crate::vault::storage::atomic_replace(path, &body)
            .map_err(|_| "Sesame could not save the vault key change.".to_string())
    }

    pub fn load(path: &Path) -> VaultResult<Self> {
        let body = std::fs::read(path).map_err(|_| UNREADABLE.to_string())?;
        let stored: StoredJournal =
            serde_json::from_slice(&body).map_err(|_| UNREADABLE.to_string())?;
        if stored.version != JOURNAL_VERSION
            || stored.vault_id.is_empty()
            || stored.entry_index < 2
            || stored.epoch_after < 2
            || stored.entry_digest.is_empty()
        {
            return Err(UNREADABLE.to_string());
        }
        let mut protected = URL_SAFE_NO_PAD
            .decode(&stored.protected_key)
            .map_err(|_| UNREADABLE.to_string())?;
        let opened = unprotect_for_device(&protected);
        protected.zeroize();
        let mut bytes = opened.map_err(|_| UNREADABLE.to_string())?;
        let key: Result<[u8; 32], _> = bytes.as_slice().try_into();
        bytes.zeroize();
        let key = key.map_err(|_| UNREADABLE.to_string())?;
        Ok(Self {
            vault_id: stored.vault_id,
            entry_index: stored.entry_index,
            entry_digest: stored.entry_digest,
            base_head_digest: stored.base_head_digest,
            epoch_after: stored.epoch_after,
            created_at: stored.created_at,
            recovery: stored.recovery,
            key: Zeroizing::new(key),
        })
    }

    pub fn outcome(&self, list: &DeviceList) -> Outcome {
        let adopt = list.vault_id() == self.vault_id
            && list.digest_at(self.entry_index) == Some(self.entry_digest.as_str())
            && list.epoch() == self.epoch_after;
        if adopt {
            Outcome::Adopt
        } else {
            Outcome::Discard
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::engine::{add_entry, create_entry, remove_entry, seal_label, NewDevice};
    use crate::sync::identity::DeviceIdentity;
    use crate::sync::key_change::fictional_recovery;

    const VAULT: &str = "vaultAAAAAAAAAAAA01";

    struct World {
        creator: DeviceIdentity,
        first: DeviceIdentity,
        second: DeviceIdentity,
        base: DeviceList,
    }

    fn world() -> World {
        let creator = DeviceIdentity::generate().expect("identity");
        let first = DeviceIdentity::generate().expect("identity");
        let second = DeviceIdentity::generate().expect("identity");
        let label = |device: &DeviceIdentity| {
            seal_label(&[9u8; 32], VAULT, &device.device_id, "Device").expect("label")
        };
        let mut list =
            DeviceList::verify(&[create_entry(&creator, VAULT, &label(&creator))]).expect("list");
        for joiner in [&first, &second] {
            let entry = add_entry(
                &creator,
                &list,
                &NewDevice {
                    device_id: &joiner.device_id,
                    signing_key: &URL_SAFE_NO_PAD.encode(joiner.signing_public_key()),
                    package_key: &URL_SAFE_NO_PAD.encode(joiner.package_public_key()),
                },
                &label(joiner),
                0,
            )
            .expect("add");
            list.extend(&entry).expect("extend");
        }
        World {
            creator,
            first,
            second,
            base: list,
        }
    }

    fn removal(world: &World, list: &DeviceList, subject: &DeviceIdentity) -> DeviceListEntry {
        remove_entry(&world.creator, list, &subject.device_id).expect("removal")
    }

    fn extended(list: &DeviceList, entry: &DeviceListEntry) -> DeviceList {
        let mut next = list.clone();
        next.extend(entry).expect("extend");
        next
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sesame-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        journal_path(&dir)
    }

    fn rewritten(path: &Path, change: impl FnOnce(&mut serde_json::Value)) {
        let mut body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        change(&mut body);
        std::fs::write(path, serde_json::to_vec(&body).unwrap()).unwrap();
    }

    fn saved(world: &World, name: &str) -> (PathBuf, DeviceListEntry) {
        let entry = removal(world, &world.base, &world.second);
        let path = scratch(name);
        Journal::new(
            &entry,
            world.base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1_700_000_000,
        )
        .save(&path)
        .expect("saved");
        (path, entry)
    }

    #[test]
    fn a_saved_journal_loads_with_the_same_key_and_facts() {
        let world = world();
        let (path, entry) = saved(&world, "round-trip");
        assert!(is_pending(&path));
        let loaded = Journal::load(&path).expect("loaded");
        assert_eq!(loaded.key(), [4u8; 32]);
        assert_eq!(loaded.vault_id, VAULT);
        assert_eq!(loaded.entry_index, entry.index);
        assert_eq!(loaded.entry_digest, entry.digest());
        assert_eq!(loaded.epoch_after, entry.epoch_after);
        assert_eq!(loaded.base_head_digest, world.base.head_digest());
        let recovery = loaded.recovery.as_ref().expect("recovery");
        assert_eq!(recovery.wrap.nonce, "fictional-nonce");
        assert_eq!(recovery.kdf.salt, "fictional-salt");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_journal_from_a_build_that_kept_no_recovery_wrap_still_loads_without_one() {
        let world = world();
        let (path, _) = saved(&world, "no-recovery");
        rewritten(&path, |body| {
            body.as_object_mut().unwrap().remove("recovery");
        });
        let loaded = Journal::load(&path).expect("loaded");
        assert!(loaded.recovery.is_none());
        assert_eq!(loaded.key(), [4u8; 32]);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn saving_again_replaces_the_journal_and_forgetting_twice_is_fine() {
        let world = world();
        let (path, entry) = saved(&world, "replace");
        Journal::new(
            &entry,
            world.base.head_digest(),
            &[5u8; 32],
            fictional_recovery(),
            1,
        )
        .save(&path)
        .expect("saved");
        assert_eq!(Journal::load(&path).expect("loaded").key(), [5u8; 32]);
        forget(&path).expect("forgotten");
        forget(&path).expect("forgetting twice is fine");
        assert!(!is_pending(&path));
        assert!(Journal::load(&path).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_damaged_or_foreign_journal_is_refused() {
        let world = world();
        let (path, _) = saved(&world, "damaged");
        std::fs::write(&path, b"not json").unwrap();
        assert!(Journal::load(&path).is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(Journal::load(&path).is_err());

        let cases: [(&str, serde_json::Value); 7] = [
            ("version", serde_json::json!(2)),
            ("vaultId", serde_json::json!("")),
            ("entryIndex", serde_json::json!(1)),
            ("epochAfter", serde_json::json!(1)),
            ("entryDigest", serde_json::json!("")),
            (
                "protectedKey",
                serde_json::json!(URL_SAFE_NO_PAD.encode([4u8; 31])),
            ),
            ("protectedKey", serde_json::json!("not base64!")),
        ];
        for (field, value) in cases {
            let (path, _) = saved(&world, "field");
            rewritten(&path, |body| body[field] = value);
            assert!(Journal::load(&path).is_err(), "{field}");
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
        let (path, _) = saved(&world, "extra");
        rewritten(&path, |body| body["extra"] = serde_json::json!(true));
        assert!(Journal::load(&path).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_removal_that_reached_the_list_is_adopted() {
        let world = world();
        let entry = removal(&world, &world.base, &world.second);
        let journal = Journal::new(
            &entry,
            world.base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        );
        let committed = extended(&world.base, &entry);
        assert_eq!(journal.outcome(&committed), Outcome::Adopt);
    }

    #[test]
    fn a_removal_that_never_reached_the_list_is_discarded() {
        let world = world();
        let entry = removal(&world, &world.base, &world.second);
        let journal = Journal::new(
            &entry,
            world.base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        );
        assert_eq!(journal.outcome(&world.base), Outcome::Discard);
    }

    #[test]
    fn another_removal_at_the_same_place_or_a_later_key_change_is_discarded() {
        let world = world();
        let ours = removal(&world, &world.base, &world.second);
        let journal = Journal::new(
            &ours,
            world.base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        );

        let theirs = removal(&world, &world.base, &world.first);
        assert_eq!(
            journal.outcome(&extended(&world.base, &theirs)),
            Outcome::Discard
        );

        let committed = extended(&world.base, &ours);
        let later = removal(&world, &committed, &world.first);
        let moved_on = extended(&committed, &later);
        assert_eq!(journal.outcome(&moved_on), Outcome::Discard);
    }

    #[test]
    fn a_journal_for_another_vault_is_discarded() {
        let world = world();
        let entry = removal(&world, &world.base, &world.second);
        let mut journal = Journal::new(
            &entry,
            world.base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        );
        journal.vault_id = "vaultBBBBBBBBBBBB02".to_string();
        assert_eq!(
            journal.outcome(&extended(&world.base, &entry)),
            Outcome::Discard
        );
    }
}
